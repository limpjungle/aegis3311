package pep

import (
	"context"
	"fmt"
	"sort"
	"strconv"

	"github.com/limpjungle/aegis3311/internal/catalog"
	"github.com/limpjungle/aegis3311/internal/policyengine"
	"github.com/limpjungle/aegis3311/internal/step"
)

// PolicyEvaluator — политика уровней и ограничителей (Rego).
type PolicyEvaluator interface {
	Eval(context.Context, any) (policyengine.Decision, error)
	Digest() string
}

// Engine — PEP. Состояние только читается: Evaluate безопасен для параллельных вызовов.
type Engine struct {
	cat   *catalog.Catalog
	pol   PolicyEvaluator
	rules step.Registry
}

func New(cat *catalog.Catalog, pol PolicyEvaluator) *Engine {
	return &Engine{cat: cat, pol: pol, rules: step.DefaultRegistry()}
}

// EvaluateRaw разбирает action из ответа модели и вычисляет вердикт; нечитаемое предложение — deny/proposal_invalid.
func (e *Engine) EvaluateRaw(ctx context.Context, proposal []byte, c Context) Verdict {
	p, err := ParseProposal(proposal)
	if err != nil {
		v := e.newVerdict(Proposal{}, c)
		v.Reasons = []Reason{{Code: "proposal_invalid", Source: "catalog", Effect: "deny", Detail: err.Error()}}
		return v
	}
	return e.Evaluate(ctx, p, c)
}

func (e *Engine) newVerdict(p Proposal, c Context) Verdict {
	v := Verdict{Schema: VerdictSchema, Mode: ModeDryRun, Decision: "deny",
		Action:  VerdictAction{Type: p.Type, Params: p.Params, Computed: map[string]any{}},
		Ceiling: "L0", EffectiveLevel: "L0", Reasons: []Reason{},
		CatalogDigest: e.cat.Digest(), PolicyDigest: e.pol.Digest(), InputDigest: inputDigest(p, c)}
	if c.Level != nil && c.Level.Level != nil {
		v.RequestedLevel = *c.Level.Level
	}
	return v
}

// Evaluate никогда не возвращает ошибку: любой сбой — deny.
func (e *Engine) Evaluate(ctx context.Context, p Proposal, c Context) Verdict {
	v := e.newVerdict(p, c)
	var rs []Reason
	deny := func(code, source, format string, a ...any) {
		rs = append(rs, Reason{Code: code, Source: source, Effect: "deny", Detail: fmt.Sprintf(format, a...)})
	}
	done := func() Verdict {
		sortReasons(rs)
		v.Reasons = append(v.Reasons, rs...)
		return v
	}

	// 1. recommend / none: действия нет, нужны только пустые параметры.
	if p.Type == "recommend" || p.Type == "none" {
		if p.Params != (ModelParams{}) {
			deny("param_unexpected", "catalog", "%s не принимает параметры", p.Type)
			return done()
		}
		v.Decision = "noop"
		return v
	}

	// 2. Действие должно быть в каталоге.
	entry, ok := e.cat.Get(p.Type)
	ctxProblems := c.Validate()
	if !ok {
		deny("unknown_action", "catalog", "действия %q нет в каталоге", p.Type)
		if len(ctxProblems) == 0 {
			if d, err := e.pol.Eval(ctx, e.policyInput(unknownEntry(p.Type), "", nil, p.Params, c)); err == nil {
				for _, r := range d.Deny {
					if r.Code == "forbidden_action" {
						deny(r.Code, "policy", "%s", r.Detail)
					}
				}
			}
		}
		return done()
	}
	v.Action.Version, v.Action.Reversibility = entry.Version, string(entry.Reversibility)

	// 3. Контекст.
	if len(ctxProblems) > 0 {
		rs = append(rs, ctxProblems...)
		return done()
	}

	// 4. Действие должно быть доступно для цели.
	var av *step.AvailableAction
	for _, a := range step.Available(e.cat, *c.State) {
		if a.Type == p.Type {
			a := a
			av = &a
			break
		}
	}
	if av == nil {
		deny("action_unavailable", "step", "%s недоступно для цели в текущем состоянии", p.Type)
		return done()
	}

	// 5. Параметры модели.
	e.checkParams(entry, av, p, deny)

	// 6. Вычисленные величины и повторная проверка границ.
	for k, val := range av.Computed {
		v.Action.Computed[k] = val
	}
	var goCaps []Reason
	e.checkBounds(entry, av, *c.State, deny)
	for name, param := range entry.Params {
		dep := dependsValue(param, p.Params)
		if dep == nil {
			continue
		}
		if variant, ok := param.Variants[*dep]; ok && variant.RecommendationOnly {
			delete(v.Action.Computed, name)
			goCaps = append(goCaps, Reason{Code: "recommendation_only", Source: "catalog", Effect: "cap", Level: "L1",
				Detail: fmt.Sprintf("%s=%s: правила шага нет, только рекомендация", param.DependsOn, *dep)})
		}
	}

	// 7. Цель.
	kind, skip := targetKind(p, *c.State)
	if !skip {
		if !contains(entry.Targets.Kinds, kind) {
			deny("target_kind_mismatch", "catalog", "тип цели %q не входит в targets.kinds", kind)
		}
	}
	for _, k := range sortedKeys(entry.Targets.Labels) {
		if got, ok := c.TargetLabels[k]; !ok || got != entry.Targets.Labels[k] {
			deny("target_labels_mismatch", "catalog", "у цели нет метки %s=%s", k, entry.Targets.Labels[k])
		}
	}
	v.Target = &TargetRef{Kind: kind, Namespace: *c.Namespace, Environment: *c.Environment}

	// 8. Политика.
	d, err := e.pol.Eval(ctx, e.policyInput(entry, kind, av.Computed, p.Params, c))
	if err != nil {
		deny("policy_error", "policy", "%v", err)
		return done()
	}
	v.Ceiling, v.PolicyRevision = d.Ceiling, d.PolicyRevision
	for _, r := range d.Deny {
		rs = append(rs, Reason{Code: r.Code, Source: "policy", Effect: "deny", Detail: r.Detail})
	}
	for _, r := range d.Caps {
		rs = append(rs, Reason{Code: r.Code, Source: "policy", Effect: "cap", Level: r.Level, Detail: r.Detail})
	}
	rs = append(rs, goCaps...)

	// 9. Слияние: effective = min(requested, политика, caps); L0 без deny → noop.
	if hasDeny(rs) {
		return done()
	}
	if _, known := levelRank[d.EffectiveLevel]; !known {
		deny("policy_error", "policy", "неизвестный уровень в решении: %q", d.EffectiveLevel)
		return done()
	}
	eff := minLevel(v.RequestedLevel, d.EffectiveLevel)
	for _, r := range goCaps {
		eff = minLevel(eff, r.Level)
	}
	v.EffectiveLevel = eff
	switch {
	case eff == "L0":
		v.Decision = "noop" // на L0 агент ничего не исполняет; caps остаются в reasons
	case eff != v.RequestedLevel:
		v.Decision = "downgrade"
	default:
		v.Decision = "allow"
	}
	return done()
}

func hasDeny(rs []Reason) bool {
	for _, r := range rs {
		if r.Effect == "deny" {
			return true
		}
	}
	return false
}

// checkParams проверяет параметры, выбираемые моделью, по записи каталога.
func (e *Engine) checkParams(entry *catalog.Entry, av *step.AvailableAction, p Proposal, deny func(code, source, format string, a ...any)) {
	vals := map[string]*string{"scope": p.Params.Scope, "pod_name": p.Params.PodName, "reason": p.Params.Reason, "parameter": p.Params.Parameter}
	for _, n := range sortedKeys(vals) {
		val := vals[n]
		cp, declared := entry.Params[n]
		if !declared || cp.ChosenBy != "model" {
			if val != nil {
				deny("param_unexpected", "catalog", "параметр %s не выбирается моделью для %s", n, entry.Name)
			}
			continue
		}
		if cp.RequiredIf != nil {
			dep := vals[cp.RequiredIf.Param]
			switch {
			case dep == nil: // об отсутствии зависимого параметра сообщит его собственная проверка
			case *dep != cp.RequiredIf.Equals:
				if val != nil {
					deny("param_unexpected", "catalog", "%s допустим только при %s == %s", n, cp.RequiredIf.Param, cp.RequiredIf.Equals)
				}
			case val == nil:
				deny("param_missing", "catalog", "%s обязателен при %s == %s", n, cp.RequiredIf.Param, cp.RequiredIf.Equals)
			default:
				checkEnum(n, *val, cp, av, deny)
			}
			continue
		}
		if val == nil {
			deny("param_missing", "catalog", "параметр %s обязателен", n)
			continue
		}
		checkEnum(n, *val, cp, av, deny)
	}
}

func checkEnum(name, val string, cp catalog.Param, av *step.AvailableAction, deny func(code, source, format string, a ...any)) {
	enum, code := cp.Enum, "param_not_in_enum"
	if cp.EnumFrom != "" {
		enum = av.Params[name].Enum
		if cp.EnumFrom == "target.pods" {
			code = "pod_not_found"
		}
	}
	if !contains(enum, val) {
		deny(code, "catalog", "значение %q параметра %s вне допустимых", val, name)
	}
}

// checkBounds повторно проверяет вычисленные величины по границам каталога.
func (e *Engine) checkBounds(entry *catalog.Entry, av *step.AvailableAction, s step.TargetState, deny func(code, source, format string, a ...any)) {
	for _, n := range sortedKeys(entry.Params) {
		cp := entry.Params[n]
		if cp.ChosenBy != "catalog" || cp.Bounds == nil {
			continue
		}
		val, isInt := av.Computed[n].(int)
		lim, ok := e.rules[cp.Bounds.Rule].Limits, false
		var b step.Bounds
		if lim != nil {
			b, ok = lim(s)
		}
		if !isInt || !ok {
			deny("computed_out_of_bounds", "step", "не удалось проверить границы %s (%s)", n, cp.Bounds.Rule)
			continue
		}
		if val < b.Min || val > b.Max {
			deny("computed_out_of_bounds", "step", "%s=%d вне границ [%d, %d]", n, val, b.Min, b.Max)
		}
		if lit, err := strconv.Atoi(cp.Bounds.Minimum); err == nil && val < lit {
			deny("computed_out_of_bounds", "step", "%s=%d меньше минимума каталога %d", n, val, lit)
		}
	}
}

// dependsValue возвращает значение параметра модели, от которого зависят варианты param.
func dependsValue(param catalog.Param, m ModelParams) *string {
	switch param.DependsOn {
	case "parameter":
		return m.Parameter
	case "scope":
		return m.Scope
	case "reason":
		return m.Reason
	}
	return nil
}

// targetKind определяет тип цели по действию и состоянию. skip=true — тип не определён из-за ошибок параметров, они уже учтены.
func targetKind(p Proposal, s step.TargetState) (kind string, skip bool) {
	switch p.Type {
	case "workload.scale_out", "workload.scale_in":
		if s.Autoscaler == nil {
			return "", false
		}
		switch s.Autoscaler.Kind {
		case "HorizontalPodAutoscaler":
			return "autoscaling/HorizontalPodAutoscaler", false
		case "ScaledObject":
			return "keda.sh/ScaledObject", false
		}
	case "workload.restart":
		switch {
		case p.Params.Scope == nil:
			return "", true
		case *p.Params.Scope == "pod":
			return "core/Pod", false
		case *p.Params.Scope == "deployment":
			return "apps/Deployment", false
		}
		return "", true
	case "rollout.abort_and_rollback":
		return "argoproj.io/Rollout", false
	case "pgbouncer.resize_pool":
		return "pgbouncer", false
	case "postgres.set_restart_param":
		return "postgresql-cluster", false
	}
	return "", false
}

// unknownEntry — самая строгая заглушка для действия вне каталога: нужна, чтобы политика проверила запрещённые имена.
func unknownEntry(name string) *catalog.Entry {
	return &catalog.Entry{Name: name, Reversibility: catalog.R3, Lease: "required", ErrorBudgetExhausted: "frozen",
		DegradedMode: "forbidden", RateLimit: catalog.RateLimit{PerTargetPerHour: 1}}
}

// policyInput собирает вход Rego. Контекст к этому моменту валиден (все указатели заполнены).
// computed — вычисленные step поля действия (action.computed); nil превращается в пустой объект, не в null.
func (e *Engine) policyInput(entry *catalog.Entry, kind string, computed map[string]any, mp ModelParams, c Context) map[string]any {
	cp := make(map[string]any, len(computed))
	for k, v := range computed {
		cp[k] = v
	}
	// Дискретные параметры модели: null — «не используется» (как в схеме ответа v2).
	params := map[string]any{}
	for k, v := range map[string]*string{"scope": mp.Scope, "pod_name": mp.PodName, "reason": mp.Reason, "parameter": mp.Parameter} {
		if v == nil {
			params[k] = nil
		} else {
			params[k] = *v
		}
	}
	// Вердикт анализа текущей ревизии; "" — анализа нет (или нет rollout).
	verdict := ""
	if r := c.State.Rollout; r != nil {
		verdict = r.AnalysisVerdict
	}
	f := c.Flags
	actions := f.KillSwitch.Actions
	if actions == nil {
		actions = []string{}
	}
	return map[string]any{
		"action": map[string]any{
			"type": entry.Name, "version": entry.Version, "reversibility": string(entry.Reversibility), "lease": entry.Lease,
			"error_budget_exhausted": entry.ErrorBudgetExhausted, "degraded_mode": entry.DegradedMode,
			"rate_limit": map[string]any{"per_target_per_hour": entry.RateLimit.PerTargetPerHour,
				"cooldown_seconds": int(entry.RateLimit.Cooldown.Seconds())},
			"computed": cp,
			"params":   params,
		},
		"target": map[string]any{"environment": *c.Environment, "namespace": *c.Namespace,
			"namespace_labels": c.NamespaceLabels, "kind": kind, "analysis_verdict": verdict},
		"level": map[string]any{"granted": *c.Level.Level, "by_data": *c.Level.ByData},
		"flags": map[string]any{
			"kill_switch":        map[string]any{"global": *f.KillSwitch.Global, "cluster": *f.KillSwitch.Cluster, "actions": actions},
			"liveness_confirmed": *f.LivenessConfirmed, "error_budget_exhausted": *f.ErrorBudgetExhausted,
			"degraded_mode": *f.DegradedMode, "runbook_preapproved": *f.RunbookPreapproved,
			"degraded_policy_allows_r2": *f.DegradedPolicyAllowsR2, "policy_cache_expired": *f.PolicyCacheExpired,
			"lease_held": *f.LeaseHeld, "human_engaged": *f.HumanEngaged, "circuit_breaker_open": *f.CircuitBreakerOpen,
		},
		"history": map[string]any{"actions_last_hour": *c.History.ActionsLastHour, "seconds_since_last": c.History.SecondsSinceLast},
	}
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

func sortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
