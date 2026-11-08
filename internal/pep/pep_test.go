package pep_test

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"

	catalogdata "github.com/limpjungle/aegis3311/catalog"
	"github.com/limpjungle/aegis3311/internal/catalog"
	"github.com/limpjungle/aegis3311/internal/pep"
	"github.com/limpjungle/aegis3311/internal/policyengine"
)

func TestParseProposal(t *testing.T) {
	ok := `{"type":"workload.restart","params":{"scope":"pod","pod_name":"p","reason":null,"parameter":null}}`
	p, err := pep.ParseProposal([]byte(ok))
	if err != nil || p.Type != "workload.restart" || *p.Params.Scope != "pod" || *p.Params.PodName != "p" || p.Params.Reason != nil {
		t.Fatalf("валидный: %+v %v", p, err)
	}
	bad := map[string]string{
		"без parameter":    `{"type":"none","params":{"scope":null,"pod_name":null,"reason":null}}`,
		"лишний ключ":      `{"type":"none","params":{"scope":null,"pod_name":null,"reason":null,"parameter":null,"x":null}}`,
		"scope число":      `{"type":"none","params":{"scope":1,"pod_name":null,"reason":null,"parameter":null}}`,
		"лишний в action":  `{"type":"none","extra":1,"params":{"scope":null,"pod_name":null,"reason":null,"parameter":null}}`,
		"нет params":       `{"type":"none"}`,
		"нет type":         `{"params":{"scope":null,"pod_name":null,"reason":null,"parameter":null}}`,
		"type не строка":   `{"type":1,"params":{"scope":null,"pod_name":null,"reason":null,"parameter":null}}`,
		"params null":      `{"type":"none","params":null}`,
		"не объект":        `[]`,
		"хвост после JSON": `{"type":"none","params":{"scope":null,"pod_name":null,"reason":null,"parameter":null}} x`,
		"пустой type":      `{"type":"","params":{"scope":null,"pod_name":null,"reason":null,"parameter":null}}`,
	}
	for name, in := range bad {
		if _, err := pep.ParseProposal([]byte(in)); err == nil {
			t.Errorf("%s: ошибка не возвращена", name)
		}
	}
}

// restrictedCatalog — встроенный каталог с заменой в одном файле.
func restrictedCatalog(t *testing.T, file, old, nw string) *catalog.Catalog {
	t.Helper()
	fsys := fstest.MapFS{}
	entries, err := catalogdata.FS.ReadDir("actions")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		b, _ := catalogdata.FS.ReadFile("actions/" + e.Name())
		if e.Name() == file {
			if !strings.Contains(string(b), old) {
				t.Fatalf("нет фрагмента %q", old)
			}
			b = []byte(strings.Replace(string(b), old, nw, 1))
		}
		fsys[e.Name()] = &fstest.MapFile{Data: b}
	}
	cat, err := catalog.Load(fsys)
	if err != nil {
		t.Fatal(err)
	}
	return cat
}

type scenario struct {
	name   string
	eng    *pep.Engine // nil — стандартный
	typ    string
	params pep.ModelParams
	mut    func(*pep.Context)
	want   string   // decision
	level  string   // effective_level
	codes  []string // "effect:code", все должны присутствовать
	exact  bool     // набор причин должен совпадать с codes
}

func TestEvaluate_Table(t *testing.T) {
	std := newEngine(t)
	seen := map[string]bool{}
	cases := []scenario{
		{name: "scale_out staging L3", typ: "workload.scale_out", want: "allow", level: "L3", exact: true},
		{name: "scale_in prod-cloud-hybrid", typ: "workload.scale_in", want: "downgrade", level: "L2", exact: true,
			mut: func(c *pep.Context) { c.Environment = sp("prod-cloud-hybrid") }, codes: []string{"cap:matrix_ceiling"}},
		{name: "resize prod by_data", typ: "pgbouncer.resize_pool", want: "allow", level: "L3", exact: true,
			mut: func(c *pep.Context) { c.Environment = sp("prod-cloud-hybrid"); c.Level.ByData = bp(true) }},
		{name: "restart pod ok", typ: "workload.restart", params: params(sp("pod"), sp("geo-svc-aaa-11111"), nil, nil), want: "allow", level: "L3", exact: true},
		{name: "restart deployment ok", typ: "workload.restart", params: params(sp("deployment"), nil, nil, nil), want: "allow", level: "L3", exact: true},
		{name: "restart чужой pod", typ: "workload.restart", params: params(sp("pod"), sp("other-pod"), nil, nil), want: "deny", level: "L0", codes: []string{"deny:pod_not_found"}},
		{name: "restart deployment с pod_name", typ: "workload.restart", params: params(sp("deployment"), sp("geo-svc-aaa-11111"), nil, nil), want: "deny", level: "L0", codes: []string{"deny:param_unexpected"}},
		{name: "restart pod без pod_name", typ: "workload.restart", params: params(sp("pod"), nil, nil, nil), want: "deny", level: "L0", codes: []string{"deny:param_missing"}},
		{name: "restart без scope", typ: "workload.restart", params: params(nil, nil, nil, nil), want: "deny", level: "L0", codes: []string{"deny:param_missing"}},
		{name: "restart scope вне enum", typ: "workload.restart", params: params(sp("node"), nil, nil, nil), want: "deny", level: "L0", codes: []string{"deny:param_not_in_enum"}},
		{name: "rollout reason вне enum", typ: "rollout.abort_and_rollback", params: params(nil, nil, sp("bogus"), nil), want: "deny", level: "L0", codes: []string{"deny:param_not_in_enum"}},
		{name: "rollout ok", typ: "rollout.abort_and_rollback", params: params(nil, nil, sp("canary_degradation"), nil), want: "allow", level: "L3", exact: true},
		{name: "rollout без анализа", typ: "rollout.abort_and_rollback", params: params(nil, nil, sp("canary_degradation"), nil), want: "downgrade", level: "L1",
			codes: []string{"cap:analysis_missing"}, exact: true, mut: func(c *pep.Context) { c.State.Rollout.AnalysisRun = "" }},
		{name: "rollout без анализа в Bake", typ: "rollout.abort_and_rollback", params: params(nil, nil, sp("canary_degradation"), nil), want: "downgrade", level: "L1",
			codes: []string{"cap:analysis_missing"}, exact: true, mut: func(c *pep.Context) { c.State.Rollout.Phase = "Bake"; c.State.Rollout.AnalysisRun = "" }},
		{name: "rollout без анализа, insufficient_data_policy", typ: "rollout.abort_and_rollback", params: params(nil, nil, sp("insufficient_data_policy"), nil), want: "downgrade", level: "L1",
			codes: []string{"cap:analysis_missing"}, exact: true, mut: func(c *pep.Context) { c.State.Rollout.AnalysisRun = "" }},
		{name: "rollout без анализа, запрошен L0", typ: "rollout.abort_and_rollback", params: params(nil, nil, sp("canary_degradation"), nil), want: "noop", level: "L0",
			codes: []string{"cap:analysis_missing"}, mut: func(c *pep.Context) { c.State.Rollout.AnalysisRun = ""; c.Level.Level = sp("L0") }},
		{name: "rollout bake_degradation ok", typ: "rollout.abort_and_rollback", params: params(nil, nil, sp("bake_degradation"), nil), want: "allow", level: "L3", exact: true,
			mut: func(c *pep.Context) { c.State.Rollout.Phase = "Bake" }},
		{name: "rollout insufficient_data_policy при inconclusive", typ: "rollout.abort_and_rollback", params: params(nil, nil, sp("insufficient_data_policy"), nil), want: "allow", level: "L3", exact: true,
			mut: func(c *pep.Context) { c.State.Rollout.AnalysisVerdict = "inconclusive" }},
		{name: "rollout при вердикте error", typ: "rollout.abort_and_rollback", params: params(nil, nil, sp("canary_degradation"), nil), want: "downgrade", level: "L1",
			codes: []string{"cap:analysis_verdict"}, exact: true, mut: func(c *pep.Context) { c.State.Rollout.AnalysisVerdict = "error" }},
		{name: "rollout при вердикте running", typ: "rollout.abort_and_rollback", params: params(nil, nil, sp("canary_degradation"), nil), want: "downgrade", level: "L1",
			codes: []string{"cap:analysis_verdict"}, exact: true, mut: func(c *pep.Context) { c.State.Rollout.AnalysisVerdict = "running" }},
		{name: "rollout при вердикте success", typ: "rollout.abort_and_rollback", params: params(nil, nil, sp("canary_degradation"), nil), want: "downgrade", level: "L1",
			codes: []string{"cap:analysis_verdict"}, exact: true, mut: func(c *pep.Context) { c.State.Rollout.AnalysisVerdict = "success" }},
		{name: "rollout canary_degradation при inconclusive", typ: "rollout.abort_and_rollback", params: params(nil, nil, sp("canary_degradation"), nil), want: "downgrade", level: "L1",
			codes: []string{"cap:analysis_verdict"}, exact: true, mut: func(c *pep.Context) { c.State.Rollout.AnalysisVerdict = "inconclusive" }},
		{name: "rollout insufficient_data_policy при degradation", typ: "rollout.abort_and_rollback", params: params(nil, nil, sp("insufficient_data_policy"), nil), want: "downgrade", level: "L1",
			codes: []string{"cap:analysis_verdict"}, exact: true},
		{name: "rollout без вердикта", typ: "rollout.abort_and_rollback", params: params(nil, nil, sp("canary_degradation"), nil), want: "downgrade", level: "L1",
			codes: []string{"cap:analysis_verdict"}, exact: true, mut: func(c *pep.Context) { c.State.Rollout.AnalysisVerdict = "" }},
		{name: "rollout при error, запрошен L0", typ: "rollout.abort_and_rollback", params: params(nil, nil, sp("canary_degradation"), nil), want: "noop", level: "L0",
			codes: []string{"cap:analysis_verdict"}, mut: func(c *pep.Context) { c.State.Rollout.AnalysisVerdict = "error"; c.Level.Level = sp("L0") }},
		{name: "scale_out при вердикте error", typ: "workload.scale_out", want: "allow", level: "L3", exact: true,
			mut: func(c *pep.Context) { c.State.Rollout.AnalysisVerdict = "error" }},
		{name: "scale_out без анализа", typ: "workload.scale_out", want: "allow", level: "L3", exact: true,
			mut: func(c *pep.Context) { c.State.Rollout.AnalysisRun = "" }},
		{name: "scale_out с лишним scope", typ: "workload.scale_out", params: params(sp("pod"), nil, nil, nil), want: "deny", level: "L0", codes: []string{"deny:param_unexpected"}},
		{name: "postgres shared_buffers", typ: "postgres.set_restart_param", params: params(nil, nil, nil, sp("shared_buffers")), want: "downgrade", level: "L1",
			codes: []string{"cap:recommendation_only", "cap:reversibility_r3", "cap:matrix_ceiling"}, exact: true},
		{name: "postgres max_connections", typ: "postgres.set_restart_param", params: params(nil, nil, nil, sp("max_connections")), want: "downgrade", level: "L1",
			codes: []string{"cap:reversibility_r3", "cap:matrix_ceiling"}, exact: true},
		{name: "postgres без parameter", typ: "postgres.set_restart_param", want: "deny", level: "L0", codes: []string{"deny:param_missing"}},
		{name: "resize pool=3", typ: "pgbouncer.resize_pool", want: "deny", level: "L0", codes: []string{"deny:computed_out_of_bounds"},
			mut: func(c *pep.Context) { c.State.DB.PgBouncer.PoolSize = 3; c.State.DB.Postgres.OtherPoolsTotal = 0 }},
		{name: "resize недоступен", typ: "pgbouncer.resize_pool", want: "deny", level: "L0", codes: []string{"deny:action_unavailable"},
			mut: func(c *pep.Context) { c.State.DB.Postgres.OtherPoolsTotal = 150 }},
		{name: "rollout Healthy", typ: "rollout.abort_and_rollback", params: params(nil, nil, sp("canary_degradation"), nil), want: "deny", level: "L0",
			codes: []string{"deny:action_unavailable"}, mut: func(c *pep.Context) { c.State.Rollout.Phase = "Healthy" }},
		{name: "recommend пустой", typ: "recommend", want: "noop", level: "L0", exact: true},
		{name: "none пустой", typ: "none", want: "noop", level: "L0", exact: true},
		{name: "recommend с reason", typ: "recommend", params: params(nil, nil, sp("canary_degradation"), nil), want: "deny", level: "L0", codes: []string{"deny:param_unexpected"}},
		{name: "контекст без flags", typ: "workload.scale_out", want: "deny", level: "L0", codes: []string{"deny:context_invalid"}, exact: true,
			mut: func(c *pep.Context) { c.Flags = nil }},
		{name: "контекст: неизвестный уровень", typ: "workload.scale_out", want: "deny", level: "L0", codes: []string{"deny:context_invalid"},
			mut: func(c *pep.Context) { c.Level.Level = sp("L7") }},
		{name: "контекст: database не совпадает", typ: "workload.scale_out", want: "deny", level: "L0", codes: []string{"deny:context_invalid"},
			mut: func(c *pep.Context) { c.State.Database = sp("other") }},
		{name: "контекст: отрицательное", typ: "workload.scale_out", want: "deny", level: "L0", codes: []string{"deny:context_invalid"},
			mut: func(c *pep.Context) { c.State.Autoscaler.Max = -1 }},
		{name: "неизвестное действие", typ: "workload.teleport", want: "deny", level: "L0", codes: []string{"deny:unknown_action"}, exact: true},
		{name: "запрещённое действие", typ: "storage.delete_volume", want: "deny", level: "L0", codes: []string{"deny:unknown_action", "deny:forbidden_action"}, exact: true},
		{name: "запрещённое без контекста", typ: "audit.delete_record", want: "deny", level: "L0", codes: []string{"deny:unknown_action"}, exact: true,
			mut: func(c *pep.Context) { c.Flags = nil }},
		{name: "метки цели", typ: "workload.scale_out", want: "deny", level: "L0", codes: []string{"deny:target_labels_mismatch"},
			mut: func(c *pep.Context) { c.TargetLabels = map[string]string{} }},
		{name: "kind не из targets.kinds", typ: "workload.scale_out", want: "deny", level: "L0", codes: []string{"deny:target_kind_mismatch"},
			eng: pep.New(restrictedCatalog(t, "workload.scale_out.yaml", "kinds: [apps/Deployment, autoscaling/HorizontalPodAutoscaler, keda.sh/ScaledObject]", "kinds: [apps/Deployment]"), sharedPolicy(t))},
		{name: "ScaledObject", typ: "workload.scale_out", want: "allow", level: "L3", exact: true,
			mut: func(c *pep.Context) { c.State.Autoscaler.Kind = "ScaledObject" }},
		{name: "kube-system", typ: "workload.scale_out", want: "deny", level: "L0", codes: []string{"deny:forbidden_namespace"},
			mut: func(c *pep.Context) { c.Namespace = sp("kube-system") }},
		{name: "namespace не managed", typ: "workload.scale_out", want: "deny", level: "L0", codes: []string{"deny:namespace_not_managed"},
			mut: func(c *pep.Context) { c.NamespaceLabels = map[string]string{} }},
		{name: "неизвестная среда", typ: "workload.scale_out", want: "deny", level: "L0", codes: []string{"deny:no_matrix_cell"},
			mut: func(c *pep.Context) { c.Environment = sp("dev") }},
		{name: "kill switch", typ: "workload.scale_out", want: "downgrade", level: "L1", codes: []string{"cap:kill_switch"}, exact: true,
			mut: func(c *pep.Context) { c.Flags.KillSwitch.Global = bp(true) }},
		{name: "kill switch по действию", typ: "workload.scale_out", want: "downgrade", level: "L1", codes: []string{"cap:kill_switch"}, exact: true,
			mut: func(c *pep.Context) { c.Flags.KillSwitch.Actions = []string{"workload.scale_out"} }},
		{name: "liveness", typ: "workload.scale_out", want: "downgrade", level: "L1", codes: []string{"cap:liveness_unconfirmed"}, exact: true,
			mut: func(c *pep.Context) { c.Flags.LivenessConfirmed = bp(false) }},
		{name: "нет lease", typ: "workload.scale_out", want: "downgrade", level: "L1", codes: []string{"cap:lease_missing"}, exact: true,
			mut: func(c *pep.Context) { c.Flags.LeaseHeld = bp(false) }},
		{name: "человек в инциденте", typ: "workload.scale_out", want: "downgrade", level: "L1", codes: []string{"cap:human_engaged"}, exact: true,
			mut: func(c *pep.Context) { c.Flags.HumanEngaged = bp(true) }},
		{name: "circuit breaker", typ: "workload.scale_out", want: "downgrade", level: "L1", codes: []string{"cap:circuit_breaker_open"}, exact: true,
			mut: func(c *pep.Context) { c.Flags.CircuitBreakerOpen = bp(true) }},
		{name: "rate limit", typ: "workload.scale_out", want: "downgrade", level: "L1", codes: []string{"cap:rate_limit_exceeded"}, exact: true,
			mut: func(c *pep.Context) { c.History.ActionsLastHour = ip(4) }},
		{name: "cooldown", typ: "workload.scale_out", want: "downgrade", level: "L1", codes: []string{"cap:cooldown_active"}, exact: true,
			mut: func(c *pep.Context) { c.History.SecondsSinceLast = ip(60) }},
		{name: "error budget scale_in", typ: "workload.scale_in", want: "downgrade", level: "L1", codes: []string{"cap:error_budget_frozen"}, exact: true,
			mut: func(c *pep.Context) { c.Flags.ErrorBudgetExhausted = bp(true) }},
		{name: "error budget scale_out проходит", typ: "workload.scale_out", want: "allow", level: "L3", exact: true,
			mut: func(c *pep.Context) { c.Flags.ErrorBudgetExhausted = bp(true) }},
		{name: "degraded без предодобрения", typ: "workload.scale_out", want: "downgrade", level: "L1", codes: []string{"cap:degraded_runbook_not_preapproved"}, exact: true,
			mut: func(c *pep.Context) { c.Flags.DegradedMode = bp(true) }},
		{name: "degraded R2 без политики", typ: "workload.restart", params: params(sp("deployment"), nil, nil, nil), want: "downgrade", level: "L1",
			codes: []string{"cap:degraded_r2_not_permitted"}, exact: true, mut: func(c *pep.Context) { c.Flags.DegradedMode = bp(true) }},
		{name: "degraded forbidden", typ: "workload.scale_in", want: "downgrade", level: "L1", codes: []string{"cap:degraded_forbidden"}, exact: true,
			mut: func(c *pep.Context) { c.Flags.DegradedMode = bp(true) }},
		{name: "кэш политик истёк", typ: "workload.scale_out", want: "downgrade", level: "L1", codes: []string{"cap:policy_cache_expired"}, exact: true,
			mut: func(c *pep.Context) { c.Flags.PolicyCacheExpired = bp(true) }},
		{name: "deny перекрывает cap", typ: "workload.scale_out", want: "deny", level: "L0", codes: []string{"deny:forbidden_namespace", "cap:human_engaged"},
			mut: func(c *pep.Context) { c.Namespace = sp("kube-system"); c.Flags.HumanEngaged = bp(true) }},
		{name: "запрошен L0", typ: "workload.scale_out", want: "noop", level: "L0", exact: true,
			mut: func(c *pep.Context) { c.Level.Level = sp("L0") }},
		{name: "запрошен L0 + human_engaged", typ: "workload.scale_out", want: "noop", level: "L0", codes: []string{"cap:human_engaged"}, exact: true,
			mut: func(c *pep.Context) { c.Level.Level = sp("L0"); c.Flags.HumanEngaged = bp(true) }},
		{name: "запрошен L0 + kube-system", typ: "workload.scale_out", want: "deny", level: "L0", codes: []string{"deny:forbidden_namespace"},
			mut: func(c *pep.Context) { c.Level.Level = sp("L0"); c.Namespace = sp("kube-system") }},
		{name: "запрошен L1 + cap L1", typ: "workload.scale_out", want: "allow", level: "L1",
			mut: func(c *pep.Context) { c.Level.Level = sp("L1"); c.Flags.HumanEngaged = bp(true) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			eng := c.eng
			if eng == nil {
				eng = std
			}
			ctx := permissive(richState())
			if c.mut != nil {
				c.mut(&ctx)
			}
			v := eng.Evaluate(context.Background(), pep.Proposal{Type: c.typ, Params: c.params}, ctx)
			got := map[string]bool{}
			for _, r := range v.Reasons {
				got[r.Effect+":"+r.Code] = true
				seen[r.Code] = true
			}
			if v.Decision != c.want || v.EffectiveLevel != c.level {
				t.Errorf("decision=%s level=%s, want %s %s; reasons=%+v", v.Decision, v.EffectiveLevel, c.want, c.level, v.Reasons)
			}
			for _, code := range c.codes {
				if !got[code] {
					t.Errorf("нет причины %s; reasons=%+v", code, v.Reasons)
				}
			}
			if c.exact && len(got) != len(c.codes) {
				t.Errorf("набор причин %v, ожидался %v", got, c.codes)
			}
			if v.Reasons == nil {
				t.Error("Reasons == nil")
			}
			// would-be нарушение G0 — только deny: у не-deny вердикта причин deny быть не должно (решение 07.11.2026).
			if c.want != "deny" && hasDenyReason(v.Reasons) {
				t.Errorf("%s вердикт содержит причину deny: %+v", v.Decision, v.Reasons)
			}
		})
	}
	// Каждый код причины со стороны Go встретился хотя бы раз.
	for _, code := range []string{"unknown_action", "context_invalid", "action_unavailable", "param_unexpected", "param_missing",
		"param_not_in_enum", "pod_not_found", "computed_out_of_bounds", "recommendation_only", "target_kind_mismatch", "target_labels_mismatch"} {
		if !seen[code] {
			t.Errorf("код %s не покрыт сценариями", code)
		}
	}
}

type fakePolicy struct {
	d   policyengine.Decision
	err error
}

func (f fakePolicy) Eval(context.Context, any) (policyengine.Decision, error) { return f.d, f.err }
func (f fakePolicy) Digest() string                                           { return "sha256:fake" }

func TestEvaluate_PolicyError(t *testing.T) {
	cat := catalog.MustLoadEmbedded()
	eng := pep.New(cat, fakePolicy{err: errors.New("boom")})
	v := eng.Evaluate(context.Background(), pep.Proposal{Type: "workload.scale_out"}, permissive(richState()))
	if v.Decision != "deny" || v.EffectiveLevel != "L0" || len(v.Reasons) != 1 || v.Reasons[0].Code != "policy_error" {
		t.Fatalf("%+v", v)
	}
	// Политика вернула мусорный уровень — тоже deny.
	eng = pep.New(cat, fakePolicy{d: policyengine.Decision{Ceiling: "L3", EffectiveLevel: "L9"}})
	v = eng.Evaluate(context.Background(), pep.Proposal{Type: "workload.scale_out"}, permissive(richState()))
	if v.Decision != "deny" || v.Reasons[0].Code != "policy_error" {
		t.Fatalf("%+v", v)
	}
}

func TestEvaluateRaw_InvalidProposal(t *testing.T) {
	v := newEngine(t).EvaluateRaw(context.Background(), []byte(`{"type":"none"}`), permissive(richState()))
	if v.Decision != "deny" || v.Reasons[0].Code != "proposal_invalid" {
		t.Fatalf("%+v", v)
	}
}

func TestVerdictDeterminism(t *testing.T) {
	eng := newEngine(t)
	p := pep.Proposal{Type: "workload.restart", Params: params(sp("pod"), sp("geo-svc-aaa-11111"), nil, nil)}
	mk := func() []byte {
		c := permissive(richState())
		c.Flags.HumanEngaged = bp(true)
		c.History.SecondsSinceLast = ip(10)
		b, err := json.Marshal(eng.Evaluate(context.Background(), p, c))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	first := mk()
	for i := 0; i < 100; i++ {
		if got := mk(); string(got) != string(first) {
			t.Fatalf("итерация %d: вердикт изменился\n%s\n%s", i, first, got)
		}
	}

	// input_digest не зависит от порядка ключей входного JSON.
	a := `{"proposal":{"type":"none","params":{"scope":null,"pod_name":null,"reason":null,"parameter":null}},"context":{"environment":"staging","namespace":"s","namespace_labels":{"a":"1","b":"2"}}}`
	b := `{"context":{"namespace_labels":{"b":"2","a":"1"},"namespace":"s","environment":"staging"},"proposal":{"params":{"parameter":null,"reason":null,"pod_name":null,"scope":null},"type":"none"}}`
	digest := func(in string) string {
		var req struct {
			Proposal json.RawMessage `json:"proposal"`
			Context  pep.Context     `json:"context"`
		}
		if err := json.Unmarshal([]byte(in), &req); err != nil {
			t.Fatal(err)
		}
		return eng.EvaluateRaw(context.Background(), req.Proposal, req.Context).InputDigest
	}
	if da, db := digest(a), digest(b); da != db || !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(da) {
		t.Errorf("input_digest: %s vs %s", da, db)
	}
}

func TestVerdictShape(t *testing.T) {
	v := newEngine(t).Evaluate(context.Background(), pep.Proposal{Type: "workload.scale_out"}, permissive(richState()))
	b, _ := json.Marshal(v)
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"schema", "mode", "decision", "action", "target", "requested_level", "ceiling", "effective_level",
		"reasons", "catalog_digest", "policy_bundle_digest", "policy_revision", "input_digest"} {
		if _, ok := m[k]; !ok {
			t.Errorf("нет поля %s", k)
		}
	}
	if m["schema"] != "aegisops/pep-verdict/v1" || m["mode"] != "dry-run" {
		t.Errorf("schema/mode: %v %v", m["schema"], m["mode"])
	}
	if !strings.Contains(string(b), `"computed":{"new_min_replicas":6}`) {
		t.Errorf("computed: %s", b)
	}
}
