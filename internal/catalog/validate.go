package catalog

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ForbiddenPatterns — запрещённые имена действий. Список обязан совпадать с forbidden_patterns
// в policy/aegis/autonomy/matrix.rego (синхронность проверяет тест).
var ForbiddenPatterns = []string{"*.delete*", "*.delete", "audit.*", "policy.*", "autonomy.*"}

// MatchesForbidden сопоставляет имя с шаблонами так же, как glob.match(p, ["."], name) в Rego: "*" не пересекает ".".
func MatchesForbidden(name string) bool {
	n := strings.ReplaceAll(name, ".", "/")
	for _, p := range ForbiddenPatterns {
		if ok, _ := path.Match(strings.ReplaceAll(p, ".", "/"), n); ok {
			return true
		}
	}
	return false
}

// RuleSet — набор зарегистрированных Go-правил (реализует step.Registry).
type RuleSet interface {
	HasStep(id string) bool
	HasBounds(id string) bool
}

var (
	nameRe   = regexp.MustCompile(`^[a-z0-9_]+\.[a-z0-9_]+$`)
	semverRe = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)
)

// Validate проверяет все записи и возвращает объединённую ошибку.
func (c *Catalog) Validate(rules RuleSet) error {
	var errs []error
	for _, name := range c.Names() {
		e := c.entries[name]
		for _, msg := range c.validateEntry(e, rules) {
			errs = append(errs, fmt.Errorf("%s: %s", name, msg))
		}
	}
	return errors.Join(errs...)
}

func (c *Catalog) validateEntry(e *Entry, rules RuleSet) []string {
	var m []string
	add := func(format string, a ...any) { m = append(m, fmt.Sprintf(format, a...)) }

	if !nameRe.MatchString(e.Name) {
		add("недопустимое имя")
	}
	if MatchesForbidden(e.Name) {
		add("имя совпадает с запрещённым шаблоном")
	}
	if !semverRe.MatchString(e.Version) {
		add("version %q не semver", e.Version)
	}
	switch e.Reversibility {
	case R1, R2, R3:
	default:
		add("reversibility %q не из R1/R2/R3", e.Reversibility)
	}
	if len(e.Targets.Kinds) == 0 {
		add("targets.kinds пуст")
	}

	pnames := make([]string, 0, len(e.Params))
	for n := range e.Params {
		pnames = append(pnames, n)
	}
	sort.Strings(pnames)
	for _, pn := range pnames {
		p := e.Params[pn]
		switch p.ChosenBy {
		case "model", "catalog":
		default:
			add("params.%s: chosen_by %q не из model/catalog", pn, p.ChosenBy)
			continue
		}
		if p.Bounds != nil && !rules.HasBounds(p.Bounds.Rule) {
			add("params.%s: правило границ %q не зарегистрировано", pn, p.Bounds.Rule)
		}
		if p.ChosenBy != "catalog" {
			continue
		}
		if len(p.Variants) == 0 {
			if needsValue(p) && !hasStep(e, pn, "", "", rules) && !p.RecommendationOnly {
				add("params.%s: величина без зарегистрированного правила шага", pn)
			}
			continue
		}
		vnames := make([]string, 0, len(p.Variants))
		for v := range p.Variants {
			vnames = append(vnames, v)
		}
		sort.Strings(vnames)
		for _, vn := range vnames {
			v := p.Variants[vn]
			if needsValue(v) && !v.RecommendationOnly && !hasStep(e, pn, p.DependsOn, vn, rules) {
				add("params.%s.%s: величина без зарегистрированного правила шага", pn, vn)
			}
		}
	}
	for i, s := range e.Step {
		if !rules.HasStep(s.Rule) {
			add("step[%d]: правило %q не зарегистрировано", i, s.Rule)
		}
		if _, ok := e.Params[s.Param]; !ok {
			add("step[%d]: неизвестный параметр %q", i, s.Param)
		}
	}

	m = append(m, checks("preconditions", e.Preconditions)...)
	m = append(m, checks("postconditions.checks", e.Postconditions.Checks)...)
	if e.Postconditions.Window.Duration <= 0 {
		add("postconditions.window должен быть > 0")
	}

	switch e.Rollback.Action {
	case "manual", "none":
	default:
		if _, ok := c.entries[e.Rollback.Action]; !ok {
			add("rollback.action %q не manual/none и не действие каталога", e.Rollback.Action)
		}
	}
	if e.Execution != "gitops" && e.Execution != "api" {
		add("execution %q не из gitops/api", e.Execution)
	}
	if e.RateLimit.PerTargetPerHour <= 0 {
		add("rate_limit.per_target_per_hour должен быть > 0")
	}
	if e.BlastRadius == (BlastRadius{}) {
		add("blast_radius пуст")
	}
	if e.Lease != "required" {
		add("lease должен быть required (все действия изменяющие)")
	}

	// Инварианты §4.5 и деградационного режима.
	if e.ErrorBudgetExhausted != "allowed" && e.ErrorBudgetExhausted != "frozen" {
		add("error_budget_exhausted %q не из allowed/frozen", e.ErrorBudgetExhausted)
	}
	switch e.DegradedMode {
	case "allowed", "policy", "forbidden":
	default:
		add("degraded_mode %q не из allowed/policy/forbidden", e.DegradedMode)
	}
	if e.ErrorBudgetExhausted == "allowed" && e.Reversibility != R1 {
		add("error_budget_exhausted: allowed допустим только у R1")
	}
	if e.DegradedMode == "allowed" && e.Reversibility != R1 {
		add("degraded_mode: allowed допустим только у R1")
	}
	if e.DegradedMode == "policy" && e.Reversibility != R2 {
		add("degraded_mode: policy допустим только у R2")
	}
	if e.Reversibility == R3 && (e.DegradedMode != "forbidden" || e.ErrorBudgetExhausted != "frozen") {
		add("у R3 обязательны degraded_mode: forbidden и error_budget_exhausted: frozen")
	}
	return m
}

func needsValue(p Param) bool { return p.Type == "int" || p.Type == "size" }

// hasStep: есть ли правило шага для параметра (и варианта: when[dependsOn] == variant).
func hasStep(e *Entry, param, dependsOn, variant string, rules RuleSet) bool {
	for _, s := range e.Step {
		if s.Param != param || !rules.HasStep(s.Rule) {
			continue
		}
		if variant == "" || s.When[dependsOn] == variant {
			return true
		}
	}
	return false
}

func checks(kind string, cs []Check) []string {
	var m []string
	if len(cs) == 0 {
		m = append(m, kind+": нужна хотя бы одна проверка")
	}
	seen := map[string]bool{}
	for i, c := range cs {
		if c.ID == "" {
			m = append(m, kind+"["+strconv.Itoa(i)+"]: пустой id")
		}
		if seen[c.ID] {
			m = append(m, kind+": дубль id "+strconv.Quote(c.ID))
		}
		seen[c.ID] = true
	}
	return m
}
