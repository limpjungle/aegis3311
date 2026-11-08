package intake

import (
	"github.com/limpjungle/aegis3311/internal/pep"
	"github.com/limpjungle/aegis3311/internal/step"
)

// ShadowContext — контекст PEP dry-run для shadow MVP-A. Запрошенный уровень L0, by_data=false; флаги — факты MVP-A:
// lease не взят, живость цели не подтверждена, прочие false, действий за час нет. Лимиты (caps) на G0 не влияют,
// все deny (каталог, шаг, параметры, namespace_not_managed, no_matrix_cell) — честные и не зависят от запрошенного уровня.
func ShadowContext(env string, t Topology, st step.TargetState) pep.Context {
	f, zero := false, 0
	lvl := "L0"
	ns := t.Namespace
	cp := func(m map[string]string) map[string]string {
		out := make(map[string]string, len(m))
		for k, v := range m {
			out[k] = v
		}
		return out
	}
	return pep.Context{Environment: &env, Namespace: &ns, NamespaceLabels: cp(t.NamespaceLabels), TargetLabels: cp(t.TargetLabels), State: &st,
		Level: &pep.LevelGrant{Level: &lvl, ByData: &f},
		Flags: &pep.Flags{KillSwitch: &pep.KillSwitch{Global: &f, Cluster: &f, Actions: []string{}}, LivenessConfirmed: &f,
			ErrorBudgetExhausted: &f, DegradedMode: &f, RunbookPreapproved: &f, DegradedPolicyAllowsR2: &f, PolicyCacheExpired: &f,
			LeaseHeld: &f, HumanEngaged: &f, CircuitBreakerOpen: &f},
		History: &pep.History{ActionsLastHour: &zero}}
}
