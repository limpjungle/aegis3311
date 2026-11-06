package pep_test

import (
	"context"
	"math"
	"testing"

	"github.com/limpjungle/aegis3311/internal/pep"
)

// Потолок целых состояния (1<<31): на границе допустимо и не даёт отрицательных величин; выше — context_invalid.
func TestEvaluate_MaxValueBoundary(t *testing.T) {
	eng := newEngine(t)
	const lim = 1 << 31
	type mk func(*pep.Context, int)
	setters := map[string]struct {
		typ   string
		p     pep.ModelParams
		apply mk
	}{
		"pool_size":       {"pgbouncer.resize_pool", pep.ModelParams{}, func(c *pep.Context, v int) { c.State.DB.PgBouncer.PoolSize = v }},
		"max_connections": {"postgres.set_restart_param", params(nil, nil, nil, sp("max_connections")), func(c *pep.Context, v int) { c.State.DB.Postgres.MaxConnections = v }},
		"current_min":     {"workload.scale_out", pep.ModelParams{}, func(c *pep.Context, v int) { c.State.Autoscaler.CurrentMin = v; c.State.Autoscaler.Max = v }},
	}
	for name, s := range setters {
		t.Run(name, func(t *testing.T) {
			// На границе: не context_invalid; вычисленные величины неотрицательны.
			c := permissive(richState())
			s.apply(&c, lim)
			v := eng.Evaluate(context.Background(), pep.Proposal{Type: s.typ, Params: s.p}, c)
			if hasReason(v.Reasons, "deny:context_invalid") {
				t.Errorf("значение 2^31 отвергнуто как context_invalid")
			}
			for k, val := range v.Action.Computed {
				if n, ok := val.(int); ok && n < 0 {
					t.Errorf("%s=%d отрицательное", k, n)
				}
				if m, ok := val.(map[string]int); ok {
					for kk, nn := range m {
						if nn < 0 || nn > math.MaxInt32*4 {
							t.Errorf("%s.%s=%d вне разумного диапазона", k, kk, nn)
						}
					}
				}
			}
			// Выше границы: context_invalid.
			c = permissive(richState())
			s.apply(&c, lim+1)
			v = eng.Evaluate(context.Background(), pep.Proposal{Type: s.typ, Params: s.p}, c)
			if v.Decision != "deny" || !hasReason(v.Reasons, "deny:context_invalid") {
				t.Errorf("значение 2^31+1: decision=%s reasons=%+v", v.Decision, v.Reasons)
			}
		})
	}
}
