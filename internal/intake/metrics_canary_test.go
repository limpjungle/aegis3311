package intake

import (
	"strings"
	"testing"
	"time"

	"github.com/limpjungle/aegis3311/internal/llmrouter"
)

func canaryMetrics(t testing.TB, s llmrouter.State) []series {
	t.Helper()
	st, err := OpenState("")
	if err != nil {
		t.Fatal(err)
	}
	m := NewMetrics("prod-eu-1", &fakeKS{o: stoppedObs()}, fakeRouter{s}, fakeChain{1}, st, func() time.Time { return time.Unix(1_700_000_000, 0) })
	body, err := m.Render()
	if err != nil {
		t.Fatal(err)
	}
	types, ss := parseExposition(t, string(body))
	if types["aegis_intake_router_canary_markers"] != "gauge" || types["aegis_intake_router_canary_blocked_total"] != "counter" {
		t.Fatalf("типы: %q %q", types["aegis_intake_router_canary_markers"], types["aegis_intake_router_canary_blocked_total"])
	}
	return ss
}

func TestMetricsCanarySeries(t *testing.T) {
	ss := canaryMetrics(t, llmrouter.State{CanaryMarkers: 3, CanaryBlocked: 7})
	if v := val(t, ss, "aegis_intake_router_canary_markers"); v != "3" {
		t.Errorf("canary_markers=%s", v)
	}
	if v := val(t, ss, "aegis_intake_router_canary_blocked_total"); v != "7" {
		t.Errorf("canary_blocked_total=%s", v)
	}
	// Выключенная проверка: маркеров 0 (по этому ряду срабатывает алерт IntakeEgressCanaryDisabled), счётчик 0.
	ss = canaryMetrics(t, llmrouter.State{})
	if v := val(t, ss, "aegis_intake_router_canary_markers"); v != "0" {
		t.Errorf("canary_markers=%s, ожидается 0", v)
	}
	if v := val(t, ss, "aegis_intake_router_canary_blocked_total"); v != "0" {
		t.Errorf("canary_blocked_total=%s, ожидается 0", v)
	}
}

func TestMetricsHaltReasonEgressCanary(t *testing.T) {
	ss := canaryMetrics(t, llmrouter.State{Halted: true, HaltReason: "egress_canary", CanaryMarkers: 1, CanaryBlocked: 1})
	if v := val(t, ss, "aegis_intake_router_halt_reason", "reason", "egress_canary"); v != "1" {
		t.Errorf("egress_canary=%s", v)
	}
	if v := val(t, ss, "aegis_intake_router_halted"); v != "1" {
		t.Errorf("halted=%s", v)
	}
	ones := 0
	for _, s := range ss {
		if s.name != "aegis_intake_router_halt_reason" {
			continue
		}
		if s.value == "1" {
			ones++
			if s.labels["reason"] != "egress_canary" {
				t.Errorf("единица у %q", s.labels["reason"])
			}
		} else if s.value != "0" {
			t.Errorf("значение %s", s.value)
		}
	}
	if ones != 1 {
		t.Errorf("one-hot: единиц %d", ones)
	}
	for _, r := range []string{"none", "auth", "estimator", "audit_failed", "state_store", "state_lost", "chain_lost", "other"} {
		if v := val(t, ss, "aegis_intake_router_halt_reason", "reason", r); v != "0" {
			t.Errorf("%s=%s", r, v)
		}
	}
	// Неизвестная причина сворачивается в other, а не пропадает и не создаёт новый ряд.
	ss = canaryMetrics(t, llmrouter.State{Halted: true, HaltReason: "egress_canary_" + strings.Repeat("x", 5)})
	if v := val(t, ss, "aegis_intake_router_halt_reason", "reason", "other"); v != "1" {
		t.Errorf("other=%s", v)
	}
}
