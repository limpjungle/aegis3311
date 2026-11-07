package pep_test

import (
	"context"
	"testing"

	"github.com/limpjungle/aegis3311/internal/catalog"
	"github.com/limpjungle/aegis3311/internal/pep"
	"github.com/limpjungle/aegis3311/internal/policyengine"
)

// TestNoopOnL0CarriesContract: noop при эффективном L0 заполняет поля, которые описаны в policy/README.md
// (action.version, computed, target, ceiling), а effective_level = L0 и причин deny нет.
func TestNoopOnL0CarriesContract(t *testing.T) {
	eng := newEngine(t)
	ctx := permissive(richState())
	ctx.Level.Level = sp("L0")
	v := eng.Evaluate(context.Background(), pep.Proposal{Type: "workload.scale_out"}, ctx)
	if v.Decision != "noop" || v.EffectiveLevel != "L0" || v.RequestedLevel != "L0" {
		t.Fatalf("decision=%s eff=%s req=%s, want noop/L0/L0; reasons=%+v", v.Decision, v.EffectiveLevel, v.RequestedLevel, v.Reasons)
	}
	if v.Action.Version == "" || v.Target == nil || v.Ceiling == "" || v.PolicyRevision == "" {
		t.Errorf("у noop на L0 не заполнены поля: action.version=%q target=%v ceiling=%q policy_revision=%q",
			v.Action.Version, v.Target, v.Ceiling, v.PolicyRevision)
	}
	if _, ok := v.Action.Computed["new_min_replicas"]; !ok {
		t.Errorf("у noop на L0 нет computed.new_min_replicas: %+v", v.Action.Computed)
	}
	if hasDenyReason(v.Reasons) {
		t.Errorf("причины deny у noop: %+v", v.Reasons)
	}
}

// TestPolicyL0WithoutDenyIsNoop: политика сама опускает эффективный уровень до L0 без deny —
// по правилу решения 07.11.2026 это noop, а не downgrade (downgrade только при L0 < эффективный < запрошенный).
func TestPolicyL0WithoutDenyIsNoop(t *testing.T) {
	cat := catalog.MustLoadEmbedded()
	for _, requested := range []string{"L1", "L2", "L3"} {
		eng := pep.New(cat, fakePolicy{d: policyengine.Decision{Ceiling: "L3", EffectiveLevel: "L0", PolicyRevision: "test"}})
		ctx := permissive(richState())
		ctx.Level.Level = sp(requested)
		v := eng.Evaluate(context.Background(), pep.Proposal{Type: "workload.scale_out"}, ctx)
		if v.Decision != "noop" || v.EffectiveLevel != "L0" {
			t.Errorf("запрошен %s, политика L0: decision=%s eff=%s, want noop/L0; reasons=%+v",
				requested, v.Decision, v.EffectiveLevel, v.Reasons)
		}
		if hasDenyReason(v.Reasons) {
			t.Errorf("запрошен %s: причины deny у noop: %+v", requested, v.Reasons)
		}
	}
}

// TestNonDenyNeverL0Allow: ни при каком запрошенном уровне вердикт allow не имеет эффективного L0.
func TestNonDenyNeverL0Allow(t *testing.T) {
	eng := newEngine(t)
	for _, requested := range []string{"L0", "L1", "L2", "L3"} {
		for _, typ := range []string{"workload.scale_out", "workload.restart", "none", "recommend"} {
			ctx := permissive(richState())
			ctx.Level.Level = sp(requested)
			v := eng.Evaluate(context.Background(), pep.Proposal{Type: typ}, ctx)
			if v.Decision == "allow" && v.EffectiveLevel == "L0" {
				t.Errorf("%s/%s: allow на L0: %+v", requested, typ, v)
			}
			if v.Decision == "noop" && v.EffectiveLevel != "L0" {
				t.Errorf("%s/%s: noop на %s", requested, typ, v.EffectiveLevel)
			}
		}
	}
}
