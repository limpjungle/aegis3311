package pep_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/limpjungle/aegis3311/internal/catalog"
	"github.com/limpjungle/aegis3311/internal/pep"
	"github.com/limpjungle/aegis3311/internal/policyengine"
)

// capturePolicy запоминает вход политики и портит action.computed, имитируя мутацию на стороне движка.
type capturePolicy struct {
	in     map[string]any
	mutate bool
}

func (c *capturePolicy) Eval(_ context.Context, in any) (policyengine.Decision, error) {
	c.in = in.(map[string]any)
	if comp, ok := c.in["action"].(map[string]any)["computed"].(map[string]any); ok && c.mutate {
		comp["analysis_run"] = "MUTATED"
		comp["extra"] = 1
	}
	return policyengine.Decision{Ceiling: "L3", EffectiveLevel: "L3", PolicyRevision: "test"}, nil
}
func (c *capturePolicy) Digest() string { return "sha256:capture" }

func TestPolicyInputNilComputedIsEmptyObject(t *testing.T) {
	cat := catalog.MustLoadEmbedded()
	cp := &capturePolicy{}
	eng := pep.New(cat, cp)
	// unknown action: политика вызывается с computed == nil
	eng.Evaluate(context.Background(), pep.Proposal{Type: "no.such.action"}, permissive(richState()))
	if cp.in == nil {
		t.Skip("политика для неизвестного действия не вызвана")
	}
	raw, err := json.Marshal(cp.in["action"].(map[string]any)["computed"])
	if err != nil || string(raw) != "{}" {
		t.Errorf("action.computed в JSON = %s (err %v), ожидалось {}: Rego не должен видеть null", raw, err)
	}
}
