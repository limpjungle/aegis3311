package routerstate

import (
	"errors"
	"reflect"
	"testing"
)

func haltedFailover(reason string) Failover {
	return Failover{Primary: up(), Fallback: up(), Active: "primary", Halted: true, HaltReason: reason}
}

// halt_reason egress_canary допустима во всех операциях, несущих Failover; неизвестная — ErrInvalidOp, состояние не меняется.
func TestHaltReasonEgressCanary(t *testing.T) {
	f := haltedFailover("egress_canary")
	ops := map[string]struct {
		pre []Op
		op  Op
	}{
		"failover_set": {op: Op{Kind: OpFailoverSet, At: testAt, Failover: &f}},
		"intent":       {op: intent(testEvent, f)},
		"abort":        {pre: []Op{intent(testEvent, downNext())}, op: abort(testEvent, f)},
	}
	for name, c := range ops {
		t.Run(name+": допустима", func(t *testing.T) {
			s := NewState(testID)
			for _, p := range c.pre {
				if err := s.Apply(p); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.Apply(c.op); err != nil {
				t.Fatalf("egress_canary отвергнута: %v", err)
			}
		})
	}
	for _, bad := range []string{"egress_canary ", "Egress_Canary", "egress-canary", "canary", "bogus"} {
		s := NewState(testID)
		before := s.Clone()
		bf := haltedFailover(bad)
		err := s.Apply(Op{Kind: OpFailoverSet, At: testAt, Failover: &bf})
		if !errors.Is(err, ErrInvalidOp) {
			t.Errorf("%q: %v", bad, err)
		}
		if !reflect.DeepEqual(s, before) {
			t.Errorf("%q: состояние изменилось", bad)
		}
	}
	// Согласованность halted/halt_reason сохраняется и для новой причины.
	s := NewState(testID)
	nf := Failover{Primary: up(), Fallback: up(), Active: "primary", HaltReason: "egress_canary"}
	if err := s.Apply(Op{Kind: OpFailoverSet, At: testAt, Failover: &nf}); err == nil {
		t.Error("egress_canary без halted принята")
	}
}

// Halt egress_canary переживает перезапуск (журнал и компактный снимок) и возвращается через Load.
func TestHaltReasonEgressCanaryPersisted(t *testing.T) {
	path := statePath(t)
	fs := mustOpen(t, path, FileOptions{})
	f := haltedFailover("egress_canary")
	mustAppend(t, fs, Op{Kind: OpFailoverSet, At: testAt, Failover: &f})
	if err := fs.Close(); err != nil {
		t.Fatal(err)
	}
	fs2 := mustOpen(t, path, FileOptions{})
	defer fs2.Close()
	st, _, err := fs2.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !st.Failover.Halted || st.Failover.HaltReason != "egress_canary" {
		t.Fatalf("%+v", st.Failover)
	}
}

func TestHaltReasonEgressCanaryMemory(t *testing.T) {
	m := NewMemory(testID)
	f := haltedFailover("egress_canary")
	mustAppend(t, m, Op{Kind: OpFailoverSet, At: testAt, Failover: &f})
	if got := m.Snapshot().Failover; got.HaltReason != "egress_canary" || !got.Halted {
		t.Fatalf("%+v", got)
	}
	bad := haltedFailover("bogus")
	if err := m.Append(Op{Kind: OpFailoverSet, At: testAt, Failover: &bad}); !errors.Is(err, ErrInvalidOp) {
		t.Errorf("bogus: %v", err)
	}
}
