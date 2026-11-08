package intake

import (
	"context"
	"testing"
	"time"

	"github.com/limpjungle/aegis3311/internal/audit"
	"github.com/limpjungle/aegis3311/internal/killswitch"
	"github.com/limpjungle/aegis3311/internal/pyjson"
	"github.com/limpjungle/aegis3311/internal/step"
)

func stoppedState(reason string) killswitch.State {
	return killswitch.State{KillSwitchState: audit.KillSwitchState{Stopped: true, Reason: reason, Global: reason == "global", Cluster: reason == "cluster",
		Actions: []string{}, LivenessConfirmed: reason != "no_confirmation"}}
}

// Остановка (global, cluster, нет подтверждения): сбор выполнен, Route в off, модель не вызвана, слот лимита не списан.
func TestPipelineKillSwitchStopped(t *testing.T) {
	for _, reason := range []string{"global", "cluster", "no_confirmation"} {
		t.Run(reason, func(t *testing.T) {
			p, inc, _, recs, snap := newPipeFix(t, replyFor(answerWith("workload.scale_out")))
			cc := &countingCollector{inner: FixtureCollector{snap}}
			p.Collector = cc
			p.KillSwitch = killswitch.Static{S: stoppedState(reason)}
			if err := p.Handle(context.Background(), &inc); err != nil {
				t.Fatal(err)
			}
			r := recs()[0]
			if cc.n != 1 {
				t.Errorf("сбор вызван %d раз", cc.n)
			}
			if r.LLM == nil || r.LLM.Mode != "off" || r.LLM.Reason != "mode_off" || r.Model != nil || r.Verdict != nil {
				t.Errorf("запись: llm=%+v model=%v verdict=%v", r.LLM, r.Model, r.Verdict)
			}
			if r.KillSwitch == nil || !r.KillSwitch.State.Stopped || r.KillSwitch.State.Reason != reason || r.KillSwitch.StoppedDuringRoute {
				t.Errorf("kill_switch: %+v", r.KillSwitch)
			}
			if len(r.Intake.Sources) == 0 || r.Intake.Outcome != "routed" {
				t.Errorf("intake: %+v", r.Intake)
			}
			if n := len(p.hist["notify-worker"]); n != 0 {
				t.Errorf("слот лимита списан: %v", p.hist)
			}
		})
	}
}

func TestPipelineKillSwitchNilIsStopped(t *testing.T) {
	p, inc, _, recs, _ := newPipeFix(t, replyFor(answerWith("none")))
	p.KillSwitch = nil
	if err := p.Handle(context.Background(), &inc); err != nil {
		t.Fatal(err)
	}
	if r := recs()[0]; r.LLM.Mode != "off" || r.KillSwitch == nil || r.KillSwitch.State.Reason != "no_confirmation" {
		t.Errorf("запись: %+v %+v", r.LLM, r.KillSwitch)
	}
}

// Запрет типа действия: роутер остаётся hybrid, PEP получает реальный флаг и ставит cap kill_switch.
func TestPipelineKillSwitchActions(t *testing.T) {
	p, inc, _, recs, snap := newPipeFix(t, replyFor(answerWith("workload.scale_out")))
	snap.Topology.NamespaceLabels = map[string]string{"aegisops.io/managed": "true"}
	snap.Topology.TargetLabels = map[string]string{"aegisops.io/stateless": "true"}
	p.Collector = FixtureCollector{snap}
	st := runningState()
	st.Actions = []string{"workload.scale_out"}
	p.KillSwitch = killswitch.Static{S: st}
	if err := p.Handle(context.Background(), &inc); err != nil {
		t.Fatal(err)
	}
	r := recs()[0]
	if r.LLM.Mode != "hybrid" || r.Model == nil || r.Verdict == nil {
		t.Fatalf("запись: %+v", r.LLM)
	}
	found := false
	for _, rs := range r.Verdict.Reasons {
		found = found || rs.Code == "kill_switch"
	}
	if !found {
		t.Errorf("нет cap kill_switch: %+v", r.Verdict.Reasons)
	}
	if len(r.KillSwitch.State.Actions) != 1 {
		t.Errorf("actions в записи: %+v", r.KillSwitch)
	}
}

func TestShadowContextFlags(t *testing.T) {
	st := runningState()
	st.Global, st.Cluster, st.Actions = true, true, []string{"a.b"}
	st.LivenessConfirmed = false
	c := ShadowContext("staging", Topology{Namespace: "shop"}, step.TargetState{}, st)
	f := c.Flags
	if !*f.KillSwitch.Global || !*f.KillSwitch.Cluster || len(f.KillSwitch.Actions) != 1 || f.KillSwitch.Actions[0] != "a.b" || *f.LivenessConfirmed {
		t.Errorf("флаги: %+v %+v", f.KillSwitch, *f.LivenessConfirmed)
	}
	if *f.LeaseHeld || *f.DegradedMode {
		t.Error("прочие флаги должны остаться false")
	}
}

// guardKS — kill switch с управляемой отменой Guard'а.
type guardKS struct {
	s      killswitch.State
	cancel chan context.CancelCauseFunc
}

func (g *guardKS) State() killswitch.State { return g.s }
func (g *guardKS) Guard(ctx context.Context) (context.Context, context.CancelFunc) {
	c, cancel := context.WithCancelCause(ctx)
	g.cancel <- cancel
	return c, func() { cancel(context.Canceled) }
}

// Остановка во время вызова модели: запись есть, stopped_during_route, проходит Validate.
func TestPipelineKillSwitchStoppedDuringRoute(t *testing.T) {
	tr := &blockTr{started: make(chan struct{}, 1)}
	rt, cfg, keys := openTestRuntime(t, tr)
	c := loadCases(t, "probe-v3.jsonl")[0]
	snap := snapshotFromGolden(t, pyjson.Marshal(c.Get("input"), pyjson.Canonical))
	p, inc, _ := newTestPipeline(t, rt, snap, t.TempDir())
	g := &guardKS{s: runningState(), cancel: make(chan context.CancelCauseFunc, 1)}
	p.KillSwitch = g
	go func() {
		<-tr.started
		(<-g.cancel)(killswitch.ErrEngaged)
	}()
	done := make(chan error, 1)
	go func() { done <- p.Handle(context.Background(), &inc) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Handle не завершился")
	}
	recs := verifyRecords(t, cfg, keys)
	if len(recs) != 1 || recs[0].KillSwitch == nil || !recs[0].KillSwitch.StoppedDuringRoute || recs[0].KillSwitch.State.Stopped {
		t.Fatalf("записи: %+v", recs)
	}
}
