package intake

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/limpjungle/aegis3311/internal/audit"
	"github.com/limpjungle/aegis3311/internal/catalog"
	"github.com/limpjungle/aegis3311/internal/killswitch"
	"github.com/limpjungle/aegis3311/internal/openrouter"
	"github.com/limpjungle/aegis3311/internal/pep"
	"github.com/limpjungle/aegis3311/internal/policyengine"
	"github.com/limpjungle/aegis3311/internal/pyjson"
	"github.com/limpjungle/aegis3311/internal/routersvc"
	"github.com/limpjungle/aegis3311/internal/step"
	"github.com/limpjungle/aegis3311/policy"
)

const modelAnswer = `{"incident_class":"RB-006","root_cause":"load_growth","action":{"type":"workload.scale_out","params":{"scope":null,"pod_name":null,"reason":null,"parameter":null}},"confidence":0.9,"evidence":["a"],"summary":"s"}`

func okReply() openrouter.Response {
	c, _ := json.Marshal(modelAnswer)
	return openrouter.Response{Status: 200, Body: []byte(fmt.Sprintf(`{"id":"g1","model":"m","provider":"Inceptron","choices":[{"finish_reason":"stop","message":{"content":%s}}],"usage":{"prompt_tokens":100,"completion_tokens":50,"total_tokens":150}}`, c))}
}

// verifyRecords читает цепочку и возвращает decision record'ы.
func verifyRecords(t testing.TB, cfg routersvc.Config, keys audit.Keyring) []audit.DecisionRecord {
	t.Helper()
	b, err := os.ReadFile(cfg.Audit.Chain)
	if err != nil {
		t.Fatal(err)
	}
	var recs []audit.DecisionRecord
	if _, err := audit.Verify(bytes.NewReader(b), keys, audit.VerifyOptions{ChainID: cfg.Audit.ChainID,
		OnRecord: func(_ uint64, r *audit.DecisionRecord) { recs = append(recs, *r) }}); err != nil {
		t.Fatal(err)
	}
	return recs
}

// runningState — kill switch в рабочем состоянии: подтверждено, ничего не остановлено.
func runningState() killswitch.State {
	return killswitch.State{KillSwitchState: audit.KillSwitchState{LivenessConfirmed: true, Actions: []string{}}}
}

func newTestPipeline(t testing.TB, rt *routersvc.Runtime, snap Snapshot, dir string) (*Pipeline, Incident, *State) {
	t.Helper()
	pol, err := policyengine.Load(context.Background(), policy.FS)
	if err != nil {
		t.Fatal(err)
	}
	cat := catalog.MustLoadEmbedded()
	inc, svc := ReplayIncident("staging", snap)
	st, _ := OpenState("")
	st.Do(func(d *Data) { d.Incidents[inc.ID] = &inc })
	p := &Pipeline{IntakeID: "intake-test", Env: "staging", MaxPerHour: 6, SnapshotDir: dir, Cat: cat, Collector: FixtureCollector{snap},
		Router: rt.Router, Writer: rt.Writer, PEP: pep.New(cat, pol), State: st, KillSwitch: killswitch.Static{S: runningState()},
		Lookup: func(ns, s string) (ServiceConfig, bool) { return svc, ns == svc.Namespace && s == svc.Service }}
	return p, inc, st
}

func TestPipelineShadowRecord(t *testing.T) {
	rt, cfg, keys := openTestRuntime(t, &stubTr{post: func([]byte) (openrouter.Response, error) { return okReply(), nil }})
	cases := loadCases(t, "probe-v3.jsonl")
	snap := snapshotFromGolden(t, pyjson.Marshal(cases[0].Get("input"), pyjson.Canonical))
	dir := filepath.Join(t.TempDir(), "snaps")
	p, inc, st := newTestPipeline(t, rt, snap, dir)
	if err := p.Handle(context.Background(), &inc); err != nil {
		t.Fatal(err)
	}
	recs := verifyRecords(t, cfg, keys)
	if len(recs) != 1 {
		t.Fatalf("записей %d", len(recs))
	}
	r := recs[0]
	if r.Mode != audit.ModeShadow || r.Initiator.Kind != "agent" || r.Intake == nil || r.Intake.Outcome != "routed" || r.Verdict == nil || r.Answer == nil || r.Answer.Status != "ok" {
		t.Fatalf("запись: %+v", r)
	}
	// namespace без метки managed: PEP честно говорит deny
	if r.Verdict.Decision != "deny" || r.AutonomyLevel != "L0" {
		t.Errorf("вердикт: %s %s", r.Verdict.Decision, r.AutonomyLevel)
	}
	fn := filepath.Join(dir, trimSHA(r.Prompt.InputSHA256)+".json")
	b, err := os.ReadFile(fn)
	if err != nil || sha256Hex(b) != trimSHA(r.Prompt.InputSHA256) {
		t.Fatalf("снимок входа: %v", err)
	}
	if fi, _ := os.Stat(fn); fi.Mode().Perm() != 0o600 {
		t.Errorf("права снимка %v", fi.Mode().Perm())
	}
	if got, _ := st.Get(inc.ID); got.Status != StatusRecorded {
		t.Errorf("статус %s", got.Status)
	}
	// повторная обработка не пишет вторую запись
	if err := p.Handle(context.Background(), &inc); err != nil {
		t.Fatal(err)
	}
	if n := len(verifyRecords(t, cfg, keys)); n != 1 {
		t.Errorf("записей после повтора %d", n)
	}
	_ = step.TargetState{}
}

func trimSHA(s string) string { return s[len("sha256:"):] }

func TestPipelineNotRoutedSourceUnavailable(t *testing.T) {
	rt, cfg, keys := openTestRuntime(t, &stubTr{post: func([]byte) (openrouter.Response, error) { return okReply(), nil }})
	cases := loadCases(t, "probe-v3.jsonl")
	snap := snapshotFromGolden(t, pyjson.Marshal(cases[0].Get("input"), pyjson.Canonical))
	p, inc, _ := newTestPipeline(t, rt, snap, "")
	p.Collector = failingCollector{}
	p.RetryPause = time.Millisecond
	p.Settle = time.Hour
	inc.OpenedAt = time.Now()
	if err := p.Handle(context.Background(), &inc); err != nil {
		t.Fatal(err)
	}
	r := verifyRecords(t, cfg, keys)[0]
	if r.LLM != nil || r.Intake.Outcome != "not_routed" || r.Intake.Reason != "source_unavailable" {
		t.Fatalf("запись: %+v %+v", r, r.Intake)
	}
}

type failingCollector struct{}

func (failingCollector) Collect(context.Context, Incident, ServiceConfig, time.Time) (Snapshot, error) {
	return Snapshot{Status: []audit.SourceStatus{{Source: "platform.topology", Status: "unavailable", Error: "timeout"}}},
		&ErrCriticalSource{"platform.topology", &SourceError{"timeout"}}
}
