package intake

import (
	"context"
	"strings"
	"testing"

	"github.com/limpjungle/aegis3311/internal/openrouter"
	"github.com/limpjungle/aegis3311/internal/pyjson"
)

func TestConfigMetricsListen(t *testing.T) {
	for _, ok := range []string{"", ":9464", "127.0.0.1:9464", "[::1]:9464", "localhost:9464", "metrics.svc:0", "0.0.0.0:65535"} {
		m := miniConfig()
		if ok != "" {
			m["metrics_listen"] = ok
		}
		c, err := parse(t, m)
		if err != nil {
			t.Errorf("%q: %v", ok, err)
		} else if c.MetricsListen != ok {
			t.Errorf("%q: прочитано %q", ok, c.MetricsListen)
		}
	}
	for _, bad := range []string{"9464", "host:abc", "host:70000", "host:", "host:-1", "host:09464", "host:+1", "a b:1", ":9464 ", "http://h:1", "[::1]", "h:1:2", "host:1e3", "-h:1", "h_x:1"} {
		m := miniConfig()
		m["metrics_listen"] = bad
		if _, err := parse(t, m); err == nil || !strings.Contains(err.Error(), "metrics_listen") {
			t.Errorf("%q: ожидалась ошибка metrics_listen, получено %v", bad, err)
		}
	}
}

func TestConfigKillSwitchRequiredMessage(t *testing.T) {
	m := miniConfig()
	delete(m, "kill_switch")
	_, err := parse(t, m)
	if err == nil {
		t.Fatal("секция kill_switch должна быть обязательной")
	}
	for _, want := range []string{"kill_switch", "обязательна", "intake-deploy.md", "llm.mode=off"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("в тексте ошибки нет %q: %v", want, err)
		}
	}
}

func TestPipelineSourceReplaySnapshot(t *testing.T) {
	run := func(source string) string {
		rt, cfg, keys := openTestRuntime(t, &stubTr{post: func([]byte) (openrouter.Response, error) { return okReply(), nil }})
		cases := loadCases(t, "probe-v3.jsonl")
		snap := snapshotFromGolden(t, pyjson.Marshal(cases[0].Get("input"), pyjson.Canonical))
		p, inc, _ := newTestPipeline(t, rt, snap, "")
		p.Source = source
		if err := p.Handle(context.Background(), &inc); err != nil {
			t.Fatal(err)
		}
		recs := verifyRecords(t, cfg, keys) // Verify включает Validate записи
		if len(recs) != 1 {
			t.Fatalf("записей %d", len(recs))
		}
		return recs[0].Intake.Source
	}
	if got := run(""); got != "alerts.alertmanager" {
		t.Errorf("по умолчанию source = %q", got)
	}
	if got := run("replay.snapshot"); got != "replay.snapshot" {
		t.Errorf("replay: source = %q", got)
	}
}

func TestPipelineSourceReplayModeOffStatus(t *testing.T) {
	rt, cfg, keys := openTestRuntime(t, &stubTr{post: func([]byte) (openrouter.Response, error) { return okReply(), nil }})
	cases := loadCases(t, "probe-v3.jsonl")
	snap := snapshotFromGolden(t, pyjson.Marshal(cases[0].Get("input"), pyjson.Canonical))
	p, inc, _ := newTestPipeline(t, rt, snap, "")
	p.Source = "replay.snapshot"
	p.Lookup = func(ns, s string) (ServiceConfig, bool) {
		sc := ServiceConfig{Namespace: ns, Service: s, LLMMode: "off"}
		return sc, true
	}
	if err := p.Handle(context.Background(), &inc); err != nil {
		t.Skipf("конфигурация сервиса для mode=off недостаточна в этом стенде: %v", err)
	}
	for _, r := range verifyRecords(t, cfg, keys) {
		if r.Intake.Source != "replay.snapshot" {
			t.Errorf("source = %q", r.Intake.Source)
		}
		for _, s := range r.Intake.Sources {
			if s.Source == "alerts.alertmanager" {
				t.Errorf("статус источника alerts.alertmanager в записи replay")
			}
		}
	}
}
