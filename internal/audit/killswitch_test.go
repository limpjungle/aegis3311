package audit

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func ksState(stopped bool, reason string) KillSwitchState {
	return KillSwitchState{Stopped: stopped, Reason: reason, Global: reason == "global", Cluster: reason == "cluster", Actions: []string{},
		LivenessConfirmed: !stopped || reason != "no_confirmation", EvaluatedAt: "2026-11-07T12:00:00Z"}
}

func validKSEvent(kind string) *KillSwitchEvent {
	ms := int64(1500)
	e := &KillSwitchEvent{Schema: KillSwitchEventSchema, EventID: NewKillSwitchEventID(), RecordedAt: Timestamp(time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)),
		Kind: kind, From: "running", TargetCluster: "prod-eu-1", Triggers: []string{h('a')}, IssuedAt: "2026-11-07T11:59:58.5Z", Signers: []string{"oncall-a"},
		AppliedAt: "2026-11-07T12:00:00Z", LatencyMs: &ms, StopWatermark: "2026-11-07T11:59:58.5Z",
		Channels:  []KillSwitchChannel{{Channel: "oob", Status: "fresh", Effect: "stop", Confirmation: "none", Signers: []string{"oncall-a"}, IssuedAt: "2026-11-07T11:59:58.5Z", DocSHA256: h('a')}},
		Initiator: Actor{Kind: "system", ID: "intake-1"}}
	switch kind {
	case "kill_switch_engaged":
		e.State = ksState(true, "global")
	case "kill_switch_released":
		e.From, e.State = "stopped", ksState(false, "")
	case "kill_switch_updated":
		e.State = ksState(false, "")
	}
	return e
}

func TestKillSwitchEventValidate(t *testing.T) {
	for _, k := range []string{"kill_switch_engaged", "kill_switch_released", "kill_switch_updated"} {
		if err := validKSEvent(k).Validate(); err != nil {
			t.Errorf("%s: %v", k, err)
		}
	}
	bad := map[string]func(e *KillSwitchEvent){
		"engaged без stopped": func(e *KillSwitchEvent) { e.State = ksState(false, "") },
		"engaged из stopped":  func(e *KillSwitchEvent) { e.From = "stopped" },
		"released из running": func(e *KillSwitchEvent) {
			e.Kind, e.From, e.State = "kill_switch_released", "running", ksState(false, "")
		},
		"updated из none":             func(e *KillSwitchEvent) { e.Kind, e.From = "kill_switch_updated", "none" },
		"reason не согласован":        func(e *KillSwitchEvent) { e.State.Reason = "cluster" },
		"stopped не согласован":       func(e *KillSwitchEvent) { e.State.Stopped = false },
		"actions nil":                 func(e *KillSwitchEvent) { e.State.Actions = nil },
		"actions не отсортированы":    func(e *KillSwitchEvent) { e.State.Actions = []string{"b.x", "a.x"} },
		"actions дубль":               func(e *KillSwitchEvent) { e.State.Actions = []string{"a.x", "a.x"} },
		"actions форма":               func(e *KillSwitchEvent) { e.State.Actions = []string{"Bad"} },
		"не UTC":                      func(e *KillSwitchEvent) { e.AppliedAt = "2026-11-07T15:00:00+03:00" },
		"триггеры без latency":        func(e *KillSwitchEvent) { e.LatencyMs = nil },
		"latency без триггеров":       func(e *KillSwitchEvent) { e.Triggers, e.IssuedAt, e.Signers = []string{}, "", []string{} },
		"no_confirmation с триггером": func(e *KillSwitchEvent) { e.State = ksState(true, "no_confirmation") },
		"нет каналов":                 func(e *KillSwitchEvent) { e.Channels = nil },
		"канал повторён":              func(e *KillSwitchEvent) { e.Channels = append(e.Channels, e.Channels[0]) },
		"неизвестный канал":           func(e *KillSwitchEvent) { e.Channels[0].Channel = "etcd" },
		"initiator не system":         func(e *KillSwitchEvent) { e.Initiator.Kind = "agent" },
		"event_id":                    func(e *KillSwitchEvent) { e.EventID = "re-" + strings.Repeat("0", 32) },
		"длинная строка":              func(e *KillSwitchEvent) { e.TargetCluster = strings.Repeat("x", 300) },
	}
	for name, mut := range bad {
		e := validKSEvent("kill_switch_engaged")
		mut(e)
		if e.Validate() == nil {
			t.Errorf("%s: принято", name)
		}
	}
}

func TestKillSwitchChainAndWriter(t *testing.T) {
	signer, keys := newSigner(t)
	path := filepath.Join(t.TempDir(), "chain.jsonl")
	w, err := OpenWriter(path, "chain-ks", signer, keys)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := w.LastKillSwitchEvent(); ok {
		t.Fatal("в пустой цепочке событий нет")
	}
	e1, e2 := validKSEvent("kill_switch_engaged"), validKSEvent("kill_switch_released")
	for _, e := range []*KillSwitchEvent{e1, e2} {
		if _, err := w.AppendKillSwitchEvent(e); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := w.AppendKillSwitchEvent(e1); err == nil {
		t.Error("повтор event_id принят")
	}
	if _, err := w.AppendEvent(validEvent("router_halted")); err != nil {
		t.Fatal(err)
	}
	if last, ok := w.LastKillSwitchEvent(); !ok || last.EventID != e2.EventID {
		t.Errorf("последнее: %+v", last)
	}
	w.Close()
	w2, err := OpenWriter(path, "chain-ks", signer, keys)
	if err != nil {
		t.Fatal(err)
	}
	if last, ok := w2.LastKillSwitchEvent(); !ok || last.EventID != e2.EventID || last.LatencyMs == nil {
		t.Errorf("после переоткрытия: %+v", last)
	}
	w2.Close()
	var st VerifyStats
	var seen []string
	if _, err := verifyFile(t, path, keys, VerifyOptions{Stats: &st, OnKillSwitchEvent: func(_ uint64, ev *KillSwitchEvent) { seen = append(seen, ev.Kind) }}); err != nil {
		t.Fatal(err)
	}
	if st.KillSwitchEvents != 2 || st.RouterEvents != 1 || len(seen) != 2 {
		t.Errorf("статистика: %+v %v", st, seen)
	}
	// неизвестное поле в событии отвергается Verify
	b, _ := os.ReadFile(path)
	if bytes.Contains(b, []byte(`"initiator"`)) {
		ls := lines(t, path)
		ls[0] = bytes.Replace(ls[0], []byte(`\"initiator\"`), []byte(`\"initiator2\"`), 1)
		ls[0] = bytes.Replace(ls[0], []byte(`"initiator"`), []byte(`"initiator2"`), 1)
		if _, err := verifyFile(t, writeLines(t, ls), keys, VerifyOptions{}); err == nil {
			t.Error("подмена записи принята")
		}
	}
}

func TestValidateKillSwitchRecord(t *testing.T) {
	ok := func(r *DecisionRecord) { r.KillSwitch = &KillSwitchInfo{State: ksState(false, "")} }
	r := routedRecord(t)
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	ok(r)
	if err := r.Validate(); err != nil {
		t.Errorf("работа: %v", err)
	}
	cases := map[string]func(r *DecisionRecord){
		"stopped при hybrid": func(r *DecisionRecord) { r.KillSwitch.State = ksState(true, "global") },
		"reason":             func(r *DecisionRecord) { r.KillSwitch.State.Reason = "global" },
		"actions порядок":    func(r *DecisionRecord) { r.KillSwitch.State.Actions = []string{"b.x", "a.x"} },
		"stopped_during при stopped": func(r *DecisionRecord) {
			r.LLM, r.Model, r.Prompt, r.Answer, r.Verdict, r.AutonomyLevel = nil, nil, nil, nil, nil, "L0"
			r.Intake.Outcome, r.Intake.Reason = "not_routed", "source_unavailable"
			r.KillSwitch = &KillSwitchInfo{State: ksState(true, "global"), StoppedDuringRoute: true}
		},
	}
	for name, mut := range cases {
		r := routedRecord(t)
		ok(r)
		mut(r)
		if r.Validate() == nil {
			t.Errorf("%s: принято", name)
		}
	}
	// остановка с not_routed и без модели допустима
	r = notRoutedRecord(t, "source_unavailable")
	r.KillSwitch = &KillSwitchInfo{State: ksState(true, "no_confirmation")}
	if err := r.Validate(); err != nil {
		t.Errorf("stopped + not_routed: %v", err)
	}
}
