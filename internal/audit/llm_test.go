package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func notSent(reason string) func(r *DecisionRecord) {
	return func(r *DecisionRecord) {
		r.Model, r.Prompt, r.Answer = nil, nil, nil
		r.LLM = &LLMInfo{Mode: "hybrid", Outcome: "not_sent", Reason: reason, DataClass: "internal", Backend: "openrouter",
			Jurisdiction: "US", Masker: "test/1", Sources: []string{}, ExcludedFragments: []FragmentRef{}, DroppedFragments: []FragmentRef{}}
		switch reason {
		case "unavailable", "halted", "budget_incident", "budget_service_day":
			r.LLM.DegradeL1 = true
		case "required_excluded":
			r.LLM.ExcludedFragments = []FragmentRef{{ID: "f1", Source: "logs.loki", Class: "confidential", Reason: "source_class", Required: true}}
		case "context_ceiling":
			r.LLM.DroppedFragments = []FragmentRef{{ID: "f1", Source: "k8s.events", Class: "internal", Reason: "context_ceiling"}}
			r.LLM.ContextTruncated = true
		}
	}
}

func TestValidateLLM(t *testing.T) {
	const base = "noop_requested_l0" // L0
	for _, reason := range []string{"required_excluded", "context_ceiling", "budget_incident", "budget_service_day", "unavailable", "halted", "canceled"} {
		r := shadowRecord(t, base)
		notSent(reason)(r)
		if err := r.Validate(); err != nil {
			t.Errorf("not_sent %s: %v", reason, err)
		}
	}
	errAnswer := shadowRecord(t, base)
	errAnswer.Answer = &AnswerInfo{Status: "error", ErrorKind: "transport_timeout", Attempts: 6}
	if err := errAnswer.Validate(); err != nil {
		t.Errorf("error без sha256: %v", err)
	}
	bad := map[string]func(r *DecisionRecord){
		"model без llm":         func(r *DecisionRecord) { r.LLM = nil },
		"sent без model":        func(r *DecisionRecord) { r.Model, r.Prompt, r.Answer = nil, nil, nil },
		"restricted при sent":   func(r *DecisionRecord) { r.LLM.DataClass = "restricted" },
		"confidential при sent": func(r *DecisionRecord) { r.LLM.DataClass = "confidential" },
		"неизвестный класс":     func(r *DecisionRecord) { r.LLM.DataClass = "secret" },
		"off с excluded": func(r *DecisionRecord) {
			notSent("unavailable")(r)
			r.LLM.Mode, r.LLM.Reason, r.LLM.DegradeL1 = "off", "mode_off", false
		},
		"неизвестная причина": func(r *DecisionRecord) { notSent("x")(r) },
		"required в excluded при sent": func(r *DecisionRecord) {
			r.LLM.ExcludedFragments = []FragmentRef{{ID: "f", Source: "s", Class: "internal", Reason: "masker_failure", Required: true}}
		},
		"dropped с required":    func(r *DecisionRecord) { notSent("context_ceiling")(r); r.LLM.DroppedFragments[0].Required = true },
		"truncated без dropped": func(r *DecisionRecord) { r.LLM.ContextTruncated = true },
		"degrade без причины":   func(r *DecisionRecord) { r.LLM.DegradeL1 = true },
		"switched при not_sent": func(r *DecisionRecord) { notSent("halted")(r); r.LLM.EndpointSwitched = true },
		"degrade при L2":        func(r *DecisionRecord) { notSent("halted")(r); r.AutonomyLevel = "L2" },
		"answer при not_sent":   func(r *DecisionRecord) { a := r.Answer; notSent("halted")(r); r.Answer = a },
		"zdr false":             func(r *DecisionRecord) { r.Model.RequestFlags.ZDR = false },
		"allow_fallbacks true":  func(r *DecisionRecord) { r.Model.RequestFlags.AllowFallbacks = true },
		"роль endpoint":         func(r *DecisionRecord) { r.Model.EndpointRole = "x" },
		"error_kind при ok":     func(r *DecisionRecord) { r.Answer.ErrorKind = "x" },
		"error без error_kind":  func(r *DecisionRecord) { r.Answer = &AnswerInfo{Status: "error"} },
		"отрицательный usage":   func(r *DecisionRecord) { n := int64(-1); r.Answer.Usage = &Usage{PromptTokens: &n} },
		"плохой request_sha256": func(r *DecisionRecord) { r.Prompt.RequestSHA256 = "x" },
		"повтор ID фрагмента": func(r *DecisionRecord) {
			notSent("context_ceiling")(r)
			r.LLM.ExcludedFragments = []FragmentRef{{ID: "f1", Source: "s", Class: "internal", Reason: "masker_failure"}}
		},
		"слишком много schema_errors": func(r *DecisionRecord) { r.Answer.SchemaErrors = make([]string, 17) },
		"sent с reason": func(r *DecisionRecord) { r.LLM.Reason = "halted" },
		"строка провайдера > 256 байт": func(r *DecisionRecord) { r.Model.Provider = strings.Repeat("x", 257) },
	}
	for name, f := range bad {
		r := shadowRecord(t, base)
		f(r)
		if err := r.Validate(); err == nil {
			t.Errorf("%s: ошибка не возвращена", name)
		}
	}
}

func validEvent(kind string) *RouterEvent {
	e := &RouterEvent{Schema: RouterEventSchema, EventID: NewEventID(), RecordedAt: Timestamp(time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)),
		Kind: kind, Model: "z-ai/glm-5.3-flash-20260826", Initiator: Actor{Kind: "system", ID: "llm-router-1"}}
	switch kind {
	case "endpoint_down":
		e.Endpoint, e.Role, e.Reason, e.ConsecutiveFailures = "inceptron-fp8", "primary", "consecutive_failures", 3
	case "endpoint_up":
		e.Endpoint, e.Role, e.Reason, e.StableForS = "inceptron-fp8", "primary", "health_stable", 600
	case "endpoint_quarantined":
		e.Endpoint, e.Role, e.Reason = "wafer-nvfp4", "fallback", "provider_mismatch"
	case "active_changed":
		e.From, e.To, e.Reason = "inceptron-fp8", "wafer-nvfp4", "consecutive_failures"
	case "router_halted":
		e.Reason = "auth"
	case "router_resumed":
		e.Initiator = Actor{Kind: "human", ID: "sre-1"}
		e.Reason = "operator"
	}
	return e
}

func TestRouterEventValidate(t *testing.T) {
	for _, k := range []string{"endpoint_down", "endpoint_up", "endpoint_quarantined", "active_changed", "router_halted", "router_resumed"} {
		if err := validEvent(k).Validate(); err != nil {
			t.Errorf("%s: %v", k, err)
		}
	}
	bad := map[string]func(e *RouterEvent){
		"неизвестный kind":             func(e *RouterEvent) { e.Kind = "x" },
		"down без Role":                func(e *RouterEvent) { e.Kind, e.Role = "endpoint_down", "" },
		"down без счётчика":            func(e *RouterEvent) { e.Kind, e.ConsecutiveFailures = "endpoint_down", 0 },
		"down с чужой причиной":        func(e *RouterEvent) { e.Kind, e.Reason = "endpoint_down", "auth" },
		"up без stable_for_s":          func(e *RouterEvent) { e.Kind, e.StableForS = "endpoint_up", 0 },
		"up с чужой причиной":          func(e *RouterEvent) { e.Kind, e.Reason, e.StableForS = "endpoint_up", "x", 1 },
		"quarantined с чужой причиной": func(e *RouterEvent) { e.Kind, e.Reason = "endpoint_quarantined", "x" },
		"active_changed from == to":    func(e *RouterEvent) { e.Kind, e.From, e.To = "active_changed", "a", "a" },
		"active_changed с endpoint":    func(e *RouterEvent) { e.Kind, e.From, e.To, e.Reason = "active_changed", "a", "b", "x" },
		"halted с чужой причиной":      func(e *RouterEvent) { e.Kind, e.Reason = "router_halted", "x" },
		"resumed не человеком":         func(e *RouterEvent) { e.Kind = "router_resumed" },
		"плохой event_id":              func(e *RouterEvent) { e.EventID = "dr-1" },
		"пустая модель":                func(e *RouterEvent) { e.Model = "" },
	}
	for name, f := range bad {
		e := validEvent("endpoint_down")
		f(e)
		if err := e.Validate(); err == nil {
			t.Errorf("%s: ошибка не возвращена", name)
		}
	}
}

func TestMixedChain(t *testing.T) {
	s, k := newSigner(t)
	path := filepath.Join(t.TempDir(), "c.jsonl")
	w, err := OpenWriter(path, "agent-staging-1", s, k)
	if err != nil {
		t.Fatal(err)
	}
	must := func(_ Entry, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(w.Append(shadowRecord(t, "noop_requested_l0")))
	must(w.AppendEvent(validEvent("endpoint_down")))
	must(w.Append(shadowRecord(t, "noop_requested_l0")))
	must(w.AppendEvent(validEvent("active_changed")))
	must(w.Append(shadowRecord(t, "noop_requested_l0")))
	w.Close()
	var st VerifyStats
	if _, err := verifyFile(t, path, k, VerifyOptions{Stats: &st}); err != nil || st.Records != 3 || st.RouterEvents != 2 || st.KillSwitchEvents != 0 || st.Unverified != 0 {
		t.Fatalf("verify: %v %+v", err, st)
	}
	w, err = OpenWriter(path, "agent-staging-1", s, k)
	if err != nil {
		t.Fatal(err)
	}
	must(w.AppendEvent(validEvent("router_halted")))
	w.Close()

	orig := lines(t, path)
	mutate := func(i int, f func(rec map[string]any)) {
		t.Helper()
		var e map[string]any
		json.Unmarshal(bytes.TrimSpace(orig[i]), &e)
		rec := e["record"].(map[string]any)
		f(rec)
		b, _ := json.Marshal(rec)
		e["record_sha256"] = sha256Prefixed(b)
		e["hash"] = entryHash(e["chain_id"].(string), uint64(e["seq"].(float64)), e["prev_hash"].(string), e["record_sha256"].(string))
		e["record"] = rec
		out, _ := json.Marshal(e)
		ls := append([][]byte(nil), orig...)
		ls[i] = append(out, '\n')
		// подпись не пересчитана: любая правка записи ловится уже ею.
		if _, err := verifyFile(t, writeLines(t, ls), k, VerifyOptions{}); err == nil {
			t.Fatal("подмена события не обнаружена")
		}
	}
	mutate(1, func(rec map[string]any) { rec["schema"] = RecordSchema })
	mutate(1, func(rec map[string]any) { rec["schema"] = "x" })
	mutate(1, func(rec map[string]any) { rec["kind"] = "x" })
	// Дубль event_id (подписи верны).
	if _, err := verifyFile(t, writeLines(t, [][]byte{orig[1], orig[1]}), k, VerifyOptions{}); err == nil {
		t.Fatal("дубль строки принят")
	}
	// Неизвестная схема записи с верной подписью.
	w2, err := OpenWriter(filepath.Join(t.TempDir(), "u.jsonl"), "agent-staging-1", s, k)
	if err != nil {
		t.Fatal(err)
	}
	defer w2.Close()
	if _, err := w2.appendBody([]byte(`{"schema":"x"}`)); err != nil {
		t.Fatal(err)
	}
	f, _ := os.Open(w2.f.Name())
	defer f.Close()
	if _, err := Verify(f, k, VerifyOptions{}); err == nil || !strings.Contains(err.Error(), "неизвестная схема") {
		t.Fatalf("неизвестная схема: %v", err)
	}
	// Fail-closed: после сбоя подписи события не пишутся.
	w3, err := OpenWriter(filepath.Join(t.TempDir(), "f.jsonl"), "agent-staging-1", failingSigner{s}, k)
	if err != nil {
		t.Fatal(err)
	}
	defer w3.Close()
	if _, err := w3.AppendEvent(validEvent("router_halted")); !errors.Is(err, ErrWriterFailed) {
		t.Fatalf("подпись: %v", err)
	}
	if _, err := w3.AppendEvent(validEvent("router_halted")); !errors.Is(err, ErrWriterFailed) {
		t.Fatalf("после отказа: %v", err)
	}
}
