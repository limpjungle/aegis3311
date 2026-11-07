package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Подпись верна, но schema подменена: запись не должна проходить проверку ни в одну сторону.
func TestSignedSchemaSwapRejected(t *testing.T) {
	s, k := newSigner(t)
	dir := t.TempDir()

	evBody, err := json.Marshal(validEvent("endpoint_down"))
	if err != nil {
		t.Fatal(err)
	}
	recBody, err := json.Marshal(shadowRecord(t, "noop_requested_l0"))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"событие под схемой решения": bytes.Replace(evBody, []byte(RouterEventSchema), []byte(RecordSchema), 1),
		"решение под схемой события": bytes.Replace(recBody, []byte(RecordSchema), []byte(RouterEventSchema), 1),
	}
	for name, body := range cases {
		path := filepath.Join(dir, strings.ReplaceAll(name, " ", "_")+".jsonl")
		w, err := OpenWriter(path, "agent-staging-1", s, k)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.appendBody(body); err != nil {
			t.Fatal(err)
		}
		w.Close()
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		_, verr := Verify(f, k, VerifyOptions{})
		f.Close()
		if verr == nil {
			t.Errorf("%s: подписанная подмена схемы принята", name)
		}
	}
}

// Дополнительные негативы инвариантов decision record (план, раздел «Тесты», п. 5).
func TestValidateLLMExtraNegatives(t *testing.T) {
	const base = "noop_requested_l0"
	bad := map[string]func(r *DecisionRecord){
		"класс фрагмента не парсится": func(r *DecisionRecord) {
			r.LLM.ExcludedFragments = []FragmentRef{{ID: "f", Source: "s", Class: "secret", Reason: "masker_failure"}}
		},
		"неизвестная причина исключения": func(r *DecisionRecord) {
			r.LLM.ExcludedFragments = []FragmentRef{{ID: "f", Source: "s", Class: "internal", Reason: "bogus"}}
		},
		"причина отбрасывания не context_ceiling": func(r *DecisionRecord) {
			notSent("context_ceiling")(r)
			r.LLM.DroppedFragments[0].Reason = "masker_failure"
		},
		"off с data_class": func(r *DecisionRecord) {
			notSent("unavailable")(r)
			r.LLM.Mode, r.LLM.Reason, r.LLM.DegradeL1, r.LLM.DataClass = "off", "mode_off", false, "internal"
		},
		"sent с пустым data_class": func(r *DecisionRecord) { r.LLM.DataClass = "" },
		"required_excluded с degrade_l1": func(r *DecisionRecord) {
			notSent("required_excluded")(r)
			r.LLM.DegradeL1 = true
		},
		"ok без body": func(r *DecisionRecord) { r.Answer.Body = nil },
		"error с body": func(r *DecisionRecord) {
			r.Answer = &AnswerInfo{Status: "error", ErrorKind: "transport_timeout", Body: json.RawMessage(`{"a":1}`)}
		},
		"строка schema_errors длиннее 200": func(r *DecisionRecord) {
			r.Answer.SchemaErrors = []string{strings.Repeat("я", 201)}
		},
		"ok без sha256": func(r *DecisionRecord) { r.Answer.SHA256 = "" },
		"отрицательная стоимость": func(r *DecisionRecord) {
			r.Answer.Usage = &Usage{ChargedTokens: 1, CostUSD: -1}
		},
		"пустой endpoint_role":       func(r *DecisionRecord) { r.Model.EndpointRole = "" },
		"отрицательный input_tokens": func(r *DecisionRecord) { r.Prompt.InputTokens = -1 },
		"пустой slug":                func(r *DecisionRecord) { r.Model.Slug = "" },
		"model при not_sent": func(r *DecisionRecord) {
			notSent("halted")(r)
			r.Model = &ModelInfo{Profile: "p", Slug: "s", EndpointRole: "primary", RequestFlags: ProviderFlags{ZDR: true, DataCollection: "deny"}}
		},
		"dropped при reason unavailable": func(r *DecisionRecord) {
			notSent("unavailable")(r)
			r.LLM.DroppedFragments = []FragmentRef{{ID: "f1", Source: "k8s.events", Class: "internal", Reason: "context_ceiling"}}
		},
		"answer при error без error_kind": func(r *DecisionRecord) {
			r.Answer = &AnswerInfo{Status: "error", SHA256: h('c')}
		},
		"неизвестный статус ответа": func(r *DecisionRecord) { r.Answer.Status = "maybe" },
	}
	for name, f := range bad {
		r := shadowRecord(t, base)
		f(r)
		if err := r.Validate(); err == nil {
			t.Errorf("%s: ошибка не возвращена", name)
		}
	}

	// Корректные исходы: mode off без фрагментов и с причиной mode_off; error без sha256.
	off := shadowRecord(t, base)
	off.Model, off.Prompt, off.Answer = nil, nil, nil
	off.LLM = &LLMInfo{Mode: "off", Outcome: "not_sent", Reason: "mode_off", Backend: "openrouter", Jurisdiction: "US",
		Sources: []string{}, ExcludedFragments: []FragmentRef{}, DroppedFragments: []FragmentRef{}}
	if err := off.Validate(); err != nil {
		t.Errorf("mode off: %v", err)
	}
	errNoSHA := shadowRecord(t, base)
	errNoSHA.Answer = &AnswerInfo{Status: "error", ErrorKind: "stopped", Attempts: 3}
	if err := errNoSHA.Validate(); err != nil {
		t.Errorf("error без sha256: %v", err)
	}
}

// Дополнительные негативы событий роутера.
func TestRouterEventExtraNegatives(t *testing.T) {
	if err := validEvent("endpoint_down").Validate(); err != nil {
		t.Fatal(err)
	}
	// no_endpoint допускается без счётчика.
	noEP := validEvent("endpoint_down")
	noEP.Reason, noEP.ConsecutiveFailures = "no_endpoint", 0
	if err := noEP.Validate(); err != nil {
		t.Errorf("no_endpoint: %v", err)
	}
	bad := map[string]func(e *RouterEvent){
		"роль x": func(e *RouterEvent) { e.Role = "x" },
		"active_changed без reason": func(e *RouterEvent) {
			e.Kind, e.From, e.To, e.Endpoint, e.Role, e.Reason = "active_changed", "a", "b", "", "", ""
		},
		"время не UTC":          func(e *RouterEvent) { e.RecordedAt = "2026-11-07T12:00:00+03:00" },
		"отрицательный счётчик": func(e *RouterEvent) { e.ConsecutiveFailures = -1 },
		"initiator unknown":     func(e *RouterEvent) { e.Initiator.Kind = "robot" },
		"model больше 256":      func(e *RouterEvent) { e.Model = strings.Repeat("m", 257) },
	}
	for name, f := range bad {
		e := validEvent("endpoint_down")
		f(e)
		if err := e.Validate(); err == nil {
			t.Errorf("%s: ошибка не возвращена", name)
		}
	}
}

// canceled — not_sent без модели и без деградации; при degrade_l1 или модели запись отвергается.
func TestCanceledInvariants(t *testing.T) {
	ok := shadowRecord(t, "noop_requested_l0")
	notSent("canceled")(ok)
	if err := ok.Validate(); err != nil {
		t.Fatalf("canceled без деградации: %v", err)
	}
	deg := shadowRecord(t, "noop_requested_l0")
	notSent("canceled")(deg)
	deg.LLM.DegradeL1 = true
	if err := deg.Validate(); err == nil {
		t.Error("canceled с degrade_l1 принят")
	}
	withModel := shadowRecord(t, "noop_requested_l0")
	notSent("canceled")(withModel)
	withModel.Model = &ModelInfo{Profile: "p", Slug: "s", EndpointRole: "primary", RequestFlags: ProviderFlags{ZDR: true, DataCollection: "deny"}}
	if err := withModel.Validate(); err == nil {
		t.Error("canceled с model принят")
	}
}

// endpoint_switched: только при sent и при наличии модели; sent с переключением и моделью проходит.
func TestEndpointSwitchedInvariants(t *testing.T) {
	sentSwitched := shadowRecord(t, "noop_requested_l0")
	sentSwitched.LLM.EndpointSwitched = true
	if err := sentSwitched.Validate(); err != nil {
		t.Errorf("sent с переключением: %v", err)
	}
	noModel := shadowRecord(t, "noop_requested_l0")
	noModel.LLM.EndpointSwitched = true
	noModel.Model, noModel.Prompt = nil, nil
	if err := noModel.Validate(); err == nil {
		t.Error("sent с переключением без model принят")
	}
	unavail := shadowRecord(t, "noop_requested_l0")
	notSent("unavailable")(unavail)
	unavail.LLM.EndpointSwitched = true
	if err := unavail.Validate(); err == nil {
		t.Error("unavailable с endpoint_switched принят")
	}
}
