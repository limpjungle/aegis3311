package audit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/limpjungle/aegis3311/internal/strictjson"
)

// notRoutedRecord — запись без обращения к модели: нет llm/model/prompt/answer, вердикта нет, уровень L0.
func notRoutedRecord(t testing.TB, reason string) *DecisionRecord {
	t.Helper()
	r := shadowRecord(t, "noop_requested_l0")
	r.LLM, r.Model, r.Prompt, r.Answer, r.Verdict = nil, nil, nil, nil, nil
	r.AutonomyLevel = "L0"
	r.Intake = &IntakeInfo{Source: "alerts.alertmanager", FirstAlertAt: "2026-11-07T11:50:00Z", CollectedAt: "2026-11-07T11:52:00Z",
		Alerts: []string{"0123456789abcdef"}, Sources: []SourceStatus{{Source: "platform.topology", Status: "unavailable", Error: "timeout"}},
		Outcome: "not_routed", Reason: reason}
	return r
}

func routedRecord(t testing.TB) *DecisionRecord {
	t.Helper()
	r := shadowRecord(t, "noop_requested_l0")
	r.Intake = &IntakeInfo{Source: "alerts.alertmanager", FirstAlertAt: "2026-11-07T11:50:00Z", CollectedAt: "2026-11-07T11:52:00Z",
		Alerts: []string{"0123456789abcdef"}, Sources: []SourceStatus{{Source: "metrics.prometheus", Status: "ok", Items: 3}}, Outcome: "routed"}
	return r
}

// Каждое правило validateIntake: допустимые формы проходят, каждое нарушение отвергается.
func TestValidateIntake(t *testing.T) {
	if err := routedRecord(t).Validate(); err != nil {
		t.Fatalf("routed: %v", err)
	}
	for _, reason := range []string{"source_unavailable", "rate_limited", "resolved_before_collect", "attempts_exhausted", "invalid_request"} {
		if err := notRoutedRecord(t, reason).Validate(); err != nil {
			t.Errorf("not_routed/%s: %v", reason, err)
		}
	}
	// запись без блока intake (старый формат) проходит
	old := shadowRecord(t, "noop_requested_l0")
	if err := old.Validate(); err != nil {
		t.Errorf("запись без intake: %v", err)
	}
	for _, st := range []string{"ok", "empty", "partial", "truncated", "unavailable", "skipped"} {
		r := routedRecord(t)
		r.Intake.Sources = []SourceStatus{{Source: "k8s.events", Status: st}}
		if err := r.Validate(); err != nil {
			t.Errorf("статус %s: %v", st, err)
		}
	}
	for _, e := range []string{"timeout", "network", "oversize", "decode", "http_503", "http_404"} {
		r := routedRecord(t)
		r.Intake.Sources = []SourceStatus{{Source: "k8s.events", Status: "unavailable", Error: e}}
		if err := r.Validate(); err != nil {
			t.Errorf("класс ошибки %s: %v", e, err)
		}
	}

	manyAlerts := make([]string, 65)
	for i := range manyAlerts {
		manyAlerts[i] = "0123456789abcdef"
	}
	okAlerts := manyAlerts[:64]
	manySrc := make([]SourceStatus, 33)
	for i := range manySrc {
		manySrc[i] = SourceStatus{Source: "s", Status: "ok"}
	}
	bad := map[string]func(r *DecisionRecord){
		"routed без llm": func(r *DecisionRecord) {
			r.LLM, r.Model, r.Prompt, r.Answer, r.Verdict = nil, nil, nil, nil, nil
			r.AutonomyLevel = "L0"
		},
		"not_routed с llm":               func(r *DecisionRecord) { r.Intake.Outcome, r.Intake.Reason = "not_routed", "rate_limited" },
		"routed с причиной":              func(r *DecisionRecord) { r.Intake.Reason = "rate_limited" },
		"неизвестный outcome":            func(r *DecisionRecord) { r.Intake.Outcome = "maybe" },
		"пустой outcome":                 func(r *DecisionRecord) { r.Intake.Outcome = "" },
		"пустой source":                  func(r *DecisionRecord) { r.Intake.Source = "" },
		"first_alert_at не UTC":          func(r *DecisionRecord) { r.Intake.FirstAlertAt = "2026-11-07T14:50:00+03:00" },
		"first_alert_at мусор":           func(r *DecisionRecord) { r.Intake.FirstAlertAt = "вчера" },
		"first_alert_at пуст":            func(r *DecisionRecord) { r.Intake.FirstAlertAt = "" },
		"collected_at +00:00 вместо Z":   func(r *DecisionRecord) { r.Intake.CollectedAt = "2026-11-07T11:52:00+00:00" },
		"collected_at не UTC":            func(r *DecisionRecord) { r.Intake.CollectedAt = "2026-11-07T11:52:00-05:00" },
		"fingerprint не hex":             func(r *DecisionRecord) { r.Intake.Alerts = []string{"zzzzzzzzzzzzzzzz"} },
		"fingerprint заглавные":          func(r *DecisionRecord) { r.Intake.Alerts = []string{"0123456789ABCDEF"} },
		"fingerprint короткий":           func(r *DecisionRecord) { r.Intake.Alerts = []string{"0123"} },
		"fingerprint с переводом строки": func(r *DecisionRecord) { r.Intake.Alerts = []string{"0123456789abcdef\n"} },
		"алертов 65":                     func(r *DecisionRecord) { r.Intake.Alerts = manyAlerts },
		"источников 33":                  func(r *DecisionRecord) { r.Intake.Sources = manySrc },
		"пустое имя источника":           func(r *DecisionRecord) { r.Intake.Sources = []SourceStatus{{Source: "", Status: "ok"}} },
		"неизвестный статус":             func(r *DecisionRecord) { r.Intake.Sources = []SourceStatus{{Source: "s", Status: "fine"}} },
		"отрицательные items":            func(r *DecisionRecord) { r.Intake.Sources = []SourceStatus{{Source: "s", Status: "ok", Items: -1}} },
		"ошибка свободным текстом": func(r *DecisionRecord) {
			r.Intake.Sources = []SourceStatus{{Source: "s", Status: "unavailable", Error: "boom: body"}}
		},
		"http без кода": func(r *DecisionRecord) {
			r.Intake.Sources = []SourceStatus{{Source: "s", Status: "unavailable", Error: "http_"}}
		},
		"http_4040": func(r *DecisionRecord) {
			r.Intake.Sources = []SourceStatus{{Source: "s", Status: "unavailable", Error: "http_4040"}}
		},
		"ошибка > 64 байт": func(r *DecisionRecord) {
			r.Intake.Sources = []SourceStatus{{Source: "s", Status: "unavailable", Error: strings.Repeat("a", 65)}}
		},
	}
	for name, f := range bad {
		r := routedRecord(t)
		f(r)
		if err := r.Validate(); err == nil {
			t.Errorf("%s: ошибка не возвращена", name)
		}
	}
	badNR := map[string]func(r *DecisionRecord){
		"not_routed без причины":        func(r *DecisionRecord) { r.Intake.Reason = "" },
		"not_routed, чужая причина":     func(r *DecisionRecord) { r.Intake.Reason = "because" },
		"not_routed + routed в outcome": func(r *DecisionRecord) { r.Intake.Outcome = "routed"; r.Intake.Reason = "" },
	}
	for name, f := range badNR {
		r := notRoutedRecord(t, "rate_limited")
		f(r)
		if err := r.Validate(); err == nil {
			t.Errorf("%s: ошибка не возвращена", name)
		}
	}
	// границы: ровно 64 fingerprint и 32 источника допустимы
	r := routedRecord(t)
	r.Intake.Alerts, r.Intake.Sources = okAlerts, manySrc[:32]
	if err := r.Validate(); err != nil {
		t.Errorf("границы 64/32: %v", err)
	}
}

// OnRecord вызывается для каждой записи решения (но не для событий роутера); HasIncidentRecord работает сразу после
// Append и после повторного открытия Writer; старые записи без intake читаются.
func TestIntakeOnRecordAndHasIncidentRecord(t *testing.T) {
	path, s, k, w := writeChain(t, 2) // записи без intake, инцидент inc-42
	if !w.HasIncidentRecord("inc-42") || w.HasIncidentRecord("inc-1") {
		t.Fatal("HasIncidentRecord после Append")
	}
	r := routedRecord(t)
	r.Incident.ID = "inc-20260107T100000Z-0123456789ab"
	if _, err := w.Append(r); err != nil {
		t.Fatal(err)
	}
	if !w.HasIncidentRecord(r.Incident.ID) {
		t.Fatal("новый инцидент не виден")
	}
	// отклонённая Validate запись не попадает во множество
	badR := routedRecord(t)
	badR.Incident.ID = "inc-bad"
	badR.Intake.Outcome = "zzz"
	if _, err := w.Append(badR); err == nil {
		t.Fatal("невалидная запись принята")
	}
	if w.HasIncidentRecord("inc-bad") {
		t.Error("отклонённая запись попала во множество инцидентов")
	}
	w.Close()

	w2, err := OpenWriter(path, "agent-staging-1", s, k)
	if err != nil {
		t.Fatal(err)
	}
	defer w2.Close()
	if !w2.HasIncidentRecord("inc-42") || !w2.HasIncidentRecord(r.Incident.ID) || w2.HasIncidentRecord("inc-bad") {
		t.Error("множество инцидентов после повторного открытия")
	}
	var seen []uint64
	var withIntake int
	if _, err := verifyFile(t, path, k, VerifyOptions{ChainID: "agent-staging-1", OnRecord: func(seq uint64, rec *DecisionRecord) {
		seen = append(seen, seq)
		if rec.Intake != nil {
			withIntake++
		}
	}}); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 3 || withIntake != 1 {
		t.Errorf("OnRecord: seq=%v с intake=%d", seen, withIntake)
	}
}

// Запись без блока intake не содержит ключа (omitempty); запись с блоком переживает strict-разбор и сериализуется
// побайтно так же; неизвестное поле внутри intake отвергается.
func TestIntakeJSONForm(t *testing.T) {
	b, _ := json.Marshal(shadowRecord(t, "noop_requested_l0"))
	if strings.Contains(string(b), `"intake"`) {
		t.Error("запись без intake содержит ключ intake")
	}
	a, _ := json.Marshal(notRoutedRecord(t, "rate_limited"))
	var back DecisionRecord
	if err := strictjson.Decode(a, &back); err != nil {
		t.Fatal(err)
	}
	if c, _ := json.Marshal(&back); !bytes.Equal(a, c) {
		t.Errorf("повторная сериализация отличается:\n%s\n%s", a, c)
	}
	extra := strings.Replace(string(a), `"outcome":"not_routed"`, `"outcome":"not_routed","x":1`, 1)
	if err := strictjson.Decode([]byte(extra), &DecisionRecord{}); err == nil {
		t.Error("неизвестное поле внутри intake принято")
	}
}
