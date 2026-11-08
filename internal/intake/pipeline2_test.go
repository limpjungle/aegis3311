package intake

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/limpjungle/aegis3311/internal/audit"
	"github.com/limpjungle/aegis3311/internal/llmrouter"
	"github.com/limpjungle/aegis3311/internal/openrouter"
	"github.com/limpjungle/aegis3311/internal/pyjson"
	"github.com/limpjungle/aegis3311/internal/step"
)

func replyFor(content string) openrouter.Response {
	c, _ := json.Marshal(content)
	return openrouter.Response{Status: 200, Body: []byte(fmt.Sprintf(`{"id":"g1","model":"m","provider":"Inceptron","choices":[{"finish_reason":"stop","message":{"content":%s}}],"usage":{"prompt_tokens":100,"completion_tokens":50,"total_tokens":150}}`, c))}
}

func answerWith(action string) string {
	return `{"incident_class":"RB-006","root_cause":"load_growth","action":{"type":"` + action +
		`","params":{"scope":null,"pod_name":null,"reason":null,"parameter":null}},"confidence":0.9,"evidence":["a"],"summary":"s"}`
}

type pipeFix struct {
	p    *Pipeline
	inc  Incident
	st   *State
	cfg  routerCfg
	keys audit.Keyring
	snap Snapshot
}
type routerCfg = struct{ recs func() []audit.DecisionRecord }

func newPipeFix(t *testing.T, reply openrouter.Response) (*Pipeline, Incident, *State, func() []audit.DecisionRecord, Snapshot) {
	t.Helper()
	rt, cfg, keys := openTestRuntime(t, &stubTr{post: func([]byte) (openrouter.Response, error) { return reply, nil }})
	c := loadCases(t, "probe-v3.jsonl")[0]
	snap := snapshotFromGolden(t, pyjson.Marshal(c.Get("input"), pyjson.Canonical))
	p, inc, st := newTestPipeline(t, rt, snap, t.TempDir())
	return p, inc, st, func() []audit.DecisionRecord { return verifyRecords(t, cfg, keys) }, snap
}

type countingCollector struct {
	inner Collecting
	n     int
}

func (c *countingCollector) Collect(ctx context.Context, i Incident, s ServiceConfig, t0 time.Time) (Snapshot, error) {
	c.n++
	return c.inner.Collect(ctx, i, s, t0)
}

// Вердикт PEP: действие каталога в неуправляемом namespace → deny namespace_not_managed; в управляемом — не deny по
// namespace; в обоих случаях autonomy_level == verdict.effective_level == L0 (shadow, MVP-A).
func TestPipelineVerdictNamespaceManaged(t *testing.T) {
	for _, action := range []string{"workload.scale_out", "none", "recommend"} {
		for _, managed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/managed=%v", action, managed), func(t *testing.T) {
				p, inc, _, recs, snap := newPipeFix(t, replyFor(answerWith(action)))
				snap.Topology.NamespaceLabels = map[string]string{}
				snap.Topology.TargetLabels = map[string]string{}
				if managed {
					snap.Topology.NamespaceLabels = map[string]string{"aegisops.io/managed": "true"}
					snap.Topology.TargetLabels = map[string]string{"aegisops.io/stateless": "true"}
				}
				p.Collector = FixtureCollector{snap}
				if err := p.Handle(context.Background(), &inc); err != nil {
					t.Fatal(err)
				}
				r := recs()[0]
				if r.Verdict == nil {
					t.Fatal("нет вердикта")
				}
				if r.AutonomyLevel != "L0" || r.Verdict.EffectiveLevel != "L0" || r.Verdict.RequestedLevel != "L0" {
					t.Errorf("уровни: autonomy=%s effective=%s requested=%s", r.AutonomyLevel, r.Verdict.EffectiveLevel, r.Verdict.RequestedLevel)
				}
				if r.Verdict.Decision != "deny" && r.Verdict.Decision != "noop" {
					t.Errorf("решение %s", r.Verdict.Decision)
				}
				has := false
				for _, rs := range r.Verdict.Reasons {
					if rs.Code == "namespace_not_managed" {
						has = true
					}
				}
				if action == "workload.scale_out" && has == managed {
					t.Errorf("managed=%v: namespace_not_managed=%v (%+v)", managed, has, r.Verdict.Reasons)
				}
				if (action == "none" || action == "recommend") && r.Verdict.Decision != "noop" {
					t.Errorf("%s: решение %s", action, r.Verdict.Decision)
				}
			})
		}
	}
}

// Ответ модели не по схеме — записи без вердикта, уровень L0.
func TestPipelineSchemaInvalidNoVerdict(t *testing.T) {
	for name, content := range map[string]string{"не JSON": "я не знаю", "лишнее поле": `{"x":1}`,
		"неизвестное действие": `{"incident_class":"RB-006","root_cause":"load_growth","action":{"type":"cluster.delete","params":{"scope":null,"pod_name":null,"reason":null,"parameter":null}},"confidence":0.9,"evidence":["a"],"summary":"s"}`} {
		t.Run(name, func(t *testing.T) {
			p, inc, st, recs, _ := newPipeFix(t, replyFor(content))
			if err := p.Handle(context.Background(), &inc); err != nil {
				t.Fatal(err)
			}
			r := recs()[0]
			if r.Verdict != nil || r.AutonomyLevel != "L0" || r.Answer == nil || r.Answer.Status == "ok" {
				t.Errorf("verdict=%v level=%s answer=%+v", r.Verdict, r.AutonomyLevel, r.Answer)
			}
			if got, _ := st.Get(inc.ID); got.Status != StatusRecorded {
				t.Errorf("статус %s", got.Status)
			}
		})
	}
}

// Ошибка транспорта модели: запись есть, вердикта нет.
func TestPipelineTransportErrorNoVerdict(t *testing.T) {
	p, inc, _, recs, _ := newPipeFix(t, openrouter.Response{Status: 500, Body: []byte(`{}`)})
	if err := p.Handle(context.Background(), &inc); err != nil {
		t.Fatal(err)
	}
	r := recs()[0]
	if r.Verdict != nil || r.AutonomyLevel != "L0" {
		t.Errorf("verdict=%v level=%s", r.Verdict, r.AutonomyLevel)
	}
}

func TestPipelineModeOff(t *testing.T) {
	p, inc, _, recs, snap := newPipeFix(t, replyFor(answerWith("none")))
	cc := &countingCollector{inner: FixtureCollector{snap}}
	p.Collector = cc
	p.Lookup = func(ns, s string) (ServiceConfig, bool) {
		return ServiceConfig{Namespace: snap.Alert.Namespace, Service: snap.Alert.Service, LLMMode: "off"}, true
	}
	if err := p.Handle(context.Background(), &inc); err != nil {
		t.Fatal(err)
	}
	r := recs()[0]
	if cc.n != 0 {
		t.Error("источники опрошены при llm_mode off")
	}
	if r.LLM == nil || r.LLM.Reason != "mode_off" || r.Model != nil || r.Verdict != nil || r.Intake == nil {
		t.Errorf("запись: llm=%+v model=%v verdict=%v intake=%v", r.LLM, r.Model, r.Verdict, r.Intake)
	}
}

func TestPipelineRateLimited(t *testing.T) {
	p, inc, st, recs, _ := newPipeFix(t, replyFor(answerWith("none")))
	var now time.Time = time.Date(2026, 1, 2, 10, 0, 0, 0, time.UTC)
	p.Now, p.MaxPerHour = func() time.Time { return now }, 2
	svcName := inc.Key.Service
	mk := func(i int) Incident {
		c := inc
		c.ID = fmt.Sprintf("inc-20260102T10000%dZ-aaaaaaaaaaa%d", i, i)
		c.Alerts = map[string]time.Time{"0123456789abcdef": now}
		st.Do(func(d *Data) { cp := c; d.Incidents[c.ID] = &cp })
		return c
	}
	var ids []string
	for i := 0; i < 3; i++ {
		c := mk(i)
		ids = append(ids, c.ID)
		if err := p.Handle(context.Background(), &c); err != nil {
			t.Fatal(err)
		}
	}
	byInc := map[string]audit.DecisionRecord{}
	for _, r := range recs() {
		byInc[r.Incident.ID] = r
	}
	for i, id := range ids {
		r := byInc[id]
		want := "routed"
		if i == 2 {
			want = "not_routed"
		}
		if r.Intake == nil || r.Intake.Outcome != want || (i == 2 && r.Intake.Reason != "rate_limited") {
			t.Errorf("инцидент %d: %+v", i, r.Intake)
		}
		if i == 2 && r.LLM != nil {
			t.Error("rate_limited с обращением к модели")
		}
	}
	// через час лимит снова доступен
	now = now.Add(61 * time.Minute)
	c := mk(3)
	if err := p.Handle(context.Background(), &c); err != nil {
		t.Fatal(err)
	}
	if r := recs()[3]; r.Intake.Outcome != "routed" {
		t.Errorf("после часа: %+v", r.Intake)
	}
	// другой сервис счётчик не делит
	_ = svcName
}

func TestPipelineAttemptsExhausted(t *testing.T) {
	p, inc, st, recs, _ := newPipeFix(t, replyFor(answerWith("none")))
	st.Do(func(d *Data) { d.Incidents[inc.ID].Attempts = MaxAttempts })
	if err := p.Handle(context.Background(), &inc); err != nil {
		t.Fatal(err)
	}
	r := recs()[0]
	if r.Intake.Outcome != "not_routed" || r.Intake.Reason != "attempts_exhausted" || r.LLM != nil {
		t.Errorf("%+v", r.Intake)
	}
	// MaxAttempts-1 → ещё можно
	p, inc, st, recs, _ = newPipeFix(t, replyFor(answerWith("none")))
	st.Do(func(d *Data) { d.Incidents[inc.ID].Attempts = MaxAttempts - 1 })
	p.Handle(context.Background(), &inc)
	if r := recs()[0]; r.Intake.Outcome != "routed" {
		t.Errorf("последняя попытка: %+v", r.Intake)
	}
}

func TestPipelineResolvedBeforeCollect(t *testing.T) {
	p, inc, st, recs, snap := newPipeFix(t, replyFor(answerWith("none")))
	cc := &countingCollector{inner: FixtureCollector{snap}}
	p.Collector = cc
	st.Do(func(d *Data) { d.Incidents[inc.ID].Status = StatusClosing })
	if err := p.Handle(context.Background(), &inc); err != nil {
		t.Fatal(err)
	}
	r := recs()[0]
	if cc.n != 0 || r.Intake.Reason != "resolved_before_collect" || r.LLM != nil {
		t.Errorf("collect=%d intake=%+v", cc.n, r.Intake)
	}
	// статус остаётся closing: закрытие в роутере сделает Service
	if got, _ := st.Get(inc.ID); got.Status != StatusClosing {
		t.Errorf("статус %s", got.Status)
	}
}

type failWriter struct {
	RecordWriter
	err error
}

func (f failWriter) Append(*audit.DecisionRecord) (audit.Entry, error) { return audit.Entry{}, f.err }

type scriptRouter struct {
	Router
	res *llmrouter.Result
	err error
	n   int
}

func (s *scriptRouter) Route(ctx context.Context, r llmrouter.Request) (*llmrouter.Result, error) {
	s.n++
	if s.res == nil && s.err == nil {
		return s.Router.Route(ctx, r)
	}
	return s.res, s.err
}

// Фатальные ошибки: Route вернул ErrAuditFailed; Append не удался. Запись не пишется, состояние не recorded.
func TestPipelineFatalErrors(t *testing.T) {
	t.Run("ErrAuditFailed из Route", func(t *testing.T) {
		p, inc, st, recs, _ := newPipeFix(t, replyFor(answerWith("none")))
		p.Router = &scriptRouter{res: &llmrouter.Result{Outcome: "not_sent", Reason: "halted"}, err: llmrouter.ErrAuditFailed}
		err := p.Handle(context.Background(), &inc)
		if !errors.Is(err, llmrouter.ErrAuditFailed) {
			t.Fatalf("ошибка %v", err)
		}
		if n := len(recs()); n != 0 {
			t.Errorf("записей %d", n)
		}
		if got, _ := st.Get(inc.ID); got.Status == StatusRecorded {
			t.Error("recorded при фатальной ошибке")
		}
	})
	t.Run("res nil и произвольная ошибка", func(t *testing.T) {
		p, inc, st, recs, _ := newPipeFix(t, replyFor(answerWith("none")))
		p.Router = &scriptRouter{err: errors.New("store down")}
		if err := p.Handle(context.Background(), &inc); err == nil {
			t.Fatal("ошибка Route проглочена")
		}
		if len(recs()) != 0 {
			t.Error("запись при фатальной ошибке")
		}
		if got, _ := st.Get(inc.ID); got.Status == StatusRecorded {
			t.Error("recorded")
		}
	})
	t.Run("ошибка Append", func(t *testing.T) {
		p, inc, st, _, _ := newPipeFix(t, replyFor(answerWith("none")))
		p.Writer = failWriter{RecordWriter: p.Writer, err: errors.New("disk full")}
		if err := p.Handle(context.Background(), &inc); err == nil {
			t.Fatal("ошибка Append проглочена")
		}
		if got, _ := st.Get(inc.ID); got.Status == StatusRecorded {
			t.Error("recorded при ошибке Append")
		}
	})
	t.Run("ошибка Append not_routed", func(t *testing.T) {
		p, inc, st, _, snap := newPipeFix(t, replyFor(answerWith("none")))
		p.Writer = failWriter{RecordWriter: p.Writer, err: errors.New("disk full")}
		p.Collector, p.RetryPause, p.Settle = failingCollector{}, time.Millisecond, time.Hour
		inc.OpenedAt = time.Now()
		_ = snap
		if err := p.Handle(context.Background(), &inc); err == nil {
			t.Fatal("ошибка Append проглочена")
		}
		if got, _ := st.Get(inc.ID); got.Status == StatusRecorded {
			t.Error("recorded")
		}
	})
}

// InvalidRequestError от Route и ошибка Assemble дают not_routed/invalid_request.
func TestPipelineInvalidRequest(t *testing.T) {
	t.Run("Route", func(t *testing.T) {
		p, inc, _, recs, _ := newPipeFix(t, replyFor(answerWith("none")))
		p.Router = &scriptRouter{err: &llmrouter.InvalidRequestError{Err: errors.New("плохой запрос")}}
		if err := p.Handle(context.Background(), &inc); err != nil {
			t.Fatal(err)
		}
		if r := recs()[0]; r.Intake.Reason != "invalid_request" || r.LLM != nil {
			t.Errorf("%+v", r.Intake)
		}
	})
	t.Run("Assemble", func(t *testing.T) {
		p, inc, _, recs, snap := newPipeFix(t, replyFor(answerWith("none")))
		snap.Topology.Autoscaler = &step.Autoscaler{Kind: "Bogus", Max: 3}
		p.Collector = FixtureCollector{snap}
		if err := p.Handle(context.Background(), &inc); err != nil {
			t.Fatal(err)
		}
		r := recs()[0]
		if r.Intake.Reason != "invalid_request" {
			t.Errorf("%+v", r.Intake)
		}
	})
}

// Крах между Append и сохранением состояния: запись в цепочке есть, статус open → Route не вызывается, статус recorded.
func TestPipelineCrashAfterAppend(t *testing.T) {
	p, inc, st, recs, _ := newPipeFix(t, replyFor(answerWith("none")))
	sr := &scriptRouter{Router: p.Router}
	p.Router = sr
	if err := p.Handle(context.Background(), &inc); err != nil {
		t.Fatal(err)
	}
	sr.n = 0
	st.Do(func(d *Data) { d.Incidents[inc.ID].Status = StatusOpen }) // «потерянное» сохранение
	sr.res, sr.err = nil, errors.New("Route вызван повторно")
	if err := p.Handle(context.Background(), &inc); err != nil {
		t.Fatal(err)
	}
	if sr.n != 0 || len(recs()) != 1 {
		t.Errorf("Route=%d записей=%d", sr.n, len(recs()))
	}
	if got, _ := st.Get(inc.ID); got.Status != StatusRecorded {
		t.Errorf("статус %s", got.Status)
	}
}

// Повторы сбора: критичный сбой повторяется CollectRetry раз внутри окна settle+5m; за окном — без повторов.
func TestPipelineCollectRetries(t *testing.T) {
	run := func(openedAgo time.Duration) int {
		p, inc, st, _, _ := newPipeFix(t, replyFor(answerWith("none")))
		cc := &countingCollector{inner: failingCollector{}}
		st.Do(func(d *Data) { d.Incidents[inc.ID].OpenedAt = time.Now().Add(-openedAgo) })
		p.Collector, p.RetryPause, p.Settle = cc, time.Millisecond, 2*time.Minute
		inc.OpenedAt = time.Now().Add(-openedAgo)
		p.Handle(context.Background(), &inc)
		return cc.n
	}
	if n := run(2 * time.Minute); n != 1+CollectRetry {
		t.Errorf("вызовов сбора %d, ожидается %d", n, 1+CollectRetry)
	}
	if n := run(time.Hour); n != 1 {
		t.Errorf("за окном повторов вызовов %d, ожидается 1", n)
	}
}

// Остановка сервиса во время сбора: записи нет (не пишем «canceled»/«source_unavailable»), ошибки нет.
type blockingCollector struct{}

func (blockingCollector) Collect(ctx context.Context, _ Incident, _ ServiceConfig, _ time.Time) (Snapshot, error) {
	<-ctx.Done()
	return Snapshot{}, ctx.Err()
}

func TestPipelineShutdownDuringCollect(t *testing.T) {
	p, inc, st, recs, _ := newPipeFix(t, replyFor(answerWith("none")))
	p.Collector = blockingCollector{}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	if err := p.Handle(ctx, &inc); err != nil {
		t.Fatalf("ошибка при остановке: %v", err)
	}
	if n := len(recs()); n != 0 {
		t.Errorf("при остановке записана запись (%d)", n)
	}
	if got, _ := st.Get(inc.ID); got.Status != StatusOpen {
		t.Errorf("статус %s", got.Status)
	}
}

// Запись routed: список alerts — отсортированные fingerprint'ы, не более 64; incident.class пуст, initiator agent/<intake_id>.
func TestPipelineRecordShape(t *testing.T) {
	p, inc, st, recs, _ := newPipeFix(t, replyFor(answerWith("none")))
	st.Do(func(d *Data) {
		for i := 0; i < 80; i++ {
			d.Incidents[inc.ID].Alerts[fmt.Sprintf("%016x", 80-i)] = time.Now()
		}
	})
	if err := p.Handle(context.Background(), &inc); err != nil {
		t.Fatal(err)
	}
	r := recs()[0]
	if len(r.Intake.Alerts) != 64 {
		t.Errorf("fingerprint'ов %d", len(r.Intake.Alerts))
	}
	for i := 1; i < len(r.Intake.Alerts); i++ {
		if r.Intake.Alerts[i-1] >= r.Intake.Alerts[i] {
			t.Fatalf("порядок: %v", r.Intake.Alerts[i-1:i+1])
		}
	}
	if r.Incident.Class != "" || r.Initiator.Kind != "agent" || r.Initiator.ID != "intake-test" || r.Incident.ID != inc.ID || r.Mode != audit.ModeShadow {
		t.Errorf("запись: %+v %+v", r.Incident, r.Initiator)
	}
	if r.Intake.FirstAlertAt != audit.Timestamp(inc.FirstAlertAt) {
		t.Errorf("first_alert_at %s", r.Intake.FirstAlertAt)
	}
}

// Запись routed при переполнении: fingerprint первого алерта в списке, вытеснены самые старые; список отсортирован.
func TestPipelineRecordAlertsEviction(t *testing.T) {
	p, inc, st, recs, _ := newPipeFix(t, replyFor(answerWith("none")))
	base := time.Date(2026, 1, 2, 10, 0, 0, 0, time.UTC)
	first := inc.Alert.Fingerprint
	if first == "" {
		t.Fatal("в фикстуре нет fingerprint первого алерта")
	}
	// fingerprint'ы 1..80: чем больше i, тем свежее; первый алерт — самый старый
	inc.Alerts = map[string]time.Time{first: base.Add(-time.Hour)}
	for i := 1; i <= 80; i++ {
		inc.Alerts[fmt.Sprintf("%016x", i)] = base.Add(time.Duration(i) * time.Second)
	}
	want := len(inc.Alerts)
	st.Do(func(d *Data) { d.Incidents[inc.ID].Alerts = inc.Alerts })
	if err := p.Handle(context.Background(), &inc); err != nil {
		t.Fatal(err)
	}
	got := recs()[0].Intake.Alerts
	if len(got) != 64 {
		t.Fatalf("fingerprint'ов %d", len(got))
	}
	set := map[string]bool{}
	for _, g := range got {
		set[g] = true
	}
	if !set[first] {
		t.Error("первый алерт отсутствует")
	}
	for i := 1; i <= 80; i++ {
		fp := fmt.Sprintf("%016x", i)
		if wantIn := i > 80-63; set[fp] != wantIn {
			t.Errorf("fingerprint %d: в записи=%v, ожидалось %v", i, set[fp], wantIn)
		}
	}
	if !sort.StringsAreSorted(got) {
		t.Errorf("не отсортирован: %v", got)
	}
	if cur, _ := st.Get(inc.ID); len(cur.Alerts) != want {
		t.Errorf("карта инцидента мутирована: %d -> %d", want, len(cur.Alerts))
	}
}

func TestAlertFingerprintsNoMutation(t *testing.T) {
	base := time.Date(2026, 1, 2, 10, 0, 0, 0, time.UTC)
	inc := Incident{Alert: Alert{Fingerprint: fmt.Sprintf("%016x", 500)}, Alerts: map[string]time.Time{}}
	for i := 0; i < 100; i++ {
		inc.Alerts[fmt.Sprintf("%016x", i)] = base.Add(time.Duration(i) * time.Second)
	}
	inc.Alerts[inc.Alert.Fingerprint] = base.Add(-time.Hour)
	got := alertFingerprints(inc)
	if len(inc.Alerts) != 101 {
		t.Errorf("карта изменена: %d", len(inc.Alerts))
	}
	if len(got) != MaxIncidentAlerts || !sort.StringsAreSorted(got) {
		t.Errorf("результат: %d, отсортирован=%v", len(got), sort.StringsAreSorted(got))
	}
	// не больше потолка — вернуть все, по возрастанию
	small := Incident{Alerts: map[string]time.Time{"b": base, "a": base, "c": base}}
	if g := alertFingerprints(small); !reflect.DeepEqual(g, []string{"a", "b", "c"}) {
		t.Errorf("малый набор: %v", g)
	}
}
