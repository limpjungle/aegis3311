package llmrouter

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/limpjungle/aegis3311/internal/audit"
	"github.com/limpjungle/aegis3311/internal/openrouter"
)

// runtimeMarker — маркер для проверки утечек. Генерируется в рантайме: литералов, похожих на ключи и секреты, в тестах нет.
func runtimeMarker(t testing.TB) string {
	t.Helper()
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return "mk-" + hex.EncodeToString(b[:])
}

// decisionJSON заполняет decision record из результата роутера, проверяет его и возвращает JSON (для поиска утечек).
func decisionJSON(t *testing.T, res *Result) string {
	t.Helper()
	rec := &audit.DecisionRecord{Schema: audit.RecordSchema, RecordID: audit.NewRecordID(),
		RecordedAt: audit.Timestamp(time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)), Mode: audit.ModeShadow,
		Incident:  audit.IncidentRef{ID: "inc-1", Service: "geo-svc", Environment: "staging"},
		Initiator: audit.Actor{Kind: "agent", ID: "a1"}, RetrievedDocs: []string{}, AutonomyLevel: "L0"}
	res.Apply(rec)
	if err := rec.Validate(); err != nil {
		t.Fatalf("decision record не проходит Validate: %v", err)
	}
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Данные запрещённых классов и неизвестного источника не уходят наружу: ни в тело запроса, ни в запись решения.
// Маскировщик на них не вызывается.
func TestRestrictedAndUnknownNeverLeave(t *testing.T) {
	ctx := context.Background()
	secret := runtimeMarker(t)
	var mu sync.Mutex
	var bodies [][]byte
	tr := &stubTransport{post: func(b []byte) (openrouter.Response, error) {
		mu.Lock()
		bodies = append(bodies, append([]byte(nil), b...))
		mu.Unlock()
		return reply("Inceptron", 100, 50), nil
	}}
	m := &identityMasker{}
	rg := newRig(t, m, tr, "", nil)
	val := `"` + secret + `"`
	req := simpleReq(t,
		one("alert", frag(t, "a", "alerts.alertmanager", true, 100, `{"n":1}`)),
		list("payload", frag(t, "p1", "payload.ebpf", false, 10, val)),
		list("db", frag(t, "d1", "db.pg_stat_activity", false, 10, val)),
		list("logs", frag(t, "l1", "logs.loki", false, 10, val)),
		list("tickets", frag(t, "t1", "tickets", false, 10, val)),
		list("unknown", frag(t, "u1", "no.such.source", false, 10, val)),
	)
	res, err := rg.r.Route(ctx, req)
	if err != nil || res.Outcome != "sent" {
		t.Fatalf("%v %+v", err, res)
	}
	if got := m.calls.Load(); got != 1 {
		t.Errorf("маскировщик вызван %d раз, ожидается 1 (только для alerts)", got)
	}
	reasons := map[string]string{}
	for _, f := range res.Prepared.Excluded {
		reasons[f.ID] = f.Reason
	}
	want := map[string]string{"p1": "source_class", "d1": "source_class", "l1": "source_class", "t1": "source_class", "u1": "unknown_source"}
	if len(reasons) != len(want) {
		t.Errorf("исключено %d фрагментов, ожидается %d: %v", len(reasons), len(want), reasons)
	}
	for id, reason := range want {
		if reasons[id] != reason {
			t.Errorf("фрагмент %s: причина %q, ожидается %q", id, reasons[id], reason)
		}
	}
	mu.Lock()
	for _, b := range bodies {
		if bytes.Contains(b, []byte(secret)) {
			t.Error("значение запрещённого фрагмента ушло в тело запроса")
		}
	}
	mu.Unlock()
	if strings.Contains(decisionJSON(t, res), secret) {
		t.Error("значение запрещённого фрагмента попало в decision record")
	}
}

// Обязательный исключённый фрагмент: запроса нет, транспорт не вызван, класс не повышается до отправки.
func TestRequiredExcludedNeverSends(t *testing.T) {
	tr := &stubTransport{post: func([]byte) (openrouter.Response, error) { return reply("Inceptron", 1, 1), nil }}
	rg := newRig(t, &identityMasker{}, tr, "", nil)
	req := simpleReq(t, one("alert", frag(t, "a", "alerts.alertmanager", true, 100, `{"n":1}`)),
		one("logs", frag(t, "l1", "logs.loki", true, 100, `"x"`)))
	res, err := rg.r.Route(context.Background(), req)
	if err != nil || res.Outcome != "not_sent" || res.Reason != "required_excluded" || res.DegradeL1 || tr.calls != 0 {
		t.Fatalf("%v outcome=%s reason=%s degrade=%v вызовов=%d", err, res.Outcome, res.Reason, res.DegradeL1, tr.calls)
	}
	decisionJSON(t, res)
}

// Ответ Apply на успешный вызов: флаги провайдера из отправленного тела, хеш запроса, роль, класс и источники.
func TestApplySentFields(t *testing.T) {
	tr := &stubTransport{post: func([]byte) (openrouter.Response, error) { return reply("Inceptron", 100, 50), nil }}
	rg := newRig(t, &identityMasker{}, tr, "", nil)
	res, err := rg.r.Route(context.Background(), routeReq(t))
	if err != nil || res.Outcome != "sent" {
		t.Fatalf("%v %+v", err, res)
	}
	rec := &audit.DecisionRecord{Schema: audit.RecordSchema, RecordID: audit.NewRecordID(),
		RecordedAt: audit.Timestamp(time.Now().UTC()), Mode: audit.ModeShadow,
		Incident:  audit.IncidentRef{ID: "inc-1", Service: "geo-svc", Environment: "staging"},
		Initiator: audit.Actor{Kind: "agent", ID: "a1"}, RetrievedDocs: []string{}, AutonomyLevel: "L0"}
	res.Apply(rec)
	if err := rec.Validate(); err != nil {
		t.Fatal(err)
	}
	if rec.Model.RequestFlags != (audit.ProviderFlags{ZDR: true, DataCollection: "deny", AllowFallbacks: false}) {
		t.Errorf("request_flags: %+v", rec.Model.RequestFlags)
	}
	if rec.Prompt.RequestSHA256 != "sha256:"+res.Prepared.RequestSHA256 || rec.Model.EndpointRole != "primary" || rec.Model.Profile != "inceptron-fp8" {
		t.Errorf("request_sha256 или роль: %+v %+v", rec.Prompt, rec.Model)
	}
	if rec.LLM.DataClass != "internal" || fmt.Sprint(rec.LLM.Sources) != "[alerts.alertmanager]" || rec.LLM.Backend != "openrouter" || rec.LLM.Jurisdiction != "US" {
		t.Errorf("llm: %+v", rec.LLM)
	}
	if rec.Answer.Status != "ok" || rec.Answer.Attempts != 1 || len(rec.Answer.Body) == 0 || rec.Answer.Usage.ChargedTokens != 150 {
		t.Errorf("answer: %+v usage=%+v", rec.Answer, rec.Answer.Usage)
	}
}

// Отмена контекста до первой попытки: запрос не ушёл, поэтому в decision record не должно быть «sent» с нулём попыток.
func TestCanceledBeforeAttemptNotReportedSent(t *testing.T) {
	tr := &stubTransport{post: func([]byte) (openrouter.Response, error) { return reply("Inceptron", 1, 1), nil }}
	rg := newRig(t, &identityMasker{}, tr, "", nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// Отмена до подготовки: ранний путь Route, маскировщик и клиент не вызываются.
	req := simpleReq(t, one("alert", frag(t, "a", "alerts.alertmanager", false, 100, `{"n":1}`)))
	res, err := rg.r.Route(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if tr.calls != 0 {
		t.Fatalf("транспорт вызван %d раз при отменённом контексте", tr.calls)
	}
	if res.Outcome != "not_sent" || res.Reason != "canceled" || res.Call != nil || res.Attempts != 0 {
		t.Errorf("ожидалось not_sent/canceled без вызова, получено outcome=%s reason=%s call=%+v", res.Outcome, res.Reason, res.Call)
	}
}

// Сбой записи события: состояние не публикуется, пока событие не записано (план §3.5).
func TestAuditFailureDoesNotPublishState(t *testing.T) {
	tr := &stubTransport{post: func([]byte) (openrouter.Response, error) { return openrouter.Response{Status: 503}, nil }}
	sink := &memSink{failOn: "endpoint_down"}
	rg := newRig(t, &identityMasker{}, tr, "", sink)
	_, err := rg.r.Route(context.Background(), routeReq(t))
	if !errors.Is(err, ErrAuditFailed) {
		t.Fatalf("ожидается ErrAuditFailed: %v", err)
	}
	st := rg.r.State()
	if st.Endpoints["inceptron-fp8"] != "up" || st.Active != "inceptron-fp8" {
		t.Errorf("состояние опубликовано, хотя endpoint_down не записан: endpoints=%v active=%s", st.Endpoints, st.Active)
	}
}

// Две неудачи подряд и успех: счётчик сбрасывается, переключения нет, событий нет. Повторно то же самое.
func TestTwoFailuresThenSuccessResetCounter(t *testing.T) {
	ctx := context.Background()
	seq := []bool{true, true, false, true, true, false} // true — таймаут; каждый Route: два сбоя и успех
	i := 0
	tr := &stubTransport{post: func(b []byte) (openrouter.Response, error) {
		fail := seq[i]
		i++
		if fail {
			return openrouter.Response{}, &openrouter.TransportError{Kind: "timeout"}
		}
		return reply("Inceptron", 100, 50), nil
	}}
	rg := newRig(t, &identityMasker{}, tr, "", nil)
	for n := 0; n < 2; n++ {
		res, err := rg.r.Route(ctx, routeReq(t))
		if err != nil || res.Outcome != "sent" || res.Role != RolePrimary || res.ErrorKind != "" {
			t.Fatalf("маршрут %d: %v %+v", n, err, res)
		}
	}
	if k := rg.sink.kinds(); len(k) != 0 {
		t.Errorf("переключение без трёх подряд неудач: %v", k)
	}
	if st := rg.r.State(); st.Active != "inceptron-fp8" {
		t.Errorf("active %s", st.Active)
	}
}

// Три неудачные health-check'а подряд у активного primary: down с причиной health_check_failures, переключение на fallback.
func TestHealthFailuresThreeTimesMarkDown(t *testing.T) {
	tr := &stubTransport{post: func([]byte) (openrouter.Response, error) { return reply("Wafer", 1, 1), nil }}
	// Primary отсутствует в списке endpoint'ов, fallback — есть: health primary не проходит, fallback — проходит.
	tr.get = func() (openrouter.Response, error) {
		return openrouter.Response{Status: 200, Body: []byte(`{"data":{"endpoints":[{"provider_name":"Wafer","quantization":"nvfp4","supported_parameters":["response_format","structured_outputs","seed"]}]}}`)}, nil
	}
	rg := newRig(t, &identityMasker{}, tr, "", nil)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if err := rg.r.CheckHealth(ctx); err != nil {
			t.Fatal(err)
		}
		if s := rg.r.State().Endpoints["inceptron-fp8"]; s != "up" {
			t.Fatalf("после %d неудач: %s, ожидается up", i+1, s)
		}
	}
	if err := rg.r.CheckHealth(ctx); err != nil {
		t.Fatal(err)
	}
	if st := rg.r.State(); st.Endpoints["inceptron-fp8"] != "down" || st.Active != "wafer-nvfp4" {
		t.Fatalf("после третьей неудачи: %+v", st)
	}
	ev := rg.sink.events
	if len(ev) != 2 || ev[0].Kind != "endpoint_down" || ev[0].Reason != "health_check_failures" || ev[0].ConsecutiveFailures != 3 ||
		ev[1].Kind != "active_changed" || ev[1].To != "wafer-nvfp4" {
		t.Errorf("события: %+v", ev)
	}
}

// Закреплённый за primary инцидент при падении primary переезжает на fallback и остаётся там после возврата primary;
// новый инцидент идёт на primary.
func TestPinnedIncidentMovesWhenPinnedEndpointDown(t *testing.T) {
	ctx := context.Background()
	healthyPrimary := true
	tr := &stubTransport{post: func(b []byte) (openrouter.Response, error) {
		if providerOf(b) == "inceptron" {
			return reply("Inceptron", 100, 50), nil
		}
		return reply("Wafer", 100, 50), nil
	}}
	tr.get = func() (openrouter.Response, error) {
		wafer := `{"provider_name":"Wafer","quantization":"nvfp4","supported_parameters":["response_format","structured_outputs","seed"]}`
		inc := `{"provider_name":"Inceptron","quantization":"fp8","supported_parameters":["response_format","structured_outputs","seed"]}`
		eps := wafer
		if healthyPrimary {
			eps = inc + "," + wafer
		}
		return openrouter.Response{Status: 200, Body: []byte(`{"data":{"endpoints":[` + eps + `]}}`)}, nil
	}
	rg := newRig(t, &identityMasker{}, tr, "", nil)
	routeAs := func(id string, want Role) {
		t.Helper()
		req := routeReq(t)
		req.IncidentID = id
		res, err := rg.r.Route(ctx, req)
		if err != nil || res.Outcome != "sent" || res.Role != want {
			t.Fatalf("инцидент %s: роль %s, ожидается %s (%v %+v)", id, res.Role, want, err, res)
		}
	}
	routeAs("inc-a", RolePrimary)
	healthyPrimary = false
	for i := 0; i < 3; i++ {
		if err := rg.r.CheckHealth(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if st := rg.r.State(); st.Endpoints["inceptron-fp8"] != "down" || st.Active != "wafer-nvfp4" {
		t.Fatalf("после падения primary: %+v", st)
	}
	routeAs("inc-a", RoleFallback) // закреплённый переехал
	routeAs("inc-b", RoleFallback)

	healthyPrimary = true
	for i := 0; i < 3; i++ { // 0, 5, 10 мин: гистерезис
		if err := rg.r.CheckHealth(ctx); err != nil {
			t.Fatal(err)
		}
		rg.clock.Advance(5 * time.Minute)
	}
	if st := rg.r.State(); st.Active != "inceptron-fp8" {
		t.Fatalf("primary не вернулся: %+v", st)
	}
	routeAs("inc-a", RoleFallback) // закрепление сохраняется, пока fallback up
	routeAs("inc-c", RolePrimary)
}

// provider_mismatch → quarantine: health-check карантинный endpoint не опрашивает.
func TestQuarantinedNotHealthChecked(t *testing.T) {
	ctx := context.Background()
	tr := &stubTransport{post: func([]byte) (openrouter.Response, error) { return reply("Other", 10, 10), nil }}
	gets := 0
	tr.get = func() (openrouter.Response, error) {
		gets++
		return openrouter.Response{Status: 500}, nil
	}
	rg := newRig(t, &identityMasker{}, tr, "", nil)
	res, err := rg.r.Route(ctx, routeReq(t))
	if err != nil || res.Parsed == nil || res.Parsed.Status != "provider_mismatch" {
		t.Fatalf("%v %+v", err, res)
	}
	if st := rg.r.State(); st.Endpoints["inceptron-fp8"] != "quarantined" {
		t.Fatalf("%+v", st)
	}
	gets = 0
	if err := rg.r.CheckHealth(ctx); err != nil {
		t.Fatal(err)
	}
	if gets != 1 {
		t.Errorf("health-check опросил %d endpoint'ов, ожидается 1 (только fallback)", gets)
	}
	if st := rg.r.State(); st.Endpoints["inceptron-fp8"] != "quarantined" {
		t.Errorf("карантин снят health-check'ом: %+v", st)
	}
}

// Исчерпание бюджета инцидента: транспорт не вызывается, DegradeL1; CloseIncident освобождает счёт.
func TestBudgetIncidentExhaustedAndClosed(t *testing.T) {
	tr := &stubTransport{post: func([]byte) (openrouter.Response, error) { return reply("Inceptron", 100, 50), nil }}
	rg := newRig(t, &identityMasker{}, tr, "", nil)
	ctx := context.Background()
	// Первый вызов: резерв помещается, по факту списано 150 токенов.
	first, err := rg.r.Route(ctx, routeReq(t))
	if err != nil || first.Outcome != "sent" {
		t.Fatalf("%v %+v", err, first)
	}
	reserve := int64(first.Prepared.EstInputTokens + first.Prepared.MaxTokens)
	// Лимит: резерв одного вызова проходит, резерв поверх уже израсходованных 150 токенов — нет.
	rg.r.bud.cfg.IncidentTokens = reserve + 100
	res, _ := rg.r.Route(ctx, routeReq(t))
	if res.Reason != "budget_incident" || !res.DegradeL1 || tr.calls != 1 {
		t.Fatalf("второй вызов: %+v вызовов=%d", res, tr.calls)
	}
	rg.r.CloseIncident("inc-1") // счёт инцидента освобождён
	res, err = rg.r.Route(ctx, routeReq(t))
	if err != nil || res.Outcome != "sent" {
		t.Fatalf("после CloseIncident: %v %+v", err, res)
	}
}

// Параллельные резервы на один инцидент: ровно лимит / размер резерва успешных, остальные отказ.
func TestBudgetConcurrentReserveExact(t *testing.T) {
	b := newBudgets(BudgetConfig{IncidentTokens: 10000, ServiceDayTokens: 1 << 40})
	now := func() time.Time { return time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC) }
	var granted atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok := b.forIncident("inc-1", "geo-svc", now).Reserve(1000, 0); ok {
				granted.Add(1)
			}
		}()
	}
	wg.Wait()
	if granted.Load() != 10 {
		t.Fatalf("выдано резервов %d, ожидается 10", granted.Load())
	}
}

// Таймауты: весь резерв списывается за каждую попытку (запрос мог быть оплачен), Apply фиксирует расход.
func TestApplyTimeoutChargesFullReserve(t *testing.T) {
	tr := &stubTransport{post: func([]byte) (openrouter.Response, error) {
		return openrouter.Response{}, &openrouter.TransportError{Kind: "timeout"}
	}}
	rg := newRig(t, &identityMasker{}, tr, "", nil)
	res, err := rg.r.Route(context.Background(), routeReq(t))
	if err != nil || res.Call == nil {
		t.Fatalf("%v %+v", err, res)
	}
	reserve := int64(res.Prepared.EstInputTokens + res.Prepared.MaxTokens)
	if res.Call.Tokens != int64(res.Call.Attempts)*reserve {
		t.Fatalf("списано %d токенов за %d попыток, резерв %d", res.Call.Tokens, res.Call.Attempts, reserve)
	}
	js := decisionJSON(t, res)
	if !strings.Contains(js, `"status":"error"`) {
		t.Errorf("при таймауте статус ответа не error: %s", js)
	}
}

// Сетевой сбой без ответа: ничего не списывается.
func TestApplyNetworkFailureChargesNothing(t *testing.T) {
	tr := &stubTransport{post: func([]byte) (openrouter.Response, error) {
		return openrouter.Response{}, &openrouter.TransportError{Kind: "network"}
	}}
	rg := newRig(t, &identityMasker{}, tr, "", nil)
	res, err := rg.r.Route(context.Background(), routeReq(t))
	if err != nil || res.Call == nil {
		t.Fatalf("%v %+v", err, res)
	}
	if res.Call.Tokens != 0 || res.Call.CostUSD != 0 {
		t.Errorf("сетевой сбой списал %d токенов", res.Call.Tokens)
	}
	decisionJSON(t, res)
}

// Ключ API не попадает ни в запись решения, ни в события аудита, ни в состояние, даже если 401-ответ его эхом повторяет.
func TestAbortNeverEchoesKey(t *testing.T) {
	ctx := context.Background()
	key := runtimeMarker(t)
	tr := &stubTransport{post: func([]byte) (openrouter.Response, error) {
		return openrouter.Response{Status: 401, Body: []byte("invalid key: " + key)}, nil
	}}
	a := loadAssets(t)
	cl, err := openrouter.NewClient(&a.Config, testKey(t, key), tr,
		openrouter.WithSleep(func(context.Context, time.Duration) error { return nil }))
	if err != nil {
		t.Fatal(err)
	}
	sink, clock := &memSink{}, newFakeClock()
	r, err := New(Options{Assets: a, Client: cl, Masker: &identityMasker{}, Events: sink, Clock: clock,
		Budgets: BudgetConfig{IncidentTokens: 1 << 40, ServiceDayTokens: 1 << 40}, Failover: DefaultFailover(), RouterID: "llm-router-test"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := r.Route(ctx, routeReq(t))
	if err != nil || res.ErrorKind != "auth" || !r.State().Halted {
		t.Fatalf("%v %+v", err, res)
	}
	if strings.Contains(decisionJSON(t, res), key) {
		t.Error("ключ в decision record")
	}
	for _, e := range sink.events {
		b, _ := json.Marshal(e)
		if strings.Contains(string(b), key) {
			t.Errorf("ключ в событии аудита %s", e.Kind)
		}
	}
	if strings.Contains(fmt.Sprintf("%+v %v", r.State(), res.Call.LastError), key) {
		t.Error("ключ в состоянии или в ошибке вызова")
	}
	if strings.Contains(fmt.Sprintf("%+v", r), key) {
		t.Error("ключ в выводе fmt роутера")
	}
}

// Resume после сбоя записи: halt по auth остаётся с причиной auth (план §3.5).
func TestResumeFailureKeepsAuthHalt(t *testing.T) {
	ctx := context.Background()
	tr := &stubTransport{post: func([]byte) (openrouter.Response, error) { return openrouter.Response{Status: 401}, nil }}
	sink := &memSink{}
	rg := newRig(t, &identityMasker{}, tr, "", sink)
	if _, err := rg.r.Route(ctx, routeReq(t)); err != nil {
		t.Fatal(err)
	}
	if st := rg.r.State(); !st.Halted || st.HaltReason != "auth" {
		t.Fatalf("%+v", st)
	}
	sink.failOn = "*"
	if err := rg.r.Resume(ctx, "sre-1"); !errors.Is(err, ErrAuditFailed) {
		t.Fatalf("Resume при сбое записи: %v", err)
	}
	if st := rg.r.State(); !st.Halted || st.HaltReason != "auth" {
		t.Errorf("после неудачного Resume halt: %+v, ожидается auth", st)
	}
}

// Apply на каждом статусе разбора ответа: запись проходит Validate, статус переносится как есть, без тела.
func TestApplyParsedStatuses(t *testing.T) {
	mk := func(provider, finish, content string) openrouter.Response {
		return openrouter.Response{Status: 200, Body: []byte(`{"id":"g1","model":"m","provider":"` + provider +
			`","choices":[{"finish_reason":"` + finish + `","message":{"content":` + content + `}}],"usage":{"prompt_tokens":10,"completion_tokens":5}}`)}
	}
	cases := map[string]struct {
		resp openrouter.Response
		want string
	}{
		"schema_invalid":    {mk("Inceptron", "stop", `"{\"x\":1}"`), "schema_invalid"},
		"truncated":         {mk("Inceptron", "length", `"{"`), "truncated"},
		"provider_mismatch": {mk("Other", "stop", `"{}"`), "provider_mismatch"},
	}
	for name, c := range cases {
		tr := &stubTransport{post: func([]byte) (openrouter.Response, error) { return c.resp, nil }}
		rg := newRig(t, &identityMasker{}, tr, "", nil)
		res, err := rg.r.Route(context.Background(), routeReq(t))
		if err != nil || res.Outcome != "sent" || res.Parsed == nil || res.Parsed.Status != c.want {
			t.Fatalf("%s: %v %+v", name, err, res)
		}
		js := decisionJSON(t, res)
		if !strings.Contains(js, `"status":"`+c.want+`"`) || strings.Contains(js, `"body":{`) {
			t.Errorf("%s: статус или тело в записи: %s", name, js)
		}
	}
}

// ---- Проверки записи при переключении, отмене и бюджете ----

// failoverTransport: primary отвечает таймаутом (платёж неизвестен), fallback — ответом ok.
// onPrimary вызывается перед каждой попыткой на primary, n — номер попытки с 1.
func failoverTransport(onPrimary func(n int)) *stubTransport {
	n := 0
	return &stubTransport{post: func(b []byte) (openrouter.Response, error) {
		if providerOf(b) == "inceptron" {
			n++
			if onPrimary != nil {
				onPrimary(n)
			}
			return openrouter.Response{}, &openrouter.TransportError{Kind: "timeout"}
		}
		return reply("Wafer", 100, 50), nil
	}}
}

// runFallbackNotSent: три таймаута primary; после третьего потолок контекста меньше входа, поэтому
// подготовка к fallback возвращает NotSent (context_ceiling) уже после попыток на primary.
func runFallbackNotSent(t *testing.T) (*rig, *stubTransport, *Result) {
	t.Helper()
	var rg *rig
	tr := failoverTransport(func(n int) {
		if n == 3 {
			rg.assets.Config.ContextCeiling = 1
		}
	})
	rg = newRig(t, &identityMasker{}, tr, "", nil)
	orig := rg.assets.Config.ContextCeiling
	t.Cleanup(func() { rg.assets.Config.ContextCeiling = orig })
	res, err := rg.r.Route(context.Background(), routeReq(t))
	if err != nil {
		t.Fatal(err)
	}
	return rg, tr, res
}

// Непокрытая ветка (отчёт кодера): подготовка к fallback вернула NotSent после попыток на primary.
// Решение — sent/stopped: запрос на primary уже ушёл и оплачен, not_sent было бы неверной записью.
func TestFallbackNotSentAfterPrimaryAttemptsIsSentStopped(t *testing.T) {
	_, tr, res := runFallbackNotSent(t)
	if res.Outcome != "sent" || res.ErrorKind != "stopped" || res.Attempts != 3 {
		t.Fatalf("outcome=%s error_kind=%s attempts=%d, ожидается sent/stopped/3", res.Outcome, res.ErrorKind, res.Attempts)
	}
	if tr.calls != 3 {
		t.Errorf("транспорт вызван %d раз, ожидается 3 (fallback не должен получить запрос)", tr.calls)
	}
	reserve := int64(res.Prepared.EstInputTokens + res.Prepared.MaxTokens)
	if res.Tokens != 3*reserve {
		t.Errorf("учтено %d токенов, ожидается 3 таймаута по резерву %d = %d", res.Tokens, reserve, 3*reserve)
	}
	if err := recordValidate(res); err != nil {
		t.Errorf("запись не проходит Validate: %v", err)
	}
	rec := decisionRecord(res)
	if rec.Answer == nil || rec.Answer.Status != "error" || rec.Answer.ErrorKind != "stopped" || rec.Answer.Attempts != 3 ||
		rec.Answer.Usage == nil || rec.Answer.Usage.ChargedTokens != 3*reserve {
		t.Errorf("answer в записи: %+v usage=%+v", rec.Answer, rec.Answer.Usage)
	}
}

// Атрибуция той же ветки: запроса на fallback не было, значит переключения нет, модель — primary.
func TestFallbackNotSentRecordAttribution(t *testing.T) {
	_, _, res := runFallbackNotSent(t)
	rec := decisionRecord(res)
	if rec.LLM.EndpointSwitched {
		t.Errorf("endpoint_switched=true, хотя запрос на fallback не отправлялся (подготовка вернула context_ceiling)")
	}
	if rec.Model == nil || rec.Model.Profile != "inceptron-fp8" || rec.Model.EndpointRole != "primary" {
		t.Errorf("model в записи: %+v, ожидается primary (единственный endpoint, получивший запрос)", rec.Model)
	}
}

// Бюджет исчерпан ровно перед переключением (счёт инцидента): fallback не получает запроса.
// Исход — sent/budget с учтёнными попытками primary.
func TestFallbackBudgetDeniedAfterPrimaryAttempts(t *testing.T) {
	var rg *rig
	tr := failoverTransport(func(n int) {
		if n == 3 {
			rg.r.bud.cfg.IncidentTokens = 1
		}
	})
	rg = newRig(t, &identityMasker{}, tr, "", nil)
	res, err := rg.r.Route(context.Background(), routeReq(t))
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != "sent" || res.ErrorKind != "budget" || res.Attempts != 3 || tr.calls != 3 {
		t.Fatalf("outcome=%s error_kind=%s attempts=%d вызовов=%d; ожидается sent/budget/3/3", res.Outcome, res.ErrorKind, res.Attempts, tr.calls)
	}
	reserve := int64(res.Prepared.EstInputTokens + res.Prepared.MaxTokens)
	if res.Tokens != 3*reserve {
		t.Errorf("учтено %d, ожидается %d", res.Tokens, 3*reserve)
	}
	if err := recordValidate(res); err != nil {
		t.Errorf("запись не проходит Validate: %v", err)
	}
}

// Атрибуция отказа бюджета на fallback: запрос туда не ушёл, поэтому в записи не должно быть
// ни переключения, ни модели и хеша тела fallback'а.
func TestFallbackBudgetDeniedRecordAttribution(t *testing.T) {
	var rg *rig
	tr := failoverTransport(func(n int) {
		if n == 3 {
			rg.r.bud.cfg.IncidentTokens = 1
		}
	})
	rg = newRig(t, &identityMasker{}, tr, "", nil)
	res, err := rg.r.Route(context.Background(), routeReq(t))
	if err != nil {
		t.Fatal(err)
	}
	rec := decisionRecord(res)
	if rec.LLM.EndpointSwitched {
		t.Errorf("endpoint_switched=true при отказе бюджета до отправки на fallback")
	}
	if rec.Model == nil || rec.Model.EndpointRole != "primary" || rec.Model.Profile != "inceptron-fp8" {
		t.Errorf("model в записи: %+v, ожидается primary", rec.Model)
	}
	if res.Role != RolePrimary {
		t.Errorf("role=%s, ожидается primary: fallback не получил запроса", res.Role)
	}
}

// Отмена в начале вызова fallback (после трёх таймаутов primary): fallback не получает запроса.
// Исход — sent/stopped; атрибуция в записи должна отражать primary.
func TestCanceledAtFallbackStartAttribution(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	primaryPosts, clockCalls := 0, 0
	tr := failoverTransport(nil)
	tr.post = func(b []byte) (openrouter.Response, error) {
		if providerOf(b) == "inceptron" {
			mu.Lock()
			primaryPosts++
			mu.Unlock()
			return openrouter.Response{}, &openrouter.TransportError{Kind: "timeout"}
		}
		mu.Lock()
		defer mu.Unlock()
		return reply("Wafer", 100, 50), nil
	}
	// После третьего таймаута primary первые два обращения часов — завершение вызова primary, третье — старт вызова fallback.
	clientClock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		if primaryPosts == 3 {
			clockCalls++
			if clockCalls == 3 {
				cancel()
			}
		}
		return time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	}
	wr := newWriterRig(t, &identityMasker{}, tr, openrouter.WithClock(clientClock))
	res, err := wr.r.Route(ctx, routeReq(t))
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != "sent" || res.ErrorKind != "stopped" || res.Attempts != 3 {
		t.Fatalf("outcome=%s error_kind=%s attempts=%d, ожидается sent/stopped/3", res.Outcome, res.ErrorKind, res.Attempts)
	}
	mu.Lock()
	if primaryPosts != 3 {
		t.Errorf("попыток на primary %d, ожидается 3", primaryPosts)
	}
	mu.Unlock()
	rec := decisionRecord(res)
	if err := rec.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if rec.LLM.EndpointSwitched {
		t.Errorf("endpoint_switched=true: fallback не получил запроса (отмена до его первой попытки)")
	}
	if rec.Model == nil || rec.Model.Profile != "inceptron-fp8" || rec.Model.EndpointRole != "primary" {
		t.Errorf("model в записи: %+v, ожидается primary (единственный endpoint, получивший запрос)", rec.Model)
	}
}

// Баланс бюджета и записи: по каждому инциденту spent == сумма Result.Tokens всех Route, held == 0.
// Сценарии: сбой с переключением, обычный успех на fallback, отмена до отправки (ничего не списано).
func TestBudgetSpentMatchesRecordedCharges(t *testing.T) {
	ctx := context.Background()
	tr := failoverTransport(nil)
	rg := newRig(t, &identityMasker{}, tr, "", nil)
	sums := map[string]int64{}
	run := func(id string, c context.Context) {
		req := routeReq(t)
		req.IncidentID = id
		res, err := rg.r.Route(c, req)
		if err != nil {
			t.Fatal(err)
		}
		if got := decisionRecord(res).Answer; got != nil && got.Usage != nil {
			if got.Usage.ChargedTokens != res.Tokens {
				t.Errorf("%s: в записи %d, в Result %d", id, got.Usage.ChargedTokens, res.Tokens)
			}
		}
		sums[id] += res.Tokens
	}
	run("inc-fail", ctx) // три таймаута primary, затем ok на fallback
	run("inc-ok", ctx)   // сразу fallback
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	run("inc-cancel", canceled) // ничего не списано

	rg.r.bud.mu.Lock()
	defer rg.r.bud.mu.Unlock()
	for id, want := range sums {
		acc := rg.r.bud.incidents[id]
		var spent, held int64
		if acc != nil {
			spent, held = acc.spent, acc.held
		}
		if spent != want || held != 0 {
			t.Errorf("%s: бюджет spent=%d held=%d, сумма записей=%d", id, spent, held, want)
		}
	}
	if sums["inc-cancel"] != 0 {
		t.Errorf("отмена учла %d токенов", sums["inc-cancel"])
	}
}

// Таблица degrade_l1: по каждому пути Route — причина, DegradeL1 и валидность записи.
func TestDegradeL1OnEveryPath(t *testing.T) {
	ctx := context.Background()
	okTr := func() *stubTransport {
		return &stubTransport{post: func([]byte) (openrouter.Response, error) { return reply("Inceptron", 100, 50), nil }}
	}
	plain := func() Request { return routeReq(t) }
	cases := []struct {
		name    string
		tr      func() *stubTransport
		setup   func(rg *rig)
		steps   func(rg *rig) (*Result, error) // последний шаг определяет проверку
		outcome string
		reason  string
		degrade bool
	}{
		{name: "mode off", tr: okTr, steps: func(rg *rig) (*Result, error) {
			req := plain()
			req.Mode = ModeOff
			return rg.r.Route(ctx, req)
		}, outcome: "not_sent", reason: "mode_off"},
		{name: "canceled", tr: okTr, steps: func(rg *rig) (*Result, error) {
			c, cancel := context.WithCancel(ctx)
			cancel()
			return rg.r.Route(c, plain())
		}, outcome: "not_sent", reason: "canceled"},
		{name: "required excluded", tr: okTr, steps: func(rg *rig) (*Result, error) {
			return rg.r.Route(ctx, simpleReq(t, one("alert", frag(t, "a", "alerts.alertmanager", true, 100, `{"n":1}`)),
				one("logs", frag(t, "l1", "logs.loki", true, 100, `"x"`))))
		}, outcome: "not_sent", reason: "required_excluded"},
		{name: "sent", tr: okTr, steps: func(rg *rig) (*Result, error) { return rg.r.Route(ctx, plain()) }, outcome: "sent"},
		{name: "budget incident", tr: okTr, setup: func(rg *rig) { rg.r.bud.cfg.IncidentTokens = 1 },
			steps:   func(rg *rig) (*Result, error) { return rg.r.Route(ctx, plain()) },
			outcome: "not_sent", reason: "budget_incident", degrade: true},
		{name: "budget service day", tr: okTr, setup: func(rg *rig) { rg.r.bud.cfg.ServiceDayTokens = 1 },
			steps:   func(rg *rig) (*Result, error) { return rg.r.Route(ctx, plain()) },
			outcome: "not_sent", reason: "budget_service_day", degrade: true},
		{name: "halted after auth", tr: func() *stubTransport {
			return &stubTransport{post: func([]byte) (openrouter.Response, error) { return openrouter.Response{Status: 401}, nil }}
		}, steps: func(rg *rig) (*Result, error) {
			if _, err := rg.r.Route(ctx, plain()); err != nil {
				return nil, err
			}
			return rg.r.Route(ctx, plain())
		}, outcome: "not_sent", reason: "halted", degrade: true},
		{name: "unavailable after both 404", tr: func() *stubTransport {
			return &stubTransport{post: func([]byte) (openrouter.Response, error) { return openrouter.Response{Status: 404}, nil }}
		}, steps: func(rg *rig) (*Result, error) {
			for i := 0; i < 2; i++ {
				req := plain()
				req.IncidentID = fmt.Sprintf("inc-404-%d", i)
				if _, err := rg.r.Route(ctx, req); err != nil {
					return nil, err
				}
			}
			return rg.r.Route(ctx, plain())
		}, outcome: "not_sent", reason: "unavailable", degrade: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rg := newRig(t, &identityMasker{}, c.tr(), "", nil)
			if c.setup != nil {
				c.setup(rg)
			}
			res, err := c.steps(rg)
			if err != nil || res == nil {
				t.Fatalf("%v", err)
			}
			if res.Outcome != c.outcome || res.Reason != c.reason || res.DegradeL1 != c.degrade {
				t.Errorf("outcome=%s reason=%q degrade=%v, ожидается %s/%q/%v", res.Outcome, res.Reason, res.DegradeL1, c.outcome, c.reason, c.degrade)
			}
			if err := recordValidate(res); err != nil {
				t.Errorf("запись не проходит Validate: %v", err)
			}
		})
	}
}

// endpoint_switched = true только когда запрос реально ушёл на другой endpoint.
func TestEndpointSwitchedOnlyOnRealSwitch(t *testing.T) {
	ctx := context.Background()
	ok := func(provider string) openrouter.Response { return reply(provider, 100, 50) }
	cases := []struct {
		name string
		tr   *stubTransport
		want bool
	}{
		{name: "primary ok", tr: &stubTransport{post: func([]byte) (openrouter.Response, error) { return ok("Inceptron"), nil }}, want: false},
		{name: "503 503 ok на primary", want: false, tr: func() *stubTransport {
			seq := []openrouter.Response{{Status: 503}, {Status: 503}, ok("Inceptron")}
			i := 0
			return &stubTransport{post: func([]byte) (openrouter.Response, error) { r := seq[i]; i++; return r, nil }}
		}()},
		{name: "таймаут x3 → fallback", tr: failoverTransport(nil), want: true},
		{name: "401 на primary", want: false, tr: &stubTransport{post: func([]byte) (openrouter.Response, error) {
			return openrouter.Response{Status: 401}, nil
		}}},
		{name: "404 на primary", want: false, tr: &stubTransport{post: func([]byte) (openrouter.Response, error) {
			return openrouter.Response{Status: 404}, nil
		}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rg := newRig(t, &identityMasker{}, c.tr, "", nil)
			res, err := rg.r.Route(ctx, routeReq(t))
			if err != nil || res.Outcome != "sent" {
				t.Fatalf("%v %+v", err, res)
			}
			if rec := decisionRecord(res); rec.LLM.EndpointSwitched != c.want {
				t.Errorf("endpoint_switched=%v, ожидается %v", rec.LLM.EndpointSwitched, c.want)
			}
		})
	}
}

// Конкурентные Route одного инцидента (-race): сумма учтённых токенов равна spent, held не остаётся, лимит не превышен.
func TestConcurrentRoutesBudgetMatchesCharges(t *testing.T) {
	ctx := context.Background()
	tr := &stubTransport{post: func(b []byte) (openrouter.Response, error) {
		if providerOf(b) == "inceptron" {
			return reply("Inceptron", 100, 50), nil
		}
		return reply("Wafer", 100, 50), nil
	}}
	rg := newRig(t, &identityMasker{}, tr, "", nil)
	prep, err := rg.r.Prepare(ctx, routeReq(t), RolePrimary)
	if err != nil {
		t.Fatal(err)
	}
	limit := 3 * int64(prep.EstInputTokens+prep.MaxTokens)
	rg.r.bud.cfg.IncidentTokens = limit
	var mu sync.Mutex
	var total int64
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := routeReq(t)
			req.IncidentID = "inc-c"
			res, err := rg.r.Route(ctx, req)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				t.Error(err)
				return
			}
			if res.Outcome == "sent" {
				total += res.Tokens
			} else if res.Reason != "budget_incident" {
				t.Errorf("неожиданный исход: %s/%s", res.Outcome, res.Reason)
			}
		}()
	}
	wg.Wait()
	rg.r.bud.mu.Lock()
	acc := rg.r.bud.incidents["inc-c"]
	spent, held := acc.spent, acc.held
	rg.r.bud.mu.Unlock()
	if spent != total || held != 0 {
		t.Errorf("бюджет spent=%d held=%d, сумма Result.Tokens=%d", spent, held, total)
	}
	if spent > limit {
		t.Errorf("списано %d при лимите %d", spent, limit)
	}
}

// Отмена во время паузы между попытками: попытка уже учтена, исход — sent/stopped, а не not_sent.
func TestCancelDuringRetrySleepKeepsAttempt(t *testing.T) {
	a := loadAssets(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tr := &stubTransport{post: func([]byte) (openrouter.Response, error) { return openrouter.Response{Status: 503}, nil }}
	cl, err := openrouter.NewClient(&a.Config, testKey(t, runtimeSecret(t)), tr,
		openrouter.WithSleep(func(context.Context, time.Duration) error { cancel(); return context.Canceled }))
	if err != nil {
		t.Fatal(err)
	}
	r, err := New(Options{Assets: a, Client: cl, Masker: &identityMasker{}, Events: &memSink{}, Clock: newFakeClock(),
		Budgets: BudgetConfig{IncidentTokens: 1 << 40, ServiceDayTokens: 1 << 40}, Failover: DefaultFailover(), RouterID: "llm-router-test"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := r.Route(ctx, routeReq(t))
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != "sent" || res.ErrorKind != "stopped" || res.Attempts != 1 || tr.calls != 1 {
		t.Fatalf("outcome=%s error_kind=%s attempts=%d вызовов=%d; ожидается sent/stopped/1/1", res.Outcome, res.ErrorKind, res.Attempts, tr.calls)
	}
	if err := recordValidate(res); err != nil {
		t.Errorf("запись не проходит Validate: %v", err)
	}
}

// 404 на primary: endpoint down сразу, запрос завершается no_endpoint без переключения внутри Route,
// следующий Route уходит на fallback.
func TestNoEndpointThenNextRouteUsesFallback(t *testing.T) {
	ctx := context.Background()
	tr := &stubTransport{post: func(b []byte) (openrouter.Response, error) {
		if providerOf(b) == "inceptron" {
			return openrouter.Response{Status: 404}, nil
		}
		return reply("Wafer", 100, 50), nil
	}}
	rg := newRig(t, &identityMasker{}, tr, "", nil)
	res, err := rg.r.Route(ctx, routeReq(t))
	if err != nil || res.Outcome != "sent" || res.ErrorKind != "no_endpoint" || res.Role != RolePrimary {
		t.Fatalf("%v %+v", err, res)
	}
	if err := recordValidate(res); err != nil {
		t.Errorf("запись не проходит Validate: %v", err)
	}
	req := routeReq(t)
	req.IncidentID = "inc-2"
	res, err = rg.r.Route(ctx, req)
	if err != nil || res.Outcome != "sent" || res.Role != RoleFallback || res.ErrorKind != "" {
		t.Fatalf("второй Route: %v %+v", err, res)
	}
	if st := rg.r.State(); st.Endpoints["inceptron-fp8"] != "down" || st.Active != "wafer-nvfp4" {
		t.Errorf("состояние: %+v", st)
	}
}

// Ошибка сборки fallback после попыток на primary (нарушение инварианта конфигурации): Route должен вернуть
// частичный Result с учтёнными попытками primary, а не nil — иначе расход и факт отправки не попадут в аудит.
func TestBuildErrorAfterPrimaryAttemptsKeepsPartialResult(t *testing.T) {
	var rg *rig
	tr := failoverTransport(func(n int) {
		if n == 3 {
			p := *rg.r.eps[RoleFallback].profile
			p.Provider = pj(t, `{"only":["wafer"],"zdr":false,"data_collection":"deny","allow_fallbacks":false}`)
			rg.r.eps[RoleFallback].profile = &p
		}
	})
	rg = newRig(t, &identityMasker{}, tr, "", nil)
	res, err := rg.r.Route(context.Background(), routeReq(t))
	if err == nil {
		t.Fatalf("ожидается ошибка сборки fallback: %+v", res)
	}
	if res == nil || res.Attempts != 3 || res.Tokens == 0 {
		t.Errorf("частичный Result потерян: res=%v (ожидается Attempts=3 и учтённый расход primary)", res)
	}
}
