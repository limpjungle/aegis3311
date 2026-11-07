package llmrouter

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/limpjungle/aegis3311/internal/audit"
	"github.com/limpjungle/aegis3311/internal/dataclass"
	"github.com/limpjungle/aegis3311/internal/openrouter"
)

// flakySink — приёмник событий поверх реального *audit.Writer: при failKind событие не пишется и возвращается ошибка.
// "*" — падать на любом событии.
type flakySink struct {
	w        *audit.Writer
	mu       sync.Mutex
	failKind string
}

func (s *flakySink) setFail(kind string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failKind = kind
}

func (s *flakySink) AppendEvent(ev *audit.RouterEvent) (audit.Entry, error) {
	s.mu.Lock()
	fail := s.failKind == "*" || s.failKind == ev.Kind
	s.mu.Unlock()
	if fail {
		return audit.Entry{}, errors.New("сбой записи события (тест)")
	}
	return s.w.AppendEvent(ev)
}

// writerRig — роутер с реальной цепочкой аудита во временном каталоге.
type writerRig struct {
	r     *Router
	sink  *flakySink
	w     *audit.Writer
	chain string
	keys  audit.Keyring
}

func newWriterRig(t *testing.T, m dataclass.Masker, tr *stubTransport, clientOpts ...openrouter.ClientOption) *writerRig {
	t.Helper()
	signer, keys := newAuditSigner(t)
	chain := filepath.Join(t.TempDir(), "chain.jsonl")
	w, err := audit.OpenWriter(chain, "router-test", signer, keys)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	a := loadAssets(t)
	opts := append([]openrouter.ClientOption{openrouter.WithSleep(func(context.Context, time.Duration) error { return nil })}, clientOpts...)
	cl, err := openrouter.NewClient(&a.Config, testKey(t, runtimeSecret(t)), tr, opts...)
	if err != nil {
		t.Fatal(err)
	}
	sink := &flakySink{w: w}
	r, err := New(Options{Assets: a, Client: cl, Masker: m, Events: sink, Clock: newFakeClock(),
		Budgets: BudgetConfig{IncidentTokens: 1 << 40, ServiceDayTokens: 1 << 40}, Failover: DefaultFailover(), RouterID: "llm-router-test"})
	if err != nil {
		t.Fatal(err)
	}
	return &writerRig{r: r, sink: sink, w: w, chain: chain, keys: keys}
}

// chainEvents читает из файла цепочки все записи типа router-event (в порядке цепочки).
func chainEvents(t *testing.T, path string) []audit.RouterEvent {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []audit.RouterEvent
	for _, line := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
		if line == "" {
			continue
		}
		var e struct {
			Record json.RawMessage `json:"record"`
		}
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatal(err)
		}
		var head struct {
			Schema string `json:"schema"`
		}
		if err := json.Unmarshal(e.Record, &head); err != nil {
			t.Fatal(err)
		}
		if head.Schema != audit.RouterEventSchema {
			continue
		}
		var ev audit.RouterEvent
		if err := json.Unmarshal(e.Record, &ev); err != nil {
			t.Fatal(err)
		}
		out = append(out, ev)
	}
	return out
}

// replayEvents восстанавливает состояние роутера из событий цепочки. Правила те же, что в коде роутера:
// начальное состояние — оба up, активен primary; endpoint_* меняет состояние endpoint'а; active_changed — активного;
// router_halted/router_resumed — остановку; router_resumed снимает карантин (→ down) без отдельного события.
func replayEvents(evs []audit.RouterEvent) (active string, eps map[string]string, halted bool, reason string) {
	const prim, fb = "inceptron-fp8", "wafer-nvfp4"
	active = prim
	eps = map[string]string{prim: "up", fb: "up"}
	for _, ev := range evs {
		switch ev.Kind {
		case "endpoint_down":
			eps[ev.Endpoint] = "down"
		case "endpoint_up":
			eps[ev.Endpoint] = "up"
		case "endpoint_quarantined":
			eps[ev.Endpoint] = "quarantined"
		case "active_changed":
			active = ev.To
		case "router_halted":
			halted, reason = true, ev.Reason
		case "router_resumed":
			halted, reason = false, ""
			for name, s := range eps {
				if s == "quarantined" {
					eps[name] = "down"
				}
			}
		}
	}
	return active, eps, halted, reason
}

// check сверяет состояние, восстановленное из цепочки, с состоянием в памяти. Опубликованный активный —
// активный из цепочки, если его endpoint up, иначе none. Halt по audit_failed в цепочку не попадает (писать некуда),
// поэтому его не сверяем.
func (wr *writerRig) check(t *testing.T, label string) {
	t.Helper()
	active, eps, halted, reason := replayEvents(chainEvents(t, wr.chain))
	want := active
	if eps[active] != "up" {
		want = "none"
	}
	st := wr.r.State()
	if st.Active != want {
		t.Errorf("%s: active в памяти %q, по цепочке %q", label, st.Active, want)
	}
	for name, s := range eps {
		if st.Endpoints[name] != s {
			t.Errorf("%s: endpoint %s в памяти %q, по цепочке %q", label, name, st.Endpoints[name], s)
		}
	}
	if st.HaltReason != "audit_failed" && (st.Halted != halted || st.HaltReason != reason) {
		t.Errorf("%s: halt в памяти (%v, %q), по цепочке (%v, %q)", label, st.Halted, st.HaltReason, halted, reason)
	}
}

// activeChanged возвращает active_changed события цепочки.
func activeChanged(evs []audit.RouterEvent) []audit.RouterEvent {
	var out []audit.RouterEvent
	for _, ev := range evs {
		if ev.Kind == "active_changed" {
			out = append(out, ev)
		}
	}
	return out
}

// Сбой active_changed после endpoint_down; повторный Route на halt; Resume с тем же сбоем оставляет halt;
// Resume при рабочей записи: from — последний записанный активный (primary), запрос уходит на fallback.
// После каждого шага состояние в памяти совпадает с восстановленным из цепочки.
func TestReplayMatchesMemoryAfterAuditFailureAndResume(t *testing.T) {
	ctx := context.Background()
	var mu sync.Mutex
	primaryPosts := 0
	tr := &stubTransport{post: func(b []byte) (openrouter.Response, error) {
		if providerOf(b) == "inceptron" {
			mu.Lock()
			primaryPosts++
			mu.Unlock()
			return openrouter.Response{Status: 503}, nil
		}
		return reply("Wafer", 100, 50), nil
	}}
	wr := newWriterRig(t, &identityMasker{}, tr)
	wr.check(t, "старт")

	wr.sink.setFail("active_changed")
	if _, err := wr.r.Route(ctx, routeReq(t)); !errors.Is(err, ErrAuditFailed) {
		t.Fatalf("ожидается ErrAuditFailed: %v", err)
	}
	wr.check(t, "после сбоя active_changed")
	if st := wr.r.State(); st.Active != "none" || !st.Halted || st.HaltReason != "audit_failed" {
		t.Fatalf("состояние после сбоя: %+v", st)
	}

	mu.Lock()
	before := primaryPosts
	mu.Unlock()
	res, err := wr.r.Route(ctx, routeReq(t))
	if err != nil || res.Reason != "halted" || !res.DegradeL1 {
		t.Fatalf("Route на halt: %v %+v", err, res)
	}

	if err := wr.r.Resume(ctx, "sre-1"); !errors.Is(err, ErrAuditFailed) {
		t.Fatalf("Resume при сбое active_changed: %v", err)
	}
	wr.check(t, "после Resume со сбоем active_changed")
	if st := wr.r.State(); !st.Halted || st.HaltReason != "audit_failed" {
		t.Fatalf("Resume со сбоем записи должен оставить halt: %+v", st)
	}
	if _, err := wr.r.Route(ctx, routeReq(t)); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if primaryPosts != before {
		t.Errorf("при halt ушло %d запросов на primary", primaryPosts-before)
	}
	mu.Unlock()

	wr.sink.setFail("")
	if err := wr.r.Resume(ctx, "sre-1"); err != nil {
		t.Fatalf("Resume при рабочей записи: %v", err)
	}
	wr.check(t, "после успешного Resume")
	req := routeReq(t)
	req.IncidentID = "inc-2"
	res, err = wr.r.Route(ctx, req)
	if err != nil || res.Outcome != "sent" || res.Role != RoleFallback {
		t.Fatalf("после Resume: %v %+v", err, res)
	}
	mu.Lock()
	if primaryPosts != before {
		t.Errorf("после Resume запрос ушёл на down-endpoint (%d попыток)", primaryPosts-before)
	}
	mu.Unlock()

	evs := chainEvents(t, wr.chain)
	ac := activeChanged(evs)
	if len(ac) == 0 {
		t.Fatalf("в цепочке нет active_changed: %v", evs)
	}
	last := ac[len(ac)-1]
	if last.From != "inceptron-fp8" || last.To != "wafer-nvfp4" || last.Reason != "operator_resume" {
		t.Errorf("active_changed после Resume: from=%q to=%q reason=%q, ожидается inceptron-fp8 → wafer-nvfp4 (operator_resume)",
			last.From, last.To, last.Reason)
	}
	if err := wr.w.Close(); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(wr.chain)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var st audit.VerifyStats
	if _, err := audit.Verify(f, wr.keys, audit.VerifyOptions{Stats: &st}); err != nil {
		t.Fatalf("цепочка не проходит проверку: %v", err)
	}
	if st.RouterEvents != uint64(len(evs)) {
		t.Errorf("Verify видит %d событий роутера, прочитано %d", st.RouterEvents, len(evs))
	}
}

// provider_mismatch → quarantine → Resume: карантин снимается в down, по цепочке и в памяти одинаково.
func TestReplayMatchesMemoryQuarantineResume(t *testing.T) {
	ctx := context.Background()
	mismatch := true
	tr := &stubTransport{post: func(b []byte) (openrouter.Response, error) {
		if providerOf(b) == "inceptron" && mismatch {
			return reply("Other", 10, 10), nil
		}
		return reply("Wafer", 10, 10), nil
	}}
	wr := newWriterRig(t, &identityMasker{}, tr)
	res, err := wr.r.Route(ctx, routeReq(t))
	if err != nil || res.Parsed == nil || res.Parsed.Status != "provider_mismatch" {
		t.Fatalf("%v %+v", err, res)
	}
	wr.check(t, "после карантина")
	if st := wr.r.State(); st.Endpoints["inceptron-fp8"] != "quarantined" || st.Active != "wafer-nvfp4" {
		t.Fatalf("%+v", st)
	}
	mismatch = false
	if err := wr.r.Resume(ctx, "sre-1"); err != nil {
		t.Fatal(err)
	}
	wr.check(t, "после Resume")
	if st := wr.r.State(); st.Endpoints["inceptron-fp8"] != "down" {
		t.Fatalf("карантин не снят в down: %+v", st)
	}
}

// Закреплённый за primary инцидент: primary переведён в карантин; инцидент уходит на fallback и запросов на
// карантинный endpoint больше нет.
func TestPinnedIncidentNotRoutedToQuarantined(t *testing.T) {
	ctx := context.Background()
	var mu sync.Mutex
	primaryPosts := 0
	mismatch := false
	tr := &stubTransport{post: func(b []byte) (openrouter.Response, error) {
		if providerOf(b) == "inceptron" {
			mu.Lock()
			primaryPosts++
			m := mismatch
			mu.Unlock()
			if m {
				return reply("Other", 10, 10), nil
			}
			return reply("Inceptron", 10, 10), nil
		}
		return reply("Wafer", 10, 10), nil
	}}
	rg := newRig(t, &identityMasker{}, tr, "", nil)
	req := routeReq(t)
	req.IncidentID = "inc-pin"
	if res, err := rg.r.Route(ctx, req); err != nil || res.Role != RolePrimary {
		t.Fatalf("первый запрос: %v %+v", err, res)
	}
	mu.Lock()
	mismatch = true
	mu.Unlock()
	other := routeReq(t)
	other.IncidentID = "inc-other"
	if res, _ := rg.r.Route(ctx, other); res.Parsed == nil || res.Parsed.Status != "provider_mismatch" {
		t.Fatalf("карантин не наступил: %+v", res)
	}
	if st := rg.r.State(); st.Endpoints["inceptron-fp8"] != "quarantined" {
		t.Fatalf("%+v", st)
	}
	mu.Lock()
	before := primaryPosts
	mu.Unlock()
	res, err := rg.r.Route(ctx, req)
	if err != nil || res.Outcome != "sent" || res.Role != RoleFallback {
		t.Fatalf("закреплённый инцидент на карантинном endpoint: %v %+v", err, res)
	}
	mu.Lock()
	if primaryPosts != before {
		t.Errorf("на карантинный endpoint ушло %d запросов", primaryPosts-before)
	}
	mu.Unlock()
}

// Закреплённый инцидент при обоих down: запроса нет, транспорт не вызван, понижение до L1.
func TestPinnedIncidentBothDownNoRequests(t *testing.T) {
	ctx := context.Background()
	tr := &stubTransport{post: func([]byte) (openrouter.Response, error) { return openrouter.Response{Status: 503}, nil }}
	rg := newRig(t, &identityMasker{}, tr, "", nil)
	req := routeReq(t)
	req.IncidentID = "inc-pin"
	if _, err := rg.r.Route(ctx, req); err != nil {
		t.Fatal(err)
	}
	if st := rg.r.State(); st.Active != "none" {
		t.Fatalf("%+v", st)
	}
	calls := tr.calls
	res, err := rg.r.Route(ctx, req)
	if err != nil || res.Outcome != "not_sent" || res.Reason != "unavailable" || !res.DegradeL1 || tr.calls != calls {
		t.Fatalf("%v %+v вызовов=%d/%d", err, res, calls, tr.calls)
	}
	if err := recordValidate(res); err != nil {
		t.Errorf("запись unavailable не проходит Validate: %v", err)
	}
}

// Отмена до подготовки: маскировщик не вызывается, endpoint не выбирается, решение not_sent/canceled
// проходит Validate и Writer.Append, в цепочке остаётся запись.
func TestCanceledEarlyNoMaskerAndWriterAppend(t *testing.T) {
	m := &identityMasker{}
	tr := &stubTransport{post: func([]byte) (openrouter.Response, error) { return reply("Inceptron", 1, 1), nil }}
	wr := newWriterRig(t, m, tr)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := wr.r.Route(ctx, routeReq(t))
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != "not_sent" || res.Reason != "canceled" || res.DegradeL1 {
		t.Fatalf("outcome=%s reason=%s degrade=%v", res.Outcome, res.Reason, res.DegradeL1)
	}
	if n := m.calls.Load(); n != 0 {
		t.Errorf("маскировщик вызван %d раз при отменённом ctx", n)
	}
	if tr.calls != 0 {
		t.Errorf("транспорт вызван %d раз", tr.calls)
	}
	rec := decisionRecord(res)
	if err := rec.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if _, err := wr.w.Append(rec); err != nil {
		t.Fatalf("Writer.Append отверг canceled: %v", err)
	}
	wr.check(t, "после canceled")
}

// Отмена в момент между попытками: попытки на primary уже ушли (платёж учтён), затем отмена на старте вызова
// fallback. Решение не должно записываться как not_sent: запрос ушёл на primary.
func TestCanceledAfterPrimaryAttemptsNotRecordedNotSent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	primaryPosts, clockCalls := 0, 0
	armed := false
	tr := &stubTransport{post: func(b []byte) (openrouter.Response, error) {
		if providerOf(b) == "inceptron" {
			mu.Lock()
			primaryPosts++
			if primaryPosts == 3 {
				armed = true
			}
			mu.Unlock()
			return openrouter.Response{Status: 503}, nil
		}
		return reply("Wafer", 10, 10), nil
	}}
	// Часы клиента: после третьей попытки primary — LatencyMS и finish; третий вызов — старт вызова fallback. Отмена здесь.
	clientClock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		if armed {
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
	mu.Lock()
	posts := primaryPosts
	mu.Unlock()
	if posts != 3 {
		t.Fatalf("сценарий не сработал: попыток на primary %d, ожидается 3", posts)
	}
	if res.Outcome == "not_sent" {
		t.Errorf("решение not_sent/%s, хотя на primary ушло %d попыток (платёж учтён); call=%+v", res.Reason, posts, res.Call)
	}
	if res.Outcome != "sent" || res.Attempts != 3 || res.Switched || res.Role != RolePrimary {
		t.Errorf("outcome=%s attempts=%d switched=%v role=%s, ожидается sent/3/false/primary", res.Outcome, res.Attempts, res.Switched, res.Role)
	}
	if rec := decisionRecord(res); rec.Model == nil || rec.Model.EndpointRole != "primary" || rec.LLM.EndpointSwitched {
		t.Errorf("атрибуция записи: model=%+v switched=%v", rec.Model, rec.LLM.EndpointSwitched)
	}
}

// decisionRecord собирает decision record из результата роутера (без проверки).
func decisionRecord(res *Result) *audit.DecisionRecord {
	rec := &audit.DecisionRecord{Schema: audit.RecordSchema, RecordID: audit.NewRecordID(),
		RecordedAt: audit.Timestamp(time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)), Mode: audit.ModeShadow,
		Incident:  audit.IncidentRef{ID: "inc-1", Service: "geo-svc", Environment: "staging"},
		Initiator: audit.Actor{Kind: "agent", ID: "a1"}, RetrievedDocs: []string{}, AutonomyLevel: "L0"}
	res.Apply(rec)
	return rec
}

// Failover после таймаутов primary: таймаут списывает весь резерв (платёж неизвестен). В записи решения
// учтённый расход должен включать попытки на primary, а не только на fallback.
func TestFailoverRecordKeepsPrimaryCharges(t *testing.T) {
	ctx := context.Background()
	tr := &stubTransport{post: func(b []byte) (openrouter.Response, error) {
		if providerOf(b) == "inceptron" {
			return openrouter.Response{}, &openrouter.TransportError{Kind: "timeout"}
		}
		return reply("Wafer", 100, 50), nil
	}}
	rg := newRig(t, &identityMasker{}, tr, "", nil)
	res, err := rg.r.Route(ctx, routeReq(t))
	if err != nil || res.Outcome != "sent" || res.Role != RoleFallback {
		t.Fatalf("%v %+v", err, res)
	}
	reserve := int64(res.Prepared.EstInputTokens + res.Prepared.MaxTokens)
	rec := decisionRecord(res)
	if err := rec.Validate(); err != nil {
		t.Fatal(err)
	}
	// На primary три таймаута: 3 резерва списаны; на fallback — 150 по факту.
	want := 3*reserve + 150
	if got := rec.Answer.Usage.ChargedTokens; got != want {
		t.Errorf("charged_tokens в записи %d, ожидается %d (3 таймаута на primary по резерву %d + 150 на fallback)", got, want, reserve)
	}
	if got := rec.Answer.Attempts; got != 4 {
		t.Errorf("attempts в записи %d, ожидается 4 (3 на primary + 1 на fallback)", got)
	}
}
