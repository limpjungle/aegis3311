package llmrouter

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/limpjungle/aegis3311/internal/audit"
	"github.com/limpjungle/aegis3311/internal/dataclass"
	"github.com/limpjungle/aegis3311/internal/openrouter"
	"github.com/limpjungle/aegis3311/internal/routerstate"
)

// stateHealthBody — ответ health-check'а: оба endpoint'а в списке (как в TestFailover).
const stateHealthBody = `{"data":{"endpoints":[{"provider_name":"Inceptron","quantization":"fp8","tag":"t","supported_parameters":["response_format","structured_outputs","seed"]},` +
	`{"provider_name":"Wafer","quantization":"nvfp4","tag":"w","supported_parameters":["response_format","structured_outputs","seed"]}]}}`

// providerCounts — число POST по провайдеру (inceptron | wafer).
type providerCounts struct {
	mu sync.Mutex
	n  map[string]int
}

func newProviderCounts() *providerCounts { return &providerCounts{n: map[string]int{}} }

func (c *providerCounts) add(p string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n[p]++
}

func (c *providerCounts) get(p string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n[p]
}

// fakeProviders — транспорт: POST на fallback (wafer) всегда успешен; на primary (inceptron) — primary(), nil — успех.
func fakeProviders(pc *providerCounts, primary func() openrouter.Response) *stubTransport {
	return &stubTransport{post: func(b []byte) (openrouter.Response, error) {
		p := providerOf(b)
		pc.add(p)
		if p == "inceptron" {
			if primary != nil {
				return primary(), nil
			}
			return reply("Inceptron", 100, 50), nil
		}
		return reply("Wafer", 100, 50), nil
	}}
}

// faultyStore — хранилище с отказом на операции: операция не передаётся дальше, и с этого момента все вызовы
// возвращают ErrFailed (как после ошибки ввода-вывода). failKind "*" — любая операция.
type faultyStore struct {
	inner    routerstate.Store
	mu       sync.Mutex
	failKind routerstate.OpKind
	dead     bool
}

func (f *faultyStore) Load() (*routerstate.State, routerstate.LoadInfo, error) { return f.inner.Load() }

func (f *faultyStore) Append(op routerstate.Op) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.dead {
		return routerstate.ErrFailed
	}
	if f.failKind == "*" || f.failKind == op.Kind {
		f.dead = true
		return routerstate.ErrFailed
	}
	return f.inner.Append(op)
}

func (f *faultyStore) Err() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.dead {
		return routerstate.ErrFailed
	}
	return f.inner.Err()
}

func (f *faultyStore) Close() error { return f.inner.Close() }

// failAt — обёртка, которая отказывает на первой операции вида kind.
func failAt(kind routerstate.OpKind) func(routerstate.Store) routerstate.Store {
	return func(s routerstate.Store) routerstate.Store { return &faultyStore{inner: s, failKind: kind} }
}

// stateRig — роутер с файловым хранилищем состояния и реальной цепочкой аудита во временном каталоге.
// Рестарт — закрыть хранилище и цепочку, открыть заново и собрать роутер (New).
type stateRig struct {
	t         *testing.T
	a         *openrouter.Assets
	m         dataclass.Masker
	tr        *stubTransport
	secret    string
	clock     *fakeClock
	chain     string
	statePath string
	signer    audit.Signer
	keys      audit.Keyring
	budgets   BudgetConfig
	sleep     func(context.Context, time.Duration) error
	wrap      func(routerstate.Store) routerstate.Store

	w    *audit.Writer
	fst  *routerstate.FileStore
	sink *flakySink
	r    *Router
}

func newStateRig(t *testing.T, m dataclass.Masker, tr *stubTransport) *stateRig {
	t.Helper()
	dir := t.TempDir()
	signer, keys := newAuditSigner(t)
	if tr.get == nil {
		tr.get = func() (openrouter.Response, error) {
			return openrouter.Response{Status: 200, Body: []byte(stateHealthBody)}, nil
		}
	}
	rg := &stateRig{t: t, a: loadAssets(t), m: m, tr: tr, secret: runtimeSecret(t), clock: newFakeClock(),
		chain: filepath.Join(dir, "chain.jsonl"), statePath: filepath.Join(dir, "state.jsonl"), signer: signer, keys: keys,
		budgets: BudgetConfig{IncidentTokens: 1 << 40, ServiceDayTokens: 1 << 40}}
	rg.boot()
	t.Cleanup(rg.closeAll)
	return rg
}

// boot открывает цепочку и хранилище и собирает роутер.
func (rg *stateRig) boot() {
	t := rg.t
	t.Helper()
	w, err := audit.OpenWriter(rg.chain, "router-test", rg.signer, rg.keys)
	if err != nil {
		t.Fatal(err)
	}
	fst, err := routerstate.OpenFile(rg.statePath, testIdentity(rg.a), routerstate.FileOptions{})
	if err != nil {
		w.Close()
		t.Fatal(err)
	}
	rg.w, rg.fst, rg.sink = w, fst, &flakySink{w: w}
	var st routerstate.Store = fst
	if rg.wrap != nil {
		st = rg.wrap(fst)
	}
	cl, err := openrouter.NewClient(&rg.a.Config, testKey(t, rg.secret), rg.tr, openrouter.WithSleep(func(ctx context.Context, d time.Duration) error {
		if rg.sleep != nil {
			return rg.sleep(ctx, d)
		}
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	r, err := New(Options{Assets: rg.a, Client: cl, Masker: rg.m, Events: rg.sink, Clock: rg.clock, State: st,
		Budgets: rg.budgets, Failover: DefaultFailover(), RouterID: "llm-router-test"})
	if err != nil {
		t.Fatal(err)
	}
	rg.r = r
}

// closeAll закрывает хранилище и цепочку (повторный вызов безопасен).
func (rg *stateRig) closeAll() {
	if rg.fst != nil {
		if err := rg.fst.Close(); err != nil {
			rg.t.Errorf("закрытие хранилища: %v", err)
		}
		rg.fst = nil
	}
	if rg.w != nil {
		if err := rg.w.Close(); err != nil {
			rg.t.Errorf("закрытие цепочки: %v", err)
		}
		rg.w = nil
	}
}

// restart — имитация перезапуска процесса: состояние дальше читается только из хранилища и цепочки.
func (rg *stateRig) restart(wrap func(routerstate.Store) routerstate.Store) {
	rg.t.Helper()
	rg.closeAll()
	rg.wrap = wrap
	rg.boot()
}

func (rg *stateRig) route(incident string) (*Result, error) {
	req := routeReq(rg.t)
	req.IncidentID = incident
	return rg.r.Route(context.Background(), req)
}

// check сверяет память с цепочкой (см. writerRig.check).
func (rg *stateRig) check(label string) {
	rg.t.Helper()
	wr := &writerRig{r: rg.r, sink: rg.sink, w: rg.w, chain: rg.chain, keys: rg.keys}
	wr.check(rg.t, label)
}

// chainLast — последнее событие роутера в цепочке.
func (rg *stateRig) chainLast() audit.RouterEvent {
	rg.t.Helper()
	evs := chainEvents(rg.t, rg.chain)
	if len(evs) == 0 {
		rg.t.Fatal("в цепочке нет событий роутера")
	}
	return evs[len(evs)-1]
}

// assertMirrors сверяет счета, закрепления и состояние failover в памяти с копией хранилища. Вызывать, когда
// хранилище работает и операций в полёте нет.
func assertMirrors(t *testing.T, label string, r *Router, s *routerstate.State) {
	t.Helper()
	r.bud.mu.Lock()
	if len(r.bud.incidents) != len(s.Incidents) {
		t.Errorf("%s: инцидентов в памяти %d, в store %d", label, len(r.bud.incidents), len(s.Incidents))
	}
	for id, a := range r.bud.incidents {
		if got, ok := s.Incidents[id]; !ok || got != a.spent || a.held != 0 {
			t.Errorf("%s: инцидент %s: память spent=%d held=%d, store spent=%d (есть=%v)", label, id, a.spent, a.held, got, ok)
		}
	}
	if len(r.bud.days) != len(s.Days) {
		t.Errorf("%s: сервисов в памяти %d, в store %d", label, len(r.bud.days), len(s.Days))
	}
	for svc, d := range r.bud.days {
		if sd := s.Days[svc]; sd.Day != d.day || sd.Spent != d.spent || d.held != 0 {
			t.Errorf("%s: сервис %s: память %+v held=%d, store %+v", label, svc, d.acct, d.held, sd)
		}
	}
	if r.bud.nextHold != s.NextHold {
		t.Errorf("%s: следующий резерв в памяти %d, в store %d", label, r.bud.nextHold, s.NextHold)
	}
	r.bud.mu.Unlock()

	r.mu.Lock()
	f := r.failoverLocked()
	pins := map[string]string{}
	for k, v := range r.pins {
		pins[k] = string(v)
	}
	r.mu.Unlock()
	if !reflect.DeepEqual(f, s.Failover) {
		t.Errorf("%s: failover в памяти %+v, в store %+v", label, f, s.Failover)
	}
	if !reflect.DeepEqual(pins, s.Pins) {
		t.Errorf("%s: закрепления в памяти %v, в store %v", label, pins, s.Pins)
	}
	if s.Pending != nil {
		t.Errorf("%s: в store остался intent %+v", label, s.Pending)
	}
	if len(s.Holds) != 0 {
		t.Errorf("%s: в store открытые резервы %+v", label, s.Holds)
	}
}

// TestRestartKeepsBudgets: счета сервиса и инцидента переживают рестарт; после CloseIncident счёт инцидента пуст.
func TestRestartKeepsBudgets(t *testing.T) {
	t.Run("сервис за сутки", func(t *testing.T) {
		tr := fakeProviders(newProviderCounts(), nil)
		rg := newStateRig(t, &identityMasker{}, tr)
		res, err := rg.route("inc-1")
		if err != nil || res.Outcome != "sent" {
			t.Fatalf("%v %+v", err, res)
		}
		est := int64(res.Prepared.EstInputTokens + res.Prepared.MaxTokens)
		// Два запроса по 150 расхода помещаются (150 + est ≤ лимит), третий — нет (300 + est > лимит).
		rg.budgets.ServiceDayTokens = 300 + est - 1
		rg.restart(nil)
		if res, err := rg.route("inc-1"); err != nil || res.Outcome != "sent" {
			t.Fatalf("второй запрос: %v %+v", err, res)
		}
		rg.restart(nil)
		res, err = rg.route("inc-1")
		if err != nil || res.Reason != "budget_service_day" || !res.DegradeL1 {
			t.Fatalf("третий запрос после рестарта: %v %+v", err, res)
		}
		if tr.calls != 2 {
			t.Errorf("POST: %d, ожидается 2 (третий запрос не должен уйти)", tr.calls)
		}
		assertMirrors(t, "после отказа бюджета", rg.r, rg.fst.Snapshot())
	})

	t.Run("инцидент и закрытие", func(t *testing.T) {
		tr := fakeProviders(newProviderCounts(), nil)
		rg := newStateRig(t, &identityMasker{}, tr)
		res, err := rg.route("inc-1")
		if err != nil || res.Outcome != "sent" {
			t.Fatalf("%v %+v", err, res)
		}
		est := int64(res.Prepared.EstInputTokens + res.Prepared.MaxTokens)
		rg.budgets.IncidentTokens = 300 + est - 1
		rg.restart(nil)
		if res, err := rg.route("inc-1"); err != nil || res.Outcome != "sent" {
			t.Fatalf("второй запрос: %v %+v", err, res)
		}
		rg.restart(nil)
		res, err = rg.route("inc-1")
		if err != nil || res.Reason != "budget_incident" {
			t.Fatalf("третий запрос после рестарта: %v %+v", err, res)
		}
		if err := rg.r.CloseIncident("inc-1"); err != nil {
			t.Fatal(err)
		}
		rg.restart(nil)
		if _, ok := rg.fst.Snapshot().Incidents["inc-1"]; ok {
			t.Error("после CloseIncident и рестарта счёт инцидента остался")
		}
		if res, err := rg.route("inc-1"); err != nil || res.Outcome != "sent" {
			t.Fatalf("после закрытия инцидента: %v %+v", err, res)
		}
		if got := rg.fst.Snapshot().Incidents["inc-1"]; got != 150 {
			t.Errorf("счёт инцидента после закрытия: %d, ожидается 150", got)
		}
	})
}

// TestRestartKeepsFailoverAndHysteresis: переключение и состояние down переживают рестарт; серия стабильных
// health-check'ов после рестарта начинается заново.
func TestRestartKeepsFailoverAndHysteresis(t *testing.T) {
	ctx := context.Background()
	pc := newProviderCounts()
	tr := fakeProviders(pc, func() openrouter.Response { return openrouter.Response{Status: 503} })
	rg := newStateRig(t, &identityMasker{}, tr)
	res, err := rg.route("inc-1")
	if err != nil || res.Outcome != "sent" || res.Role != RoleFallback {
		t.Fatalf("%v %+v", err, res)
	}
	if s := rg.r.State().Endpoints["inceptron-fp8"]; s != "down" {
		t.Fatalf("primary после трёх ошибок: %s", s)
	}
	if err := rg.r.CheckHealth(ctx); err != nil { // начало серии стабильности
		t.Fatal(err)
	}
	rg.clock.Advance(9 * time.Minute)
	if err := rg.r.CheckHealth(ctx); err != nil {
		t.Fatal(err)
	}

	rg.restart(nil)
	if st := rg.r.State(); st.Endpoints["inceptron-fp8"] != "down" || st.Active != "wafer-nvfp4" {
		t.Fatalf("после рестарта: %+v", st)
	}
	rg.check("после рестарта")
	before := pc.get("inceptron")
	if res, err := rg.route("inc-1"); err != nil || res.Role != RoleFallback {
		t.Fatalf("после рестарта: %v %+v", err, res)
	}
	if n := pc.get("inceptron") - before; n != 0 {
		t.Errorf("после рестарта ушло %d запросов на down-endpoint", n)
	}

	rg.clock.Advance(2 * time.Minute)
	if err := rg.r.CheckHealth(ctx); err != nil {
		t.Fatal(err)
	}
	if s := rg.r.State().Endpoints["inceptron-fp8"]; s != "down" {
		t.Fatalf("серия стабильности не должна переживать рестарт: primary %s через 2 минуты после рестарта", s)
	}
	rg.clock.Advance(10 * time.Minute)
	if err := rg.r.CheckHealth(ctx); err != nil {
		t.Fatal(err)
	}
	if s := rg.r.State().Endpoints["inceptron-fp8"]; s != "up" {
		t.Fatalf("через 10 минут после рестарта primary %s", s)
	}
	var up *audit.RouterEvent
	for _, ev := range chainEvents(t, rg.chain) {
		if ev.Kind == "endpoint_up" {
			e := ev
			up = &e
		}
	}
	if up == nil || up.StableForS != 600 {
		t.Errorf("endpoint_up: %+v, ожидается stable_for_s 600", up)
	}
	rg.check("после восстановления")
}

// TestRestartKeepsFailCounter: счётчик неудач переживает рестарт: после двух неудач до рестарта одна неудача
// после него переводит endpoint в down с consecutive_failures = 3.
func TestRestartKeepsFailCounter(t *testing.T) {
	pc := newProviderCounts()
	tr := fakeProviders(pc, func() openrouter.Response { return openrouter.Response{Status: 503} })
	rg := newStateRig(t, &identityMasker{}, tr)
	sleeps := 0
	rg.sleep = func(context.Context, time.Duration) error {
		sleeps++
		if sleeps == 2 { // после второй неудачи ретраи прекращаются (как отмена вызывающим)
			return context.Canceled
		}
		return nil
	}
	res, err := rg.route("inc-1")
	if err != nil || res.Attempts != 2 || rg.r.State().Endpoints["inceptron-fp8"] != "up" {
		t.Fatalf("%v %+v", err, res)
	}
	if n := rg.fst.Snapshot().Failover.Primary.ReqFails; n != 2 {
		t.Fatalf("счётчик неудач в store: %d, ожидается 2", n)
	}
	rg.sleep = nil
	rg.restart(nil)
	res, err = rg.route("inc-1")
	if err != nil || res.Role != RoleFallback {
		t.Fatalf("%v %+v", err, res)
	}
	var down *audit.RouterEvent
	for _, ev := range chainEvents(t, rg.chain) {
		if ev.Kind == "endpoint_down" {
			e := ev
			down = &e
		}
	}
	if down == nil || down.ConsecutiveFailures != 3 || down.Reason != "consecutive_failures" {
		t.Fatalf("endpoint_down: %+v", down)
	}
	assertMirrors(t, "после перехода", rg.r, rg.fst.Snapshot())
}

// TestRestartKeepsPin: закрепление инцидента за fallback переживает рестарт, даже когда primary снова up.
func TestRestartKeepsPin(t *testing.T) {
	ctx := context.Background()
	pc := newProviderCounts()
	primaryDown := true
	tr := fakeProviders(pc, func() openrouter.Response {
		if primaryDown {
			return openrouter.Response{Status: 503}
		}
		return reply("Inceptron", 100, 50)
	})
	rg := newStateRig(t, &identityMasker{}, tr)
	if res, err := rg.route("inc-pin"); err != nil || res.Role != RoleFallback {
		t.Fatalf("%v %+v", err, res)
	}
	if err := rg.r.CheckHealth(ctx); err != nil {
		t.Fatal(err)
	}
	rg.clock.Advance(10 * time.Minute)
	primaryDown = false
	if err := rg.r.CheckHealth(ctx); err != nil {
		t.Fatal(err)
	}
	if s := rg.r.State().Endpoints["inceptron-fp8"]; s != "up" {
		t.Fatalf("primary после гистерезиса: %s", s)
	}
	rg.restart(nil)
	if st := rg.r.State(); st.Endpoints["inceptron-fp8"] != "up" {
		t.Fatalf("после рестарта: %+v", st)
	}
	before := pc.get("inceptron")
	if res, err := rg.route("inc-pin"); err != nil || res.Role != RoleFallback {
		t.Errorf("закреплённый инцидент после рестарта ушёл с fallback: %v %+v", err, res)
	}
	if n := pc.get("inceptron") - before; n != 0 {
		t.Errorf("закреплённый инцидент отправил %d запросов на primary", n)
	}
	if res, err := rg.route("inc-new"); err != nil || res.Role != RolePrimary {
		t.Errorf("новый инцидент после рестарта: %v %+v", err, res)
	}
	assertMirrors(t, "после рестарта", rg.r, rg.fst.Snapshot())
}

// TestRestartKeepsHaltAndQuarantine: halt (auth, estimator, audit_failed) и карантин переживают рестарт;
// Resume снимает их, и после рестарта после Resume роутер не остановлен.
func TestRestartKeepsHaltAndQuarantine(t *testing.T) {
	t.Run("auth", func(t *testing.T) {
		pc := newProviderCounts()
		tr := fakeProviders(pc, func() openrouter.Response { return openrouter.Response{Status: 401} })
		rg := newStateRig(t, &identityMasker{}, tr)
		if _, err := rg.route("inc-1"); err != nil {
			t.Fatal(err)
		}
		if st := rg.r.State(); !st.Halted || st.HaltReason != "auth" {
			t.Fatalf("%+v", st)
		}
		rg.restart(nil)
		if st := rg.r.State(); !st.Halted || st.HaltReason != "auth" {
			t.Fatalf("после рестарта: %+v", st)
		}
		rg.check("после рестарта")
		before := pc.get("inceptron")
		if res, err := rg.route("inc-1"); err != nil || res.Reason != "halted" || !res.DegradeL1 {
			t.Fatalf("%v %+v", err, res)
		}
		if n := pc.get("inceptron") - before; n != 0 {
			t.Errorf("при halt ушло %d запросов", n)
		}
		if err := rg.r.Resume(context.Background(), "sre-1"); err != nil {
			t.Fatal(err)
		}
		rg.restart(nil)
		if st := rg.r.State(); st.Halted {
			t.Fatalf("после Resume и рестарта: %+v", st)
		}
		rg.check("после Resume")
	})

	t.Run("estimator", func(t *testing.T) {
		ceiling := loadAssets(t).Config.ContextCeiling
		tr := fakeProviders(newProviderCounts(), func() openrouter.Response { return reply("Inceptron", ceiling, 1) })
		rg := newStateRig(t, &identityMasker{}, tr)
		res, err := rg.route("inc-1")
		if err != nil || res.ErrorKind != "context_ceiling_actual" {
			t.Fatalf("%v %+v", err, res)
		}
		rg.restart(nil)
		if st := rg.r.State(); !st.Halted || st.HaltReason != "estimator" {
			t.Fatalf("после рестарта: %+v", st)
		}
		rg.check("после рестарта")
		if err := rg.r.Resume(context.Background(), "sre-1"); err != nil {
			t.Fatal(err)
		}
		rg.restart(nil)
		if st := rg.r.State(); st.Halted {
			t.Fatalf("после Resume и рестарта: %+v", st)
		}
	})

	t.Run("карантин", func(t *testing.T) {
		tr := fakeProviders(newProviderCounts(), func() openrouter.Response { return reply("Other", 10, 10) })
		rg := newStateRig(t, &identityMasker{}, tr)
		res, err := rg.route("inc-1")
		if err != nil || res.Parsed == nil || res.Parsed.Status != "provider_mismatch" {
			t.Fatalf("%v %+v", err, res)
		}
		rg.restart(nil)
		if st := rg.r.State(); st.Endpoints["inceptron-fp8"] != "quarantined" || st.Active != "wafer-nvfp4" {
			t.Fatalf("после рестарта: %+v", st)
		}
		rg.check("после рестарта")
		if res, err := rg.route("inc-2"); err != nil || res.Role != RoleFallback {
			t.Fatalf("на карантинный endpoint: %v %+v", err, res)
		}
		if err := rg.r.Resume(context.Background(), "sre-1"); err != nil {
			t.Fatal(err)
		}
		rg.restart(nil)
		if st := rg.r.State(); st.Endpoints["inceptron-fp8"] != "down" {
			t.Fatalf("карантин после Resume: %+v", st)
		}
		rg.check("после Resume")
	})

	t.Run("audit_failed", func(t *testing.T) {
		pc := newProviderCounts()
		tr := fakeProviders(pc, func() openrouter.Response { return openrouter.Response{Status: 401} })
		rg := newStateRig(t, &identityMasker{}, tr)
		rg.sink.setFail("router_halted")
		if _, err := rg.route("inc-1"); !errors.Is(err, ErrAuditFailed) {
			t.Fatalf("ожидается ErrAuditFailed: %v", err)
		}
		if st := rg.r.State(); !st.Halted || st.HaltReason != "audit_failed" {
			t.Fatalf("%+v", st)
		}
		rg.restart(nil)
		if st := rg.r.State(); !st.Halted || st.HaltReason != "audit_failed" || st.Endpoints["inceptron-fp8"] != "up" {
			t.Fatalf("после рестарта: %+v", st)
		}
		assertMirrors(t, "после рестарта при audit_failed", rg.r, rg.fst.Snapshot())
		before := pc.get("inceptron")
		if res, err := rg.route("inc-1"); err != nil || res.Reason != "halted" {
			t.Fatalf("%v %+v", err, res)
		}
		if n := pc.get("inceptron") - before; n != 0 {
			t.Errorf("при halt ушло %d запросов", n)
		}
		if err := rg.r.Resume(context.Background(), "sre-1"); err != nil {
			t.Fatalf("Resume при audit_failed: %v", err)
		}
		rg.restart(nil)
		if st := rg.r.State(); st.Halted {
			t.Fatalf("после Resume и рестарта: %+v", st)
		}
		rg.check("после Resume")
	})
}

// TestOrphanHoldChargedAfterCrash: резерв, записанный до HTTP-попытки, и краш во время запроса — при рестарте
// резерв списывается полностью (запрос мог быть оплачен).
func TestOrphanHoldChargedAfterCrash(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	var mu sync.Mutex
	blockNext := true
	tr := fakeProviders(newProviderCounts(), nil)
	tr.post = func(b []byte) (openrouter.Response, error) {
		if providerOf(b) == "inceptron" {
			mu.Lock()
			blk := blockNext
			blockNext = false
			mu.Unlock()
			if blk {
				entered <- struct{}{}
				<-release
			}
		}
		return reply("Inceptron", 100, 50), nil
	}
	rg := newStateRig(t, &identityMasker{}, tr)
	type outcome struct {
		res *Result
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		res, err := rg.route("inc-1")
		done <- outcome{res, err}
	}()
	<-entered
	raw, err := os.ReadFile(rg.statePath) // образ диска в момент краха: резерв уже записан и сброшен на диск
	if err != nil {
		t.Fatal(err)
	}
	crash := filepath.Join(t.TempDir(), "crash.jsonl")
	if err := os.WriteFile(crash, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	close(release)
	o := <-done
	if o.err != nil || o.res.Outcome != "sent" {
		t.Fatalf("%v %+v", o.err, o.res)
	}
	est := int64(o.res.Prepared.EstInputTokens + o.res.Prepared.MaxTokens)

	fs, err := routerstate.OpenFile(crash, testIdentity(rg.a), routerstate.FileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()
	st, info, err := fs.Load()
	if err != nil {
		t.Fatal(err)
	}
	if info.OrphanHolds != 1 || info.OrphanTokens != est {
		t.Errorf("осиротевший резерв: %+v, ожидается %d токенов", info, est)
	}
	if st.Incidents["inc-1"] != est || st.Days["geo-svc"].Spent != est {
		t.Errorf("счета после списания: инцидент %d, сервис %d, ожидается %d", st.Incidents["inc-1"], st.Days["geo-svc"].Spent, est)
	}
}

// TestIntentResolvedByChain: оборванный переход разрешается по цепочке: событие записано — commit, нет — abort.
func TestIntentResolvedByChain(t *testing.T) {
	t.Run("событие в цепочке — commit", func(t *testing.T) {
		rg := newStateRig(t, &identityMasker{}, fakeProviders(newProviderCounts(), nil))
		id := audit.NewEventID()
		next := routerstate.Failover{Primary: routerstate.EndpointState{State: "down"}, Fallback: routerstate.EndpointState{State: "up"}, Active: "primary"}
		if err := rg.fst.Append(routerstate.Op{Kind: routerstate.OpIntent, At: audit.Timestamp(rg.clock.Now()), EventID: id,
			EventKind: "endpoint_down", Failover: &next}); err != nil {
			t.Fatal(err)
		}
		ev := &audit.RouterEvent{Schema: audit.RouterEventSchema, EventID: id, RecordedAt: audit.Timestamp(rg.clock.Now()),
			Kind: "endpoint_down", Model: rg.a.Config.Model, Initiator: audit.Actor{Kind: "system", ID: "llm-router-test"},
			Endpoint: rg.a.Primary.Name, Role: "primary", Reason: "consecutive_failures", ConsecutiveFailures: 3}
		if _, err := rg.w.AppendEvent(ev); err != nil {
			t.Fatal(err)
		}
		rg.closeAll() // крах между событием и commit
		rg.restart(nil)
		if rg.fst.Snapshot().Pending != nil {
			t.Error("intent не разрешён после рестарта")
		}
		if s := rg.r.State().Endpoints["inceptron-fp8"]; s != "down" {
			t.Fatalf("primary после commit по цепочке: %s, ожидается down", s)
		}
		rg.check("после рестарта")
		// Активный endpoint должен уйти с упавшего primary сразу после старта, без ожидания health-check'ов.
		res, err := rg.route("inc-1")
		if err != nil || res.Outcome != "sent" || res.Role != RoleFallback {
			t.Errorf("запрос после рестарта должен уйти на fallback: %v %+v", err, res)
		}
	})

	t.Run("события нет в цепочке — abort", func(t *testing.T) {
		rg := newStateRig(t, &identityMasker{}, fakeProviders(newProviderCounts(), nil))
		next := routerstate.Failover{Primary: routerstate.EndpointState{State: "down"}, Fallback: routerstate.EndpointState{State: "up"}, Active: "primary"}
		if err := rg.fst.Append(routerstate.Op{Kind: routerstate.OpIntent, At: audit.Timestamp(rg.clock.Now()), EventID: audit.NewEventID(),
			EventKind: "endpoint_down", Failover: &next}); err != nil {
			t.Fatal(err)
		}
		rg.closeAll()
		rg.restart(nil)
		if rg.fst.Snapshot().Pending != nil {
			t.Error("intent не снят после рестарта")
		}
		if s := rg.r.State().Endpoints["inceptron-fp8"]; s != "up" {
			t.Fatalf("primary после abort: %s, ожидается up", s)
		}
		rg.check("после рестарта")
		if res, err := rg.route("inc-1"); err != nil || res.Role != RolePrimary {
			t.Errorf("%v %+v", err, res)
		}
	})
}

// TestStoreFailureBeforeSend: отказ записи резерва — запрос не уходит (not_sent/halted, L1), остановка в цепочке.
func TestStoreFailureBeforeSend(t *testing.T) {
	tr := fakeProviders(newProviderCounts(), nil)
	rg := newStateRig(t, &identityMasker{}, tr)
	rg.restart(failAt(routerstate.OpReserve))
	res, err := rg.route("inc-1")
	if err != nil || res.Outcome != "not_sent" || res.Reason != "halted" || !res.DegradeL1 || res.Call != nil {
		t.Fatalf("%v %+v", err, res)
	}
	if tr.calls != 0 {
		t.Errorf("запрос отправлен при отказе записи резерва: %d", tr.calls)
	}
	rg.r.bud.mu.Lock()
	_, incOK := rg.r.bud.incidents["inc-1"]
	_, dayOK := rg.r.bud.days["geo-svc"]
	rg.r.bud.mu.Unlock()
	if incOK || dayOK {
		t.Errorf("при отказе записи резерва счета созданы в памяти: инцидент=%v сервис=%v", incOK, dayOK)
	}
	if ev := rg.chainLast(); ev.Kind != "router_halted" || ev.Reason != "state_store" {
		t.Errorf("в цепочке последнее событие %+v, ожидается router_halted(state_store)", ev)
	}
	applyOK(t, res)
	if res, err := rg.route("inc-1"); err != nil || res.Reason != "halted" {
		t.Errorf("следующий Route: %v %+v", err, res)
	}
	if err := rg.r.Resume(context.Background(), "sre-1"); !errors.Is(err, ErrStateStore) {
		t.Errorf("Resume при мёртвом хранилище: %v, ожидается ErrStateStore", err)
	}
	if st := rg.r.State(); !st.Halted || st.HaltReason != "state_store" {
		t.Errorf("halt должен остаться: %+v", st)
	}
	rg.check("после отказа хранилища")
}

// TestStoreFailureOnSettleAfterOK: ответ 200 получен, расход не записан — ответ валиден, роутер остановлен;
// после рестарта резерв списан полностью, halt восстановлен по цепочке.
func TestStoreFailureOnSettleAfterOK(t *testing.T) {
	tr := fakeProviders(newProviderCounts(), nil)
	rg := newStateRig(t, &identityMasker{}, tr)
	rg.restart(failAt(routerstate.OpSettle))
	res, err := rg.route("inc-1")
	if err != nil || res.Outcome != "sent" || res.Parsed == nil || res.Parsed.Status != "ok" {
		t.Fatalf("ответ должен быть принят: %v %+v", err, res)
	}
	est := int64(res.Prepared.EstInputTokens + res.Prepared.MaxTokens)
	if st := rg.r.State(); !st.Halted || st.HaltReason != "state_store" {
		t.Fatalf("после отказа расхода: %+v", st)
	}
	if res, err := rg.route("inc-1"); err != nil || res.Reason != "halted" {
		t.Fatalf("следующий Route: %v %+v", err, res)
	}
	rg.restart(nil)
	if st := rg.r.State(); !st.Halted || st.HaltReason != "state_store" {
		t.Errorf("после рестарта halt не восстановлен: %+v", st)
	}
	if got := rg.fst.Snapshot().Days["geo-svc"].Spent; got != est {
		t.Errorf("расход после рестарта %d, ожидается полный резерв %d", got, est)
	}
	rg.check("после рестарта")
}

// TestStoreFailureMidRetries: отказ расхода на первой неудачной попытке — ретраи прекращаются.
func TestStoreFailureMidRetries(t *testing.T) {
	calls := 0
	tr := &stubTransport{post: func(b []byte) (openrouter.Response, error) {
		calls++
		return openrouter.Response{Status: 503}, nil
	}}
	rg := newStateRig(t, &identityMasker{}, tr)
	rg.restart(failAt(routerstate.OpSettle))
	res, err := rg.route("inc-1")
	if err != nil || res.Attempts != 1 || res.ErrorKind != "stopped" {
		t.Fatalf("%v %+v", err, res)
	}
	if calls != 1 {
		t.Errorf("POST: %d, ожидается 1", calls)
	}
}

// TestStoreFailureOnIntent: отказ intent при переходе — endpoint не переведён, событие не записано, halt state_store.
func TestStoreFailureOnIntent(t *testing.T) {
	pc := newProviderCounts()
	tr := fakeProviders(pc, func() openrouter.Response { return openrouter.Response{Status: 503} })
	rg := newStateRig(t, &identityMasker{}, tr)
	rg.restart(failAt(routerstate.OpIntent))
	if _, err := rg.route("inc-1"); err != nil {
		t.Fatal(err)
	}
	for _, ev := range chainEvents(t, rg.chain) {
		if ev.Kind == "endpoint_down" {
			t.Errorf("событие endpoint_down записано при отказе intent: %+v", ev)
		}
	}
	if ev := rg.chainLast(); ev.Kind != "router_halted" || ev.Reason != "state_store" {
		t.Errorf("последнее событие: %+v", ev)
	}
	st := rg.r.State()
	if !st.Halted || st.HaltReason != "state_store" || st.Endpoints["inceptron-fp8"] != "up" {
		t.Errorf("состояние в памяти: %+v", st)
	}
	rg.check("после отказа intent")
	// Счётчик неудач в памяти не должен опережать хранилище (там последнее успешное значение).
	rg.r.mu.Lock()
	mem := rg.r.failoverLocked().Primary.ReqFails
	rg.r.mu.Unlock()
	if stored := rg.fst.Snapshot().Failover.Primary.ReqFails; mem != stored {
		t.Errorf("счётчик неудач в памяти %d, в store %d", mem, stored)
	}

	rg.restart(nil)
	st = rg.r.State()
	if !st.Halted || st.HaltReason != "state_store" || st.Endpoints["inceptron-fp8"] != "up" {
		t.Errorf("после рестарта: %+v", st)
	}
	rg.check("после рестарта")
	assertMirrors(t, "после рестарта", rg.r, rg.fst.Snapshot())
}

// TestStoreFailureOnCommitThenRestart: событие записано, commit не записан — в памяти endpoint уже как в цепочке,
// рестарт разрешает intent по цепочке (commit), halt state_store восстанавливается, Resume переводит на fallback.
func TestStoreFailureOnCommitThenRestart(t *testing.T) {
	pc := newProviderCounts()
	tr := fakeProviders(pc, func() openrouter.Response { return openrouter.Response{Status: 503} })
	rg := newStateRig(t, &identityMasker{}, tr)
	rg.restart(failAt(routerstate.OpCommit))
	if _, err := rg.route("inc-1"); err != nil {
		t.Fatal(err)
	}
	if st := rg.r.State(); !st.Halted || st.HaltReason != "state_store" || st.Endpoints["inceptron-fp8"] != "down" || st.Active != "none" {
		t.Fatalf("после отказа commit: %+v", st)
	}
	rg.check("после отказа commit")

	rg.restart(nil)
	if st := rg.r.State(); !st.Halted || st.HaltReason != "state_store" || st.Endpoints["inceptron-fp8"] != "down" {
		t.Fatalf("после рестарта: %+v", st)
	}
	rg.check("после рестарта")
	if res, err := rg.route("inc-1"); err != nil || res.Reason != "halted" {
		t.Fatalf("до Resume: %v %+v", err, res)
	}
	if err := rg.r.Resume(context.Background(), "sre-1"); err != nil {
		t.Fatalf("Resume: %v", err)
	}
	if st := rg.r.State(); st.Halted || st.Active != "wafer-nvfp4" {
		t.Fatalf("после Resume: %+v", st)
	}
	rg.check("после Resume")
	assertMirrors(t, "после Resume", rg.r, rg.fst.Snapshot())
	if res, err := rg.route("inc-2"); err != nil || res.Role != RoleFallback {
		t.Errorf("после Resume: %v %+v", err, res)
	}
}

// TestAuditFailureAbortPersisted: сбой аудита при переходе — abort в store с halt audit_failed; рестарт
// восстанавливает halt, а состояние совпадает с памятью.
func TestAuditFailureAbortPersisted(t *testing.T) {
	pc := newProviderCounts()
	tr := fakeProviders(pc, func() openrouter.Response { return openrouter.Response{Status: 503} })
	rg := newStateRig(t, &identityMasker{}, tr)
	rg.sink.setFail("endpoint_down")
	if _, err := rg.route("inc-1"); !errors.Is(err, ErrAuditFailed) {
		t.Fatalf("ожидается ErrAuditFailed: %v", err)
	}
	if st := rg.r.State(); !st.Halted || st.HaltReason != "audit_failed" || st.Endpoints["inceptron-fp8"] != "up" {
		t.Fatalf("%+v", st)
	}
	rg.restart(nil)
	if st := rg.r.State(); !st.Halted || st.HaltReason != "audit_failed" || st.Endpoints["inceptron-fp8"] != "up" {
		t.Fatalf("после рестарта: %+v", st)
	}
	assertMirrors(t, "после рестарта", rg.r, rg.fst.Snapshot())
	before := pc.get("inceptron")
	if res, err := rg.route("inc-1"); err != nil || res.Reason != "halted" {
		t.Fatalf("%v %+v", err, res)
	}
	if n := pc.get("inceptron") - before; n != 0 {
		t.Errorf("при halt ушло %d запросов", n)
	}
}

// TestFreshStoreWithChainHistoryHalts: пустое хранилище при непустой цепочке — halt state_lost до Resume;
// пустая цепочка и пустое хранилище — без halt.
func TestFreshStoreWithChainHistoryHalts(t *testing.T) {
	t.Run("пустая цепочка — без halt", func(t *testing.T) {
		rg := newStateRig(t, &identityMasker{}, fakeProviders(newProviderCounts(), nil))
		if st := rg.r.State(); st.Halted {
			t.Fatalf("%+v", st)
		}
	})

	t.Run("пустое хранилище при непустой цепочке", func(t *testing.T) {
		pc := newProviderCounts()
		tr := fakeProviders(pc, func() openrouter.Response { return openrouter.Response{Status: 503} })
		rg := newStateRig(t, &identityMasker{}, tr)
		if _, err := rg.route("inc-1"); err != nil {
			t.Fatal(err)
		}
		rg.closeAll()
		if err := os.Remove(rg.statePath); err != nil {
			t.Fatal(err)
		}
		rg.boot()
		if st := rg.r.State(); !st.Halted || st.HaltReason != "state_lost" {
			t.Fatalf("после удаления хранилища: %+v", st)
		}
		if ev := rg.chainLast(); ev.Kind != "router_halted" || ev.Reason != "state_lost" {
			t.Errorf("в цепочке последнее событие %+v, ожидается router_halted(state_lost)", ev)
		}
		before := pc.get("inceptron")
		if res, err := rg.route("inc-2"); err != nil || res.Reason != "halted" || !res.DegradeL1 {
			t.Fatalf("%v %+v", err, res)
		}
		if n := pc.get("inceptron") - before; n != 0 {
			t.Errorf("при state_lost ушло %d запросов", n)
		}
		if err := rg.r.Resume(context.Background(), "sre-1"); err != nil {
			t.Fatalf("Resume: %v", err)
		}
		if st := rg.r.State(); st.Halted {
			t.Fatalf("после Resume: %+v", st)
		}
		// После state_lost состояние endpoint'ов восстановлено из событий цепочки (primary down, активен fallback),
		// и совпадает с цепочкой сразу после Resume, до первого запроса.
		if st := rg.r.State(); st.Endpoints[reviewPrimary] != "down" || st.Active != reviewFallback {
			t.Errorf("после state_lost и Resume: %+v, ожидается primary down, активен fallback", st)
		}
		rg.check("сразу после Resume")
		if res, err := rg.route("inc-3"); err != nil || res.Outcome != "sent" {
			t.Errorf("после Resume: %v %+v", err, res)
		}
	})
}

// newRouterWithState собирает роутер на заданном хранилище состояния (для проверки отказов New).
func newRouterWithState(t *testing.T, a *openrouter.Assets, st routerstate.Store) (*Router, error) {
	t.Helper()
	cl, err := openrouter.NewClient(&a.Config, testKey(t, runtimeSecret(t)), fakeProviders(newProviderCounts(), nil),
		openrouter.WithSleep(func(context.Context, time.Duration) error { return nil }))
	if err != nil {
		t.Fatal(err)
	}
	return New(Options{Assets: a, Client: cl, Masker: &identityMasker{}, Events: newFakeEvents(t), Clock: newFakeClock(), State: st,
		Budgets: DefaultBudgets(), Failover: DefaultFailover(), RouterID: "llm-router-test"})
}

// newFakeEvents — приёмник событий в памяти для проверок конструктора.
func newFakeEvents(t *testing.T) EventSink {
	t.Helper()
	return &memSink{}
}

// TestCorruptStoreNoRouter: испорченное хранилище не открывается (ErrCorrupt); роутер с чужой identity не собирается.
func TestCorruptStoreNoRouter(t *testing.T) {
	a := loadAssets(t)
	p := filepath.Join(t.TempDir(), "state.jsonl")
	if err := os.WriteFile(p, []byte("не журнал\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := routerstate.OpenFile(p, testIdentity(a), routerstate.FileOptions{}); !errors.Is(err, routerstate.ErrCorrupt) {
		t.Fatalf("испорченный журнал: ожидается ErrCorrupt: %v", err)
	}
	other := routerstate.NewMemory(routerstate.Identity{RouterID: "other-router", Primary: a.Primary.Name, Fallback: a.Fallback.Name})
	if _, err := newRouterWithState(t, a, other); !errors.Is(err, routerstate.ErrIdentity) {
		t.Fatalf("чужая identity: ожидается ErrIdentity: %v", err)
	}
}

// TestConcurrentRoutesFileStore: параллельные Route и CheckHealth (-race): сумма расхода в цепочке совпадает с
// хранилищем и памятью, резервы закрыты, после рестарта то же значение.
func TestConcurrentRoutesFileStore(t *testing.T) {
	ctx := context.Background()
	var mu sync.Mutex
	n := 0
	tr := fakeProviders(newProviderCounts(), nil)
	tr.post = func(b []byte) (openrouter.Response, error) {
		if providerOf(b) != "inceptron" {
			return reply("Wafer", 100, 50), nil
		}
		mu.Lock()
		n++
		k := n
		mu.Unlock()
		if k%2 == 0 {
			return openrouter.Response{Status: 503}, nil
		}
		return reply("Inceptron", 100, 50), nil
	}
	rg := newStateRig(t, &identityMasker{}, tr)
	prime, err := rg.route("inc-prime")
	if err != nil || prime.Outcome != "sent" {
		t.Fatalf("%v %+v", err, prime)
	}
	est := int64(prime.Prepared.EstInputTokens + prime.Prepared.MaxTokens)
	limit := 6 * est
	rg.r.bud.cfg.ServiceDayTokens = limit

	var (
		tmu   sync.Mutex
		total = prime.Tokens
		wg    sync.WaitGroup
		stop  = make(chan struct{})
		hdone = make(chan struct{})
	)
	go func() {
		defer close(hdone)
		for {
			select {
			case <-stop:
				return
			default:
				if err := rg.r.CheckHealth(ctx); err != nil {
					t.Error(err)
				}
				time.Sleep(time.Millisecond)
			}
		}
	}()
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			res, err := rg.route(fmt.Sprint("inc-", i))
			if err != nil {
				t.Error(err)
				return
			}
			tmu.Lock()
			total += res.Tokens
			tmu.Unlock()
		}(i)
	}
	wg.Wait()
	close(stop)
	<-hdone

	if total > limit {
		t.Errorf("расход %d превысил лимит сервиса %d", total, limit)
	}
	if got := rg.fst.Snapshot().Days["geo-svc"].Spent; got != total {
		t.Errorf("расход в store %d, по результатам Route %d", got, total)
	}
	assertMirrors(t, "после параллельной работы", rg.r, rg.fst.Snapshot())
	rg.restart(nil)
	if got := rg.fst.Snapshot().Days["geo-svc"].Spent; got != total {
		t.Errorf("после рестарта расход %d, ожидается %d", got, total)
	}
	assertMirrors(t, "после рестарта", rg.r, rg.fst.Snapshot())
}

// TestMemoryMatchesStore: память и хранилище (MemStore) совпадают после последовательности переходов, закреплений,
// закрытия инцидента и остановки. Ловит расхождение двух реализаций применения операций.
func TestMemoryMatchesStore(t *testing.T) {
	ctx := context.Background()
	var mu sync.Mutex
	primaryMode := 503
	tr := fakeProviders(newProviderCounts(), func() openrouter.Response {
		mu.Lock()
		defer mu.Unlock()
		if primaryMode == 200 {
			return reply("Inceptron", 100, 50)
		}
		return openrouter.Response{Status: primaryMode}
	})
	tr.get = func() (openrouter.Response, error) {
		return openrouter.Response{Status: 200, Body: []byte(stateHealthBody)}, nil
	}
	rg := newRig(t, &identityMasker{}, tr, "", nil)
	mirror := func(label string) { t.Helper(); assertMirrors(t, label, rg.r, rg.st.Snapshot()) }

	if res, err := rg.r.Route(ctx, withIncident(t, "inc-1")); err != nil || res.Role != RoleFallback {
		t.Fatalf("%v %+v", err, res)
	}
	mirror("после перехода на fallback")
	if _, err := rg.r.Route(ctx, withIncident(t, "inc-2")); err != nil {
		t.Fatal(err)
	}
	mirror("после второго инцидента")

	mu.Lock()
	primaryMode = 200
	mu.Unlock()
	if err := rg.r.CheckHealth(ctx); err != nil {
		t.Fatal(err)
	}
	rg.clock.Advance(10 * time.Minute)
	if err := rg.r.CheckHealth(ctx); err != nil {
		t.Fatal(err)
	}
	mirror("после возврата primary")

	if res, err := rg.r.Route(ctx, withIncident(t, "inc-3")); err != nil || res.Role != RolePrimary {
		t.Fatalf("%v %+v", err, res)
	}
	mirror("после маршрута на primary")
	if err := rg.r.CloseIncident("inc-1"); err != nil {
		t.Fatal(err)
	}
	mirror("после закрытия инцидента")

	mu.Lock()
	primaryMode = 401
	mu.Unlock()
	if _, err := rg.r.Route(ctx, withIncident(t, "inc-4")); err != nil {
		t.Fatal(err)
	}
	mirror("после остановки по auth")
	if err := rg.r.Resume(ctx, "sre-1"); err != nil {
		t.Fatal(err)
	}
	mirror("после Resume")
}

func withIncident(t *testing.T, id string) Request {
	req := routeReq(t)
	req.IncidentID = id
	return req
}

// TestSettleAfterCloseIncidentMirrorsStore: инцидент закрыт, пока по нему летит запрос, и открыт снова. Расход
// запроса, завершившегося после закрытия, в памяти и в store должен попасть в один и тот же счёт.
func TestSettleAfterCloseIncidentMirrorsStore(t *testing.T) {
	ctx := context.Background()
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	var mu sync.Mutex
	blockNext := true
	tr := fakeProviders(newProviderCounts(), nil)
	tr.post = func(b []byte) (openrouter.Response, error) {
		if providerOf(b) == "inceptron" {
			mu.Lock()
			blk := blockNext
			blockNext = false
			mu.Unlock()
			if blk {
				entered <- struct{}{}
				<-release
			}
		}
		return reply("Inceptron", 100, 50), nil
	}
	rg := newRig(t, &identityMasker{}, tr, "", nil)
	reqA, reqB := withIncident(t, "inc-1"), withIncident(t, "inc-1")
	done := make(chan *Result, 1)
	go func() {
		res, _ := rg.r.Route(ctx, reqA)
		done <- res
	}()
	<-entered
	if err := rg.r.CloseIncident("inc-1"); err != nil {
		t.Fatal(err)
	}
	if res, err := rg.r.Route(ctx, reqB); err != nil || res.Outcome != "sent" {
		t.Fatalf("%v %+v", err, res)
	}
	close(release)
	<-done
	assertMirrors(t, "после закрытия инцидента с запросом в полёте", rg.r, rg.st.Snapshot())
}

// TestBudgetDayBoundaryUTC: сутки бюджета — UTC. Смена суток по UTC обнуляет счёт, рестарт между шагами ничего
// не меняет, часы назад не сбрасывают счёт.
func TestBudgetDayBoundaryUTC(t *testing.T) {
	msk := time.FixedZone("MSK", 3*3600)
	tr := fakeProviders(newProviderCounts(), nil)
	rg := newStateRig(t, &identityMasker{}, tr)
	rg.clock.t = time.Date(2026, 11, 8, 2, 30, 0, 0, msk) // 2026-11-07 23:30 UTC
	day := func() routerstate.Day { return rg.fst.Snapshot().Days["geo-svc"] }

	if res, err := rg.route("inc-1"); err != nil || res.Outcome != "sent" {
		t.Fatalf("%v %+v", err, res)
	}
	if d := day(); d.Day != "2026-11-07" || d.Spent != 150 {
		t.Fatalf("после первого запроса: %+v", d)
	}
	rg.restart(nil)
	if d := day(); d.Day != "2026-11-07" || d.Spent != 150 {
		t.Fatalf("после рестарта: %+v", d)
	}
	rg.clock.Advance(40 * time.Minute) // 00:10 UTC 2026-11-08
	if res, err := rg.route("inc-1"); err != nil || res.Outcome != "sent" {
		t.Fatalf("%v %+v", err, res)
	}
	if d := day(); d.Day != "2026-11-08" || d.Spent != 150 {
		t.Fatalf("смена суток UTC: %+v, ожидается 2026-11-08 со счётом 150", d)
	}
	rg.clock.Advance(-2 * time.Hour) // часы ушли назад: 22:10 UTC 2026-11-07
	if res, err := rg.route("inc-1"); err != nil || res.Outcome != "sent" {
		t.Fatalf("%v %+v", err, res)
	}
	if d := day(); d.Day != "2026-11-08" || d.Spent != 300 {
		t.Fatalf("часы назад сбросили счёт: %+v", d)
	}
	rg.restart(nil)
	assertMirrors(t, "после рестарта", rg.r, rg.fst.Snapshot())
}

// TestStoreHasNoKey: ключ API не попадает ни в журнал состояния, ни в цепочку аудита.
func TestStoreHasNoKey(t *testing.T) {
	pc := newProviderCounts()
	tr := fakeProviders(pc, func() openrouter.Response { return openrouter.Response{Status: 503} })
	rg := newStateRig(t, &identityMasker{}, tr)
	if _, err := rg.route("inc-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := rg.route("inc-2"); err != nil {
		t.Fatal(err)
	}
	rg.closeAll()
	for _, p := range []string{rg.statePath, rg.chain} {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) == 0 {
			t.Fatalf("%s пуст: проверка без данных", p)
		}
		if bytes.Contains(raw, []byte(rg.secret)) {
			t.Errorf("ключ найден в %s", p)
		}
	}
}
