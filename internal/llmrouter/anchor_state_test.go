package llmrouter

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/limpjungle/aegis3311/internal/audit"
	"github.com/limpjungle/aegis3311/internal/openrouter"
	"github.com/limpjungle/aegis3311/internal/routerstate"
)

// Проверка после итерации 2: якорь state_created (крах до и после записи, сбой аудита на якоре, отказ intent),
// первый старт на цепочке из одних decision record, оборванные router_halted и router_resumed без события,
// сбой pin вместе с сбоем аудита, границы расхода в бюджете, отказ store с ErrInvalidOp.

// bareStateRig — как newStateRig, но без первого запуска роутера: цепочка и хранилище пусты.
func bareStateRig(t *testing.T, tr *stubTransport) *stateRig {
	t.Helper()
	dir := t.TempDir()
	signer, keys := newAuditSigner(t)
	if tr.get == nil {
		tr.get = func() (openrouter.Response, error) {
			return openrouter.Response{Status: 200, Body: []byte(stateHealthBody)}, nil
		}
	}
	rg := &stateRig{t: t, a: loadAssets(t), m: &identityMasker{}, tr: tr, secret: runtimeSecret(t), clock: newFakeClock(),
		chain: filepath.Join(dir, "chain.jsonl"), statePath: filepath.Join(dir, "state.jsonl"), signer: signer, keys: keys,
		budgets: BudgetConfig{IncidentTokens: 1 << 40, ServiceDayTokens: 1 << 40}}
	t.Cleanup(rg.closeAll)
	return rg
}

// tryBoot открывает цепочку и хранилище и собирает роутер. Ошибка New возвращается (не фатальна); hit — крах (panic)
// внутри New. При успехе rg.r — новый роутер.
func (rg *stateRig) tryBoot(sink func(*flakySink) EventSink, wrap func(routerstate.Store) routerstate.Store) (error, bool) {
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
	rg.w, rg.fst = w, fst
	rg.sink = &flakySink{w: w}
	var st routerstate.Store = fst
	if wrap != nil {
		st = wrap(fst)
	}
	cl, err := openrouter.NewClient(&rg.a.Config, testKey(t, rg.secret), rg.tr, openrouter.WithSleep(func(context.Context, time.Duration) error { return nil }))
	if err != nil {
		t.Fatal(err)
	}
	var events EventSink = rg.sink
	if sink != nil {
		events = sink(rg.sink)
	}
	opts := Options{Assets: rg.a, Client: cl, Masker: rg.m, Events: events, Clock: rg.clock, State: st,
		Budgets: rg.budgets, Failover: DefaultFailover(), RouterID: "llm-router-test"}
	var (
		r    *Router
		err2 error
	)
	hit := crashed(func() { r, err2 = New(opts) })
	if err2 == nil && !hit {
		rg.r = r
	}
	return err2, hit
}

// chainKinds — виды всех событий роутера в цепочке (включая якорь) в порядке записи. Цепочка проверяется целиком.
func chainKinds(t *testing.T, chain string, keys audit.Keyring) []string {
	t.Helper()
	f, err := os.Open(chain)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var kinds []string
	if _, err := audit.Verify(f, keys, audit.VerifyOptions{OnRouterEvent: func(_ uint64, ev *audit.RouterEvent) {
		kinds = append(kinds, ev.Kind+":"+ev.Reason)
	}}); err != nil {
		t.Fatalf("цепочка не проходит проверку: %v", err)
	}
	return kinds
}

// TestAnchorCrashBeforeEvent: крах до записи якоря. В store остаётся intent state_created, цепочка пуста. Рестарт
// дописывает якорь с тем же event_id и фиксирует переход; якорь ровно один.
func TestAnchorCrashBeforeEvent(t *testing.T) {
	rg := bareStateRig(t, fakeProviders(newProviderCounts(), nil))
	err, hit := rg.tryBoot(func(s *flakySink) EventSink { return &crashSink{inner: s, kind: "state_created"} }, nil)
	if err != nil || !hit {
		t.Fatalf("крах на якоре не произошёл: err=%v hit=%v", err, hit)
	}
	if p := rg.fst.Snapshot().Pending; p == nil || p.EventKind != "state_created" {
		t.Fatalf("после краха ожидается pending state_created, есть %+v", p)
	}
	if rg.w.ChainNonEmpty() {
		t.Fatal("якорь попал в цепочку до краха")
	}
	rg.closeAll()
	rg.boot()
	if p := rg.fst.Snapshot().Pending; p != nil {
		t.Errorf("intent не разрешён после рестарта: %+v", p)
	}
	if st := rg.r.State(); st.Halted || st.Active != reviewPrimary {
		t.Errorf("после рестарта: %+v", st)
	}
	if got := chainKinds(t, rg.chain, rg.keys); !reflect.DeepEqual(got, []string{"state_created:store_created"}) {
		t.Errorf("события роутера в цепочке: %v, ожидается один якорь", got)
	}
	rg.check("после рестарта")
	assertMirrors(t, "после рестарта", rg.r, rg.fst.Snapshot())
}

// TestAnchorCrashAfterEvent: крах после записи якоря и до commit. Рестарт видит событие по event_id и делает commit;
// второго якоря нет.
func TestAnchorCrashAfterEvent(t *testing.T) {
	rg := bareStateRig(t, fakeProviders(newProviderCounts(), nil))
	err, hit := rg.tryBoot(func(s *flakySink) EventSink { return &crashSink{inner: s, kind: "state_created", after: true} }, nil)
	if err != nil || !hit {
		t.Fatalf("крах после якоря не произошёл: err=%v hit=%v", err, hit)
	}
	if p := rg.fst.Snapshot().Pending; p == nil || p.EventKind != "state_created" {
		t.Fatalf("после краха ожидается pending state_created, есть %+v", p)
	}
	rg.closeAll()
	rg.boot()
	if p := rg.fst.Snapshot().Pending; p != nil {
		t.Errorf("intent не разрешён после рестарта: %+v", p)
	}
	if st := rg.r.State(); st.Halted || st.Active != reviewPrimary {
		t.Errorf("после рестарта: %+v", st)
	}
	if got := chainKinds(t, rg.chain, rg.keys); !reflect.DeepEqual(got, []string{"state_created:store_created"}) {
		t.Errorf("события роутера в цепочке: %v, ожидается один якорь (повторной записи быть не должно)", got)
	}
	rg.check("после рестарта")
	assertMirrors(t, "после рестарта", rg.r, rg.fst.Snapshot())
}

// TestAnchorAuditFailureReturnsError: сбой записи якоря — New возвращает ErrAuditFailed, store откатывается к
// состоянию до якоря (не halted, без intent). Рестарт с исправным аудитом записывает якорь.
func TestAnchorAuditFailureReturnsError(t *testing.T) {
	rg := bareStateRig(t, fakeProviders(newProviderCounts(), nil))
	err, hit := rg.tryBoot(func(s *flakySink) EventSink { s.setFail("state_created"); return s }, nil)
	if hit || !errors.Is(err, ErrAuditFailed) {
		t.Fatalf("сбой записи якоря: hit=%v err=%v, ожидается ErrAuditFailed", hit, err)
	}
	if s := rg.fst.Snapshot(); s.Pending != nil || s.Failover.Halted {
		t.Errorf("после сбоя якоря в store: pending %+v, halt %v; ожидается откат к состоянию до якоря", s.Pending, s.Failover.Halted)
	}
	rg.closeAll()
	rg.boot()
	if st := rg.r.State(); st.Halted {
		t.Errorf("после рестарта с исправным аудитом роутер остановлен: %+v", st)
	}
	if got := chainKinds(t, rg.chain, rg.keys); !reflect.DeepEqual(got, []string{"state_created:store_created"}) {
		t.Errorf("события роутера в цепочке: %v, ожидается один якорь", got)
	}
}

// TestAnchorIntentStoreFailureFailsClosed: отказ записи intent якоря — New возвращает ErrStateStore; роутер не
// создан, запросов нет. Рестарт на исправном store: роутер остановлен (halt, запросы не уходят).
func TestAnchorIntentStoreFailureFailsClosed(t *testing.T) {
	pc := newProviderCounts()
	rg := bareStateRig(t, fakeProviders(pc, nil))
	err, hit := rg.tryBoot(nil, failAt(routerstate.OpIntent))
	if hit || !errors.Is(err, ErrStateStore) {
		t.Fatalf("отказ intent якоря: hit=%v err=%v, ожидается ErrStateStore", hit, err)
	}
	if got := chainKinds(t, rg.chain, rg.keys); !reflect.DeepEqual(got, []string{"router_halted:state_store"}) {
		t.Errorf("события в цепочке: %v, ожидается router_halted(state_store)", got)
	}
	rg.closeAll()
	rg.boot()
	if st := rg.r.State(); !st.Halted {
		t.Fatalf("после рестарта роутер не остановлен: %+v", st)
	}
	if res, err := rg.route("inc-1"); err != nil || res.Reason != "halted" {
		t.Errorf("запрос после рестарта: %v %+v", err, res)
	}
	if n := pc.get("inceptron") + pc.get("wafer"); n != 0 {
		t.Errorf("запросов ушло %d, ожидается 0", n)
	}
}

// TestFirstStartOnDecisionOnlyChainHalts: первый старт на цепочке, где есть только decision record (ни якоря, ни
// событий роутера), при новом хранилище — halt state_lost до Resume (решение К1: непустая цепочка).
func TestFirstStartOnDecisionOnlyChainHalts(t *testing.T) {
	src := newStateRig(t, &identityMasker{}, fakeProviders(newProviderCounts(), nil))
	res, err := src.route("inc-1")
	if err != nil || res.Outcome != "sent" {
		t.Fatalf("подготовка: %v %+v", err, res)
	}
	rg := bareStateRig(t, fakeProviders(newProviderCounts(), nil))
	w, err := audit.OpenWriter(rg.chain, "router-test", rg.signer, rg.keys)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(decisionRecord(res)); err != nil {
		t.Fatalf("decision record: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	rg.boot()
	if st := rg.r.State(); !st.Halted || st.HaltReason != "state_lost" {
		t.Fatalf("первый старт на цепочке из одних decision record: %+v, ожидается state_lost", st)
	}
	if got := chainKinds(t, rg.chain, rg.keys); !reflect.DeepEqual(got, []string{"router_halted:state_lost"}) {
		t.Errorf("события роутера: %v, ожидается router_halted(state_lost)", got)
	}
	if res, err := rg.route("inc-2"); err != nil || res.Reason != "halted" || !res.DegradeL1 {
		t.Errorf("запрос при state_lost: %v %+v", err, res)
	}
}

// crashOnHalt готовит оборванный переход router_halted(wantReason): роутер на tr пишет halt, но крах происходит на
// записи события, так что в store остаётся intent без события. Возвращает rg, закрытый после краха.
func crashOnHalt(t *testing.T, tr *stubTransport, wantReason string) *stateRig {
	t.Helper()
	rg := newStateRig(t, &identityMasker{}, tr)
	rg.closeAll()
	if rg.crashBoot(func(s *flakySink) EventSink { return &crashSink{inner: s, kind: "router_halted"} }) {
		t.Fatal("крах при старте не ожидался")
	}
	if !rg.reviewRoute("inc-1") {
		t.Fatal("крах на router_halted не произошёл")
	}
	p := rg.fst.Snapshot().Pending
	if p == nil || p.EventKind != "router_halted" || p.Next.HaltReason != wantReason {
		t.Fatalf("после краха ожидается pending router_halted(%s), есть %+v", wantReason, p)
	}
	rg.closeAll()
	return rg
}

// TestPendingHaltWithoutEvent: intent router_halted остался в store без события (крах). Рестарт дописывает событие
// с той же причиной и фиксирует halt; сбой записи события на этом пути — New возвращает ошибку, intent остаётся.
func TestPendingHaltWithoutEvent(t *testing.T) {
	t.Run("auth", func(t *testing.T) {
		pc := newProviderCounts()
		tr := fakeProviders(pc, func() openrouter.Response { return openrouter.Response{Status: 401} })
		rg := crashOnHalt(t, tr, "auth")
		rg.boot()
		if st := rg.r.State(); !st.Halted || st.HaltReason != "auth" {
			t.Fatalf("после рестарта: %+v, ожидается halt auth", st)
		}
		if p := rg.fst.Snapshot().Pending; p != nil {
			t.Errorf("intent не разрешён: %+v", p)
		}
		if got := chainKinds(t, rg.chain, rg.keys); !reflect.DeepEqual(got, []string{"state_created:store_created", "router_halted:auth"}) {
			t.Errorf("события: %v", got)
		}
		rg.check("после рестарта")
		before := pc.get("inceptron")
		if res, err := rg.route("inc-2"); err != nil || res.Reason != "halted" {
			t.Errorf("%v %+v", err, res)
		}
		if n := pc.get("inceptron") - before; n != 0 {
			t.Errorf("при halt ушло %d запросов", n)
		}
	})

	t.Run("estimator", func(t *testing.T) {
		ceiling := loadAssets(t).Config.ContextCeiling
		tr := fakeProviders(newProviderCounts(), func() openrouter.Response { return reply("Inceptron", ceiling, 1) })
		rg := crashOnHalt(t, tr, "estimator")
		rg.boot()
		if st := rg.r.State(); !st.Halted || st.HaltReason != "estimator" {
			t.Fatalf("после рестарта: %+v, ожидается halt estimator", st)
		}
		if got := chainKinds(t, rg.chain, rg.keys); !reflect.DeepEqual(got, []string{"state_created:store_created", "router_halted:estimator"}) {
			t.Errorf("события: %v", got)
		}
		rg.check("после рестарта")
	})

	t.Run("сбой записи события при восстановлении", func(t *testing.T) {
		tr := fakeProviders(newProviderCounts(), func() openrouter.Response { return openrouter.Response{Status: 401} })
		rg := crashOnHalt(t, tr, "auth")
		err, hit := rg.tryBoot(func(s *flakySink) EventSink { s.setFail("router_halted"); return s }, nil)
		if hit || !errors.Is(err, ErrAuditFailed) {
			t.Fatalf("восстановление при сбое аудита: hit=%v err=%v, ожидается ErrAuditFailed", hit, err)
		}
		if p := rg.fst.Snapshot().Pending; p == nil || p.Next.HaltReason != "auth" {
			t.Fatalf("intent должен остаться в store: %+v", p)
		}
		rg.closeAll()
		rg.boot()
		if st := rg.r.State(); !st.Halted || st.HaltReason != "auth" {
			t.Fatalf("после исправного рестарта: %+v", st)
		}
		if got := chainKinds(t, rg.chain, rg.keys); !reflect.DeepEqual(got, []string{"state_created:store_created", "router_halted:auth"}) {
			t.Errorf("события: %v, ожидается одно router_halted", got)
		}
	})
}

// TestPendingResumeWithoutEventKeepsHalt: крах в Resume до записи router_resumed. Intent снимается abort'ом, halt
// остаётся на месте (как до Resume).
func TestPendingResumeWithoutEventKeepsHalt(t *testing.T) {
	ctx := context.Background()
	tr := fakeProviders(newProviderCounts(), func() openrouter.Response { return openrouter.Response{Status: 401} })
	rg := newStateRig(t, &identityMasker{}, tr)
	if _, err := rg.route("inc-1"); err != nil {
		t.Fatal(err)
	}
	if st := rg.r.State(); !st.Halted || st.HaltReason != "auth" {
		t.Fatalf("подготовка: %+v", st)
	}
	rg.closeAll()
	if rg.crashBoot(func(s *flakySink) EventSink { return &crashSink{inner: s, kind: "router_resumed"} }) {
		t.Fatal("крах при старте не ожидался")
	}
	if !crashed(func() { _ = rg.r.Resume(ctx, "sre-1") }) {
		t.Fatal("крах на router_resumed не произошёл")
	}
	if p := rg.fst.Snapshot().Pending; p == nil || p.EventKind != "router_resumed" || p.Next.Halted {
		t.Fatalf("pending после краха при Resume: %+v", p)
	}
	rg.closeAll()
	rg.boot()
	if st := rg.r.State(); !st.Halted || st.HaltReason != "auth" {
		t.Errorf("после краха при Resume: %+v, ожидается halt auth без снятия", st)
	}
	if p := rg.fst.Snapshot().Pending; p != nil {
		t.Errorf("intent не снят: %+v", p)
	}
	if got := chainKinds(t, rg.chain, rg.keys); !reflect.DeepEqual(got, []string{"state_created:store_created", "router_halted:auth"}) {
		t.Errorf("события: %v, router_resumed быть не должно", got)
	}
	rg.check("после рестарта")
}

// TestPinStoreFailureAndAuditFailureReturnsErr: отказ записи закрепления (store) и сбой аудита одновременно. Контракт
// Route: сбой аудита возвращается ошибкой ErrAuditFailed, результат не формируется как обычный not_sent.
func TestPinStoreFailureAndAuditFailureReturnsErr(t *testing.T) {
	rg := newStateRig(t, &identityMasker{}, fakeProviders(newProviderCounts(), nil))
	rg.restart(failAt(routerstate.OpPin))
	rg.sink.setFail("router_halted")
	res, err := rg.route("inc-1")
	if !errors.Is(err, ErrAuditFailed) {
		t.Fatalf("Route: err=%v res=%+v; ожидается ErrAuditFailed (router_halted не записан в аудит)", err, res)
	}
	if st := rg.r.State(); !st.Halted || st.HaltReason != "audit_failed" {
		t.Errorf("состояние: %+v, ожидается halt audit_failed", st)
	}
}

// TestRejectedOpFromStoreNotHalted: store отклоняет резерв с ErrInvalidOp (store исправен). Роутер не останавливается,
// запрос не уходит, результат — не отправлено.
func TestRejectedOpFromStoreNotHalted(t *testing.T) {
	pc := newProviderCounts()
	rg := newStateRig(t, &identityMasker{}, fakeProviders(pc, nil))
	rg.restart(func(s routerstate.Store) routerstate.Store {
		return &rejectStore{Store: s, kind: routerstate.OpReserve}
	})
	res, err := rg.route("inc-1")
	if !errors.Is(err, routerstate.ErrInvalidOp) {
		t.Fatalf("ожидается ErrInvalidOp: err=%v res=%+v", err, res)
	}
	if st := rg.r.State(); st.Halted {
		t.Errorf("ErrInvalidOp остановил роутер: %+v (store исправен)", st)
	}
	if n := pc.get("inceptron") + pc.get("wafer"); n != 0 {
		t.Errorf("запрос ушёл при отказе резерва: %d", n)
	}
	if res != nil && res.Outcome == "sent" {
		t.Errorf("Outcome %q при нулевых попытках и ошибке; запрос не отправлен, ожидается not_sent или nil-результат (как partial)", res.Outcome)
	}
}

// rejectStore — хранилище, которое отклоняет операции вида kind с ErrInvalidOp, не выходя из строя.
type rejectStore struct {
	routerstate.Store
	kind routerstate.OpKind
}

func (s *rejectStore) Append(op routerstate.Op) error {
	if op.Kind == s.kind {
		return routerstate.ErrInvalidOp
	}
	return s.Store.Append(op)
}

// TestSettleUsageBounds: расход в бюджете. Отрицательный расход списывает весь резерв (в памяти и в store).
// Верхняя граница не зажимается: фактический расход выше резерва учитывается полностью (принятое решение).
func TestSettleUsageBounds(t *testing.T) {
	id := routerstate.Identity{RouterID: "llm-router-test", Primary: "p", Fallback: "f"}
	st := routerstate.NewMemory(id)
	b := newBudgets(BudgetConfig{IncidentTokens: 1 << 40, ServiceDayTokens: 1 << 40}, st, routerstate.NewState(id))
	now := func() time.Time { return time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC) }
	p := b.forIncident("inc-1", "svc-1", now)

	h, ok := p.Reserve(300, 0)
	if !ok {
		t.Fatal("резерв отклонён")
	}
	p.Settle(h, -5, 0)
	if got := st.Snapshot().Incidents["inc-1"]; got != 300 {
		t.Errorf("отрицательный расход: счёт инцидента в store %d, ожидается весь резерв 300", got)
	}
	if got := st.Snapshot().Days["svc-1"].Spent; got != 300 {
		t.Errorf("отрицательный расход: сервис в store %d, ожидается 300", got)
	}

	h, ok = p.Reserve(100, 0)
	if !ok {
		t.Fatal("второй резерв отклонён")
	}
	p.Settle(h, 500, 0)
	if got := st.Snapshot().Incidents["inc-1"]; got != 800 {
		t.Errorf("расход выше резерва: счёт в store %d, ожидается 800 (фактический расход)", got)
	}
	b.mu.Lock()
	memInc := b.incidents["inc-1"].spent
	memHeld := b.incidents["inc-1"].held
	b.mu.Unlock()
	if memInc != 800 || memHeld != 0 {
		t.Errorf("память: spent %d held %d, ожидается 800 и 0", memInc, memHeld)
	}
	if err := p.storeFailed(); err != nil {
		t.Errorf("ошибка store без отказа: %v", err)
	}
}

// TestPendingResumeAfterEventCommits: крах после записи router_resumed и до commit. Рестарт видит событие по event_id,
// делает commit: halt снят, одно событие resume в цепочке.
func TestPendingResumeAfterEventCommits(t *testing.T) {
	ctx := context.Background()
	tr := fakeProviders(newProviderCounts(), func() openrouter.Response { return openrouter.Response{Status: 401} })
	rg := newStateRig(t, &identityMasker{}, tr)
	if _, err := rg.route("inc-1"); err != nil {
		t.Fatal(err)
	}
	rg.closeAll()
	if rg.crashBoot(func(s *flakySink) EventSink { return &crashSink{inner: s, kind: "router_resumed", after: true} }) {
		t.Fatal("крах при старте не ожидался")
	}
	if !crashed(func() { _ = rg.r.Resume(ctx, "sre-1") }) {
		t.Fatal("крах после router_resumed не произошёл")
	}
	if p := rg.fst.Snapshot().Pending; p == nil || p.EventKind != "router_resumed" {
		t.Fatalf("pending после краха: %+v", p)
	}
	rg.closeAll()
	rg.boot()
	if st := rg.r.State(); st.Halted {
		t.Errorf("событие resume в цепочке есть, но halt не снят: %+v", st)
	}
	if p := rg.fst.Snapshot().Pending; p != nil {
		t.Errorf("intent не разрешён: %+v", p)
	}
	if got := chainKinds(t, rg.chain, rg.keys); !reflect.DeepEqual(got, []string{"state_created:store_created", "router_halted:auth", "router_resumed:operator_resume"}) {
		t.Errorf("события: %v", got)
	}
	rg.check("после рестарта")
	assertMirrors(t, "после рестарта", rg.r, rg.fst.Snapshot())
}

// TestSwitchStoreFailureAndAuditFailureReturnsErr: инцидент закреплён за primary; primary отказывает, и при переключении
// на fallback запись закрепления в store падает вместе с аудитом. Контракт Route: ErrAuditFailed, а не обычный результат.
func TestSwitchStoreFailureAndAuditFailureReturnsErr(t *testing.T) {
	primaryOK := true
	tr := fakeProviders(newProviderCounts(), func() openrouter.Response {
		if primaryOK {
			return reply("Inceptron", 100, 50)
		}
		return openrouter.Response{Status: 503}
	})
	rg := newStateRig(t, &identityMasker{}, tr)
	if res, err := rg.route("inc-1"); err != nil || res.Role != RolePrimary {
		t.Fatalf("подготовка: %v %+v", err, res)
	}
	primaryOK = false
	rg.restart(failAt(routerstate.OpPin))
	rg.sink.setFail("router_halted")
	res, err := rg.route("inc-1")
	if !errors.Is(err, ErrAuditFailed) {
		t.Fatalf("Route: err=%v res=%+v; ожидается ErrAuditFailed (переключение: router_halted не записан)", err, res)
	}
}
