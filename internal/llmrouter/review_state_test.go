package llmrouter

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/limpjungle/aegis3311/internal/audit"
	"github.com/limpjungle/aegis3311/internal/openrouter"
	"github.com/limpjungle/aegis3311/internal/routerstate"
)

// Тесты проверки после итерации 1: окно краха при state_lost, обход бюджета удалением store без событий роутера,
// восстановление failover по событиям при state_lost, крах между endpoint_down и active_changed.

const (
	reviewPrimary  = "inceptron-fp8"
	reviewFallback = "wafer-nvfp4"
)

var errReviewCrash = errors.New("крах процесса (тест)")

// crashSink — приёмник событий, который имитирует крах процесса (panic) на событии вида kind: до записи события
// (after=false) или сразу после неё, до шага commit (after=true).
type crashSink struct {
	inner *flakySink
	kind  string
	after bool
}

func (c *crashSink) AppendEvent(ev *audit.RouterEvent) (audit.Entry, error) {
	if ev.Kind == c.kind && !c.after {
		panic(errReviewCrash)
	}
	e, err := c.inner.AppendEvent(ev)
	if err == nil && ev.Kind == c.kind && c.after {
		panic(errReviewCrash)
	}
	return e, err
}

func (c *crashSink) HasEvent(id string) bool { return c.inner.HasEvent(id) }

func (c *crashSink) RouterEvents() []audit.RouterEvent { return c.inner.RouterEvents() }

func (c *crashSink) ChainNonEmpty() bool { return c.inner.ChainNonEmpty() }

func (c *crashSink) LastRouterEvent() (audit.RouterEvent, bool) { return c.inner.LastRouterEvent() }

// crashed выполняет f и возвращает true, если f «упал» panic'ом errReviewCrash. Другие panic'и пробрасываются.
func crashed(f func()) (hit bool) {
	defer func() {
		if p := recover(); p != nil {
			if p != errReviewCrash {
				panic(p)
			}
			hit = true
		}
	}()
	f()
	return false
}

// crashBoot открывает цепочку и хранилище и собирает роутер с приёмником sink (вместо rg.sink). Крах в New
// возвращается как hit=true; открытые файлы остаются в rg (их закрывает rg.closeAll).
func (rg *stateRig) crashBoot(sink func(*flakySink) EventSink) (hit bool) {
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
	cl, err := openrouter.NewClient(&rg.a.Config, testKey(t, rg.secret), rg.tr, openrouter.WithSleep(func(context.Context, time.Duration) error { return nil }))
	if err != nil {
		t.Fatal(err)
	}
	opts := Options{Assets: rg.a, Client: cl, Masker: rg.m, Events: sink(rg.sink), Clock: rg.clock, State: fst,
		Budgets: rg.budgets, Failover: DefaultFailover(), RouterID: "llm-router-test"}
	var r *Router
	hit = crashed(func() {
		var err error
		if r, err = New(opts); err != nil {
			t.Fatal(err)
		}
	})
	if !hit {
		rg.r = r
	}
	return hit
}

// reviewRoute вызывает Route; крах процесса возвращается как hit=true.
func (rg *stateRig) reviewRoute(incident string) (hit bool) {
	return crashed(func() {
		if _, err := rg.route(incident); err != nil {
			rg.t.Fatal(err)
		}
	})
}

// spentTotal — сумма расходов по суткам из хранилища.
func spentTotal(s *routerstate.State) int64 {
	var n int64
	for _, d := range s.Days {
		n += d.Spent
	}
	return n
}

// TestStateLostHaltSurvivesCrash: крах в окне между intent(router_halted, state_lost) и записью события.
// Store уже не пуст, поэтому при следующем старте state_lost повторно не выставляется, а intent снимается abort'ом.
// Ожидание: halt state_lost переживает крах (пока человек не сделает Resume).
func TestStateLostHaltSurvivesCrash(t *testing.T) {
	setup := func(t *testing.T) *stateRig {
		tr := fakeProviders(newProviderCounts(), func() openrouter.Response { return openrouter.Response{Status: 503} })
		rg := newStateRig(t, &identityMasker{}, tr)
		if _, err := rg.route("inc-1"); err != nil {
			t.Fatal(err)
		}
		if st := rg.r.State(); st.Endpoints[reviewPrimary] != "down" {
			t.Fatalf("подготовка: %+v", st)
		}
		rg.closeAll()
		if err := os.Remove(rg.statePath); err != nil {
			t.Fatal(err)
		}
		return rg
	}

	t.Run("крах после intent, до записи события", func(t *testing.T) {
		rg := setup(t)
		if !rg.crashBoot(func(s *flakySink) EventSink { return &crashSink{inner: s, kind: "router_halted"} }) {
			t.Fatal("крах не произошёл: окно не воспроизведено")
		}
		if p := rg.fst.Snapshot().Pending; p == nil || p.Next.HaltReason != "state_lost" {
			t.Fatalf("после краха в store ожидается pending intent state_lost, есть %+v", p)
		}
		rg.closeAll()
		rg.boot()
		if st := rg.r.State(); !st.Halted || st.HaltReason != "state_lost" {
			t.Errorf("после краха и рестарта: halt %v %q, ожидается state_lost (обход бюджета через rm + крах)", st.Halted, st.HaltReason)
		}
		if st := rg.r.State(); st.Endpoints[reviewPrimary] != "down" {
			t.Errorf("после краха и рестарта primary %q, по цепочке down (failover сброшен в up)", st.Endpoints[reviewPrimary])
		}
		if res, err := rg.route("inc-2"); err != nil || res.Outcome == "sent" {
			t.Errorf("запрос ушёл после рестарта без Resume: %v %+v", err, res)
		}
	})

	t.Run("крах после записи события, до commit", func(t *testing.T) {
		rg := setup(t)
		if !rg.crashBoot(func(s *flakySink) EventSink { return &crashSink{inner: s, kind: "router_halted", after: true} }) {
			t.Fatal("крах не произошёл: окно не воспроизведено")
		}
		rg.closeAll()
		rg.boot()
		if st := rg.r.State(); !st.Halted || st.HaltReason != "state_lost" || st.Endpoints[reviewPrimary] != "down" {
			t.Errorf("после краха после события: %+v", st)
		}
		rg.check("после краха после события")
		assertMirrors(t, "после краха после события", rg.r, rg.fst.Snapshot())
	})
}

// TestDeletedStoreAfterSpendHalts: удаление store после расхода бюджета при цепочке без событий роутера.
// Расход пишется только в store, а state_lost выставляется только при наличии событий роутера: удалённый store
// откатывает бюджет без halt. Ожидание: halt state_lost (цепочка не пуста — есть decision record).
func TestDeletedStoreAfterSpendHalts(t *testing.T) {
	t.Run("цепочка с decision record, без событий роутера", func(t *testing.T) {
		rg := newStateRig(t, &identityMasker{}, fakeProviders(newProviderCounts(), nil))
		res, err := rg.route("inc-1")
		if err != nil || res.Outcome != "sent" {
			t.Fatalf("подготовка: %v %+v", err, res)
		}
		if _, err := rg.w.Append(decisionRecord(res)); err != nil {
			t.Fatalf("decision record: %v", err)
		}
		if n := len(chainEvents(t, rg.chain)); n != 0 {
			t.Fatalf("подготовка: в цепочке событий роутера %d, ожидается 0", n)
		}
		if spent := spentTotal(rg.fst.Snapshot()); spent == 0 {
			t.Fatal("подготовка: расход не записан в store")
		}
		rg.closeAll()
		if err := os.Remove(rg.statePath); err != nil {
			t.Fatal(err)
		}
		rg.boot()
		if st := rg.r.State(); !st.Halted || st.HaltReason != "state_lost" {
			t.Errorf("после удаления store при расходе: halt %v %q, ожидается state_lost (расход обнулился без halt)", st.Halted, st.HaltReason)
		}
		if spent := spentTotal(rg.fst.Snapshot()); spent != 0 {
			t.Errorf("расход после удаления store: %d (новое хранилище)", spent)
		}
	})

	t.Run("цепочка только с якорем, расход без записи решения", func(t *testing.T) {
		rg := newStateRig(t, &identityMasker{}, fakeProviders(newProviderCounts(), nil))
		if res, err := rg.route("inc-1"); err != nil || res.Outcome != "sent" {
			t.Fatalf("подготовка: %v %+v", err, res)
		}
		if n := len(chainEvents(t, rg.chain)); n != 0 {
			t.Fatalf("подготовка: в цепочке событий %d", n)
		}
		rg.closeAll()
		if err := os.Remove(rg.statePath); err != nil {
			t.Fatal(err)
		}
		rg.boot()
		if st := rg.r.State(); !st.Halted || st.HaltReason != "state_lost" {
			t.Errorf("пустая цепочка, удалён store с расходом: halt %v %q, ожидается state_lost", st.Halted, st.HaltReason)
		}
	})
}

// TestStateLostReplaysEndpointsAndActive: при state_lost состояние endpoint'ов и активный endpoint восстанавливаются
// из событий цепочки; Resume пересчитывает активный endpoint; карантин переживает state_lost.
func TestStateLostReplaysEndpointsAndActive(t *testing.T) {
	t.Run("down и активный fallback", func(t *testing.T) {
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
		st := rg.r.State()
		if !st.Halted || st.HaltReason != "state_lost" {
			t.Fatalf("%+v", st)
		}
		if st.Endpoints[reviewPrimary] != "down" || st.Active != reviewFallback {
			t.Errorf("после state_lost по цепочке: endpoints %v, active %q; ожидается primary down, active %s", st.Endpoints, st.Active, reviewFallback)
		}
		rg.check("после state_lost")
		assertMirrors(t, "после state_lost", rg.r, rg.fst.Snapshot())

		if err := rg.r.Resume(context.Background(), "sre-1"); err != nil {
			t.Fatal(err)
		}
		before := pc.get("inceptron")
		if res, err := rg.route("inc-2"); err != nil || res.Role != RoleFallback {
			t.Fatalf("после Resume: %v %+v", err, res)
		}
		if n := pc.get("inceptron") - before; n != 0 {
			t.Errorf("после Resume на down-primary ушло %d запросов", n)
		}
		rg.check("после Resume")
		rg.closeAll()
		rg.boot()
		if st := rg.r.State(); st.Halted || st.Active != reviewFallback || st.Endpoints[reviewPrimary] != "down" {
			t.Errorf("рестарт после Resume: %+v", st)
		}
		rg.check("рестарт после Resume")
		// Восстановление primary: два прохода health-check'ов с интервалом в гистерезис.
		if err := rg.r.CheckHealth(context.Background()); err != nil {
			t.Fatal(err)
		}
		rg.clock.Advance(10 * time.Minute)
		if err := rg.r.CheckHealth(context.Background()); err != nil {
			t.Fatal(err)
		}
		if st := rg.r.State(); st.Active != reviewPrimary || st.Endpoints[reviewPrimary] != "up" {
			t.Errorf("после гистерезиса: %+v", st)
		}
		rg.check("после восстановления primary")
		assertMirrors(t, "после восстановления primary", rg.r, rg.fst.Snapshot())
	})

	t.Run("карантин переживает state_lost и снимается Resume в down", func(t *testing.T) {
		tr := fakeProviders(newProviderCounts(), func() openrouter.Response { return reply("Other", 10, 10) })
		rg := newStateRig(t, &identityMasker{}, tr)
		if res, err := rg.route("inc-1"); err != nil || res.Parsed == nil || res.Parsed.Status != "provider_mismatch" {
			t.Fatalf("подготовка: %v %+v", err, res)
		}
		rg.closeAll()
		if err := os.Remove(rg.statePath); err != nil {
			t.Fatal(err)
		}
		rg.boot()
		if st := rg.r.State(); !st.Halted || st.HaltReason != "state_lost" || st.Endpoints[reviewPrimary] != "quarantined" {
			t.Fatalf("после state_lost: %+v", st)
		}
		rg.check("после state_lost")
		if err := rg.r.Resume(context.Background(), "sre-1"); err != nil {
			t.Fatal(err)
		}
		if st := rg.r.State(); st.Endpoints[reviewPrimary] != "down" || st.Active != reviewFallback {
			t.Errorf("после Resume: %+v", st)
		}
		rg.check("после Resume")
	})

	t.Run("события неизвестного профиля пропускаются", func(t *testing.T) {
		rg := newStateRig(t, &identityMasker{}, fakeProviders(newProviderCounts(), nil))
		ev := audit.RouterEvent{Schema: audit.RouterEventSchema, EventID: audit.NewEventID(), RecordedAt: audit.Timestamp(time.Now()),
			Model: "m", Initiator: audit.Actor{Kind: "system", ID: "llm-router-test"}, Kind: "endpoint_down", Endpoint: "legacy-profile",
			Role: "primary", Reason: "consecutive_failures", ConsecutiveFailures: 3}
		if _, err := rg.w.AppendEvent(&ev); err != nil {
			t.Fatal(err)
		}
		rg.closeAll()
		if err := os.Remove(rg.statePath); err != nil {
			t.Fatal(err)
		}
		rg.boot()
		if st := rg.r.State(); !st.Halted || st.HaltReason != "state_lost" || st.Endpoints[reviewPrimary] != "up" || st.Active != reviewPrimary {
			t.Errorf("неизвестный профиль должен быть пропущен: %+v", st)
		}
	})
}

// TestCrashBetweenEndpointDownAndActiveChanged: крах после commit endpoint_down и до active_changed. При рестарте
// активным не должен оставаться упавший primary (New пересчитывает активный endpoint).
func TestCrashBetweenEndpointDownAndActiveChanged(t *testing.T) {
	tr := fakeProviders(newProviderCounts(), func() openrouter.Response { return openrouter.Response{Status: 503} })
	rg := newStateRig(t, &identityMasker{}, tr)
	rg.closeAll()
	// Store не удаляется: после якоря state_created цепочка непуста, пустой store дал бы state_lost.
	if rg.crashBoot(func(s *flakySink) EventSink { return &crashSink{inner: s, kind: "active_changed"} }) {
		t.Fatal("крах при старте не ожидался")
	}
	if hit := rg.reviewRoute("inc-1"); !hit {
		t.Fatal("крах на active_changed не произошёл")
	}
	if p := rg.fst.Snapshot().Pending; p == nil || p.EventKind != "active_changed" {
		t.Fatalf("ожидается pending intent active_changed, есть %+v", p)
	}
	rg.closeAll()
	rg.boot()
	st := rg.r.State()
	if st.Endpoints[reviewPrimary] != "down" {
		t.Fatalf("primary после краха: %+v", st)
	}
	if st.Active != reviewFallback {
		t.Errorf("после рестарта активен %q, ожидается %s (упавший primary не должен оставаться активным)", st.Active, reviewFallback)
	}
	if st.Halted {
		t.Errorf("после рестарта halt %q", st.HaltReason)
	}
	rg.check("после рестарта")
	assertMirrors(t, "после рестарта", rg.r, rg.fst.Snapshot())
}

// TestNegativeUsageFromProvider: отрицательный usage в ответе провайдера не должен портить счёт: расход в памяти и в
// store совпадает, роутер не останавливается по state_store (хранилище исправно).
func TestNegativeUsageFromProvider(t *testing.T) {
	tr := fakeProviders(newProviderCounts(), func() openrouter.Response { return reply("Inceptron", -100000, 50) })
	rg := newStateRig(t, &identityMasker{}, tr)
	res, err := rg.route("inc-1")
	if err != nil {
		t.Fatalf("%v %+v", err, res)
	}
	st := rg.r.State()
	if st.Halted {
		t.Errorf("отрицательный usage остановил роутер: halt %q (хранилище исправно)", st.HaltReason)
	}
	// Отрицательный usage — не usage: списывается весь резерв (в ответе и в store).
	est := int64(res.Prepared.EstInputTokens + res.Prepared.MaxTokens)
	if res.Tokens != est {
		t.Errorf("учтено в результате %d, ожидается весь резерв %d", res.Tokens, est)
	}
	if got := rg.fst.Snapshot().Days["geo-svc"].Spent; got != est {
		t.Errorf("расход в store %d, ожидается весь резерв %d", got, est)
	}
	assertMirrors(t, "после отрицательного usage", rg.r, rg.fst.Snapshot())
}
