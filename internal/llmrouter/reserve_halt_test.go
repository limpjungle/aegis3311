package llmrouter

import (
	"errors"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/limpjungle/aegis3311/internal/openrouter"
	"github.com/limpjungle/aegis3311/internal/routerstate"
)

// Вторая проверка остановки в pairReserver.Reserve (после записи резерва) и освобождение резерва при отказе.

func gateAfterReserveRig(wrap func(routerstate.Store) routerstate.Store) (*pairReserver, *routerstate.MemStore, *budgets) {
	id := routerstate.Identity{RouterID: "llm-router-test", Primary: "p", Fallback: "f"}
	st := routerstate.NewMemory(id)
	var store routerstate.Store = st
	if wrap != nil {
		store = wrap(st)
	}
	b := newBudgets(BudgetConfig{IncidentTokens: 1 << 40, ServiceDayTokens: 1 << 40}, store, routerstate.NewState(id))
	now := func() time.Time { return time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC) }
	p := b.forIncident("inc-1", "svc-1", now)
	var n atomic.Int64
	p.gate = func() bool { return n.Add(1) >= 2 } // 1-й вызов false, 2-й true
	return p, st, b
}

func memHeldSpent(t *testing.T, b *budgets) {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	for id, a := range b.incidents {
		if a.held != 0 || a.spent != 0 {
			t.Errorf("инцидент %s в памяти: held=%d spent=%d", id, a.held, a.spent)
		}
	}
	for svc, d := range b.days {
		if d.held != 0 || d.spent != 0 {
			t.Errorf("сервис %s в памяти: held=%d spent=%d", svc, d.held, d.spent)
		}
	}
}

func TestPairReserverGateAfterReserve(t *testing.T) {
	t.Run("освобождение", func(t *testing.T) {
		p, st, b := gateAfterReserveRig(nil)
		if h, ok := p.Reserve(100, 0); ok || h != nil {
			t.Fatalf("Reserve: %v %v", h, ok)
		}
		if d := p.lastDenied(); d != "halted" {
			t.Errorf("lastDenied=%q", d)
		}
		if p.storeFailed() != nil {
			t.Errorf("storeFailed: %v", p.storeFailed())
		}
		s := st.Snapshot()
		if len(s.Holds) != 0 || s.NextHold != 2 || s.Incidents["inc-1"] != 0 || s.Days["svc-1"].Spent != 0 {
			t.Errorf("store: holds=%d next=%d inc=%d day=%d", len(s.Holds), s.NextHold, s.Incidents["inc-1"], s.Days["svc-1"].Spent)
		}
		memHeldSpent(t, b)
	})
	t.Run("сбой store при освобождении", func(t *testing.T) {
		p, st, b := gateAfterReserveRig(failAt(routerstate.OpSettle))
		if h, ok := p.Reserve(100, 0); ok || h != nil {
			t.Fatalf("Reserve: %v %v", h, ok)
		}
		if d := p.lastDenied(); d != "halted" {
			t.Errorf("lastDenied=%q", d)
		}
		var se settleError
		if !errors.As(p.storeFailed(), &se) {
			t.Errorf("storeFailed=%v, ожидается settleError", p.storeFailed())
		}
		if got := len(st.Snapshot().Holds); got != 1 {
			t.Errorf("в store висит резерв: %d, ожидается 1 (settle не записан)", got)
		}
		memHeldSpent(t, b)
	})
}

// haltOnReserve вызывает hook после записи первого (n-го) резерва; failSettle — отказ записи OpSettle.
type haltOnReserve struct {
	routerstate.Store
	hook       func()
	nth        int64 // номер резерва, после которого срабатывает hook (1-based)
	seen       atomic.Int64
	fired      atomic.Bool
	failSettle bool
}

func (h *haltOnReserve) Append(op routerstate.Op) error {
	if h.failSettle && op.Kind == routerstate.OpSettle {
		return routerstate.ErrFailed
	}
	if err := h.Store.Append(op); err != nil {
		return err
	}
	if op.Kind == routerstate.OpReserve && h.seen.Add(1) == h.nth && h.fired.CompareAndSwap(false, true) {
		h.hook()
	}
	return nil
}

// Хук идёт под b.mu и берёт r.mu (порядок b.mu -> r.mu). Пути r.mu -> b.mu нет — тест сторожит этот инвариант
// (при его появлении здесь будет взаимная блокировка).
func haltRig(t *testing.T, tr *stubTransport, nth int64, failSettle bool) (*stateRig, *haltOnReserve) {
	t.Helper()
	rg := newStateRig(t, &identityMasker{}, tr)
	var hs *haltOnReserve
	rg.restart(func(s routerstate.Store) routerstate.Store {
		hs = &haltOnReserve{Store: s, nth: nth, failSettle: failSettle}
		hs.hook = func() { _ = rg.r.haltCanary() }
		return hs
	})
	return rg, hs
}

func haltedEvents(t *testing.T, rg *stateRig) (egress, other int) {
	t.Helper()
	for _, k := range chainKinds(t, rg.chain, rg.keys) {
		switch k {
		case "router_halted:egress_canary":
			egress++
		default:
			if len(k) >= 13 && k[:13] == "router_halted" {
				other++
			}
		}
	}
	return
}

func TestRouteHaltDuringReserveWrite(t *testing.T) {
	newTr := func() *stubTransport {
		return &stubTransport{post: func([]byte) (openrouter.Response, error) { return reply("Inceptron", 10, 5), nil }}
	}
	t.Run("release_ok", func(t *testing.T) {
		tr := newTr()
		rg, hs := haltRig(t, tr, 1, false)
		res, err := rg.route("inc-1")
		if err != nil || res == nil {
			t.Fatalf("%v %v", res, err)
		}
		if res.Outcome != "not_sent" || res.Reason != "halted" || res.Attempts != 0 || res.Call != nil || !res.DegradeL1 {
			t.Fatalf("outcome=%q reason=%q attempts=%d call=%v l1=%v", res.Outcome, res.Reason, res.Attempts, res.Call, res.DegradeL1)
		}
		if !hs.fired.Load() {
			t.Fatal("хук не сработал")
		}
		if tr.calls != 0 {
			t.Fatalf("Post: %d", tr.calls)
		}
		applyOK(t, res)
		if st := rg.r.State(); !st.Halted || st.HaltReason != "egress_canary" {
			t.Fatalf("состояние: %+v", st)
		}
		s := rg.fst.Snapshot()
		if len(s.Holds) != 0 || s.Incidents["inc-1"] != 0 || s.Days["geo-svc"].Spent != 0 {
			t.Errorf("store: holds=%d inc=%d day=%d", len(s.Holds), s.Incidents["inc-1"], s.Days["geo-svc"].Spent)
		}
		assertMirrors(t, "release_ok", rg.r, s)
		rg.check("release_ok")
		if e, o := haltedEvents(t, rg); e != 1 || o != 0 {
			t.Errorf("router_halted: egress_canary=%d прочие=%d, kinds=%v", e, o, chainKinds(t, rg.chain, rg.keys))
		}
	})
	t.Run("release_store_fail", func(t *testing.T) {
		tr := newTr()
		rg, hs := haltRig(t, tr, 1, true)
		res, err := rg.route("inc-1")
		if err != nil || res == nil {
			t.Fatalf("%v %v", res, err)
		}
		if res.Outcome != "not_sent" || res.Reason != "halted" || res.Attempts != 0 || res.Call != nil {
			t.Fatalf("outcome=%q reason=%q attempts=%d call=%v", res.Outcome, res.Reason, res.Attempts, res.Call)
		}
		if !hs.fired.Load() || tr.calls != 0 {
			t.Fatalf("fired=%v Post=%d", hs.fired.Load(), tr.calls)
		}
		if st := rg.r.State(); !st.Halted || st.HaltReason != "egress_canary" {
			t.Fatalf("состояние: %+v", st)
		}
		if e, o := haltedEvents(t, rg); e != 1 || o != 0 {
			t.Errorf("router_halted: egress_canary=%d прочие=%d, kinds=%v", e, o, chainKinds(t, rg.chain, rg.keys))
		}
		est := int64(res.Prepared.EstInputTokens + res.Prepared.MaxTokens)
		rg.restart(nil)
		s := rg.fst.Snapshot()
		if len(s.Holds) != 0 || s.Incidents["inc-1"] != est || s.Days["geo-svc"].Spent != est {
			t.Errorf("после рестарта: holds=%d inc=%d day=%d, ожидается списание %d", len(s.Holds), s.Incidents["inc-1"], s.Days["geo-svc"].Spent, est)
		}
	})
}

func TestRouteHaltDuringRetryReserve(t *testing.T) {
	tr := &stubTransport{post: func([]byte) (openrouter.Response, error) { return openrouter.Response{Status: 503}, nil }}
	rg, hs := haltRig(t, tr, 2, false)
	res, err := rg.route("inc-1")
	if err != nil || res == nil {
		t.Fatalf("%v %v", res, err)
	}
	if !hs.fired.Load() {
		t.Fatal("хук на втором резерве не сработал")
	}
	if tr.calls != 1 || res.Outcome != "sent" || res.ErrorKind != "stopped" || res.Attempts != 1 {
		t.Fatalf("calls=%d outcome=%q kind=%q attempts=%d", tr.calls, res.Outcome, res.ErrorKind, res.Attempts)
	}
	applyOK(t, res)
	s := rg.fst.Snapshot()
	if len(s.Holds) != 0 {
		t.Errorf("висящие резервы: %d", len(s.Holds))
	}
	assertMirrors(t, "retry", rg.r, s)
	if !reflect.DeepEqual(rg.r.State().HaltReason, "egress_canary") {
		t.Errorf("причина: %q", rg.r.State().HaltReason)
	}
}
