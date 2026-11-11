package llmrouter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/limpjungle/aegis3311/internal/dataclass"
	"github.com/limpjungle/aegis3311/internal/openrouter"
	"github.com/limpjungle/aegis3311/internal/pyjson"
	"github.com/limpjungle/aegis3311/internal/routerstate"
)

// Фрагмент с canary-маркером: кириллица и перевод строки вокруг, регистр маркера не совпадает с файлом.
const canaryRouteMarker = "canary-pii-user-0042"

func canaryReq(t testing.TB, text string) Request {
	return simpleReq(t, one("alert", frag(t, "a", "alerts.alertmanager", true, 100, string(jsonStr(text)))))
}

func jsonStr(s string) []byte { b, _ := json.Marshal(s); return b }

func okTransport() *stubTransport {
	return &stubTransport{post: func([]byte) (openrouter.Response, error) { return reply("Inceptron", 100, 50), nil }}
}

func newCanaryRig(t testing.TB, tr openrouter.Transport, c *CanarySet) *rig {
	t.Helper()
	rg := newRig(t, &identityMasker{}, tr, "", nil)
	rg.r.o.Canary = c
	return rg
}

func budgetsOf(rg *rig) string {
	s := rg.st.Snapshot()
	return fmt.Sprintf("%v %v %d %d", s.Incidents, s.Days, s.NextHold, len(s.Holds))
}

func TestCanaryRouteBlocks(t *testing.T) {
	ctx := context.Background()
	tr := okTransport()
	rg := newCanaryRig(t, tr, mustCanary(t, "other-marker-0001", strings.ToUpper(canaryRouteMarker)))
	before := budgetsOf(rg)
	res, err := rg.r.Route(ctx, canaryReq(t, "Ошибка у пользователя\n"+canaryRouteMarker+"\nконец"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != "not_sent" || res.Reason != "egress_canary" || !res.DegradeL1 {
		t.Fatalf("outcome=%q reason=%q l1=%v", res.Outcome, res.Reason, res.DegradeL1)
	}
	if tr.calls != 0 || res.Attempts != 0 || res.Call != nil {
		t.Fatalf("запрос ушёл: calls=%d attempts=%d call=%v", tr.calls, res.Attempts, res.Call)
	}
	if got := budgetsOf(rg); got != before {
		t.Errorf("бюджеты тронуты: было %s стало %s", before, got)
	}
	st := rg.r.State()
	if !st.Halted || st.HaltReason != "egress_canary" || st.CanaryBlocked != 1 || st.CanaryMarkers != 2 {
		t.Fatalf("%+v", st)
	}
	if fo := rg.st.Snapshot().Failover; !fo.Halted || fo.HaltReason != "egress_canary" {
		t.Errorf("halt не записан в store: %+v", fo)
	}
	evs := rg.sink.RouterEvents()
	if len(evs) != 1 || evs[0].Kind != "router_halted" || evs[0].Reason != "egress_canary" {
		t.Fatalf("события: %+v", evs)
	}
	applyOK(t, res) // decision record с not_sent/egress_canary и degrade_l1 проходит Validate

	// Маркер не попадает ни в Result, ни в события, ни в запись.
	evJSON, _ := json.Marshal(evs)
	resJSON := fmt.Sprintf("%+v", res)
	for name, s := range map[string]string{"events": string(evJSON), "result": resJSON, "record": decisionJSON(t, res), "state": fmt.Sprintf("%+v", st)} {
		if strings.Contains(strings.ToLower(s), canaryRouteMarker) {
			t.Errorf("маркер в %s", name)
		}
	}

	// Следующий запрос (без маркера) — halted, транспорт не вызывается.
	res2, err := rg.r.Route(ctx, routeReq(t))
	if err != nil || res2.Outcome != "not_sent" || res2.Reason != "halted" || tr.calls != 0 {
		t.Fatalf("после halt: %v %+v calls=%d", err, res2, tr.calls)
	}
	// Resume снимает halt, чистый запрос уходит.
	if err := rg.r.Resume(ctx, "sec-1"); err != nil || rg.r.State().Halted {
		t.Fatalf("Resume: %v", err)
	}
	res3, err := rg.r.Route(ctx, routeReq(t))
	if err != nil || res3.Outcome != "sent" || tr.calls != 1 {
		t.Fatalf("после Resume: %v %+v", err, res3)
	}
	// Повторный запрос с маркером снова останавливает роутер и увеличивает счётчик.
	res4, err := rg.r.Route(ctx, canaryReq(t, "again "+strings.ToUpper(canaryRouteMarker)))
	if err != nil || res4.Reason != "egress_canary" || rg.r.State().CanaryBlocked != 2 || tr.calls != 1 {
		t.Fatalf("повтор: %v %+v blocked=%d", err, res4, rg.r.State().CanaryBlocked)
	}
	if k := rg.sink.kinds(); fmt.Sprint(k) != "[router_halted router_resumed router_halted]" {
		t.Errorf("события: %v", k)
	}
}

func TestCanaryRouteCleanAndDisabled(t *testing.T) {
	ctx := context.Background()
	set := mustCanary(t, canaryRouteMarker)
	t.Run("без маркера уходит", func(t *testing.T) {
		tr := okTransport()
		rg := newCanaryRig(t, tr, set)
		res, err := rg.r.Route(ctx, canaryReq(t, "обычный текст, почти canary-pii-user-004"))
		if err != nil || res.Outcome != "sent" || tr.calls != 1 {
			t.Fatalf("%v %+v", err, res)
		}
		if st := rg.r.State(); st.Halted || st.CanaryBlocked != 0 || st.CanaryMarkers != 1 {
			t.Fatalf("%+v", st)
		}
	})
	for name, c := range map[string]*CanarySet{"nil": nil, "пустой набор": {}} {
		t.Run("Canary "+name+": маркер не проверяется", func(t *testing.T) {
			tr := okTransport()
			rg := newCanaryRig(t, tr, c)
			res, err := rg.r.Route(ctx, canaryReq(t, canaryRouteMarker))
			if err != nil || res.Outcome != "sent" || tr.calls != 1 {
				t.Fatalf("%v %+v", err, res)
			}
			if st := rg.r.State(); st.Halted || st.CanaryMarkers != 0 || st.CanaryBlocked != 0 {
				t.Fatalf("%+v", st)
			}
		})
	}
	t.Run("mode off: проверка не выполняется", func(t *testing.T) {
		tr := okTransport()
		rg := newCanaryRig(t, tr, set)
		req := canaryReq(t, canaryRouteMarker)
		req.Mode = ModeOff
		res, err := rg.r.Route(ctx, req)
		if err != nil || res.Reason != "mode_off" || rg.r.State().Halted || rg.r.State().CanaryBlocked != 0 {
			t.Fatalf("%v %+v", err, res)
		}
	})
	t.Run("исключённый фрагмент с маркером не ушёл — запрос уходит", func(t *testing.T) {
		tr := okTransport()
		rg := newCanaryRig(t, tr, set)
		req := simpleReq(t, one("alert", frag(t, "a", "alerts.alertmanager", true, 100, `{"n":1}`)),
			list("logs", frag(t, "l1", "logs.loki", false, 1, string(jsonStr(canaryRouteMarker)))))
		res, err := rg.r.Route(ctx, req)
		if err != nil || res.Outcome != "sent" || len(res.Prepared.Excluded) != 1 {
			t.Fatalf("%v %+v", err, res)
		}
		if bytes.Contains(res.Prepared.Body, []byte(canaryRouteMarker)) {
			t.Error("тест: маркер в теле")
		}
	})
}

// Реальный маскировщик: секрет вырезается до проверки, поэтому маркер-секрет в теле не остаётся и запрос уходит;
// маркер, который маскировщик не трогает, останавливает отправку.
func TestCanaryRouteRealMasker(t *testing.T) {
	ctx := context.Background()
	secret := ("ghp_" + strings.TrimPrefix(runtimeMarker(t), "mk-") + strings.TrimPrefix(runtimeMarker(t), "mk-"))[:40]
	set := mustCanary(t, secret, canaryRouteMarker)

	ir := newIntRig(t)
	ir.r.o.Canary = set
	js := fmt.Sprintf(`{"annotations":{"summary":%q},"n":1}`, "leaked "+secret+" in logs")
	res, err := ir.r.Route(ctx, simpleReq(t, one("alert", frag(t, "a", "alerts.alertmanager", true, 100, js))))
	if err != nil || res.Outcome != "sent" || ir.r.State().Halted || ir.r.State().CanaryBlocked != 0 {
		t.Fatalf("секрет вырезан, ожидается sent: %v %+v", err, res)
	}
	if bytes.Contains(bytes.ToLower(ir.lastBody(t)), []byte(strings.ToLower(secret))) {
		t.Fatal("секрет ушёл")
	}

	ir2 := newIntRig(t)
	ir2.r.o.Canary = set
	js2 := fmt.Sprintf(`{"annotations":{"summary":%q},"n":1}`, "см. "+canaryRouteMarker)
	res, err = ir2.r.Route(ctx, simpleReq(t, one("alert", frag(t, "a", "alerts.alertmanager", true, 100, js2))))
	if err != nil || res.Reason != "egress_canary" || ir2.tr.calls != 0 {
		t.Fatalf("%v %+v calls=%d", err, res, ir2.tr.calls)
	}
}

// Сбой аудита при halt: ErrAuditFailed, запрос не ушёл.
func TestCanaryRouteAuditFailure(t *testing.T) {
	tr := okTransport()
	sink := &memSink{failOn: "router_halted"}
	rg := newRig(t, &identityMasker{}, tr, "", sink)
	rg.r.o.Canary = mustCanary(t, canaryRouteMarker)
	res, err := rg.r.Route(context.Background(), canaryReq(t, canaryRouteMarker))
	if !errors.Is(err, ErrAuditFailed) {
		t.Fatalf("err=%v", err)
	}
	if res == nil || res.Outcome != "not_sent" || tr.calls != 0 {
		t.Fatalf("%+v calls=%d", res, tr.calls)
	}
	if !rg.r.State().Halted {
		t.Error("роутер не остановлен")
	}
	// Роутер остановлен: следующий запрос тоже не уходит.
	if res, _ := rg.r.Route(context.Background(), routeReq(t)); res == nil || res.Outcome != "not_sent" || tr.calls != 0 {
		t.Fatalf("после сбоя: %+v calls=%d", res, tr.calls)
	}
}

// Параллельные запросы с маркером: ни один не уходит, счётчик атомарен, остальные получают halted. Запускать с -race.
func TestCanaryRouteConcurrent(t *testing.T) {
	var posts atomic.Int64
	tr := &stubTransport{post: func([]byte) (openrouter.Response, error) {
		posts.Add(1)
		return reply("Inceptron", 10, 5), nil
	}}
	rg := newCanaryRig(t, tr, mustCanary(t, canaryRouteMarker))
	const n = 32
	var wg sync.WaitGroup
	reasons := make([]string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			res, err := rg.r.Route(context.Background(), canaryReq(t, fmt.Sprintf("x%d %s", i, canaryRouteMarker)))
			if err != nil || res == nil {
				reasons[i] = fmt.Sprint("err ", err)
				return
			}
			reasons[i] = res.Outcome + "/" + res.Reason
		}(i)
	}
	wg.Wait()
	if posts.Load() != 0 {
		t.Fatalf("запросов в сеть: %d", posts.Load())
	}
	for i, r := range reasons {
		if r != "not_sent/egress_canary" && r != "not_sent/halted" {
			t.Errorf("%d: %s", i, r)
		}
	}
	st := rg.r.State()
	if st.CanaryBlocked < 1 || st.CanaryBlocked > n || !st.Halted || st.HaltReason != "egress_canary" {
		t.Fatalf("%+v", st)
	}
	if halts := len(rg.sink.RouterEvents()); halts != 1 {
		t.Errorf("router_halted записан %d раз", halts)
	}
}

// После переключения на резерв (Attempts > 0) тело резерва проверяется тоже: маркер, которого нет в теле primary,
// но есть в теле fallback, останавливает запрос с исходом sent/stopped, а не not_sent (запрос уже уходил на primary).
func TestCanaryRouteAfterSwitchAttemptsPositive(t *testing.T) {
	const fbMarker = "wafer-nvfp4-marker"
	a := loadAssets(t)
	for _, p := range a.Fallback.Provider.Get("quantizations").Items {
		p.S = fbMarker
	}
	a.Fallback.Quantizations = []string{fbMarker}
	var fbCalls int
	tr := &stubTransport{post: func(b []byte) (openrouter.Response, error) {
		if bytes.Contains(b, []byte(fbMarker)) {
			fbCalls++
			return reply("Wafer", 10, 5), nil
		}
		return openrouter.Response{}, &openrouter.TransportError{Kind: "timeout"}
	}}
	rg := newRigAssets(t, a, &identityMasker{}, tr, "", nil)
	rg.r.o.Canary = mustCanary(t, fbMarker)
	res, err := rg.r.Route(context.Background(), routeReq(t))
	if err != nil {
		t.Fatal(err)
	}
	if fbCalls != 0 {
		t.Fatalf("тело с маркером ушло на резерв: %d", fbCalls)
	}
	if res.Attempts == 0 || res.Outcome != "sent" || res.ErrorKind != "stopped" || res.Reason != "" {
		t.Fatalf("attempts=%d outcome=%q kind=%q reason=%q", res.Attempts, res.Outcome, res.ErrorKind, res.Reason)
	}
	if st := rg.r.State(); !st.Halted || st.HaltReason != "egress_canary" || st.CanaryBlocked != 1 {
		t.Fatalf("%+v", st)
	}
	applyOK(t, res)
}

// Ретраи на том же endpoint'е шлют те же байты: проверка до первой попытки, после неё повторно не требуется;
// маркер не может появиться между попытками. Проверяем, что все тела, ушедшие в Post, не содержат маркера,
// а при чистом запросе ретраи (503) не вызывают canary-halt.
func TestCanaryRouteRetriesSameBytes(t *testing.T) {
	var bodies [][]byte
	n := 0
	tr := &stubTransport{post: func(b []byte) (openrouter.Response, error) {
		bodies = append(bodies, append([]byte(nil), b...))
		n++
		if n < 3 {
			return openrouter.Response{Status: 503}, nil
		}
		return reply("Inceptron", 10, 5), nil
	}}
	rg := newCanaryRig(t, tr, mustCanary(t, canaryRouteMarker))
	res, err := rg.r.Route(context.Background(), canaryReq(t, "clean"))
	if err != nil || res.Outcome != "sent" || len(bodies) != 3 {
		t.Fatalf("%v %+v bodies=%d", err, res, len(bodies))
	}
	for i, b := range bodies {
		if !bytes.Equal(b, bodies[0]) || bytes.Contains(bytes.ToLower(b), []byte(canaryRouteMarker)) {
			t.Errorf("попытка %d: тело отличается или содержит маркер", i)
		}
	}
	if !bytes.Equal(bodies[0], res.Prepared.Body) {
		t.Error("проверенные байты (Prepared.Body) не совпадают с ушедшими в Post")
	}
}

// gateMasker: первый вызов Mask сигнализирует о входе и ждёт release; остальные проходят без задержки.
type gateMasker struct {
	identityMasker
	first   atomic.Bool
	entered chan struct{}
	release chan struct{}
}

func (m *gateMasker) Mask(ctx context.Context, meta dataclass.FragmentMeta, v *pyjson.Value) (*pyjson.Value, dataclass.MaskReport, error) {
	if m.first.CompareAndSwap(false, true) {
		close(m.entered)
		select {
		case <-m.release:
		case <-time.After(5 * time.Second):
		}
	}
	return m.identityMasker.Mask(ctx, meta, v)
}

// Основной сценарий ревью: чистый запрос A подготавливается (выбор endpoint'а уже или ещё не сделан), в это время
// запрос B с маркером останавливает роутер; A не должен уйти в сеть.
func TestCanaryRouteHaltWhilePreparing(t *testing.T) {
	gm := &gateMasker{entered: make(chan struct{}), release: make(chan struct{})}
	var bodies [][]byte
	var bmu sync.Mutex
	tr := &stubTransport{post: func(b []byte) (openrouter.Response, error) {
		bmu.Lock()
		bodies = append(bodies, append([]byte(nil), b...))
		bmu.Unlock()
		return reply("Inceptron", 10, 5), nil
	}}
	rg := newRig(t, gm, tr, "", nil)
	rg.r.o.Canary = mustCanary(t, canaryRouteMarker)
	before := budgetsOf(rg)

	type out struct {
		res *Result
		err error
	}
	ch := make(chan out, 1)
	go func() {
		res, err := rg.r.Route(context.Background(), canaryReq(t, "clean"))
		ch <- out{res, err}
	}()
	select {
	case <-gm.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("A не дошёл до маскировщика")
	}
	resB, errB := rg.r.Route(context.Background(), canaryReq(t, canaryRouteMarker))
	if errB != nil || resB == nil || resB.Outcome != "not_sent" || resB.Reason != "egress_canary" {
		t.Fatalf("B: %v %+v", errB, resB)
	}
	if st := rg.r.State(); !st.Halted || st.HaltReason != "egress_canary" {
		t.Fatalf("состояние: %+v", st)
	}
	close(gm.release)
	var o out
	select {
	case o = <-ch:
	case <-time.After(10 * time.Second):
		t.Fatal("A не завершился")
	}
	if o.err != nil || o.res == nil {
		t.Fatalf("A: %v %v", o.res, o.err)
	}
	a := o.res
	if a.Outcome != "not_sent" || a.Reason != "halted" || !a.DegradeL1 || a.Attempts != 0 || a.Call != nil {
		t.Fatalf("A: outcome=%q reason=%q l1=%v attempts=%d call=%v", a.Outcome, a.Reason, a.DegradeL1, a.Attempts, a.Call)
	}
	applyOK(t, a)
	if tr.calls != 0 || len(bodies) != 0 {
		t.Fatalf("Post вызван %d раз", tr.calls)
	}
	if after := budgetsOf(rg); after != before {
		t.Errorf("бюджеты изменились: %s -> %s", before, after)
	}
	if n := len(rg.st.Snapshot().Holds); n != 0 {
		t.Errorf("резервов: %d", n)
	}
	if halts := len(rg.sink.RouterEvents()); halts != 1 {
		t.Errorf("router_halted записан %d раз", halts)
	}
}

// Остановка в паузе между ретраями: вторая попытка не уходит; исход sent/stopped, причины нет.
func TestRouteHaltBetweenRetries(t *testing.T) {
	tr := &stubTransport{post: func([]byte) (openrouter.Response, error) { return openrouter.Response{Status: 503}, nil }}
	rg := newRig(t, &identityMasker{}, tr, "", nil)
	f := func() { _ = rg.r.haltCanary() }
	rg.onSleep.Store(&f)
	res, err := rg.r.Route(context.Background(), routeReq(t))
	if err != nil || res == nil {
		t.Fatalf("%v %v", res, err)
	}
	if tr.calls != 1 || res.Outcome != "sent" || res.ErrorKind != "stopped" || res.Attempts != 1 || res.Reason != "" {
		t.Fatalf("calls=%d outcome=%q kind=%q attempts=%d reason=%q", tr.calls, res.Outcome, res.ErrorKind, res.Attempts, res.Reason)
	}
	applyOK(t, res)
}

// Gate резервирования: при остановке Reserve отказывает до обращения к хранилищу.
func TestPairReserverGate(t *testing.T) {
	id := routerstate.Identity{RouterID: "llm-router-test", Primary: "p", Fallback: "f"}
	st := routerstate.NewMemory(id)
	b := newBudgets(BudgetConfig{IncidentTokens: 1 << 40, ServiceDayTokens: 1 << 40}, st, routerstate.NewState(id))
	now := func() time.Time { return time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC) }
	p := b.forIncident("inc-1", "svc-1", now)
	p.gate = func() bool { return true }
	snap := fmt.Sprintf("%+v", st.Snapshot())
	if h, ok := p.Reserve(100, 0); ok || h != nil {
		t.Fatalf("резерв при остановке: %v %v", h, ok)
	}
	if d := p.lastDenied(); d != "halted" {
		t.Errorf("lastDenied=%q", d)
	}
	if p.storeFailed() != nil {
		t.Errorf("storeFailed: %v", p.storeFailed())
	}
	if got := fmt.Sprintf("%+v", st.Snapshot()); got != snap {
		t.Errorf("store изменён:\n%s\n%s", snap, got)
	}
	p.gate = func() bool { return false }
	h, ok := p.Reserve(100, 0)
	if !ok || h == nil {
		t.Fatal("резерв без остановки отклонён")
	}
	if len(st.Snapshot().Holds) != 1 {
		t.Errorf("holds: %d", len(st.Snapshot().Holds))
	}
}

// Смесь чистых и маркерных запросов: маркер не уходит никогда, чистые sent либо not_sent/halted. Запускать с -race.
func TestCanaryRouteConcurrentMixed(t *testing.T) {
	var posts atomic.Int64
	var leaked atomic.Int64
	tr := &stubTransport{post: func(b []byte) (openrouter.Response, error) {
		posts.Add(1)
		if bytes.Contains(bytes.ToLower(b), []byte(canaryRouteMarker)) {
			leaked.Add(1)
		}
		return reply("Inceptron", 10, 5), nil
	}}
	rg := newCanaryRig(t, tr, mustCanary(t, canaryRouteMarker))
	const n = 32
	var wg sync.WaitGroup
	res := make([]*Result, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			txt := fmt.Sprintf("clean %d", i)
			if i%2 == 0 {
				txt = fmt.Sprintf("x%d %s", i, canaryRouteMarker)
			}
			res[i], errs[i] = rg.r.Route(context.Background(), canaryReq(t, txt))
		}(i)
	}
	wg.Wait()
	if leaked.Load() != 0 {
		t.Fatalf("тел с маркером в Post: %d", leaked.Load())
	}
	sent := 0
	for i := 0; i < n; i++ {
		if errs[i] != nil || res[i] == nil {
			t.Errorf("%d: %v %v", i, res[i], errs[i])
			continue
		}
		r := res[i]
		switch {
		case i%2 == 0 && r.Outcome == "not_sent" && (r.Reason == "egress_canary" || r.Reason == "halted"):
		case i%2 == 1 && r.Outcome == "sent" && r.Reason == "":
			sent++
		case i%2 == 1 && r.Outcome == "not_sent" && r.Reason == "halted":
		default:
			t.Errorf("%d: %s/%s kind=%s", i, r.Outcome, r.Reason, r.ErrorKind)
		}
	}
	if int64(sent) != posts.Load() {
		t.Errorf("sent=%d posts=%d", sent, posts.Load())
	}
	if st := rg.r.State(); !st.Halted || st.HaltReason != "egress_canary" {
		t.Fatalf("%+v", st)
	}
	if halts := len(rg.sink.RouterEvents()); halts != 1 {
		t.Errorf("router_halted записан %d раз", halts)
	}
}
