package llmrouter

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/limpjungle/aegis3311/internal/openrouter"
	"github.com/limpjungle/aegis3311/internal/routerstate"
)

// Перепроверка после итерации 4 (тестировщик): Result при отказе закрепления, результат при сбое аудита на
// ретраях, остановка на settle, потеря события chain_lost при крахе, якорь со сбоем аудита при использованном store.

// llmRecordErrors возвращает ошибки проверки decision record, относящиеся к блоку llm (остальные поля этого теста
// не заполнены).
func llmRecordErrors(t *testing.T, res *Result) string {
	t.Helper()
	err := decisionRecord(res).Validate()
	if err == nil {
		return ""
	}
	var parts []string
	for _, line := range strings.Split(err.Error(), "\n") {
		if strings.Contains(line, "llm") {
			parts = append(parts, line)
		}
	}
	return strings.Join(parts, "; ")
}

// TestPinRejectedResultRecordValid: store отклоняет закрепление (ErrInvalidOp). Допустимы два ответа: nil-результат
// с ошибкой (как при отклонённом резерве) либо результат, из которого собирается валидный decision record. Результат
// not_sent без причины не допустим: llm.reason пуст, запись не проходит Validate.
func TestPinRejectedResultRecordValid(t *testing.T) {
	pc := newProviderCounts()
	rg := newStateRig(t, &identityMasker{}, fakeProviders(pc, nil))
	rg.restart(func(s routerstate.Store) routerstate.Store { return &rejectStore{Store: s, kind: routerstate.OpPin} })
	res, err := rg.route("inc-1")
	if !errors.Is(err, routerstate.ErrInvalidOp) {
		t.Fatalf("err=%v, ожидается ErrInvalidOp", err)
	}
	if res == nil {
		return
	}
	if e := llmRecordErrors(t, res); e != "" {
		t.Errorf("результат outcome=%q reason=%q degrade=%v при err=%v не собирается в валидный decision record: %s",
			res.Outcome, res.Reason, res.DegradeL1, err, e)
	}
}

// TestAuditFailureBeforeAnyAttemptRecordValid: сбой store и аудита до первой попытки. Результат — not_sent/halted без
// следов запроса; блок llm decision record валиден.
func TestAuditFailureBeforeAnyAttemptRecordValid(t *testing.T) {
	pc := newProviderCounts()
	rg := newStateRig(t, &identityMasker{}, fakeProviders(pc, nil))
	rg.restart(failAt(routerstate.OpReserve))
	rg.sink.setFail("router_halted")
	res, err := rg.route("inc-1")
	if !errors.Is(err, ErrAuditFailed) || res == nil {
		t.Fatalf("res=%+v err=%v; ожидается результат и ErrAuditFailed", res, err)
	}
	if res.Outcome != "not_sent" || res.Reason != "halted" || !res.DegradeL1 {
		t.Errorf("outcome=%q reason=%q degrade=%v; ожидается not_sent/halted/L1", res.Outcome, res.Reason, res.DegradeL1)
	}
	if res.Call != nil || res.Prepared != nil || res.Role != "" || res.ResponseSHA256 != "" || res.Attempts != 0 {
		t.Errorf("следы запроса в результате без попыток: %+v", res)
	}
	if e := llmRecordErrors(t, res); e != "" {
		t.Errorf("блок llm не проходит проверку: %s", e)
	}
	if n := pc.get("inceptron") + pc.get("wafer"); n != 0 {
		t.Errorf("запрос ушёл: %d", n)
	}
}

// TestSettleRejectedHaltReasonAndRestart: store отклоняет расход (ErrInvalidOp), ответ 200 получен. Роутер
// останавливается с причиной state_store, событие router_halted(state_store) — в цепочке ровно одно. Память
// согласована с цепочкой. После рестарта (хранилище исправно) halt восстанавливается один раз, без дубля события;
// открытый резерв списан.
func TestSettleRejectedHaltReasonAndRestart(t *testing.T) {
	pc := newProviderCounts()
	rg := newStateRig(t, &identityMasker{}, fakeProviders(pc, nil))
	rg.restart(func(s routerstate.Store) routerstate.Store { return &rejectStore{Store: s, kind: routerstate.OpSettle} })
	_, err := rg.route("inc-1")
	if !errors.Is(err, routerstate.ErrInvalidOp) {
		t.Fatalf("err=%v, ожидается ErrInvalidOp", err)
	}
	if st := rg.r.State(); !st.Halted || st.HaltReason != "state_store" {
		t.Errorf("состояние %+v, ожидается halt state_store", st)
	}
	if got := chainKinds(t, rg.chain, rg.keys); !reflect.DeepEqual(got, []string{"state_created:store_created", "router_halted:state_store"}) {
		t.Errorf("события в цепочке: %v", got)
	}
	rg.check("после отказа расхода")
	if res, err := rg.route("inc-1"); err != nil || res.Outcome != "not_sent" || res.Reason != "halted" {
		t.Errorf("запрос после остановки: %v %+v", err, res)
	}
	if n := pc.get("inceptron") + pc.get("wafer"); n != 1 {
		t.Errorf("запросов к провайдеру %d, ожидается 1 (до отказа расхода)", n)
	}

	rg.closeAll()
	rg.wrap = nil // хранилище исправно: отклонение расхода — только в прошлом процессе
	rg.boot()
	if st := rg.r.State(); !st.Halted || st.HaltReason != "state_store" {
		t.Errorf("после рестарта: %+v, ожидается halt state_store", st)
	}
	if got := chainKinds(t, rg.chain, rg.keys); !reflect.DeepEqual(got, []string{"state_created:store_created", "router_halted:state_store"}) {
		t.Errorf("после рестарта события в цепочке: %v (дубль halt?)", got)
	}
	if s := rg.fst.Snapshot(); len(s.Holds) != 0 || spentTotal(s) == 0 {
		t.Errorf("после рестарта резерв не списан: holds=%d spent=%d", len(s.Holds), spentTotal(s))
	}
	rg.check("после рестарта")
}

// TestAuditFailureMidRetriesErrorKind: первая попытка 503, на третьей endpoint переходит в down, и запись
// endpoint_down не удалась. Запрос ушёл три раза, ответа нет. Результат — sent с ErrorKind stopped (как при
// отказе store на ретраях); ответ no_response в решении говорил бы, что провайдер не ответил.
func TestAuditFailureMidRetriesErrorKind(t *testing.T) {
	pc := newProviderCounts()
	tr := fakeProviders(pc, func() openrouter.Response { return openrouter.Response{Status: 503} })
	rg := newStateRig(t, &identityMasker{}, tr)
	rg.sink.setFail("endpoint_down")
	res, err := rg.route("inc-1")
	if !errors.Is(err, ErrAuditFailed) || res == nil {
		t.Fatalf("res=%+v err=%v; ожидается частичный результат и ErrAuditFailed", res, err)
	}
	if res.Attempts != 3 || pc.get("inceptron") != 3 {
		t.Errorf("попыток %d, запросов к primary %d; ожидается 3 и 3", res.Attempts, pc.get("inceptron"))
	}
	if res.Outcome != "sent" || res.ErrorKind != "stopped" {
		t.Errorf("outcome=%q error_kind=%q; ожидается sent/stopped", res.Outcome, res.ErrorKind)
	}
	if e := llmRecordErrors(t, res); e != "" {
		t.Errorf("блок llm не проходит проверку: %s", e)
	}
}

// TestChainLostHaltEventAfterCrash: цепочка удалена при живом store (учёт есть), крах или сбой записи — на router_halted.
// Store уже содержит halt chain_lost (intent/commit якоря), событие в цепочке не записано.
func TestChainLostHaltEventAfterCrash(t *testing.T) {
	rg, spent := usedRigChainRemoved(t)
	if hit := rg.crashBoot(func(s *flakySink) EventSink { return &crashSink{inner: s, kind: "router_halted"} }); !hit {
		t.Fatal("крах не произошёл")
	}
	rg.closeAll()
	rg.boot()
	if st := rg.r.State(); !st.Halted || st.HaltReason != "chain_lost" {
		t.Fatalf("после краха и рестарта: %+v, ожидается chain_lost", st)
	}
	if got := chainKinds(t, rg.chain, rg.keys); !reflect.DeepEqual(got, []string{"state_created:store_created", "router_halted:chain_lost"}) {
		t.Errorf("события в цепочке: %v; halt chain_lost есть в store, но не в цепочке (оператор не увидит причину)", got)
	}
	rg.check("после краха и рестарта")
	if got := spentTotal(rg.fst.Snapshot()); got != spent {
		t.Errorf("бюджет: %d, было %d", got, spent)
	}
	if err := rg.r.Resume(context.Background(), "op-1"); err != nil {
		t.Fatalf("Resume: %v", err)
	}
	rg.check("после Resume")
}

// TestChainLostHaltEventAfterAuditFailure: тот же сценарий без краха — сбой записи router_halted(chain_lost).
// New возвращает ошибку ErrAuditFailed; halt chain_lost остаётся в store без события в цепочке.
func TestChainLostHaltEventAfterAuditFailure(t *testing.T) {
	rg, _ := usedRigChainRemoved(t)
	err, hit := rg.tryBoot(func(s *flakySink) EventSink { s.setFail("router_halted"); return s }, nil)
	if hit || !errors.Is(err, ErrAuditFailed) {
		t.Fatalf("hit=%v err=%v; ожидается ErrAuditFailed", hit, err)
	}
	rg.closeAll()
	rg.boot()
	if got := chainKinds(t, rg.chain, rg.keys); !reflect.DeepEqual(got, []string{"state_created:store_created", "router_halted:chain_lost"}) {
		t.Errorf("события в цепочке: %v; ожидается halt chain_lost в цепочке", got)
	}
	rg.check("после рестарта")
}

// TestChainLostAnchorAuditFailureThenHalts: цепочка удалена, при живом store сбой записи якоря. Store откатывается
// к состоянию до якоря; рестарт с исправным аудитом даёт halt chain_lost и событие в цепочке.
func TestChainLostAnchorAuditFailureThenHalts(t *testing.T) {
	rg, spent := usedRigChainRemoved(t)
	err, hit := rg.tryBoot(func(s *flakySink) EventSink { s.setFail("state_created"); return s }, nil)
	if hit || !errors.Is(err, ErrAuditFailed) {
		t.Fatalf("hit=%v err=%v; ожидается ErrAuditFailed", hit, err)
	}
	if s := rg.fst.Snapshot(); s.Pending != nil || s.Failover.Halted {
		t.Errorf("после сбоя якоря: pending %+v halt %v; ожидается откат", s.Pending, s.Failover.Halted)
	}
	rg.closeAll()
	rg.boot()
	if st := rg.r.State(); !st.Halted || st.HaltReason != "chain_lost" {
		t.Errorf("после рестарта: %+v, ожидается chain_lost", st)
	}
	if got := chainKinds(t, rg.chain, rg.keys); !reflect.DeepEqual(got, []string{"state_created:store_created", "router_halted:chain_lost"}) {
		t.Errorf("события в цепочке: %v", got)
	}
	if got := spentTotal(rg.fst.Snapshot()); got != spent {
		t.Errorf("бюджет: %d, было %d", got, spent)
	}
}

// TestAnchorRestoreFailureRecoversOnNextStart: сбой записи якоря при живом store и отказ восстановления failover
// (failover_set с состоянием до якоря). Первый старт завершается ошибкой. Второй старт с исправным хранилищем и
// аудитом должен пройти: halt audit_failed уже снят abort'ом и откатом, а сбой аудита на якоре больше не
// действует. Ожидается успешный старт.
func TestAnchorRestoreFailureRecoversOnNextStart(t *testing.T) {
	rg := bareStateRig(t, fakeProviders(newProviderCounts(), nil))
	err, hit := rg.tryBoot(func(s *flakySink) EventSink { s.setFail("state_created"); return s }, failAt(routerstate.OpFailoverSet))
	if hit || err == nil {
		t.Fatalf("первый старт: hit=%v err=%v; ожидается ошибка", hit, err)
	}
	rg.closeAll()
	err, hit = rg.tryBoot(nil, nil)
	if hit || err != nil {
		t.Fatalf("второй старт при исправном аудите и store: hit=%v err=%v; ожидается успех", hit, err)
	}
	if st := rg.r.State(); st.Halted {
		t.Errorf("второй старт: %+v", st)
	}
	if got := chainKinds(t, rg.chain, rg.keys); !reflect.DeepEqual(got, []string{"state_created:store_created"}) {
		t.Errorf("события: %v", got)
	}
}

// TestChainRemovedPristineStoreNoHalt: первый старт записал только якорь (учёта нет, failover начальный). Цепочку
// удалили. Потерять нечего: halt не ставится, якорь пишется заново.
func TestChainRemovedPristineStoreNoHalt(t *testing.T) {
	rg := bareStateRig(t, fakeProviders(newProviderCounts(), nil))
	rg.boot()
	rg.closeAll()
	if err := os.Remove(rg.chain); err != nil {
		t.Fatal(err)
	}
	rg.boot()
	if st := rg.r.State(); st.Halted {
		t.Errorf("пустое по учёту store остановлен: %+v", st)
	}
	if got := chainKinds(t, rg.chain, rg.keys); !reflect.DeepEqual(got, []string{"state_created:store_created"}) {
		t.Errorf("события: %v", got)
	}
}

// TestChainRemovedFailoverOnlyStoreHalts: учёта бюджета нет, но failover отличается от начального (оба endpoint'а
// down после проверок здоровья). Цепочку удалили: состояние в store не начальное, halt chain_lost (решение К2).
func TestChainRemovedFailoverOnlyStoreHalts(t *testing.T) {
	rg := newStateRig(t, &identityMasker{}, fakeProviders(newProviderCounts(), nil))
	rg.tr.get = func() (openrouter.Response, error) { return openrouter.Response{Status: 503}, nil }
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := rg.r.CheckHealth(ctx); err != nil {
			t.Fatalf("CheckHealth: %v", err)
		}
	}
	if st := rg.r.State(); st.Endpoints["inceptron-fp8"] != "down" {
		t.Fatalf("подготовка: %+v", st)
	}
	spent := spentTotal(rg.fst.Snapshot())
	rg.closeAll()
	if err := os.Remove(rg.chain); err != nil {
		t.Fatal(err)
	}
	rg.boot()
	if st := rg.r.State(); !st.Halted || st.HaltReason != "chain_lost" {
		t.Errorf("после удаления цепочки: %+v, ожидается chain_lost", st)
	}
	if got := spentTotal(rg.fst.Snapshot()); got != spent {
		t.Errorf("бюджет: %d, было %d", got, spent)
	}
}
