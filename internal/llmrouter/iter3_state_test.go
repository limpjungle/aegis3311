package llmrouter

import (
	"errors"
	"reflect"
	"testing"

	"github.com/limpjungle/aegis3311/internal/openrouter"
	"github.com/limpjungle/aegis3311/internal/routerstate"
)

// nthStore — хранилище, которое отказывает на n-й операции вида kind; после отказа все вызовы возвращают ErrFailed
// (как после ошибки ввода-вывода). Операции до отказа проходят в настоящее хранилище.
type nthStore struct {
	inner routerstate.Store
	kind  routerstate.OpKind
	n     int
	seen  int
	dead  bool
}

func (f *nthStore) Load() (*routerstate.State, routerstate.LoadInfo, error) { return f.inner.Load() }

func (f *nthStore) Append(op routerstate.Op) error {
	if f.dead {
		return routerstate.ErrFailed
	}
	if op.Kind == f.kind {
		f.seen++
		if f.seen == f.n {
			f.dead = true
			return routerstate.ErrFailed
		}
	}
	return f.inner.Append(op)
}

func (f *nthStore) Err() error {
	if f.dead {
		return routerstate.ErrFailed
	}
	return f.inner.Err()
}

func (f *nthStore) Close() error { return f.inner.Close() }

// rejectOnce — хранилище, которое один раз отклоняет операцию kind с ErrInvalidOp (store исправен).
type rejectOnce struct {
	routerstate.Store
	kind routerstate.OpKind
	done bool
}

func (s *rejectOnce) Append(op routerstate.Op) error {
	if !s.done && op.Kind == s.kind {
		s.done = true
		return routerstate.ErrInvalidOp
	}
	return s.Store.Append(op)
}

// TestAuditFailureBeforeAnyAttemptNotSent: сбой store (резерв) и сбой аудита (router_halted) одновременно, ни одной
// попытки. Запрос не уходил, расход не учтён: результат не должен говорить «sent» и нести ответ (как partial при
// нулевых попытках). Вызывающий получает ErrAuditFailed.
func TestAuditFailureBeforeAnyAttemptNotSent(t *testing.T) {
	t.Run("reserve", func(t *testing.T) {
		pc := newProviderCounts()
		rg := newStateRig(t, &identityMasker{}, fakeProviders(pc, nil))
		rg.restart(failAt(routerstate.OpReserve))
		rg.sink.setFail("router_halted")
		res, err := rg.route("inc-1")
		if !errors.Is(err, ErrAuditFailed) {
			t.Fatalf("err=%v, ожидается ErrAuditFailed", err)
		}
		if n := pc.get("inceptron") + pc.get("wafer"); n != 0 {
			t.Errorf("запрос ушёл при отказе резерва: %d", n)
		}
		if res != nil && (res.Outcome == "sent" || res.Attempts != 0 || res.Call != nil) {
			t.Errorf("результат без единой попытки: outcome=%q attempts=%d call!=nil=%v; ожидается nil или not_sent "+
				"(запрос не отправлен, в решении не должно быть «sent»)", res.Outcome, res.Attempts, res.Call != nil)
		}
	})
	t.Run("pin", func(t *testing.T) {
		pc := newProviderCounts()
		rg := newStateRig(t, &identityMasker{}, fakeProviders(pc, nil))
		rg.restart(failAt(routerstate.OpPin))
		rg.sink.setFail("router_halted")
		res, err := rg.route("inc-1")
		if !errors.Is(err, ErrAuditFailed) {
			t.Fatalf("err=%v, ожидается ErrAuditFailed", err)
		}
		if res == nil || res.Outcome != "not_sent" {
			t.Errorf("результат %+v, ожидается not_sent", res)
		}
		if n := pc.get("inceptron") + pc.get("wafer"); n != 0 {
			t.Errorf("запрос ушёл при отказе закрепления: %d", n)
		}
	})
}

// TestPinRejectedByStoreNoRequest: store отклоняет закрепление (ErrInvalidOp, store исправен). Запрос не уходит,
// ошибка возвращается вызывающему, роутер не останавливается. Заметка кодера утверждала «not_sent без ошибки»:
// проверяется, что ошибка возвращается.
func TestPinRejectedByStoreNoRequest(t *testing.T) {
	pc := newProviderCounts()
	rg := newStateRig(t, &identityMasker{}, fakeProviders(pc, nil))
	rg.restart(func(s routerstate.Store) routerstate.Store { return &rejectStore{Store: s, kind: routerstate.OpPin} })
	res, err := rg.route("inc-1")
	if !errors.Is(err, routerstate.ErrInvalidOp) {
		t.Fatalf("err=%v res=%+v; ожидается ErrInvalidOp (ошибка не должна теряться)", err, res)
	}
	if res != nil { // nil-результат допустим (как при отклонённом резерве), см. TestPinRejectedResultRecordValid
		t.Errorf("при отказе закрепления результат не ожидается: %+v", res)
	}
	if n := pc.get("inceptron") + pc.get("wafer"); n != 0 {
		t.Errorf("запрос ушёл при отказе закрепления: %d", n)
	}
	if st := rg.r.State(); st.Halted {
		t.Errorf("ErrInvalidOp остановил роутер при исправном store: %+v", st)
	}
}

// TestRejectedReserveLeavesNoTrace: store один раз отклоняет резерв (ErrInvalidOp). В памяти и в store ничего не
// создаётся (ни счёта, ни резерва, номер резерва не растёт), запрос не уходит; следующий Route работает и счета
// сходятся с хранилищем.
func TestRejectedReserveLeavesNoTrace(t *testing.T) {
	pc := newProviderCounts()
	rg := newStateRig(t, &identityMasker{}, fakeProviders(pc, nil))
	rg.restart(func(s routerstate.Store) routerstate.Store { return &rejectOnce{Store: s, kind: routerstate.OpReserve} })
	before := rg.fst.Snapshot()
	_, err := rg.route("inc-1")
	if !errors.Is(err, routerstate.ErrInvalidOp) {
		t.Fatalf("первый Route: err=%v, ожидается ErrInvalidOp", err)
	}
	if n := pc.get("inceptron") + pc.get("wafer"); n != 0 {
		t.Errorf("запрос ушёл при отказе резерва: %d", n)
	}
	after := rg.fst.Snapshot()
	if !reflect.DeepEqual(before.Incidents, after.Incidents) || !reflect.DeepEqual(before.Days, after.Days) ||
		before.NextHold != after.NextHold || len(after.Holds) != 0 {
		t.Errorf("store изменился при отказе резерва: до %+v после %+v", before, after)
	}
	rg.r.bud.mu.Lock()
	_, incOK := rg.r.bud.incidents["inc-1"]
	_, dayOK := rg.r.bud.days["geo-svc"]
	next := rg.r.bud.nextHold
	rg.r.bud.mu.Unlock()
	if incOK || dayOK || next != after.NextHold {
		t.Errorf("память после отказа резерва: инцидент=%v сервис=%v nextHold=%d (store %d)", incOK, dayOK, next, after.NextHold)
	}
	res, err := rg.route("inc-1")
	if err != nil || res.Outcome != "sent" {
		t.Fatalf("второй Route после отказа store: %v %+v", err, res)
	}
	assertMirrors(t, "после второго Route", rg.r, rg.fst.Snapshot())
	rg.check("после второго Route")
}

// TestReserveStoreFailureMidRetriesErrorKind: первая попытка 503, на второй отказывает запись резерва. Причина —
// хранилище, а не исчерпанный счёт: ErrorKind — stopped (план), не budget. Запрос ушёл один раз; роутер halted.
func TestReserveStoreFailureMidRetriesErrorKind(t *testing.T) {
	pc := newProviderCounts()
	tr := fakeProviders(pc, func() openrouter.Response { return openrouter.Response{Status: 503} })
	rg := newStateRig(t, &identityMasker{}, tr)
	rg.restart(func(s routerstate.Store) routerstate.Store {
		return &nthStore{inner: s, kind: routerstate.OpReserve, n: 2}
	})
	res, err := rg.route("inc-1")
	if err != nil || res == nil {
		t.Fatalf("err=%v res=%+v", err, res)
	}
	if res.Outcome != "sent" || res.Attempts != 1 {
		t.Errorf("outcome=%q attempts=%d, ожидается sent и 1 попытка", res.Outcome, res.Attempts)
	}
	if res.ErrorKind != "stopped" {
		t.Errorf("ErrorKind=%q при отказе записи резерва на второй попытке, ожидается stopped "+
			"(budget — только при исчерпанном счёте; в решении не должно быть ложной причины)", res.ErrorKind)
	}
	if n := pc.get("inceptron"); n != 1 {
		t.Errorf("запросов к primary %d, ожидается 1", n)
	}
	if st := rg.r.State(); !st.Halted || st.HaltReason != "state_store" {
		t.Errorf("состояние %+v, ожидается halt state_store", st)
	}
}

// TestSettleRejectedByStoreHaltsRouter: ответ 200 получен, store отклоняет расход (ErrInvalidOp). Память уже
// учла расход (held снят, spent вырос), в store резерв остался открытым: память и store расходятся. Роутер
// должен остановиться, иначе следующие вызовы работают на расходящемся состоянии до рестарта.
func TestSettleRejectedByStoreHaltsRouter(t *testing.T) {
	tr := fakeProviders(newProviderCounts(), nil)
	rg := newStateRig(t, &identityMasker{}, tr)
	rg.restart(func(s routerstate.Store) routerstate.Store { return &rejectStore{Store: s, kind: routerstate.OpSettle} })
	res, err := rg.route("inc-1")
	if !errors.Is(err, routerstate.ErrInvalidOp) {
		t.Fatalf("err=%v res=%+v; ожидается ErrInvalidOp", err, res)
	}
	if st := rg.r.State(); !st.Halted {
		t.Errorf("память и store расходятся (settle отклонён), роутер не остановлен: %+v", st)
	}
}
