package routerstate

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

var testID = Identity{RouterID: "llm-router-x", Primary: "inceptron-fp8", Fallback: "wafer-nvfp4"}

const (
	testAt     = "2026-11-07T12:00:00Z"
	testDay    = "2026-11-07"
	testEvent  = "re-0123456789abcdef0123456789abcdef"
	testEvent2 = "re-fedcba9876543210fedcba9876543210"
)

func reserve(hold uint64, inc, svc, day string, tokens int64) Op {
	return Op{Kind: OpReserve, At: testAt, Hold: hold, Incident: inc, Service: svc, Day: day, Tokens: tokens}
}

func settle(hold uint64, tokens int64) Op {
	return Op{Kind: OpSettle, At: testAt, Hold: hold, Tokens: tokens}
}

func intent(id string, f Failover) Op {
	return Op{Kind: OpIntent, At: testAt, EventID: id, EventKind: "endpoint_down", Failover: &f}
}

func commit(id string) Op { return Op{Kind: OpCommit, At: testAt, EventID: id} }

func abort(id string, f Failover) Op { return Op{Kind: OpAbort, At: testAt, EventID: id, Failover: &f} }

func up() EndpointState { return EndpointState{State: "up"} }

func downNext() Failover {
	return Failover{Primary: EndpointState{State: "down"}, Fallback: up(), Active: "fallback"}
}

// snapper — хранилище, из которого можно взять копию состояния (FileStore и MemStore).
type snapper interface{ Snapshot() *State }

// nextReserve — резерв с номером, который ждёт хранилище.
func nextReserve(s snapper, inc, svc string, tokens int64) Op {
	return reserve(s.Snapshot().NextHold, inc, svc, testDay, tokens)
}

// TestApplyRules: допустимые и недопустимые операции. При ошибке состояние не меняется, ошибка — ErrInvalidOp.
func TestApplyRules(t *testing.T) {
	long := strings.Repeat("a", 257)
	cases := []struct {
		name string
		pre  []Op
		op   Op
		ok   bool
	}{
		{name: "reserve допустим", op: reserve(1, "inc-1", "svc", testDay, 100), ok: true},
		{name: "reserve с нулём токенов", op: reserve(1, "inc-1", "svc", testDay, 0), ok: true},
		{name: "reserve не по порядку", op: reserve(5, "inc-1", "svc", testDay, 1)},
		{name: "reserve отрицательные токены", op: reserve(1, "inc-1", "svc", testDay, -1)},
		{name: "reserve день 13 месяца", op: reserve(1, "inc-1", "svc", "2026-13-01", 1)},
		{name: "reserve день в чужом формате", op: reserve(1, "inc-1", "svc", "07.11.2026", 1)},
		{name: "reserve пустой инцидент", op: reserve(1, "", "svc", testDay, 1)},
		{name: "reserve инцидент с пробелом", op: reserve(1, "inc 1", "svc", testDay, 1)},
		{name: "reserve инцидент 257 символов", op: reserve(1, long, "svc", testDay, 1)},
		{name: "settle неизвестного резерва", op: settle(1, 10)},
		{name: "settle отрицательные токены", pre: []Op{reserve(1, "inc-1", "svc", testDay, 5)}, op: settle(1, -5)},
		{name: "settle резерва", pre: []Op{reserve(1, "inc-1", "svc", testDay, 5)}, op: settle(1, 50), ok: true},
		{name: "settle дважды", pre: []Op{reserve(1, "inc-1", "svc", testDay, 5), settle(1, 5)}, op: settle(1, 5)},
		{name: "intent с event_id не по формату", op: intent("re-XYZ", downNext())},
		{name: "intent с dr- id", op: intent("dr-0123456789abcdef0123456789abcdef", downNext())},
		{name: "intent допустим", op: intent(testEvent, downNext()), ok: true},
		{name: "intent при неразрешённом intent", pre: []Op{intent(testEvent, downNext())}, op: intent(testEvent2, downNext())},
		{name: "commit без intent", op: commit(testEvent)},
		{name: "commit с чужим event_id", pre: []Op{intent(testEvent, downNext())}, op: commit(testEvent2)},
		{name: "commit допустим", pre: []Op{intent(testEvent, downNext())}, op: commit(testEvent), ok: true},
		{name: "abort с чужим event_id", pre: []Op{intent(testEvent, downNext())}, op: abort(testEvent2, NewState(testID).Failover)},
		{name: "abort допустим с halt audit_failed", pre: []Op{intent(testEvent, downNext())},
			op: abort(testEvent, Failover{Primary: up(), Fallback: up(), Active: "primary", Halted: true, HaltReason: "audit_failed"}), ok: true},
		{name: "failover_set при неразрешённом intent", pre: []Op{intent(testEvent, downNext())},
			op: Op{Kind: OpFailoverSet, At: testAt, Failover: &Failover{Primary: up(), Fallback: up(), Active: "primary"}}},
		{name: "failover_set: halted без причины", op: Op{Kind: OpFailoverSet, At: testAt,
			Failover: &Failover{Primary: up(), Fallback: up(), Active: "primary", Halted: true}}},
		{name: "failover_set: причина без halted", op: Op{Kind: OpFailoverSet, At: testAt,
			Failover: &Failover{Primary: up(), Fallback: up(), Active: "primary", HaltReason: "auth"}}},
		{name: "failover_set: неизвестная причина", op: Op{Kind: OpFailoverSet, At: testAt,
			Failover: &Failover{Primary: up(), Fallback: up(), Active: "primary", Halted: true, HaltReason: "bogus"}}},
		{name: "failover_set: неизвестное состояние endpoint'а", op: Op{Kind: OpFailoverSet, At: testAt,
			Failover: &Failover{Primary: EndpointState{State: "paused"}, Fallback: up(), Active: "primary"}}},
		{name: "failover_set: отрицательный счётчик", op: Op{Kind: OpFailoverSet, At: testAt,
			Failover: &Failover{Primary: EndpointState{State: "up", ReqFails: -1}, Fallback: up(), Active: "primary"}}},
		{name: "failover_set: неизвестный active", op: Op{Kind: OpFailoverSet, At: testAt,
			Failover: &Failover{Primary: up(), Fallback: up(), Active: "wafer"}}},
		{name: "failover_set без failover", op: Op{Kind: OpFailoverSet, At: testAt}},
		{name: "failover_set допустим", op: Op{Kind: OpFailoverSet, At: testAt,
			Failover: &Failover{Primary: EndpointState{State: "down", ReqFails: 3}, Fallback: up(), Active: "fallback"}}, ok: true},
		{name: "pin с неизвестной ролью", op: Op{Kind: OpPin, At: testAt, Incident: "inc-1", Role: "tertiary"}},
		{name: "pin допустим", op: Op{Kind: OpPin, At: testAt, Incident: "inc-1", Role: "fallback"}, ok: true},
		{name: "снятие закрепления", pre: []Op{{Kind: OpPin, At: testAt, Incident: "inc-1", Role: "primary"}},
			op: Op{Kind: OpPin, At: testAt, Incident: "inc-1"}, ok: true},
		{name: "close_incident с пустым id", op: Op{Kind: OpCloseIncident, At: testAt}},
		{name: "snapshot через Apply", op: Op{Kind: OpSnapshot, At: testAt, State: NewState(testID)}},
		{name: "неизвестный вид", op: Op{Kind: "zzz", At: testAt}},
		{name: "некорректный at", op: Op{Kind: OpCloseIncident, At: "вчера", Incident: "inc-1"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := NewState(testID)
			for _, p := range c.pre {
				if err := s.Apply(p); err != nil {
					t.Fatalf("предусловие: %v", err)
				}
			}
			before := s.Clone()
			err := s.Apply(c.op)
			if c.ok {
				if err != nil {
					t.Fatalf("ожидается допустимая операция: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("ожидается ошибка")
			}
			if !errors.Is(err, ErrInvalidOp) {
				t.Errorf("ошибка должна быть ErrInvalidOp: %v", err)
			}
			if !reflect.DeepEqual(s, before) {
				t.Errorf("при ошибке состояние изменилось:\nдо:    %+v\nпосле: %+v", before, s)
			}
		})
	}
}

// TestDayRolloverForwardOnly: сутки сбрасывают счёт только вперёд; назад (часы ушли назад) счёт сохраняется.
func TestDayRolloverForwardOnly(t *testing.T) {
	s := NewState(testID)
	must := func(op Op) {
		t.Helper()
		if err := s.Apply(op); err != nil {
			t.Fatal(err)
		}
	}
	must(reserve(1, "inc-1", "svc", "2026-11-07", 100))
	must(settle(1, 100))
	if d := s.Days["svc"]; d.Day != "2026-11-07" || d.Spent != 100 {
		t.Fatalf("после расхода за 07: %+v", d)
	}

	must(reserve(2, "inc-1", "svc", "2026-11-08", 10))
	if d := s.Days["svc"]; d.Day != "2026-11-08" || d.Spent != 0 {
		t.Fatalf("смена суток вперёд должна обнулить счёт: %+v", d)
	}
	must(settle(2, 10))
	if d := s.Days["svc"]; d.Spent != 10 {
		t.Fatalf("расход после смены суток: %+v", d)
	}

	must(reserve(3, "inc-1", "svc", "2026-11-07", 5)) // часы ушли назад
	if d := s.Days["svc"]; d.Day != "2026-11-08" || d.Spent != 10 {
		t.Fatalf("возврат к прежним суткам не должен сбрасывать счёт: %+v", d)
	}
	must(settle(3, 5))
	if d := s.Days["svc"]; d.Day != "2026-11-08" || d.Spent != 15 {
		t.Fatalf("расход резерва прошлых суток идёт в текущие сутки: %+v", d)
	}
}

// TestCloneIsDeep: копия не разделяет карты, слайсы и intent с исходным состоянием.
func TestCloneIsDeep(t *testing.T) {
	s := NewState(testID)
	if err := s.Apply(reserve(1, "inc-1", "svc", testDay, 7)); err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(intent(testEvent, downNext())); err != nil {
		t.Fatal(err)
	}
	c := s.Clone()
	c.Incidents["inc-1"] = 999
	c.Days["svc"] = Day{Day: testDay, Spent: 999}
	c.Holds[0].Tokens = 999
	c.Pending.EventKind = "changed"
	c.Pending.Next.Primary.State = "quarantined"
	if s.Incidents["inc-1"] != 0 || s.Days["svc"].Spent != 0 || s.Holds[0].Tokens != 7 ||
		s.Pending.EventKind != "endpoint_down" || s.Pending.Next.Primary.State != "down" {
		t.Fatalf("изменение копии затронуло исходное состояние: %+v", s)
	}
	if err := NewState(testID).validate(); err != nil {
		t.Fatalf("начальное состояние не проходит проверку: %v", err)
	}
}
