package intake

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/limpjungle/aegis3311/internal/llmrouter"
	"github.com/limpjungle/aegis3311/internal/step"
)

// cancelRouter отменяет контекст сервиса внутри Route и возвращает результат not_sent/canceled (отмена до первой попытки).
type cancelRouter struct {
	Router
	cancel context.CancelFunc
	n      int
}

func (c *cancelRouter) Route(context.Context, llmrouter.Request) (*llmrouter.Result, error) {
	c.n++
	c.cancel()
	return &llmrouter.Result{Mode: llmrouter.ModeHybrid, Outcome: "not_sent", Reason: "canceled"}, nil
}

// Отмена до первой попытки Route: записи нет, статус open; после «рестарта» одна запись.
func TestPipelineCancelBeforeFirstAttempt(t *testing.T) {
	p, inc, st, recs, _ := newPipeFix(t, replyFor(answerWith("none")))
	real := p.Router
	ctx, cancel := context.WithCancel(context.Background())
	cr := &cancelRouter{Router: real, cancel: cancel}
	p.Router = cr
	if err := p.Handle(ctx, &inc); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if cr.n != 1 || len(recs()) != 0 {
		t.Fatalf("Route=%d записей=%d", cr.n, len(recs()))
	}
	if got, _ := st.Get(inc.ID); got.Status != StatusOpen {
		t.Fatalf("статус %s", got.Status)
	}
	// рестарт: тот же state, живой роутер
	p.Router = real
	if err := p.Handle(context.Background(), &inc); err != nil {
		t.Fatal(err)
	}
	rs := recs()
	if len(rs) != 1 || rs[0].Intake.Outcome != "routed" {
		t.Fatalf("после рестарта: %+v", rs)
	}
	if got, _ := st.Get(inc.ID); got.Status != StatusRecorded {
		t.Errorf("статус %s", got.Status)
	}
}

// Слот лимита списывается только при Route: source_unavailable и invalid_request его не тратят.
func TestPipelineRateSlotSpentOnlyByRoute(t *testing.T) {
	p, inc, st, recs, snap := newPipeFix(t, replyFor(answerWith("none")))
	p.MaxPerHour = 1
	bad := snap
	bad.Topology.Autoscaler = &step.Autoscaler{Kind: "Bogus", Max: 3}
	mk := func(i int) Incident {
		c := inc
		c.ID = fmt.Sprintf("inc-20260102T10000%dZ-bbbbbbbbbbb%d", i, i)
		c.Alerts = map[string]time.Time{"0123456789abcdef": time.Now()}
		st.Do(func(d *Data) { cp := c; d.Incidents[c.ID] = &cp })
		return c
	}
	var ids []string
	run := func(i int, col Collecting) {
		c := mk(i)
		ids = append(ids, c.ID)
		p.Collector = col
		if err := p.Handle(context.Background(), &c); err != nil {
			t.Fatal(err)
		}
	}
	run(0, failingCollector{})
	run(1, failingCollector{})
	run(2, FixtureCollector{bad})
	run(3, FixtureCollector{bad})
	run(4, FixtureCollector{snap}) // первый успешный Route: слот есть
	run(5, FixtureCollector{snap}) // слот потрачен
	by := map[string][2]string{}
	for _, r := range recs() {
		by[r.Incident.ID] = [2]string{r.Intake.Outcome, r.Intake.Reason}
	}
	want := [][2]string{{"not_routed", "source_unavailable"}, {"not_routed", "source_unavailable"}, {"not_routed", "invalid_request"},
		{"not_routed", "invalid_request"}, {"routed", ""}, {"not_routed", "rate_limited"}}
	for i, id := range ids {
		if by[id] != want[i] {
			t.Errorf("инцидент %d: %v, ожидается %v", i, by[id], want[i])
		}
	}
}

// Выбор событий при превышении лимита: 20 самых поздних по времени, порядок выбранных — порядок входа.
func TestSanitizeEventsLatestByTimeKeepsInputOrder(t *testing.T) {
	_, s := baseSnapshot(t)
	pod := "pod/p-x"
	// возраст в минутах в «перемешанном» порядке входа; значения различны, count = возраст
	ages := []int{29, 3, 17, 25, 1, 28, 9, 22, 5, 14, 30, 7, 19, 2, 26, 11, 24, 4, 16, 8, 21, 6, 27, 12, 15, 10, 23, 13, 20, 18}
	s.Events = nil
	for _, a := range ages {
		s.Events = append(s.Events, Event{Type: "Warning", Reason: "BackOff", Object: pod, Count: a, At: s.T0.Add(-time.Duration(a) * time.Minute)})
	}
	got, trunc := Sanitize(s)
	if !trunc["k8s_events"] || len(got.Events) != MaxEvents {
		t.Fatalf("trunc=%v, событий %d", trunc, len(got.Events))
	}
	var want []int
	for _, a := range ages {
		if a <= 20 { // 20 самых поздних: возраст 1..20
			want = append(want, a)
		}
	}
	for i, e := range got.Events {
		if e.Count != want[i] {
			t.Fatalf("позиция %d: %d, ожидается %d (весь вывод %v)", i, e.Count, want[i], got.Events)
		}
	}
	// равные времена: стабильность — берутся поздние по порядку входа среди равных
	s.Events = nil
	for i := 0; i < MaxEvents+3; i++ {
		s.Events = append(s.Events, Event{Type: "Warning", Reason: "BackOff", Object: pod, Count: i + 1, At: s.T0})
	}
	got, _ = Sanitize(s)
	if got.Events[0].Count != 4 || got.Events[MaxEvents-1].Count != MaxEvents+3 {
		t.Errorf("равные времена: %d..%d", got.Events[0].Count, got.Events[MaxEvents-1].Count)
	}
}
