package intake

import (
	"context"
	"errors"
	"os"
	"regexp"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/limpjungle/aegis3311/internal/openrouter"
	"github.com/limpjungle/aegis3311/internal/pyjson"
)

// idRe роутера (llmrouter/types.go, неэкспортируемый): ID инцидента обязан ему соответствовать.
var routerIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$`)

type fakeAlerts struct {
	mu  sync.Mutex
	as  []Alert
	err error
}

func (f *fakeAlerts) set(as []Alert, err error) { f.mu.Lock(); f.as, f.err = as, err; f.mu.Unlock() }
func (f *fakeAlerts) Firing(context.Context) ([]Alert, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Alert(nil), f.as...), f.err
}

type clock struct{ ns atomic.Int64 }

func (c *clock) now() time.Time          { return time.Unix(0, c.ns.Load()).UTC() }
func (c *clock) advance(d time.Duration) { c.ns.Add(int64(d)) }

// closeRec записывает вызовы CloseIncident поверх настоящего роутера.
type closeRec struct {
	Router
	mu     sync.Mutex
	closed []string
	fail   atomic.Bool
}

func (c *closeRec) CloseIncident(id string) error {
	if c.fail.Load() {
		return errors.New("store down")
	}
	c.mu.Lock()
	c.closed = append(c.closed, id)
	c.mu.Unlock()
	return c.Router.CloseIncident(id)
}
func (c *closeRec) ids() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.closed...)
}

type svcFixture struct {
	s      *Service
	alerts *fakeAlerts
	clk    *clock
	cr     *closeRec
	st     *State
	alert  Alert
}

func newSvcFixture(t *testing.T, closePolls int) *svcFixture {
	t.Helper()
	rt, _, _ := openTestRuntime(t, &stubTr{post: func([]byte) (openrouter.Response, error) { return okReply(), nil }})
	c := loadCases(t, "probe-v3.jsonl")[0]
	snap := snapshotFromGolden(t, pyjson.Marshal(c.Get("input"), pyjson.Canonical))
	p, inc, st := newTestPipeline(t, rt, snap, t.TempDir())
	st.Do(func(d *Data) { delete(d.Incidents, inc.ID) }) // пустое состояние: инцидент откроет трекер
	clk := &clock{}
	clk.ns.Store(time.Date(2026, 1, 2, 10, 0, 0, 0, time.UTC).UnixNano())
	p.Now, p.Settle, p.RetryPause = clk.now, 2*time.Minute, time.Millisecond
	cr := &closeRec{Router: rt.Router}
	al := &fakeAlerts{}
	svc := &Service{Cfg: Config{Workers: 2, MaxOpenIncidents: 8}, D: Durations{Poll: 15 * time.Second, Settle: 2 * time.Minute, SnapshotRetention: time.Hour},
		Alerts: al, State: st, Tracker: NewTracker("staging", func(ns, s string) bool { return ns == snap.Alert.Namespace && s == snap.Alert.Service },
			closePolls, 8, st, nil), Pipe: p, Router: cr, Now: clk.now, DispatchEvery: 5 * time.Millisecond}
	a := SanitizeAlert(snap.Alert)
	a.StartsAt = clk.now().Add(-time.Minute)
	return &svcFixture{s: svc, alerts: al, clk: clk, cr: cr, st: st, alert: a}
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; i < 400; i++ {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("не дождались: %s", what)
}

// ID инцидента: формат inc-<время>-<12 hex>, подходит под idRe роутера, детерминирован, зависит от каждого компонента.
func TestIncidentIDFormat(t *testing.T) {
	k := Key{"staging", "shop", "geo-svc"}
	ts := time.Date(2026, 1, 2, 9, 59, 7, 0, time.UTC)
	id := IncidentID(k, ts)
	if !regexp.MustCompile(`^inc-20260102T095907Z-[0-9a-f]{12}$`).MatchString(id) || !routerIDRe.MatchString(id) {
		t.Fatalf("ID %q", id)
	}
	if id != IncidentID(k, ts.In(time.FixedZone("x", 3*3600))) {
		t.Error("ID зависит от часового пояса")
	}
	for name, other := range map[string]string{
		"env": IncidentID(Key{"prod-cloud-hybrid", "shop", "geo-svc"}, ts), "ns": IncidentID(Key{"staging", "shop2", "geo-svc"}, ts),
		"svc": IncidentID(Key{"staging", "shop", "geo"}, ts), "startsAt": IncidentID(k, ts.Add(time.Second)),
	} {
		if other == id {
			t.Errorf("ID не зависит от %s", name)
		}
	}
	// разделитель: ("a","bc") и ("ab","c") не коллидируют
	if IncidentID(Key{"e", "a", "bc"}, ts)[len("inc-20260102T095907Z-"):] == IncidentID(Key{"e", "ab", "c"}, ts)[len("inc-20260102T095907Z-"):] {
		t.Error("коллизия ключей без разделителя")
	}
}

func TestTrackerFlappingAndReopen(t *testing.T) {
	st, _ := OpenState("")
	known := func(ns, s string) bool { return ns == "shop" && s == "geo-svc" }
	tr := NewTracker("staging", known, 3, 10, st, nil)
	t0 := time.Date(2026, 1, 2, 10, 0, 0, 0, time.UTC)
	a := Alert{Fingerprint: "0123456789abcdef", Name: "X", Severity: "critical", Namespace: "shop", Service: "geo-svc", StartsAt: t0}
	op, _, _ := tr.Observe(t0, []Alert{a})
	if len(op) != 1 {
		t.Fatal("не открыт")
	}
	id := op[0].ID
	// флаппинг внутри окна: пустой, пустой, алерт вернулся → тот же инцидент, счётчик пропусков сброшен
	tr.Observe(t0.Add(15*time.Second), nil)
	if _, cl, _ := tr.Observe(t0.Add(30*time.Second), nil); len(cl) != 0 {
		t.Fatal("закрытие раньше срока")
	}
	if op, _, _ = tr.Observe(t0.Add(45*time.Second), []Alert{a}); len(op) != 0 {
		t.Fatal("флаппинг открыл новый инцидент")
	}
	if inc, _ := st.Get(id); inc.AbsentPolls != 0 || inc.Status != StatusOpen {
		t.Errorf("после возврата: %+v", inc)
	}
	// ровно closePolls пустых опросов подряд → закрытие, не раньше
	for i := 1; i <= 2; i++ {
		if _, cl, _ := tr.Observe(t0.Add(time.Minute+time.Duration(i)*15*time.Second), nil); len(cl) != 0 {
			t.Fatalf("опрос %d: закрытие рано", i)
		}
	}
	_, cl, _ := tr.Observe(t0.Add(2*time.Minute), nil)
	if len(cl) != 1 || cl[0].ID != id || cl[0].Status != StatusClosing {
		t.Fatalf("закрытие: %+v", cl)
	}
	// закрытие не подтверждено, алерт вернулся → closing обратно в open, ID прежний
	if op, cl, _ = tr.Observe(t0.Add(2*time.Minute+15*time.Second), []Alert{a}); len(op) != 0 || len(cl) != 0 {
		t.Fatalf("возврат при closing: opened=%v close=%v", op, cl)
	}
	if inc, _ := st.Get(id); inc.Status != StatusOpen {
		t.Errorf("статус %s", inc.Status)
	}
	// не подтверждённое закрытие повторяется в каждом опросе
	for i := 0; i < 3; i++ {
		tr.Observe(t0.Add(3*time.Minute+time.Duration(i)*15*time.Second), nil)
	}
	if _, cl, _ = tr.Observe(t0.Add(4*time.Minute), nil); len(cl) != 1 {
		t.Fatalf("closing не повторяется: %v", cl)
	}
	// после закрытия в роутере новый startsAt даёт новый ID
	st.Do(func(d *Data) { delete(d.Incidents, id); d.Closed[id] = t0.Add(5 * time.Minute) })
	b := a
	b.StartsAt = t0.Add(10 * time.Minute)
	op, _, _ = tr.Observe(t0.Add(11*time.Minute), []Alert{b})
	if len(op) != 1 || op[0].ID == id || !routerIDRe.MatchString(op[0].ID) {
		t.Fatalf("новое срабатывание: %v", op)
	}
}

func TestTrackerIgnoreMaxOpenRetention(t *testing.T) {
	st, _ := OpenState("")
	known := func(ns, s string) bool { return ns == "shop" }
	tr := NewTracker("staging", known, 2, 2, st, nil)
	t0 := time.Date(2026, 1, 2, 10, 0, 0, 0, time.UTC)
	mk := func(svc string, fp string) Alert {
		return Alert{Fingerprint: fp, Namespace: "shop", Service: svc, StartsAt: t0}
	}
	op, _, err := tr.Observe(t0, []Alert{
		{Fingerprint: "0000000000000001", Service: "a", StartsAt: t0},                            // без namespace
		{Fingerprint: "0000000000000002", Namespace: "shop", StartsAt: t0},                       // без service
		{Fingerprint: "0000000000000003", Namespace: "other", Service: "a", StartsAt: t0},        // вне реестра
		mk("s1", "0000000000000004"), mk("s2", "0000000000000005"), mk("s3", "0000000000000006"), // третий — сверх лимита
	})
	if err != nil || len(op) != 2 || tr.Ignored != 3 {
		t.Fatalf("opened=%d ignored=%d err=%v", len(op), tr.Ignored, err)
	}
	// лимит не мешает присоединению к уже открытым
	if op, _, _ = tr.Observe(t0.Add(time.Minute), []Alert{mk("s1", "0000000000000004"), mk("s1", "0000000000000007")}); len(op) != 0 {
		t.Error("открытие сверх лимита")
	}
	// множество закрытых ID: чистится после 7 суток
	st.Do(func(d *Data) {
		d.Closed["old"] = t0.Add(-8 * 24 * time.Hour)
		d.Closed["fresh"] = t0.Add(-6 * 24 * time.Hour)
	})
	tr.Observe(t0.Add(2*time.Minute), nil)
	st.View(func(d *Data) {
		if _, ok := d.Closed["old"]; ok {
			t.Error("старый закрытый ID не удалён")
		}
		if _, ok := d.Closed["fresh"]; !ok {
			t.Error("свежий закрытый ID удалён")
		}
	})
}

func TestTrackerStatePersistsAcrossRestart(t *testing.T) {
	path := t.TempDir() + "/s.json"
	known := func(ns, s string) bool { return true }
	t0 := time.Date(2026, 1, 2, 10, 0, 0, 0, time.UTC)
	a := Alert{Fingerprint: "0123456789abcdef", Namespace: "shop", Service: "geo-svc", StartsAt: t0}
	st, _ := OpenState(path)
	op, _, _ := NewTracker("staging", known, 2, 8, st, nil).Observe(t0, []Alert{a})
	st.Close()
	st, err := OpenState(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if op2, _, _ := NewTracker("staging", known, 2, 8, st, nil).Observe(t0.Add(15*time.Second), []Alert{a}); len(op2) != 0 {
		t.Fatalf("после рестарта открыт дубль %v (был %v)", op2, op)
	}
}

// Ошибка опроса Alertmanager не закрывает инциденты: Tracker.Observe не вызывается, счётчики не меняются.
func TestPollErrorDoesNotClose(t *testing.T) {
	f := newSvcFixture(t, 2)
	f.alerts.set([]Alert{f.alert}, nil)
	f.s.inflight = map[string]bool{}
	if err := f.s.poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.alerts.set(nil, &SourceError{"network"})
	for i := 0; i < 10; i++ {
		f.clk.advance(15 * time.Second)
		if err := f.s.poll(context.Background()); err != nil {
			t.Fatalf("ошибка опроса фатальна: %v", err)
		}
	}
	f.st.View(func(d *Data) {
		for _, inc := range d.Incidents {
			if inc.AbsentPolls != 0 || inc.Status != StatusOpen {
				t.Errorf("ошибка опроса изменила инцидент: %+v", inc)
			}
		}
		if len(d.Incidents) != 1 {
			t.Errorf("инцидентов %d", len(d.Incidents))
		}
	})
	// пустой, но успешный ответ — разрешение
	f.alerts.set(nil, nil)
	f.s.poll(context.Background())
	f.s.poll(context.Background())
	f.st.View(func(d *Data) {
		for _, inc := range d.Incidents {
			if inc.Status != StatusClosing {
				t.Errorf("после 2 пустых опросов статус %s", inc.Status)
			}
		}
	})
}

// Полный цикл на фейковых часах: алерт → после settle запись → алерт пропал → CloseIncident → Closed; повторного открытия нет.
func TestServiceRunLifecycle(t *testing.T) {
	f := newSvcFixture(t, 2)
	f.s.D.Poll = 20 * time.Millisecond
	f.alerts.set([]Alert{f.alert}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- f.s.Run(ctx) }()
	var id string
	eventually(t, "инцидент открыт", func() bool {
		f.st.View(func(d *Data) {
			for k := range d.Incidents {
				id = k
			}
		})
		return id != ""
	})
	time.Sleep(100 * time.Millisecond)
	if f.s.Pipe.Writer.HasIncidentRecord(id) {
		t.Fatal("запись до наступления T0 (settle)")
	}
	f.clk.advance(3 * time.Minute)
	eventually(t, "запись", func() bool { return f.s.Pipe.Writer.HasIncidentRecord(id) })
	// алерт разрешён
	f.alerts.set(nil, nil)
	eventually(t, "закрытие в роутере", func() bool { return len(f.cr.ids()) == 1 })
	if f.cr.ids()[0] != id {
		t.Errorf("закрыт %v, ожидался %s", f.cr.ids(), id)
	}
	eventually(t, "инцидент перенесён в Closed", func() bool {
		var ok bool
		f.st.View(func(d *Data) { _, ok = d.Closed[id]; ok = ok && len(d.Incidents) == 0 })
		return ok
	})
	// алерт с тем же startsAt вернулся: закрытый ID не открывается
	f.alerts.set([]Alert{f.alert}, nil)
	time.Sleep(150 * time.Millisecond)
	f.st.View(func(d *Data) {
		if len(d.Incidents) != 0 {
			t.Errorf("закрытый инцидент открыт повторно: %v", d.Incidents)
		}
	})
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run не завершился после отмены")
	}
}

// Алерт исчез до T0: запись not_routed/resolved_before_collect без вызова модели, затем закрытие.
func TestServiceResolvedBeforeCollect(t *testing.T) {
	f := newSvcFixture(t, 2)
	f.s.D.Poll = 20 * time.Millisecond
	f.alerts.set([]Alert{f.alert}, nil)
	f.s.inflight = map[string]bool{}
	if err := f.s.poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.alerts.set(nil, nil)
	f.s.poll(context.Background())
	f.s.poll(context.Background())
	var id string
	f.st.View(func(d *Data) {
		for k, inc := range d.Incidents {
			id = k
			if inc.Status != StatusClosing {
				t.Fatalf("статус %s", inc.Status)
			}
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- f.s.Run(ctx) }()
	eventually(t, "запись resolved_before_collect", func() bool { return f.s.Pipe.Writer.HasIncidentRecord(id) })
	eventually(t, "закрытие", func() bool { return len(f.cr.ids()) == 1 })
	cancel()
	<-done
}

// CloseIncident падает (store роутера) — инцидент остаётся closing и закрывается при следующем проходе.
func TestCloseResolvedRetry(t *testing.T) {
	f := newSvcFixture(t, 1)
	f.s.inflight = map[string]bool{}
	f.alerts.set([]Alert{f.alert}, nil)
	f.s.poll(context.Background())
	f.alerts.set(nil, nil)
	f.s.poll(context.Background())
	var inc Incident
	f.st.View(func(d *Data) {
		for _, i := range d.Incidents {
			inc = *i
		}
	})
	if inc.Status != StatusClosing {
		t.Fatalf("статус %s", inc.Status)
	}
	if err := f.s.Pipe.RecordNotRouted(inc, ServiceConfig{Service: "svc", Namespace: "ns"}, "resolved_before_collect"); err != nil {
		t.Fatal(err)
	}
	f.cr.fail.Store(true)
	f.s.closeResolved(context.Background())
	if _, ok := f.st.Get(inc.ID); !ok || len(f.cr.ids()) != 0 {
		t.Fatal("закрытие при ошибке роутера")
	}
	f.cr.fail.Store(false)
	f.s.closeResolved(context.Background())
	if _, ok := f.st.Get(inc.ID); ok || len(f.cr.ids()) != 1 {
		t.Fatalf("повтор закрытия не прошёл: %v", f.cr.ids())
	}
	// инцидент в обработке не закрывается
	f.s.closeResolved(context.Background())
	if len(f.cr.ids()) != 1 {
		t.Error("повторное закрытие")
	}
}

// Рестарт: open без записи → обрабатывается; closing с записью → дозакрывается.
func TestServiceRestartRecovery(t *testing.T) {
	f := newSvcFixture(t, 2)
	now := f.clk.now()
	mk := func(svc string, st string, opened time.Time) Incident {
		k := Key{"staging", f.alert.Namespace, f.alert.Service}
		inc := Incident{ID: IncidentID(k, f.alert.StartsAt), Key: k, FirstAlertAt: f.alert.StartsAt, OpenedAt: opened, Alerts: map[string]time.Time{f.alert.Fingerprint: opened},
			Alert: f.alert, Status: st}
		return inc
	}
	inc := mk("", StatusOpen, now.Add(-10*time.Minute)) // T0 давно наступил
	f.st.Do(func(d *Data) { d.Incidents[inc.ID] = &inc })
	f.alerts.set([]Alert{f.alert}, nil)
	f.s.D.Poll = 20 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- f.s.Run(ctx) }()
	eventually(t, "обработка open без записи", func() bool { return f.s.Pipe.Writer.HasIncidentRecord(inc.ID) })
	cancel()
	<-done
	// второй запуск: запись есть, инцидент closing → дозакрытие без повторной записи
	f.st.Do(func(d *Data) { d.Incidents[inc.ID].Status = StatusClosing })
	f.alerts.set(nil, nil)
	ctx2, cancel2 := context.WithCancel(context.Background())
	go func() { done <- f.s.Run(ctx2) }()
	eventually(t, "дозакрытие closing", func() bool { return len(f.cr.ids()) == 1 })
	cancel2()
	<-done
	if f.cr.ids()[0] != inc.ID {
		t.Errorf("закрыт %v", f.cr.ids())
	}
}

func TestCleanSnapshots(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	mkf := func(name string, age time.Duration) {
		p := dir + "/" + name
		if err := writeFileAtomic(dir, name, []byte("x")); err != nil {
			t.Fatal(err)
		}
		_ = p
		old := now.Add(-age)
		if err := osChtimes(p, old); err != nil {
			t.Fatal(err)
		}
	}
	mkf("old.json", 91*24*time.Hour)
	mkf("new.json", 24*time.Hour)
	mkf("note.txt", 200*24*time.Hour)
	n, err := CleanSnapshots(dir, 90*24*time.Hour, now)
	if err != nil || n != 1 {
		t.Fatalf("удалено %d, %v", n, err)
	}
	if _, err := CleanSnapshots(dir+"/нет", time.Hour, now); err != nil {
		t.Errorf("нет каталога: %v", err)
	}
}

func osChtimes(p string, t time.Time) error { return os.Chtimes(p, t, t) }
