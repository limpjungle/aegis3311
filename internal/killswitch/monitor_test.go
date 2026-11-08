package killswitch

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/limpjungle/aegis3311/internal/audit"
)

type fakeSrc struct {
	name string
	mu   sync.Mutex
	raw  []byte
	err  error
}

func (f *fakeSrc) Channel() string { return f.name }
func (f *fakeSrc) Fetch(context.Context) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.raw, f.err
}
func (f *fakeSrc) set(raw []byte, err error) { f.mu.Lock(); f.raw, f.err = raw, err; f.mu.Unlock() }

type kerr string

func (k kerr) Error() string   { return string(k) }
func (k kerr) ErrKind() string { return string(k) }

type fakeEvents struct {
	mu   sync.Mutex
	evs  []audit.KillSwitchEvent
	fail error
}

func (f *fakeEvents) AppendKillSwitchEvent(ev *audit.KillSwitchEvent) (audit.Entry, error) {
	if err := ev.Validate(); err != nil {
		return audit.Entry{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return audit.Entry{}, f.fail
	}
	f.evs = append(f.evs, *ev)
	return audit.Entry{}, nil
}

type mfix struct {
	tk      *tkeys
	cm, oob *fakeSrc
	ev      *fakeEvents
	m       *Monitor
	now     time.Time
	logs    *bytes.Buffer
}

func newMFix(t *testing.T) *mfix {
	f := &mfix{tk: newTKeys(t), cm: &fakeSrc{name: "configmap", err: kerr("http_404")}, oob: &fakeSrc{name: "oob", err: kerr("http_404")},
		ev: &fakeEvents{}, now: t0.Add(time.Minute), logs: &bytes.Buffer{}}
	f.m = NewMonitor([]Source{f.cm, f.oob}, f.tk.ring, ParseOptions{}, Options{Cluster: "c1", MaxSkew: 2 * time.Minute}, time.Second, time.Second,
		f.ev, audit.Actor{Kind: "system", ID: "intake-1"})
	f.m.Now = func() time.Time { return f.now }
	f.m.Log = slog.New(slog.NewTextHandler(f.logs, nil))
	return f
}

func (f *mfix) both(raw []byte) { f.cm.set(raw, nil); f.oob.set(raw, nil) }

func TestMonitorInitialStoppedAndGuard(t *testing.T) {
	f := newMFix(t)
	if !f.m.Stopped() || f.m.State().Reason != "no_confirmation" {
		t.Fatal("до PollOnce цель должна быть остановлена")
	}
	g, cancel := f.m.Guard(context.Background())
	defer cancel()
	if !errors.Is(context.Cause(g), ErrEngaged) {
		t.Error("Guard остановленной цели должен быть отменён сразу")
	}
}

func TestMonitorReleaseStopRelease(t *testing.T) {
	f := newMFix(t)
	ctx := context.Background()
	f.both(f.tk.doc(t, false, nil, nil, t0, time.Hour, "a", "b"))
	if err := f.m.PollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if f.m.Stopped() || len(f.ev.evs) != 1 || f.ev.evs[0].Kind != "kill_switch_released" || f.ev.evs[0].From != "none" {
		t.Fatalf("первый run: %+v", f.ev.evs)
	}
	f.m.PollOnce(ctx)
	if len(f.ev.evs) != 1 {
		t.Error("повтор записал событие")
	}
	g, cancel := f.m.Guard(ctx)
	defer cancel()
	if g.Err() != nil {
		t.Fatal("Guard работающей цели отменён")
	}
	// stop в одном канале с одной подписью, issued_at на 1.5 с раньше "сейчас"
	f.now = t0.Add(2 * time.Minute)
	f.cm.set(f.tk.doc(t, true, nil, nil, f.now.Add(-1500*time.Millisecond), time.Hour, "a"), nil)
	if err := f.m.PollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if !f.m.Stopped() || len(f.ev.evs) != 2 {
		t.Fatalf("stop: %+v", f.ev.evs)
	}
	ev := f.ev.evs[1]
	if ev.Kind != "kill_switch_engaged" || ev.From != "running" || ev.State.Reason != "global" || ev.LatencyMs == nil || *ev.LatencyMs != 1500 {
		t.Errorf("событие stop: %+v latency=%v", ev, ev.LatencyMs)
	}
	<-g.Done()
	if !errors.Is(context.Cause(g), ErrEngaged) {
		t.Error("Guard не отменён с ErrEngaged")
	}
	if !strings.Contains(f.logs.String(), "kill_switch_engaged") || !strings.Contains(f.logs.String(), "latency_ms=1500") {
		t.Errorf("журнал: %s", f.logs)
	}
	// снятие: run двумя oncall новее stop в обоих каналах
	f.now = t0.Add(3 * time.Minute)
	f.both(f.tk.doc(t, false, nil, nil, f.now, time.Hour, "b", "c"))
	f.ev.fail = errors.New("диск")
	if err := f.m.PollOnce(ctx); err == nil {
		t.Fatal("сбой записи должен вернуть ошибку")
	}
	if !f.m.Stopped() {
		t.Fatal("при сбое записи снятия цель должна остаться остановленной")
	}
	f.ev.fail = nil
	if err := f.m.PollOnce(ctx); err != nil || f.m.Stopped() {
		t.Fatalf("снятие: %v stopped=%v", err, f.m.Stopped())
	}
	if last := f.ev.evs[len(f.ev.evs)-1]; last.Kind != "kill_switch_released" || last.From != "stopped" {
		t.Errorf("событие снятия: %+v", last)
	}
}

func TestMonitorCache(t *testing.T) {
	f := newMFix(t)
	ctx := context.Background()
	f.both(f.tk.doc(t, false, nil, nil, t0, time.Hour, "a", "b"))
	f.m.PollOnce(ctx)
	// транспортная ошибка держит кэш
	f.cm.set(nil, kerr("timeout"))
	f.oob.set(nil, kerr("http_503"))
	f.m.PollOnce(ctx)
	if f.m.Stopped() {
		t.Error("транспортная ошибка не должна снимать подтверждение до TTL")
	}
	// после TTL — остановка
	f.now = t0.Add(2 * time.Hour)
	f.m.PollOnce(ctx)
	if !f.m.Stopped() {
		t.Error("по истечении TTL цель должна быть остановлена")
	}
	// 404 сбрасывает кэш сразу
	f2 := newMFix(t)
	f2.both(f2.tk.doc(t, false, nil, nil, t0, time.Hour, "a", "b"))
	f2.m.PollOnce(ctx)
	f2.cm.set(nil, kerr("http_404"))
	f2.oob.set([]byte(`{"schema":"x"}`), nil)
	f2.m.PollOnce(ctx)
	if !f2.m.Stopped() {
		t.Error("404 и невалидный документ должны сбросить кэш")
	}
}

func TestMonitorRestoreWatermarks(t *testing.T) {
	f := newMFix(t)
	ctx := context.Background()
	f.both(f.tk.doc(t, false, nil, nil, t0, time.Hour, "a", "b"))
	f.m.PollOnce(ctx)
	f.now = t0.Add(2 * time.Minute)
	f.both(f.tk.doc(t, true, nil, nil, f.now, time.Hour, "a"))
	f.m.PollOnce(ctx)
	last := f.ev.evs[len(f.ev.evs)-1]
	// «рестарт»: новый монитор, старый run в каналах не подтверждает (W восстановлен)
	f2 := newMFix(t)
	f2.tk = f.tk
	f2.m.Keys = f.tk.ring
	f2.m.Restore(last, true)
	f2.now = f.now
	f2.both(f.tk.doc(t, false, nil, nil, t0, time.Hour, "a", "b"))
	f2.m.PollOnce(ctx)
	if !f2.m.Stopped() {
		t.Error("старый run подтвердил после рестарта")
	}
	// renewer после рестарта не подтверждает без R > W
	f2.both(f.tk.doc(t, false, nil, nil, f.now.Add(time.Second), time.Hour, "r1", "r2"))
	f2.m.PollOnce(ctx)
	if !f2.m.Stopped() {
		t.Error("renewer снял остановку")
	}
	f2.both(f.tk.doc(t, false, nil, nil, f.now.Add(2*time.Second), time.Hour, "a", "b"))
	f2.m.PollOnce(ctx)
	if f2.m.Stopped() {
		t.Error("run двух oncall новее W должен снять остановку")
	}
}

func TestMonitorChannelWarnAndExpiring(t *testing.T) {
	f := newMFix(t)
	ctx := context.Background()
	f.both(f.tk.doc(t, false, nil, nil, t0, 6*time.Hour, "a", "b"))
	f.cm.set(nil, kerr("timeout"))
	f.m.PollOnce(ctx)
	if !strings.Contains(f.logs.String(), "kill_switch_channel") || len(f.ev.evs) != 1 {
		t.Errorf("мигание канала: %s %d", f.logs, len(f.ev.evs))
	}
	f.now = t0.Add(5 * time.Hour)
	f.both(f.tk.doc(t, false, nil, nil, t0, 6*time.Hour, "a", "b"))
	f.m.PollOnce(ctx)
	if !strings.Contains(f.logs.String(), "kill_switch_confirmation_expiring") {
		t.Errorf("нет предупреждения об истечении: %s", f.logs)
	}
}
