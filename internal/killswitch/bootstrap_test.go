package killswitch

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/limpjungle/aegis3311/internal/audit"
	"github.com/limpjungle/aegis3311/internal/killswitch/s3"
)

// Тесты bootstrap (intake без истории), stop из будущего, обнаружения отката канала, Observe и Renew.Peers.

func ts(t time.Time) string { return audit.Timestamp(t) }

func lastEv(t *testing.T, f *mfix) audit.KillSwitchEvent {
	t.Helper()
	if len(f.ev.evs) == 0 {
		t.Fatal("событий нет")
	}
	return f.ev.evs[len(f.ev.evs)-1]
}

func TestBootstrapOldRunDoesNotRelease(t *testing.T) {
	ctx := context.Background()
	f := newMFixFresh(t)
	// свежий (по TTL) run двух дежурных, выпущенный до старта intake
	f.both(f.tk.doc(t, false, nil, nil, t0, 6*time.Hour, "a", "b"))
	if err := f.m.PollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if !f.m.Stopped() || f.m.State().Reason != "no_confirmation" {
		t.Fatalf("старый run без истории снял остановку: %+v", f.m.State().KillSwitchState)
	}
	ev := lastEv(t, f)
	if ev.Kind != "kill_switch_engaged" || !ev.Bootstrap || ev.From != "none" || ev.StopWatermark != ts(f.now) {
		t.Fatalf("событие bootstrap: kind=%s bootstrap=%v from=%s W=%s now=%s", ev.Kind, ev.Bootstrap, ev.From, ev.StopWatermark, ts(f.now))
	}
	o := f.m.Observe()
	if o.BootstrapPending || !o.BootstrapAwaitingRelease {
		t.Errorf("Observe после bootstrap: pending=%v awaiting=%v", o.BootstrapPending, o.BootstrapAwaitingRelease)
	}
	if !strings.Contains(f.logs.String(), "kill_switch_bootstrap") {
		t.Errorf("нет лога kill_switch_bootstrap: %s", f.logs)
	}
	// повторные опросы: ни событий, ни снятия
	n := len(f.ev.evs)
	for i := 0; i < 3; i++ {
		f.now = f.now.Add(10 * time.Second)
		f.m.PollOnce(ctx)
	}
	if len(f.ev.evs) != n || !f.m.Stopped() {
		t.Errorf("повторные опросы: событий %d -> %d, stopped=%v", n, len(f.ev.evs), f.m.Stopped())
	}
	// release позже W снимает; следующее событие уже не bootstrap
	rel := f.now.Add(time.Second)
	f.both(f.tk.doc(t, false, nil, nil, rel, time.Hour, "a", "b"))
	if err := f.m.PollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if f.m.Stopped() {
		t.Fatal("release двух дежурных позже W не снял остановку")
	}
	ev = lastEv(t, f)
	if ev.Kind != "kill_switch_released" || ev.From != "stopped" || ev.Bootstrap {
		t.Errorf("событие release: %+v", ev)
	}
	if o := f.m.Observe(); o.BootstrapAwaitingRelease {
		t.Error("после release bootstrap_awaiting_release должен быть 0")
	}
}

func TestBootstrapReleaseInsideSkewPassesOnFirstPoll(t *testing.T) {
	f := newMFixFresh(t)
	f.both(f.tk.doc(t, false, nil, nil, f.now.Add(time.Minute), time.Hour, "a", "b")) // в пределах max_skew=2m вперёд
	if err := f.m.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.m.Stopped() {
		t.Fatal("release двумя oncall с issued_at > now в пределах skew должен пройти в первом опросе")
	}
	if ev := lastEv(t, f); ev.Kind != "kill_switch_released" || !ev.Bootstrap || ev.From != "none" {
		t.Errorf("событие: %+v", ev)
	}
}

func TestBootstrapEqualIssuedAtDoesNotRelease(t *testing.T) {
	f := newMFixFresh(t)
	f.both(f.tk.doc(t, false, nil, nil, f.now, time.Hour, "a", "b")) // issued_at == W: строго After
	f.m.PollOnce(context.Background())
	if !f.m.Stopped() {
		t.Fatal("issued_at == W не должен снимать остановку")
	}
}

func TestBootstrapRenewerAndReplayWithoutHistory(t *testing.T) {
	ctx := context.Background()
	// renewer без истории (ветка W.IsZero) не снимает
	f := newMFixFresh(t)
	f.both(f.tk.doc(t, false, nil, nil, t0, 6*time.Hour, "r1", "r2"))
	f.m.PollOnce(ctx)
	if !f.m.Stopped() {
		t.Fatal("renewer без истории снял остановку")
	}
	// ... и даже документ renewer'а позже W, пока release двумя oncall не было
	f.both(f.tk.doc(t, false, nil, nil, f.now.Add(time.Second), 6*time.Hour, "r1", "r2"))
	f.m.PollOnce(ctx)
	if !f.m.Stopped() {
		t.Fatal("renewer позже W_boot без release снял остановку")
	}
	// oncall release позже W_boot; затем oncall-документ протух, а renewer продлевает
	f.both(f.tk.doc(t, false, nil, nil, f.now.Add(2*time.Second), 10*time.Minute, "a", "b"))
	f.m.PollOnce(ctx)
	if f.m.Stopped() {
		t.Fatal("release двумя oncall не снял")
	}
	f.now = f.now.Add(30 * time.Minute)
	f.both(f.tk.doc(t, false, nil, nil, f.now, 6*time.Hour, "r1", "r2"))
	f.m.PollOnce(ctx)
	if f.m.Stopped() || !f.m.State().LivenessConfirmed {
		t.Fatalf("после release renewer должен продлевать: %+v", f.m.State().KillSwitchState)
	}

	// replay: стёртый stop + старый свежий run (oncall и renewer) — тоже остановлен
	for _, who := range [][]string{{"a", "b"}, {"r1", "r2"}} {
		r := newMFixFresh(t)
		r.both(r.tk.doc(t, false, nil, nil, t0.Add(-time.Hour), 6*time.Hour, who...))
		if err := r.m.PollOnce(ctx); err != nil {
			t.Fatal(err)
		}
		if !r.m.Stopped() {
			t.Errorf("replay без истории, подписи %v: остановка снята", who)
		}
	}
}

func TestRestoreBootstrapVariants(t *testing.T) {
	ctx := context.Background()
	// пустой stop_watermark (цепочка 320addb): bootstrap остаётся, старый run не снимает
	f := newMFixFresh(t)
	f.m.Restore(audit.KillSwitchEvent{From: "none", State: audit.KillSwitchState{Stopped: false, Actions: []string{}}}, true)
	if !f.m.Observe().BootstrapPending {
		t.Fatal("пустой stop_watermark должен оставлять bootstrap")
	}
	f.both(f.tk.doc(t, false, nil, nil, t0, 6*time.Hour, "a", "b"))
	if err := f.m.PollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if !f.m.Stopped() {
		t.Fatal("наследная цепочка без W: старый run снял остановку")
	}
	// отклонение 4: событие без пометки bootstrap (from != none), но W поднят до now и запомнен
	ev := lastEv(t, f)
	if ev.Bootstrap || ev.From != "running" || ev.StopWatermark != ts(f.now) {
		t.Errorf("наследная цепочка: bootstrap=%v from=%s W=%s", ev.Bootstrap, ev.From, ev.StopWatermark)
	}
	if !f.m.Observe().BootstrapAwaitingRelease {
		t.Error("awaiting_release должен быть 1")
	}

	// восстановление из события bootstrap: повтора нет, bootW восстановлен
	a := newMFixFresh(t)
	a.both(a.tk.doc(t, false, nil, nil, t0, 6*time.Hour, "a", "b"))
	a.m.PollOnce(ctx)
	boot := lastEv(t, a)
	if !boot.Bootstrap {
		t.Fatal("нет bootstrap-события")
	}
	b := newMFixFresh(t)
	b.now = a.now.Add(5 * time.Minute)
	b.m.Restore(boot, true)
	o := b.m.Observe()
	if o.BootstrapPending || !o.BootstrapAwaitingRelease {
		t.Fatalf("после Restore: pending=%v awaiting=%v", o.BootstrapPending, o.BootstrapAwaitingRelease)
	}
	b.both(b.tk.doc(t, false, nil, nil, t0, 6*time.Hour, "a", "b"))
	if err := b.m.PollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if len(b.ev.evs) != 0 {
		t.Errorf("повторный bootstrap после рестарта: %+v", b.ev.evs)
	}
	if !b.m.Stopped() {
		t.Error("после рестарта W (из события) не должен сдвигаться, старый run не подтверждает")
	}
	if got := b.m.State().Marks.Stop; !got.Equal(a.now) {
		t.Errorf("W после рестарта %s, ожидалось %s (не now рестарта)", got, a.now)
	}
	// release позже W_boot снимает
	b.both(b.tk.doc(t, false, nil, nil, a.now.Add(time.Second), time.Hour, "a", "b"))
	b.m.PollOnce(ctx)
	if b.m.Stopped() {
		t.Error("release позже W_boot после рестарта не снял")
	}
}

func TestBootstrapWriteFailureRetries(t *testing.T) {
	ctx := context.Background()
	f := newMFixFresh(t)
	f.both(f.tk.doc(t, false, nil, nil, f.now.Add(time.Second), time.Hour, "a", "b")) // release для первого опроса
	f.ev.fail = errors.New("диск")
	if err := f.m.PollOnce(ctx); err == nil {
		t.Fatal("сбой записи bootstrap должен вернуть ошибку")
	}
	if !f.m.Stopped() {
		t.Fatal("при сбое записи цель должна остаться остановленной")
	}
	o := f.m.Observe()
	if !o.BootstrapPending || !o.LastPoll.IsZero() {
		t.Errorf("после сбоя: pending=%v lastPoll=%v", o.BootstrapPending, o.LastPoll)
	}
	f.ev.fail = nil
	f.now = f.now.Add(time.Minute)
	if err := f.m.PollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	ev := lastEv(t, f)
	if !ev.Bootstrap || ev.StopWatermark != ts(f.now) {
		t.Errorf("повторный bootstrap: %+v", ev)
	}
	if !f.m.Stopped() {
		t.Error("release, выпущенный до нового W, не должен снять остановку")
	}
}

func TestFutureStop(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name     string
		global   bool
		clusters []string
		actions  []string
		reason   string
	}{
		{"global", true, nil, nil, "global"},
		{"cluster", false, []string{"c1"}, nil, "cluster"},
		{"actions", false, nil, []string{"workload.restart"}, "no_confirmation"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newMFix(t)
			marks := f.m.marks
			f.cm.set(f.tk.doc(t, tc.global, tc.clusters, tc.actions, f.now.Add(10*time.Minute), time.Hour, "a"), nil)
			if err := f.m.PollOnce(ctx); err != nil {
				t.Fatal(err)
			}
			st := f.m.State()
			if !st.Stopped || st.Reason != tc.reason {
				t.Fatalf("состояние: %+v", st.KillSwitchState)
			}
			if tc.actions != nil && len(st.Actions) != 1 {
				t.Errorf("actions: %v", st.Actions)
			}
			if st.Marks != marks || st.LivenessConfirmed {
				t.Errorf("stop из будущего двинул W/R или подтвердил: %+v live=%v", st.Marks, st.LivenessConfirmed)
			}
			n := len(f.ev.evs)
			if n != 1 {
				t.Fatalf("событий %d", n)
			}
			if ev := lastEv(t, f); tc.actions == nil && (ev.LatencyMs == nil || *ev.LatencyMs >= 0) {
				t.Errorf("latency у будущего stop: %v", ev.LatencyMs)
			}
			for i := 0; i < 3; i++ {
				f.m.PollOnce(ctx)
			}
			if len(f.ev.evs) != n {
				t.Errorf("повторные опросы породили события: %d", len(f.ev.evs)-n)
			}
			// release now заменяет документы в каналах и снимает остановку
			f.both(f.tk.doc(t, false, nil, nil, f.now, time.Hour, "b", "c"))
			if err := f.m.PollOnce(ctx); err != nil {
				t.Fatal(err)
			}
			if f.m.Stopped() {
				t.Errorf("release now после будущего stop не снял: %+v", f.m.State().KillSwitchState)
			}
		})
	}
}

func TestFutureDropped(t *testing.T) {
	ctx := context.Background()
	f := newMFix(t)
	f.cm.set(f.tk.doc(t, true, nil, nil, f.now.Add(25*time.Hour), time.Hour, "a"), nil)
	f.m.PollOnce(ctx)
	if st := f.m.State(); st.Global || st.Reason != "no_confirmation" {
		t.Errorf("stop дальше 24ч применился: %+v", st.KillSwitchState)
	}
	// run из будущего не подтверждает
	f2 := newMFix(t)
	f2.both(f2.tk.doc(t, false, nil, nil, f2.now.Add(10*time.Minute), time.Hour, "a", "b"))
	f2.m.PollOnce(ctx)
	if !f2.m.Stopped() {
		t.Error("run из будущего подтвердил")
	}
	// stop другого кластера из будущего — не stop-эффект: отброшен
	f3 := newMFix(t)
	f3.cm.set(f3.tk.doc(t, false, []string{"other"}, nil, f3.now.Add(10*time.Minute), time.Hour, "a"), nil)
	f3.m.PollOnce(ctx)
	if f3.m.State().Cluster {
		t.Error("stop чужого кластера применился")
	}
	// ровно в пределах суток — применяется
	f4 := newMFix(t)
	f4.cm.set(f4.tk.doc(t, true, nil, nil, f4.now.Add(23*time.Hour), time.Hour, "a"), nil)
	f4.m.PollOnce(ctx)
	if !f4.m.State().Global {
		t.Error("stop за 23ч не применился")
	}
}

func TestChannelRegressionLogged(t *testing.T) {
	ctx := context.Background()
	for _, errKind := range []string{"http_404", "no_document", "http_403"} {
		f := newMFix(t)
		f.cm.set(f.tk.doc(t, true, nil, nil, f.now, time.Hour, "a"), nil)
		f.m.PollOnce(ctx)
		before := f.m.State()
		f.cm.set(nil, kerr(errKind))
		f.m.PollOnce(ctx)
		f.m.PollOnce(ctx)
		if got := strings.Count(f.logs.String(), "kind=stop_removed"); got != 1 {
			t.Errorf("%s: stop_removed залогирован %d раз, ожидался 1: %s", errKind, got, f.logs)
		}
		if !f.m.Stopped() || before.Marks != f.m.State().Marks {
			t.Errorf("%s: лог отката повлиял на состояние", errKind)
		}
	}
	// stop не было — 404 не повод для лога
	f := newMFix(t)
	f.cm.set(f.tk.doc(t, false, nil, nil, f.now, time.Hour, "a", "b"), nil)
	f.m.PollOnce(ctx)
	f.cm.set(nil, kerr("http_404"))
	f.m.PollOnce(ctx)
	if strings.Contains(f.logs.String(), "kill_switch_channel_regressed") {
		t.Errorf("лог при пропаже run: %s", f.logs)
	}
	// older_document: один лог на переход
	g := newMFix(t)
	g.cm.set(g.tk.doc(t, false, nil, nil, g.now, time.Hour, "a", "b"), nil)
	g.m.PollOnce(ctx)
	g.cm.set(g.tk.doc(t, false, nil, nil, g.now.Add(-30*time.Minute), 2*time.Hour, "a", "b"), nil)
	g.m.PollOnce(ctx)
	g.m.PollOnce(ctx)
	if got := strings.Count(g.logs.String(), "kind=older_document"); got != 1 {
		t.Errorf("older_document залогирован %d раз: %s", got, g.logs)
	}
	// переход вперёд не логируется
	g.cm.set(g.tk.doc(t, false, nil, nil, g.now.Add(time.Second), time.Hour, "a", "b"), nil)
	g.m.PollOnce(ctx)
	if got := strings.Count(g.logs.String(), "kind=older_document"); got != 1 {
		t.Errorf("лог при движении вперёд: %d", got)
	}
}

func TestObserve(t *testing.T) {
	ctx := context.Background()
	f := newMFixFresh(t)
	o := f.m.Observe()
	if !o.BootstrapPending || !o.BootstrapAwaitingRelease || !o.LastPoll.IsZero() || o.LastEngagedLatencyMs != nil || len(o.Events) != 0 {
		t.Fatalf("до первого опроса: %+v", o)
	}
	f.both(f.tk.doc(t, false, nil, nil, t0, 6*time.Hour, "a", "b"))
	f.m.PollOnce(ctx)
	o = f.m.Observe()
	if o.BootstrapPending || !o.BootstrapAwaitingRelease || !o.LastPoll.Equal(f.now) || o.Events["kill_switch_engaged"] != 1 {
		t.Fatalf("после bootstrap: %+v", o)
	}
	if o.ChannelLastOK["configmap"] != f.now || o.ChannelLastOK["oob"] != f.now {
		t.Errorf("ChannelLastOK: %v", o.ChannelLastOK)
	}
	// stop двумя правками: latency
	f.now = f.now.Add(10 * time.Second)
	f.cm.set(f.tk.doc(t, true, nil, nil, f.now.Add(-2*time.Second), time.Hour, "a"), nil)
	f.m.PollOnce(ctx) // stop при уже остановленной цели: updated, не engaged
	if o = f.m.Observe(); o.Events["kill_switch_updated"] != 1 {
		t.Errorf("updated: %v", o.Events)
	}
	// release, затем stop
	f.now = f.now.Add(10 * time.Second)
	f.both(f.tk.doc(t, false, nil, nil, f.now, time.Hour, "b", "c"))
	f.m.PollOnce(ctx)
	o = f.m.Observe()
	if o.BootstrapAwaitingRelease || o.Events["kill_switch_released"] != 1 {
		t.Errorf("после release: %+v", o)
	}
	pollAt := o.LastPoll
	// кэш не считается успешным чтением; упавшая запись не двигает LastPoll
	f.now = f.now.Add(10 * time.Second)
	f.cm.set(nil, kerr("timeout"))
	f.m.PollOnce(ctx)
	if got := f.m.Observe(); got.ChannelLastOK["configmap"].Equal(f.now) || !got.ChannelLastOK["oob"].Equal(f.now) {
		t.Errorf("ChannelLastOK из кэша: %v now=%s", got.ChannelLastOK, f.now)
	}
	f.now = f.now.Add(10 * time.Second)
	f.both(f.tk.doc(t, true, nil, nil, f.now.Add(-1500*time.Millisecond), time.Hour, "a"))
	f.ev.fail = errors.New("диск")
	last := f.m.Observe().LastPoll
	if err := f.m.PollOnce(ctx); err == nil {
		t.Fatal("ожидалась ошибка записи")
	}
	if got := f.m.Observe(); !got.LastPoll.Equal(last) || !last.After(pollAt) {
		t.Errorf("LastPoll изменился при сбое записи: %s -> %s", last, got.LastPoll)
	}
	f.ev.fail = nil
	f.m.PollOnce(ctx)
	o = f.m.Observe()
	if o.Events["kill_switch_engaged"] != 2 || o.LastEngagedLatencyMs == nil || *o.LastEngagedLatencyMs != 1500 {
		t.Errorf("engaged/latency: %v %v", o.Events, o.LastEngagedLatencyMs)
	}
	// копия: изменение снимка не влияет на монитор
	o.Events["kill_switch_engaged"] = 99
	o.State.Actions = append(o.State.Actions, "x")
	if f.m.Observe().Events["kill_switch_engaged"] != 2 {
		t.Error("Observe вернул не копию")
	}
}

func TestMonitorConcurrentObservePollGuard(t *testing.T) {
	f := newMFix(t)
	f.both(f.tk.doc(t, false, nil, nil, f.now, time.Hour, "a", "b"))
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(3)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				f.m.Observe()
				f.m.State()
				f.m.Stopped()
			}
		}()
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				g, c := f.m.Guard(ctx)
				_ = g
				c()
			}
		}()
		go func(i int) {
			defer wg.Done()
			for j := 0; ctx.Err() == nil; j++ {
				if j%2 == 0 {
					f.both(f.tk.doc(t, true, nil, nil, f.now, time.Hour, "a"))
				} else {
					f.both(f.tk.doc(t, false, nil, nil, f.now, time.Hour, "a", "b"))
				}
				f.m.PollOnce(context.Background())
			}
		}(i)
	}
	time.Sleep(300 * time.Millisecond)
	cancel()
	wg.Wait()
}

type sigs403 struct{ memSigs }

func (s sigs403) Get(context.Context, string) ([]byte, error) {
	return nil, &s3.Error{Kind: "http_403"}
}

func TestRenewPeers(t *testing.T) {
	tk := newTKeys(t)
	ctx := context.Background()
	now := time.Date(2026, 11, 8, 10, 20, 0, 0, time.UTC)
	cfg := RenewConfig{Slot: time.Hour, TTL: 6 * time.Hour, Prefix: "renew/"}
	mk := func() []ChannelIO { return []ChannelIO{&memChan{name: "configmap", err: &s3.Error{Kind: "http_404"}}} }
	r, err := Renew(ctx, now, cfg, tk.signers["r1"], tk.ring, mk(), memSigs{}, ParseOptions{})
	if err != nil || r.Action != "waiting_peer" || len(r.Peers) != 1 || r.Peers[0].Status != "missing" || r.Peers[0].KeyID == "" {
		t.Fatalf("404: %+v %v", r, err)
	}
	r, err = Renew(ctx, now, cfg, tk.signers["r1"], tk.ring, mk(), sigs403{memSigs{}}, ParseOptions{})
	if err != nil || r.Action != "waiting_peer" || len(r.Peers) != 1 || r.Peers[0].Status != "http_403" {
		t.Fatalf("403: %+v %v", r, err)
	}
	shared := memSigs{}
	if _, err := Renew(ctx, now, cfg, tk.signers["r1"], tk.ring, mk(), shared, ParseOptions{}); err != nil {
		t.Fatal(err)
	}
	r, err = Renew(ctx, now, cfg, tk.signers["r2"], tk.ring, mk(), shared, ParseOptions{})
	if err != nil || r.Action != "published" || len(r.Peers) != 1 || r.Peers[0].Status != "ok" {
		t.Fatalf("ok: %+v %v", r, err)
	}
}
