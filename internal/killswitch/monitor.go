package killswitch

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/limpjungle/aegis3311/internal/audit"
)

// ErrEngaged — причина отмены контекста Guard: цель остановлена kill switch'ем.
var ErrEngaged = errors.New("kill switch: цель остановлена")

// Source — канал доставки документа. Fetch возвращает сырые байты; ошибка с методом ErrKind() string даёт класс.
type Source interface {
	Channel() string // configmap | oob
	Fetch(ctx context.Context) ([]byte, error)
}

// EventWriter — запись событий в цепочку аудита.
type EventWriter interface {
	AppendKillSwitchEvent(*audit.KillSwitchEvent) (audit.Entry, error)
}

// Monitor опрашивает каналы, держит текущее состояние и пишет события аудита при его смене.
// До первой оценки цель остановлена (no_confirmation).
type Monitor struct {
	Sources      []Source
	Keys         Keyring
	Parse        ParseOptions
	Opt          Options
	Every        time.Duration // период опроса
	FetchTimeout time.Duration // таймаут чтения одного канала
	Events       EventWriter
	Initiator    audit.Actor
	Now          func() time.Time
	Log          *slog.Logger

	pollMu      sync.Mutex // сериализует PollOnce
	mu          sync.Mutex
	cur         State
	cache       map[string]*Verified
	marks       Marks
	lastKey     string
	lastStopped *bool
	stopCh      chan struct{} // закрыт, пока цель остановлена
	chanErr     map[string]string
	expWarned   time.Time
}

// NewMonitor создаёт монитор в состоянии «остановлен, no_confirmation».
func NewMonitor(sources []Source, keys Keyring, po ParseOptions, o Options, every, fetchTimeout time.Duration,
	ev EventWriter, initiator audit.Actor) *Monitor {
	m := &Monitor{Sources: sources, Keys: keys, Parse: po, Opt: o, Every: every, FetchTimeout: fetchTimeout,
		Events: ev, Initiator: initiator, Now: time.Now, Log: slog.Default(),
		cache: map[string]*Verified{}, stopCh: make(chan struct{}), chanErr: map[string]string{}}
	m.cur = State{KillSwitchState: audit.KillSwitchState{Stopped: true, Reason: "no_confirmation", Actions: []string{}},
		Triggers: []string{}, TriggerSigners: []string{}}
	close(m.stopCh)
	return m
}

func stateKey(s audit.KillSwitchState, mk Marks) string {
	return fmt.Sprintf("%t|%s|%t|%t|%s|%t|%d|%d", s.Stopped, s.Reason, s.Global, s.Cluster, strings.Join(s.Actions, ","),
		s.LivenessConfirmed, mk.Stop.UnixNano(), mk.Release.UnixNano())
}

// Restore восстанавливает водяные знаки и последний записанный ключ состояния из последнего события цепочки.
// Вызывается до первого PollOnce. Без события (ok == false) ничего не делает.
func (m *Monitor) Restore(ev audit.KillSwitchEvent, ok bool) {
	if !ok {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var mk Marks
	if ev.StopWatermark != "" {
		mk.Stop, _ = time.Parse(time.RFC3339Nano, ev.StopWatermark)
	}
	if ev.ReleaseWatermark != "" {
		mk.Release, _ = time.Parse(time.RFC3339Nano, ev.ReleaseWatermark)
	}
	m.marks = mk
	m.lastKey = stateKey(ev.State, mk)
	stopped := ev.State.Stopped
	m.lastStopped = &stopped
}

func (m *Monitor) logger() *slog.Logger {
	if m.Log != nil {
		return m.Log
	}
	return slog.Default()
}

// transportClass — ошибки транспорта: канал временно недоступен, последний проверенный документ действует до своего TTL.
func transportClass(c string) bool {
	return c == "timeout" || c == "network" || c == "http_429" || (len(c) == 8 && strings.HasPrefix(c, "http_5"))
}

type kinder interface{ ErrKind() string }

func errClass(err error) string {
	var k kinder
	if errors.As(err, &k) {
		if c := k.ErrKind(); c != "" {
			return c
		}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	return "network"
}

type fetched struct {
	raw []byte
	err error
}

// PollOnce читает каналы, оценивает состояние и при смене записывает событие. Ошибка — только сбой записи аудита.
func (m *Monitor) PollOnce(ctx context.Context) error {
	m.pollMu.Lock()
	defer m.pollMu.Unlock()
	res := make([]fetched, len(m.Sources))
	var wg sync.WaitGroup
	for i, s := range m.Sources {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fctx, cancel := context.WithTimeout(ctx, m.FetchTimeout)
			defer cancel()
			raw, err := s.Fetch(fctx)
			res[i] = fetched{raw, err}
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		return nil // выключение: состояние не меняем
	}
	now := m.Now()

	m.mu.Lock()
	views := make([]ChannelView, 0, len(m.Sources))
	for i, s := range m.Sources {
		name := s.Channel()
		vw := ChannelView{Channel: name}
		if err := res[i].err; err != nil {
			vw.Err = errClass(err)
			if c := m.cache[name]; c != nil && transportClass(vw.Err) {
				vw.Doc, vw.Cached = c, true
			} else {
				delete(m.cache, name)
			}
		} else if v, err := Parse(res[i].raw, m.Keys, m.Parse); err != nil {
			delete(m.cache, name)
			vw.Err = "invalid"
			var de *DocError
			if errors.As(err, &de) {
				vw.Err = de.Class
			}
		} else if v.IssuedAt.After(now.Add(m.Opt.MaxSkew)) {
			delete(m.cache, name)
			vw.Err = "future"
		} else {
			m.cache[name] = &v
			vw.Doc = &v
		}
		views = append(views, vw)
	}
	prevMarks := m.marks
	m.mu.Unlock()

	st := Evaluate(now, views, prevMarks, m.Opt)
	m.logChannels(st)
	return m.transition(now, st)
}

func (m *Monitor) logChannels(st State) {
	for _, c := range st.Channels {
		m.mu.Lock()
		prev := m.chanErr[c.Channel]
		m.chanErr[c.Channel] = c.Error
		m.mu.Unlock()
		if c.Error != "" && c.Error != prev {
			m.logger().Warn("kill_switch_channel", "channel", c.Channel, "status", c.Status, "error", c.Error, "cached", c.Cached)
		}
	}
}

// transition применяет состояние и пишет событие. Остановка: сначала применить, потом записать. Снятие: сначала
// записать, потом применить; при сбое записи цель остаётся остановленной.
func (m *Monitor) transition(now time.Time, st State) error {
	m.mu.Lock()
	key := stateKey(st.KillSwitchState, st.Marks)
	if key == m.lastKey {
		m.applyLocked(st) // событие уже в цепочке (в том числе восстановленное Restore)
		m.mu.Unlock()
		m.warnExpiring(now, st)
		return nil
	}
	from := "none"
	if m.lastStopped != nil {
		from = map[bool]string{true: "stopped", false: "running"}[*m.lastStopped]
	}
	release := !st.Stopped && m.cur.Stopped
	appliedAt := m.Now()
	if !release {
		m.applyLocked(st)
	}
	m.mu.Unlock()

	ev := &audit.KillSwitchEvent{Schema: audit.KillSwitchEventSchema, EventID: audit.NewKillSwitchEventID(),
		RecordedAt: audit.Timestamp(m.Now()), From: from, TargetCluster: m.Opt.Cluster, State: st.Info(),
		Triggers: st.Triggers, Signers: st.TriggerSigners, AppliedAt: audit.Timestamp(appliedAt),
		StopWatermark: st.Marks.stampStop(), ReleaseWatermark: st.Marks.stampRelease(),
		Channels: st.Channels, Initiator: m.Initiator}
	switch {
	case st.Stopped && from != "stopped":
		ev.Kind = "kill_switch_engaged"
	case !st.Stopped && from != "running":
		ev.Kind = "kill_switch_released"
	default:
		ev.Kind = "kill_switch_updated"
	}
	var latency int64 = -1
	if len(st.Triggers) > 0 {
		ev.IssuedAt = audit.Timestamp(st.TriggerIssuedAt)
		latency = appliedAt.Sub(st.TriggerIssuedAt).Milliseconds()
		ev.LatencyMs = &latency
	}
	if _, err := m.Events.AppendKillSwitchEvent(ev); err != nil {
		return fmt.Errorf("kill switch: запись события аудита: %w", err)
	}
	m.mu.Lock()
	if release {
		m.applyLocked(st)
	}
	m.lastKey = key
	stopped := st.Stopped
	m.lastStopped = &stopped
	m.mu.Unlock()

	m.logger().Info(ev.Kind, "reason", st.Reason, "from", from, "latency_ms", latency, "triggers", st.Triggers,
		"signers", st.TriggerSigners, "actions", st.Actions, "liveness_confirmed", st.LivenessConfirmed)
	m.warnExpiring(now, st)
	return nil
}

func (m *Monitor) applyLocked(st State) {
	was := m.cur.Stopped
	m.cur, m.marks = st, st.Marks
	switch {
	case st.Stopped && !was:
		close(m.stopCh)
	case !st.Stopped && was:
		m.stopCh = make(chan struct{})
	}
}

// warnExpiring: до конца подтверждения осталось меньше трети его TTL — продление не пришло вовремя.
func (m *Monitor) warnExpiring(now time.Time, st State) {
	if st.Stopped || st.ConfirmedUntil.IsZero() {
		return
	}
	left := st.ConfirmedUntil.Sub(now)
	if left >= st.ConfirmedTTL/3 {
		return
	}
	m.mu.Lock()
	again := !m.expWarned.Equal(st.ConfirmedUntil)
	m.expWarned = st.ConfirmedUntil
	m.mu.Unlock()
	if again {
		m.logger().Warn("kill_switch_confirmation_expiring", "confirmed_until", audit.Timestamp(st.ConfirmedUntil), "left", left.Round(time.Second).String())
	}
}

// Run опрашивает каналы до отмены ctx. Возвращает ошибку только при сбое записи аудита (фатальна: цель остаётся остановленной).
func (m *Monitor) Run(ctx context.Context) error {
	t := time.NewTicker(m.Every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if err := m.PollOnce(ctx); err != nil {
				return err
			}
		}
	}
}

// State — текущее состояние.
func (m *Monitor) State() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cur
}

// Stopped — цель сейчас остановлена.
func (m *Monitor) Stopped() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cur.Stopped
}

// Guard возвращает контекст, который отменяется с причиной ErrEngaged, когда цель останавливается. Если цель уже
// остановлена — отменён сразу.
func (m *Monitor) Guard(ctx context.Context) (context.Context, context.CancelFunc) {
	gctx, cancel := context.WithCancelCause(ctx)
	m.mu.Lock()
	ch, stopped := m.stopCh, m.cur.Stopped
	m.mu.Unlock()
	if stopped {
		cancel(ErrEngaged)
		return gctx, func() { cancel(context.Canceled) }
	}
	go func() {
		select {
		case <-ch:
			cancel(ErrEngaged)
		case <-gctx.Done():
		}
	}()
	return gctx, func() { cancel(context.Canceled) }
}

// Static — неизменное состояние без опроса: для тестов и сборок без kill switch.
type Static struct{ S State }

func (s Static) State() State  { return s.S }
func (s Static) Stopped() bool { return s.S.Stopped }
func (s Static) Guard(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithCancel(ctx)
}
