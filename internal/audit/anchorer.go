package audit

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"
)

// AnchorPolicy — как часто фиксировать голову цепочки и какое отставание считать аварийным.
// Отставание запись не блокирует: остановка изменяющих действий при переполнении относится к G1 (CH-A14).
type AnchorPolicy struct{ Interval, MaxLag time.Duration }

// AnchorStatus — снимок для метрик и оператора.
type AnchorStatus struct {
	AnchoredSeq, HeadSeq     uint64
	LastSuccess, LastAttempt time.Time
	LastError                string // класс ошибки (s3.Error.Kind), без тел ответов; пусто — последняя попытка успешна
	Errors                   uint64
	Lag                      time.Duration // now - время первой незафиксированной записи; 0 — всё зафиксировано
	Lagging                  bool          // Lag > MaxLag
}

// Anchorer периодически подписывает голову цепочки и выгружает checkpoint во внешнее хранилище.
type Anchorer struct {
	W      *Writer
	Store  Anchor
	Policy AnchorPolicy
	Now    func() time.Time
	Log    *slog.Logger

	run          sync.Mutex // одна фиксация за раз
	mu           sync.Mutex
	st           AnchorStatus
	laggingShown bool
}

// NewAnchorer создаёт Anchorer; now == nil → time.Now, lg == nil → без вывода.
func NewAnchorer(w *Writer, s Anchor, p AnchorPolicy, now func() time.Time, lg *slog.Logger) *Anchorer {
	if now == nil {
		now = time.Now
	}
	if lg == nil {
		lg = slog.New(slog.DiscardHandler)
	}
	return &Anchorer{W: w, Store: s, Policy: p, Now: now, Log: lg}
}

// errKind — класс ошибки хранилища (ErrKind, как у s3.Error); прочее — "error".
func errKind(err error) string {
	var k interface{ ErrKind() string }
	if errors.As(err, &k) {
		return k.ErrKind()
	}
	return "error"
}

// AnchorNow фиксирует голову, если появились незафиксированные записи. Голова уже зафиксирована — nil без обращений к хранилищу.
func (a *Anchorer) AnchorNow() error {
	a.run.Lock()
	defer a.run.Unlock()
	anchored, head, _ := a.W.AnchorState()
	if head == anchored {
		return nil
	}
	now := a.Now()
	a.mu.Lock()
	a.st.LastAttempt = now
	a.mu.Unlock()
	cp, err := a.W.Checkpoint()
	if err == nil {
		err = a.Store.Put(cp)
	}
	if err != nil {
		kind := errKind(err)
		if errors.Is(err, ErrWriterFailed) {
			kind = "writer_failed" // остановкой занимается владелец Writer; здесь только лог
		}
		a.mu.Lock()
		a.st.LastError = kind
		a.st.Errors++
		a.mu.Unlock()
		a.Log.Error("audit_anchor_failed", "kind", kind, "anchored_seq", anchored, "head_seq", head)
		a.checkLag()
		return err
	}
	a.W.MarkAnchored(cp.Seq)
	a.mu.Lock()
	a.st.LastSuccess, a.st.LastError = now, ""
	a.mu.Unlock()
	a.Log.Info("audit_anchor_ok", "seq", cp.Seq)
	a.checkLag()
	return nil
}

// checkLag логирует переход в Lagging один раз.
func (a *Anchorer) checkLag() {
	st := a.Status()
	a.mu.Lock()
	show := st.Lagging && !a.laggingShown
	a.laggingShown = st.Lagging
	a.mu.Unlock()
	if show {
		a.Log.Error("audit_anchor_lagging", "lag", st.Lag.String(), "max_lag", a.Policy.MaxLag.String(),
			"anchored_seq", st.AnchoredSeq, "head_seq", st.HeadSeq,
			"hint", "checkpoint'ы не уходят в WORM: проверьте доступность bucket'а и ключи")
	}
}

// Run фиксирует голову сразу, затем по Policy.Interval до отмены ctx; при отмене делает последнюю попытку.
// Ошибки только учитываются в Status и логе.
func (a *Anchorer) Run(ctx context.Context) {
	a.AnchorNow()
	iv := a.Policy.Interval
	if iv <= 0 {
		iv = 5 * time.Minute
	}
	t := time.NewTicker(iv)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			a.AnchorNow()
			return
		case <-t.C:
			a.AnchorNow()
		}
	}
}

// Status — снимок состояния фиксации.
func (a *Anchorer) Status() AnchorStatus {
	anchored, head, since := a.W.AnchorState()
	a.mu.Lock()
	st := a.st
	a.mu.Unlock()
	st.AnchoredSeq, st.HeadSeq = anchored, head
	if head > anchored && !since.IsZero() {
		st.Lag = max(0, a.Now().Sub(since))
	}
	st.Lagging = a.Policy.MaxLag > 0 && st.Lag > a.Policy.MaxLag
	return st
}
