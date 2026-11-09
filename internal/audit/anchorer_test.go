package audit

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// memStore — Anchor в памяти с управляемым сбоем и блокировкой.
type memStore struct {
	mu    sync.Mutex
	puts  []Checkpoint
	err   error
	block chan struct{} // если не nil, Put ждёт закрытия
	in    chan struct{} // сигнал о входе в Put
}

func (m *memStore) Put(c Checkpoint) error {
	if m.in != nil {
		select {
		case m.in <- struct{}{}:
		default:
		}
	}
	if m.block != nil {
		<-m.block
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.puts = append(m.puts, c)
	return nil
}

func (m *memStore) setErr(e error) { m.mu.Lock(); m.err = e; m.mu.Unlock() }
func (m *memStore) seqs() []uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	var s []uint64
	for _, c := range m.puts {
		s = append(s, c.Seq)
	}
	return s
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newClock() *clock { return &clock{t: time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)} }

type kindErr struct{}

func (kindErr) Error() string   { return "s3: http_503" }
func (kindErr) ErrKind() string { return "http_503" }

func anchorWriter(t *testing.T, clk *clock) *Writer {
	t.Helper()
	s, k := newSigner(t)
	w, err := OpenWriter(filepath.Join(t.TempDir(), "c.jsonl"), "chain-anc", s, k)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.Close() })
	if clk != nil {
		w.now = clk.Now
	}
	return w
}

// appendEv дописывает событие с уникальным event_id.
func appendEv(t *testing.T, w *Writer) {
	t.Helper()
	if _, err := w.AppendEvent(validEvent("endpoint_down")); err != nil {
		t.Fatal(err)
	}
}

func TestAnchorNowNoNewEntriesDoesNothing(t *testing.T) {
	clk := newClock()
	w := anchorWriter(t, clk)
	st := &memStore{}
	a := NewAnchorer(w, st, AnchorPolicy{Interval: time.Minute, MaxLag: time.Hour}, clk.Now, nil)
	// пустая цепочка: ни ошибки, ни Put
	if err := a.AnchorNow(); err != nil || len(st.seqs()) != 0 {
		t.Fatalf("пустая цепочка: err=%v puts=%v", err, st.seqs())
	}
	appendEv(t, w)
	if err := a.AnchorNow(); err != nil {
		t.Fatal(err)
	}
	if got := st.seqs(); len(got) != 1 || got[0] != 1 {
		t.Fatalf("puts %v", got)
	}
	if err := a.AnchorNow(); err != nil || len(st.seqs()) != 1 {
		t.Fatalf("повторный AnchorNow без записей: err=%v puts=%v", err, st.seqs())
	}
	s := a.Status()
	if s.Errors != 0 || s.Lag != 0 || s.Lagging || s.AnchoredSeq != 1 || s.HeadSeq != 1 || s.LastError != "" {
		t.Fatalf("status %+v", s)
	}
}

func TestAnchorNowMarksAnchoredAndVerifies(t *testing.T) {
	clk := newClock()
	w := anchorWriter(t, clk)
	st := &memStore{}
	var logs bytes.Buffer
	a := NewAnchorer(w, st, AnchorPolicy{Interval: time.Minute, MaxLag: time.Hour}, clk.Now, slog.New(slog.NewJSONHandler(&logs, nil)))
	appendEv(t, w)
	appendEv(t, w)
	an, hd, since := w.AnchorState()
	if an != 0 || hd != 2 || since.IsZero() {
		t.Fatalf("до фиксации: %d %d %v", an, hd, since)
	}
	if err := a.AnchorNow(); err != nil {
		t.Fatal(err)
	}
	an, hd, since = w.AnchorState()
	if an != 2 || hd != 2 || !since.IsZero() {
		t.Fatalf("после фиксации: %d %d %v", an, hd, since)
	}
	if !strings.Contains(logs.String(), "audit_anchor_ok") {
		t.Errorf("нет audit_anchor_ok: %s", logs.String())
	}
	if st.puts[0].Seq != 2 || st.puts[0].ChainID != "chain-anc" {
		t.Fatalf("checkpoint %+v", st.puts[0])
	}
}

func TestAnchorFailureLagAndLagging(t *testing.T) {
	clk := newClock()
	w := anchorWriter(t, clk)
	st := &memStore{err: kindErr{}}
	var logs bytes.Buffer
	a := NewAnchorer(w, st, AnchorPolicy{Interval: time.Minute, MaxLag: 10 * time.Minute}, clk.Now, slog.New(slog.NewJSONHandler(&logs, nil)))
	appendEv(t, w) // since = clk.Now()
	clk.Add(time.Minute)
	if err := a.AnchorNow(); err == nil {
		t.Fatal("ошибка ожидалась")
	}
	s := a.Status()
	if s.Errors != 1 || s.AnchoredSeq != 0 || s.LastError != "http_503" || s.Lag != time.Minute || s.Lagging {
		t.Fatalf("status %+v", s)
	}
	clk.Add(5 * time.Minute)
	a.AnchorNow()
	s = a.Status()
	if s.Errors != 2 || s.Lag != 6*time.Minute || s.Lagging {
		t.Fatalf("status %+v", s)
	}
	clk.Add(5 * time.Minute) // 11 минут > MaxLag
	a.AnchorNow()
	a.AnchorNow()
	s = a.Status()
	if !s.Lagging || s.Lag != 11*time.Minute || s.Errors != 4 {
		t.Fatalf("status %+v", s)
	}
	if n := strings.Count(logs.String(), "audit_anchor_lagging"); n != 1 {
		t.Errorf("audit_anchor_lagging залогирован %d раз, ожидался 1:\n%s", n, logs.String())
	}
	if !strings.Contains(logs.String(), `"kind":"http_503"`) {
		t.Errorf("нет kind в логе: %s", logs.String())
	}
	// Восстановление: фиксация проходит, Lagging сбрасывается.
	st.setErr(nil)
	if err := a.AnchorNow(); err != nil {
		t.Fatal(err)
	}
	s = a.Status()
	if s.Lagging || s.Lag != 0 || s.LastError != "" || s.AnchoredSeq != 1 {
		t.Fatalf("после восстановления %+v", s)
	}
}

func TestAnchorRelogsLaggingAfterRecovery(t *testing.T) {
	clk := newClock()
	w := anchorWriter(t, clk)
	st := &memStore{err: kindErr{}}
	var logs bytes.Buffer
	a := NewAnchorer(w, st, AnchorPolicy{Interval: time.Minute, MaxLag: time.Minute}, clk.Now, slog.New(slog.NewJSONHandler(&logs, nil)))
	appendEv(t, w)
	clk.Add(2 * time.Minute)
	a.AnchorNow()
	st.setErr(nil)
	a.AnchorNow()
	appendEv(t, w)
	st.setErr(kindErr{})
	clk.Add(2 * time.Minute)
	a.AnchorNow()
	if n := strings.Count(logs.String(), "audit_anchor_lagging"); n != 2 {
		t.Errorf("повторное отставание после восстановления должно логироваться заново: %d", n)
	}
}

func TestAppendNotBlockedByAnchor(t *testing.T) {
	w := anchorWriter(t, nil)
	st := &memStore{block: make(chan struct{}), in: make(chan struct{}, 1)}
	a := NewAnchorer(w, st, AnchorPolicy{Interval: time.Minute, MaxLag: time.Hour}, nil, nil)
	appendEv(t, w)
	done := make(chan struct{})
	go func() { a.AnchorNow(); close(done) }()
	select {
	case <-st.in:
	case <-time.After(5 * time.Second):
		t.Fatal("Put не вызван")
	}
	ok := make(chan error, 1)
	go func() { _, err := w.AppendEvent(validEvent("endpoint_down")); ok <- err }()
	select {
	case err := <-ok:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Append заблокирован зависшим Put")
	}
	close(st.block)
	<-done
	// Запись во время Put: anchored=1, head=2, отставание отсчитывается заново.
	an, hd, since := w.AnchorState()
	if an != 1 || hd != 2 || since.IsZero() {
		t.Fatalf("state %d %d %v", an, hd, since)
	}
}

func TestAnchorWriterFailedNoCheckpointNoPanic(t *testing.T) {
	s, k := newSigner(t)
	sg := &toggleSigner{Ed25519Signer: s}
	w, err := OpenWriter(filepath.Join(t.TempDir(), "c.jsonl"), "chain-anc", sg, k)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	appendEv(t, w)
	sg.fail.Store(true)
	if _, err := w.AppendEvent(validEvent("endpoint_down")); !errors.Is(err, ErrWriterFailed) {
		t.Fatalf("ожидался ErrWriterFailed: %v", err)
	}
	st := &memStore{}
	var logs bytes.Buffer
	a := NewAnchorer(w, st, AnchorPolicy{Interval: time.Minute, MaxLag: time.Hour}, nil, slog.New(slog.NewJSONHandler(&logs, nil)))
	if err := a.AnchorNow(); !errors.Is(err, ErrWriterFailed) {
		t.Fatalf("ожидался ErrWriterFailed: %v", err)
	}
	if len(st.seqs()) != 0 {
		t.Fatal("checkpoint отправлен из сломанного Writer")
	}
	if !strings.Contains(logs.String(), `"kind":"writer_failed"`) {
		t.Errorf("лог: %s", logs.String())
	}
	if a.Status().LastError != "writer_failed" {
		t.Errorf("status %+v", a.Status())
	}
}

type toggleSigner struct {
	*Ed25519Signer
	fail atomic.Bool
}

func (s *toggleSigner) Sign(b []byte) ([]byte, error) {
	if s.fail.Load() {
		return nil, errors.New("KMS недоступен")
	}
	return s.Ed25519Signer.Sign(b)
}

func TestRunFinalPutOnCancel(t *testing.T) {
	w := anchorWriter(t, nil)
	st := &memStore{}
	a := NewAnchorer(w, st, AnchorPolicy{Interval: time.Hour, MaxLag: time.Hour}, nil, nil)
	appendEv(t, w)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.Run(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for len(st.seqs()) < 1 {
		if time.Now().After(deadline) {
			t.Fatal("Run не зафиксировал голову сразу")
		}
		time.Sleep(time.Millisecond)
	}
	appendEv(t, w)
	appendEv(t, w)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run не завершился")
	}
	got := st.seqs()
	if len(got) != 2 || got[1] != 3 {
		t.Fatalf("финальный Put: %v", got)
	}
}

func TestRunTicker(t *testing.T) {
	w := anchorWriter(t, nil)
	st := &memStore{}
	a := NewAnchorer(w, st, AnchorPolicy{Interval: 5 * time.Millisecond, MaxLag: time.Hour}, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.Run(ctx); close(done) }()
	appendEv(t, w)
	deadline := time.Now().Add(5 * time.Second)
	for a.Status().AnchoredSeq < 1 {
		if time.Now().After(deadline) {
			t.Fatal("тикер не зафиксировал голову")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
}

func TestRunSurvivesStoreFailureAndFinalAttemptOnCancel(t *testing.T) {
	w := anchorWriter(t, nil)
	st := &memStore{err: kindErr{}}
	a := NewAnchorer(w, st, AnchorPolicy{Interval: time.Hour, MaxLag: time.Hour}, nil, nil)
	appendEv(t, w)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.Run(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for a.Status().Errors < 1 {
		if time.Now().After(deadline) {
			t.Fatal("нет попытки")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	if a.Status().Errors < 2 {
		t.Errorf("ожидалась финальная попытка: %+v", a.Status())
	}
}

func TestMarkAnchoredSemantics(t *testing.T) {
	clk := newClock()
	w := anchorWriter(t, clk)
	appendEv(t, w)
	appendEv(t, w)
	appendEv(t, w)
	w.MarkAnchored(2) // не голова: отставание отсчитывается от сейчас
	clk.Add(time.Minute)
	an, hd, since := w.AnchorState()
	if an != 2 || hd != 3 || since.IsZero() {
		t.Fatalf("%d %d %v", an, hd, since)
	}
	w.MarkAnchored(1) // вниз нельзя
	if an, _, _ := w.AnchorState(); an != 2 {
		t.Errorf("anchoredSeq уменьшился до %d", an)
	}
	w.MarkAnchored(100) // выше головы нельзя
	an, hd, since = w.AnchorState()
	if an != 3 || hd != 3 || !since.IsZero() {
		t.Fatalf("после MarkAnchored(100): %d %d %v", an, hd, since)
	}
	w.MarkAnchored(3)
	if an, _, _ = w.AnchorState(); an != 3 {
		t.Error("повтор изменил состояние")
	}
}

func TestOpenWithCheckpointsSetsAnchoredSeq(t *testing.T) {
	path, s, k, w := writeChain(t, 3)
	cp, _ := w.Checkpoint()
	w.Close()
	w2, err := OpenWriterWith(path, "agent-staging-1", s, k, WriterOptions{Checkpoints: []Checkpoint{cp}})
	if err != nil {
		t.Fatal(err)
	}
	defer w2.Close()
	an, hd, since := w2.AnchorState()
	if an != 3 || hd != 3 || !since.IsZero() {
		t.Fatalf("%d %d %v", an, hd, since)
	}
	// первая новая запись запускает отсчёт отставания
	if _, err := w2.AppendEvent(validEvent("endpoint_down")); err != nil {
		t.Fatal(err)
	}
	if _, _, since := w2.AnchorState(); since.IsZero() {
		t.Error("unanchoredSince не выставлен после новой записи")
	}
}
