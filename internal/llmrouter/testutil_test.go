package llmrouter

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	goldensynthetic "github.com/limpjungle/aegis3311/eval/golden-synthetic"
	"github.com/limpjungle/aegis3311/internal/audit"
	"github.com/limpjungle/aegis3311/internal/dataclass"
	"github.com/limpjungle/aegis3311/internal/openrouter"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)} }
func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// memSink — приёмник событий в памяти с режимом сбоя.
type memSink struct {
	mu     sync.Mutex
	events []audit.RouterEvent
	failOn string // kind события, на котором запись падает; "*" — на любом
}

func (s *memSink) AppendEvent(ev *audit.RouterEvent) (audit.Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ev.Validate(); err != nil {
		return audit.Entry{}, err
	}
	if s.failOn == "*" || s.failOn == ev.Kind {
		return audit.Entry{}, os.ErrInvalid
	}
	s.events = append(s.events, *ev)
	return audit.Entry{}, nil
}

func (s *memSink) kinds() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, e := range s.events {
		out = append(out, e.Kind)
	}
	return out
}

// stubTransport — фейковый транспорт: ответы по очереди функцией.
type stubTransport struct {
	post  func(body []byte) (openrouter.Response, error)
	get   func() (openrouter.Response, error)
	mu    sync.Mutex
	calls int
}

func (s *stubTransport) Post(_ context.Context, _ string, _ http.Header, body []byte) (openrouter.Response, error) {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	return s.post(body)
}

func (s *stubTransport) Get(context.Context, string, http.Header) (openrouter.Response, error) {
	return s.get()
}

func loadAssets(t testing.TB) *openrouter.Assets {
	t.Helper()
	a, err := openrouter.LoadAssets(goldensynthetic.FS)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// testKey пишет ключ во временный файл и читает его через LoadAPIKey (как в эксплуатации).
// runtimeSecret — маркер секрета, генерируемый в рантайме (в исходниках нет токеноподобных литералов).
func runtimeSecret(t testing.TB) string {
	t.Helper()
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "m" + hex.EncodeToString(b)
}

func testKey(t testing.TB, secret string) openrouter.APIKey {
	t.Helper()
	p := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(p, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	k, err := openrouter.LoadAPIKey(func(string) string { return p })
	if err != nil {
		t.Fatal(err)
	}
	return k
}

type rig struct {
	r      *Router
	assets *openrouter.Assets
	sink   *memSink
	clock  *fakeClock
}

func newRig(t testing.TB, m dataclass.Masker, tr openrouter.Transport, url string, sink EventSink) *rig {
	t.Helper()
	a := loadAssets(t)
	opts := []openrouter.ClientOption{openrouter.WithSleep(func(context.Context, time.Duration) error { return nil })}
	if url != "" {
		opts = append(opts, openrouter.WithURL(url))
	}
	cl, err := openrouter.NewClient(&a.Config, testKey(t, runtimeSecret(t)), tr, opts...)
	if err != nil {
		t.Fatal(err)
	}
	ms, clock := &memSink{}, newFakeClock()
	if sink == nil {
		sink = ms
	} else if s, ok := sink.(*memSink); ok {
		ms = s
	}
	r, err := New(Options{Assets: a, Client: cl, Masker: m, Events: sink, Clock: clock,
		Budgets: BudgetConfig{IncidentTokens: 1 << 40, ServiceDayTokens: 1 << 40}, Failover: DefaultFailover(), RouterID: "llm-router-test"})
	if err != nil {
		t.Fatal(err)
	}
	return &rig{r: r, assets: a, sink: ms, clock: clock}
}

func newAuditSigner(t testing.TB) (audit.Signer, audit.Keyring) {
	t.Helper()
	dir := t.TempDir()
	priv, pub := filepath.Join(dir, "k.pem"), filepath.Join(dir, "k.pub")
	p, err := audit.GenerateKey(priv, pub)
	if err != nil {
		t.Fatal(err)
	}
	s, err := audit.LoadPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	k := audit.Keyring{}
	k.Add(p)
	return s, k
}
