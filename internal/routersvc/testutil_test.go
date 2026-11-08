package routersvc

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/limpjungle/aegis3311/internal/audit"
	"github.com/limpjungle/aegis3311/internal/openrouter"
)

// stateHealthBody — ответ health-check'а: оба endpoint'а в списке.
const stateHealthBody = `{"data":{"endpoints":[{"provider_name":"Inceptron","quantization":"fp8","tag":"t","supported_parameters":["response_format","structured_outputs","seed"]},` +
	`{"provider_name":"Wafer","quantization":"nvfp4","tag":"w","supported_parameters":["response_format","structured_outputs","seed"]}]}}`

const goodAnswer = `{"incident_class":"RB-006","root_cause":"load_growth","action":{"type":"workload.scale_out","params":{"scope":null,"pod_name":null,"reason":null,"parameter":null}},"confidence":0.9,"evidence":["a"],"summary":"s"}`

// stubTransport — фейковый транспорт; nil-функции дают успешные ответы по умолчанию.
type stubTransport struct {
	post  func(body []byte) (openrouter.Response, error)
	get   func() (openrouter.Response, error)
	mu    sync.Mutex
	calls int
	gets  int
}

func (s *stubTransport) Post(_ context.Context, _ string, _ http.Header, body []byte) (openrouter.Response, error) {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	if s.post == nil {
		return reply("Inceptron", 100, 50), nil
	}
	return s.post(body)
}

func (s *stubTransport) Get(context.Context, string, http.Header) (openrouter.Response, error) {
	s.mu.Lock()
	s.gets++
	g := s.get
	s.mu.Unlock()
	if g == nil {
		return openrouter.Response{Status: 200, Body: []byte(stateHealthBody)}, nil
	}
	return g()
}

func (s *stubTransport) setGet(g func() (openrouter.Response, error)) {
	s.mu.Lock()
	s.get = g
	s.mu.Unlock()
}

func (s *stubTransport) counts() (posts, gets int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls, s.gets
}

func reply(provider string, prompt, completion int) openrouter.Response {
	c, _ := json.Marshal(goodAnswer)
	return openrouter.Response{Status: 200, Body: []byte(fmt.Sprintf(`{"id":"g1","model":"m","provider":%q,"choices":[{"finish_reason":"stop","message":{"content":%s}}],"usage":{"prompt_tokens":%d,"completion_tokens":%d,"total_tokens":%d}}`,
		provider, c, prompt, completion, prompt+completion))}
}

// runtimeSecret — маркер секрета, генерируемый в рантайме (в исходниках нет токеноподобных литералов).
func runtimeSecret(t testing.TB) string {
	t.Helper()
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "m" + hex.EncodeToString(b)
}

// syncBuf — потокобезопасный буфер для журнала.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// fixture — каталог, ключи и конфигурация одного тестового сервиса.
type fixture struct {
	t       *testing.T
	dir     string
	cfg     Config
	env     map[string]string
	secret  string // маркер ключа API
	maskHex string // hex ключа маскировщика
	privPEM string // содержимое PEM приватного ключа аудита
	tr      *stubTransport
	log     *syncBuf
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	f := &fixture{t: t, dir: dir, secret: runtimeSecret(t), tr: &stubTransport{}, log: &syncBuf{}}
	mk := make([]byte, 32)
	if _, err := rand.Read(mk); err != nil {
		t.Fatal(err)
	}
	f.maskHex = hex.EncodeToString(mk)
	keys := filepath.Join(dir, "keys")
	if err := os.Mkdir(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	apiP, maskP, privP, pubP := filepath.Join(keys, "api"), filepath.Join(keys, "mask"), filepath.Join(keys, "audit.pem"), filepath.Join(keys, "audit.pub")
	must(t, os.WriteFile(apiP, []byte(f.secret+"\n"), 0o600))
	must(t, os.WriteFile(maskP, []byte(f.maskHex+"\n"), 0o600))
	if _, err := audit.GenerateKey(privP, pubP); err != nil {
		t.Fatal(err)
	}
	pb, err := os.ReadFile(privP)
	must(t, err)
	f.privPEM = string(pb)
	f.env = map[string]string{"OPENROUTER_API_KEY_FILE": apiP, "AEGIS_MASKER_KEY_FILE": maskP, AuditKeyEnv: privP}
	f.cfg = Config{RouterID: "llmrouter-test", StatePath: filepath.Join(dir, "data", "router.state"), Audit: AuditConfig{
		Chain: filepath.Join(dir, "data", "audit.jsonl"), ChainID: "chain-test"}, Failover: FailoverConfig{HealthInterval: "1h"}}
	must(t, os.Mkdir(filepath.Join(dir, "data"), 0o700))
	return f
}

func must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) getenv(k string) string { return f.env[k] }

func (f *fixture) secrets() Secrets {
	f.t.Helper()
	s, err := LoadSecrets(f.getenv)
	must(f.t, err)
	return s
}

func (f *fixture) deps() Deps {
	return Deps{Transport: f.tr, Logger: slog.New(slog.NewJSONHandler(f.log, nil)),
		ClientOptions: []openrouter.ClientOption{openrouter.WithSleep(func(context.Context, time.Duration) error { return nil })}}
}

func (f *fixture) open(create bool) (*Runtime, error) {
	return Open(f.cfg, f.secrets(), OpenOptions{Create: create}, f.deps())
}

func (f *fixture) mustOpen(create bool) *Runtime {
	f.t.Helper()
	rt, err := f.open(create)
	must(f.t, err)
	return rt
}

// keyring — ключ проверки цепочки.
func (f *fixture) keyring() audit.Keyring {
	k := audit.Keyring{}
	k.Add(f.secrets().Signer.Public())
	return k
}

type chainEvent struct {
	Seq  uint64
	Ev   audit.RouterEvent
	Kind string
}

// verifyChain проверяет цепочку и возвращает события роутера и число записей.
func (f *fixture) verifyChain() ([]chainEvent, audit.VerifyStats) {
	f.t.Helper()
	b, err := os.ReadFile(f.cfg.Audit.Chain)
	must(f.t, err)
	var evs []chainEvent
	var st audit.VerifyStats
	_, err = audit.Verify(bytes.NewReader(b), f.keyring(), audit.VerifyOptions{ChainID: f.cfg.Audit.ChainID, Stats: &st,
		OnRouterEvent: func(seq uint64, ev *audit.RouterEvent) { evs = append(evs, chainEvent{seq, *ev, ev.Kind}) }})
	must(f.t, err)
	return evs, st
}

func kinds(evs []chainEvent) []string {
	var out []string
	for _, e := range evs {
		out = append(out, e.Kind)
	}
	return out
}

func has(evs []chainEvent, kind string) bool {
	for _, e := range evs {
		if e.Kind == kind {
			return true
		}
	}
	return false
}

// requestJSON — минимальный корректный запрос route.
func requestJSON(mode string) []byte {
	return []byte(fmt.Sprintf(`{"incident_id":"inc-1","service":"geo-svc","environment":"staging","mode":%q,"sections":[{"key":"alert","list":false,"fragments":[{"id":"a","source":"alerts.alertmanager","kind":"generic","required":true,"relevance":100,"value":{"n":1}}]}]}`, mode))
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	dl := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(dl) {
			t.Fatalf("не дождались: %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func fileBytes(t testing.TB, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	must(t, err)
	return b
}

func mustJSON(t testing.TB, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	must(t, err)
	return string(b)
}
