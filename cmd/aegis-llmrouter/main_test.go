package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/limpjungle/aegis3311/internal/audit"
	"github.com/limpjungle/aegis3311/internal/openrouter"
	"github.com/limpjungle/aegis3311/internal/routerstate"
	"github.com/limpjungle/aegis3311/internal/routersvc"
)

const stateHealthBody = `{"data":{"endpoints":[{"provider_name":"Inceptron","quantization":"fp8","tag":"t","supported_parameters":["response_format","structured_outputs","seed"]},` +
	`{"provider_name":"Wafer","quantization":"nvfp4","tag":"w","supported_parameters":["response_format","structured_outputs","seed"]}]}}`

const goodAnswer = `{"incident_class":"RB-006","root_cause":"load_growth","action":{"type":"workload.scale_out","params":{"scope":null,"pod_name":null,"reason":null,"parameter":null}},"confidence":0.9,"evidence":["a"],"summary":"s"}`

type stubTransport struct {
	post  func(body []byte) (openrouter.Response, error)
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
	s.mu.Unlock()
	return openrouter.Response{Status: 200, Body: []byte(stateHealthBody)}, nil
}

func (s *stubTransport) counts() (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls, s.gets
}

func reply(provider string, prompt, completion int) openrouter.Response {
	c, _ := json.Marshal(goodAnswer)
	return openrouter.Response{Status: 200, Body: []byte(fmt.Sprintf(`{"id":"g1","model":"m","provider":%q,"choices":[{"finish_reason":"stop","message":{"content":%s}}],"usage":{"prompt_tokens":%d,"completion_tokens":%d,"total_tokens":%d}}`,
		provider, c, prompt, completion, prompt+completion))}
}

func runtimeSecret(t testing.TB) string {
	t.Helper()
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "m" + hex.EncodeToString(b)
}

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

func must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// fx — каталог, ключи, конфигурация и накопленный вывод.
type fx struct {
	t               *testing.T
	dir, cfgPath    string
	cfg             routersvc.Config
	env             map[string]string
	secret, maskHex string
	privPEM         string
	keyPaths        []string
	tr              *stubTransport
	allOut          syncBuf // весь stdout+stderr всех запусков
}

func newFx(t *testing.T) *fx {
	t.Helper()
	dir := t.TempDir()
	f := &fx{t: t, dir: dir, secret: runtimeSecret(t), tr: &stubTransport{}}
	mk := make([]byte, 32)
	_, err := rand.Read(mk)
	must(t, err)
	f.maskHex = hex.EncodeToString(mk)
	keys := filepath.Join(dir, "keys")
	must(t, os.Mkdir(keys, 0o700))
	apiP, maskP, privP, pubP := filepath.Join(keys, "api"), filepath.Join(keys, "mask"), filepath.Join(keys, "audit.pem"), filepath.Join(keys, "audit.pub")
	must(t, os.WriteFile(apiP, []byte(f.secret+"\n"), 0o600))
	must(t, os.WriteFile(maskP, []byte(f.maskHex+"\n"), 0o600))
	_, err = audit.GenerateKey(privP, pubP)
	must(t, err)
	pb, err := os.ReadFile(privP)
	must(t, err)
	f.privPEM = string(pb)
	f.keyPaths = []string{apiP, maskP, privP}
	f.env = map[string]string{"OPENROUTER_API_KEY_FILE": apiP, "AEGIS_MASKER_KEY_FILE": maskP, routersvc.AuditKeyEnv: privP}
	data := filepath.Join(dir, "data")
	must(t, os.Mkdir(data, 0o700))
	f.cfg = routersvc.Config{RouterID: "llmrouter-test", StatePath: filepath.Join(data, "router.state"),
		Audit:    routersvc.AuditConfig{Chain: filepath.Join(data, "audit.jsonl"), ChainID: "chain-test"},
		Failover: routersvc.FailoverConfig{HealthInterval: "1h"}}
	f.writeCfg()
	return f
}

func (f *fx) writeCfg() {
	b, err := json.Marshal(f.cfg)
	must(f.t, err)
	f.cfgPath = filepath.Join(f.dir, "cfg.json")
	must(f.t, os.WriteFile(f.cfgPath, b, 0o600))
}

func (f *fx) mkEnv(out, errb *syncBuf) env {
	return env{getenv: func(k string) string { return f.env[k] }, stdin: strings.NewReader(""), stdout: out, stderr: errb,
		deps: routersvc.Deps{Transport: f.tr, ClientOptions: []openrouter.ClientOption{openrouter.WithSleep(func(context.Context, time.Duration) error { return nil })}}}
}

// do выполняет run и возвращает код выхода, stdout, stderr.
func (f *fx) do(args ...string) (int, string, string) {
	f.t.Helper()
	return f.doCtx(context.Background(), args...)
}

func (f *fx) doCtx(ctx context.Context, args ...string) (int, string, string) {
	f.t.Helper()
	var out, errb syncBuf
	err := run(ctx, args, f.mkEnv(&out, &errb))
	code := codeOf(err)
	f.allOut.Write([]byte(out.String() + errb.String()))
	if err != nil {
		f.allOut.Write([]byte(err.Error() + " " + routersvc.Hint(err)))
	}
	return code, out.String(), errb.String()
}

func codeOf(err error) int {
	if err == nil {
		return 0
	}
	var ee exitError
	if errors.As(err, &ee) {
		return ee.code
	}
	return -1
}

func (f *fx) cfgArgs(cmd string, more ...string) []string {
	return append([]string{cmd, "-config", f.cfgPath}, more...)
}

// serveOnce запускает serve до llmrouter_opened и останавливает его отменой.
func (f *fx) serveOnce() {
	f.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	var out, errb syncBuf
	done := make(chan error, 1)
	go func() { done <- run(ctx, f.cfgArgs("serve"), f.mkEnv(&out, &errb)) }()
	waitFor(f.t, "llmrouter_opened", func() bool {
		select {
		case err := <-done:
			f.t.Fatalf("serve завершился: %v\n%s", err, errb.String())
		default:
		}
		return strings.Contains(errb.String(), "llmrouter_opened")
	})
	cancel()
	if err := <-done; err != nil {
		f.t.Fatalf("serve: %v", err)
	}
	f.allOut.Write([]byte(out.String() + errb.String()))
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	dl := time.Now().Add(60 * time.Second)
	for !cond() {
		if time.Now().After(dl) {
			t.Fatalf("не дождались: %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// noLeaks — в накопленном выводе нет секретов и путей к файлам ключей.
func (f *fx) noLeaks() {
	f.t.Helper()
	all := f.allOut.String()
	bad := append([]string{f.secret, f.maskHex, f.privPEM}, f.keyPaths...)
	for _, b := range strings.Split(strings.TrimSpace(f.privPEM), "\n") {
		if len(b) > 20 && !strings.HasPrefix(b, "-----") {
			bad = append(bad, b)
		}
	}
	for _, s := range bad {
		if s != "" && strings.Contains(all, s) {
			f.t.Errorf("утечка секрета/пути в выводе: %.30q", s)
		}
	}
}

func (f *fx) writeReq(mode string) string {
	p := filepath.Join(f.dir, "req.json")
	body := fmt.Sprintf(`{"incident_id":"inc-1","service":"geo-svc","environment":"staging","mode":%q,"sections":[{"key":"alert","list":false,"fragments":[{"id":"a","source":"alerts.alertmanager","kind":"generic","required":true,"relevance":100,"value":{"n":1}}]}]}`, mode)
	must(f.t, os.WriteFile(p, []byte(body), 0o600))
	return p
}

func (f *fx) secrets() routersvc.Secrets {
	s, err := routersvc.LoadSecrets(func(k string) string { return f.env[k] })
	must(f.t, err)
	return s
}

func (f *fx) keyring() audit.Keyring {
	k := audit.Keyring{}
	k.Add(f.secrets().Signer.Public())
	return k
}

// chainStats проверяет цепочку.
func (f *fx) chainStats() (audit.VerifyStats, []string) {
	f.t.Helper()
	b, err := os.ReadFile(f.cfg.Audit.Chain)
	must(f.t, err)
	var st audit.VerifyStats
	var kinds []string
	_, err = audit.Verify(bytes.NewReader(b), f.keyring(), audit.VerifyOptions{ChainID: f.cfg.Audit.ChainID, Stats: &st,
		OnRouterEvent: func(_ uint64, ev *audit.RouterEvent) { kinds = append(kinds, ev.Kind) }})
	must(f.t, err)
	return st, kinds
}

func (f *fx) status() map[string]any {
	f.t.Helper()
	code, out, errs := f.do(f.cfgArgs("status")...)
	if code != 0 {
		f.t.Fatalf("status: %d\n%s", code, errs)
	}
	var m map[string]any
	must(f.t, json.Unmarshal([]byte(out), &m))
	return m
}

func (f *fx) openHeld() *routersvc.Runtime {
	f.t.Helper()
	rt, err := routersvc.Open(f.cfg, f.secrets(), routersvc.OpenOptions{Create: true}, routersvc.Deps{Transport: f.tr})
	must(f.t, err)
	f.t.Cleanup(func() { rt.Close() })
	return rt
}

// ------------------------------------------------------------------ тесты

func TestUsageErrors(t *testing.T) {
	f := newFx(t)
	req := f.writeReq("hybrid")
	cases := map[string][]string{
		"нет подкоманды":          {},
		"неизвестная":             {"bogus", "-config", f.cfgPath},
		"serve без -config":       {"serve"},
		"status без -config":      {"status"},
		"лишние аргументы":        {"status", "-config", f.cfgPath, "extra"},
		"неизвестный флаг":        {"status", "-config", f.cfgPath, "-zzz"},
		"resume без operator":     {"resume", "-config", f.cfgPath},
		"resume плохой operator":  {"resume", "-config", f.cfgPath, "-operator", "a b"},
		"route без -in":           {"route", "-config", f.cfgPath, "-operator", "alice"},
		"route без operator":      {"route", "-config", f.cfgPath, "-in", req},
		"route нет файла":         {"route", "-config", f.cfgPath, "-operator", "alice", "-in", filepath.Join(f.dir, "нет")},
		"-prepare-only вне route": {"status", "-config", f.cfgPath, "-prepare-only"},
		"нет конфигурации":        {"status", "-config", filepath.Join(f.dir, "нет.json")},
	}
	for name, args := range cases {
		code, _, errs := f.do(args...)
		if code != 2 {
			t.Errorf("%s: код %d (%s)", name, code, errs)
		}
	}
	if n := dirCount(t, f.dir+"/data"); n != 0 {
		t.Errorf("созданы файлы: %d", n)
	}
	// Некорректный запрос — 2 до Open.
	bad := filepath.Join(f.dir, "bad.json")
	must(t, os.WriteFile(bad, []byte(`{"unknown":1}`), 0o600))
	if code, _, _ := f.do("route", "-config", f.cfgPath, "-operator", "alice", "-in", bad); code != 2 {
		t.Errorf("плохой запрос: %d", code)
	}
	f.noLeaks()
}

func dirCount(t *testing.T, d string) int {
	ents, err := os.ReadDir(d)
	must(t, err)
	return len(ents)
}

func TestStatusBeforeServe(t *testing.T) {
	f := newFx(t)
	code, out, errs := f.do(f.cfgArgs("status")...)
	if code != 2 || out != "" {
		t.Fatalf("%d %q %s", code, out, errs)
	}
	if n := dirCount(t, f.dir+"/data"); n != 0 {
		t.Errorf("файлы созданы: %d", n)
	}
	for _, c := range [][]string{f.cfgArgs("resume", "-operator", "alice"), f.cfgArgs("route", "-operator", "alice", "-in", f.writeReq("hybrid"))} {
		if code, _, _ := f.do(c...); code != 2 {
			t.Errorf("%v: %d", c[0], code)
		}
	}
	if n := dirCount(t, f.dir+"/data"); n != 0 {
		t.Errorf("файлы созданы: %d", n)
	}
}

func TestSecretsErrorsExit2(t *testing.T) {
	f := newFx(t)
	bad := filepath.Join(f.dir, "junk")
	junk := "ZZ" + runtimeSecret(t)
	must(t, os.WriteFile(bad, []byte(junk), 0o600))
	f.env[routersvc.AuditKeyEnv] = bad
	code, _, errs := f.do(f.cfgArgs("serve")...)
	if code != 2 {
		t.Fatalf("%d %s", code, errs)
	}
	f.allOut.Write([]byte(errs))
	if strings.Contains(f.allOut.String(), junk) || strings.Contains(f.allOut.String(), bad) {
		t.Error("утечка")
	}
	if n := dirCount(t, f.dir+"/data"); n != 0 {
		t.Errorf("файлы созданы: %d", n)
	}
	f.noLeaks()
}

func TestServeE2E(t *testing.T) {
	f := newFx(t)
	f.serveOnce()
	m := f.status()
	if m["halted"] != false || m["router_id"] != "llmrouter-test" {
		t.Fatalf("%v", m)
	}
	f.noLeaks()
}

func TestBusy(t *testing.T) {
	f := newFx(t)
	f.serveOnce()
	rt := f.openHeld()
	_ = rt
	req := f.writeReq("hybrid")
	for _, args := range [][]string{f.cfgArgs("status"), f.cfgArgs("resume", "-operator", "alice"), f.cfgArgs("route", "-operator", "alice", "-in", req), f.cfgArgs("route", "-operator", "alice", "-in", req, "-prepare-only"), f.cfgArgs("serve")} {
		code, _, errs := f.do(args...)
		if code != 3 {
			t.Errorf("%s: код %d\n%s", args[0], code, errs)
		}
	}
	// подсказка main() формируется Hint'ом
	_, err := routersvc.Open(f.cfg, f.secrets(), routersvc.OpenOptions{}, routersvc.Deps{})
	if h := routersvc.Hint(err); !strings.Contains(h, "остановите") {
		t.Errorf("подсказка: %q", h)
	}
	f.noLeaks()
}

func TestResumeStateLost(t *testing.T) {
	f := newFx(t)
	f.serveOnce()
	must(t, os.Remove(f.cfg.StatePath))
	f.serveOnce()
	m := f.status()
	if m["halted"] != true || m["halt_reason"] != "state_lost" {
		t.Fatalf("%v", m)
	}
	code, out, errs := f.do(f.cfgArgs("resume", "-operator", "alice")...)
	if code != 0 {
		t.Fatalf("resume: %d %s", code, errs)
	}
	var after map[string]any
	must(t, json.Unmarshal([]byte(out), &after))
	if after["halted"] != false {
		t.Errorf("после resume: %v", after)
	}
	if m := f.status(); m["halted"] != false {
		t.Errorf("%v", m)
	}
	if code, _, _ := f.do(f.cfgArgs("resume", "-operator", "alice")...); code != 1 {
		t.Errorf("повторный resume: %d", code)
	}
	_, kinds := f.chainStats()
	n := 0
	for _, k := range kinds {
		if k == "router_resumed" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("router_resumed: %d (%v)", n, kinds)
	}
	f.noLeaks()
}

func TestCorruptStoreExit1(t *testing.T) {
	f := newFx(t)
	f.serveOnce()
	must(t, os.WriteFile(f.cfg.StatePath, []byte("мусор\n"), 0o600))
	before, _ := os.ReadFile(f.cfg.Audit.Chain)
	for _, a := range [][]string{f.cfgArgs("status"), f.cfgArgs("serve"), f.cfgArgs("resume", "-operator", "alice")} {
		if code, _, errs := f.do(a...); code != 1 {
			t.Errorf("%s: %d %s", a[0], code, errs)
		}
	}
	after, _ := os.ReadFile(f.cfg.Audit.Chain)
	if !bytes.Equal(before, after) {
		t.Error("цепочка изменена")
	}
	f.noLeaks()
}

func parseJSON(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("%v\n%s", err, s)
	}
	return m
}

func TestRouteSent(t *testing.T) {
	f := newFx(t)
	f.serveOnce()
	code, out, errs := f.do(f.cfgArgs("route", "-operator", "alice", "-in", f.writeReq("hybrid"))...)
	if code != 0 {
		t.Fatalf("%d %s", code, errs)
	}
	m := parseJSON(t, out)
	llm := m["record"].(map[string]any)["llm"].(map[string]any)
	if llm["outcome"] != "sent" {
		t.Fatalf("%v", llm)
	}
	if ch := m["chain"].(map[string]any); ch["seq"] == nil || ch["hash"] == "" {
		t.Errorf("chain: %v", ch)
	}
	if st, _ := f.chainStats(); st.Records != 1 {
		t.Errorf("records: %d", st.Records)
	}
	// после переоткрытия расход учтён
	rt, err := routersvc.Open(f.cfg, f.secrets(), routersvc.OpenOptions{}, routersvc.Deps{Transport: f.tr})
	must(t, err)
	snap := rt.Store.Snapshot()
	rt.Close()
	if snap.Incidents["inc-1"] <= 0 {
		t.Errorf("расход не учтён: %v", snap.Incidents)
	}
	f.noLeaks()
	if strings.Contains(out, `"value"`) && strings.Contains(out, `"n":1`) {
		t.Log("значение фрагмента в выводе") // информативно
	}
}

func TestRouteModeOff(t *testing.T) {
	f := newFx(t)
	f.serveOnce()
	code, out, errs := f.do(f.cfgArgs("route", "-operator", "alice", "-in", f.writeReq("off"))...)
	if code != 0 {
		t.Fatalf("%d %s", code, errs)
	}
	llm := parseJSON(t, out)["record"].(map[string]any)["llm"].(map[string]any)
	if llm["outcome"] != "not_sent" || llm["reason"] != "mode_off" {
		t.Fatalf("%v", llm)
	}
	if p, _ := f.tr.counts(); p != 0 {
		t.Errorf("POST: %d", p)
	}
	// -prepare-only при mode off — 2
	if code, _, _ := f.do(f.cfgArgs("route", "-operator", "alice", "-in", f.writeReq("off"), "-prepare-only")...); code != 2 {
		t.Errorf("prepare-only/off: %d", code)
	}
}

func TestRoutePrepareOnly(t *testing.T) {
	f := newFx(t)
	f.serveOnce()
	st0, _ := f.chainStats()
	p0, g0 := f.tr.counts()
	code, out, errs := f.do(f.cfgArgs("route", "-operator", "alice", "-in", f.writeReq("hybrid"), "-prepare-only")...)
	if code != 0 {
		t.Fatalf("%d %s", code, errs)
	}
	m := parseJSON(t, out)
	for _, k := range []string{"request_sha256", "input_sha256", "data_class", "sources", "excluded", "dropped", "est_input_tokens", "not_sent"} {
		if _, ok := m[k]; !ok {
			t.Errorf("нет %s: %v", k, m)
		}
	}
	if s, _ := m["request_sha256"].(string); len(s) != 64 {
		t.Errorf("request_sha256 %v", m["request_sha256"])
	}
	for _, banned := range []string{"messages", `"body"`, "model"} {
		if strings.Contains(out, banned) {
			t.Errorf("в выводе prepare-only %q", banned)
		}
	}
	if p, g := f.tr.counts(); p != p0 || g != g0 {
		t.Errorf("сеть: POST %d->%d GET %d->%d", p0, p, g0, g)
	}
	st1, _ := f.chainStats()
	if st1.Records != st0.Records || st1.RouterEvents != st0.RouterEvents {
		t.Errorf("цепочка изменена: %+v -> %+v", st0, st1)
	}
	rt, err := routersvc.Open(f.cfg, f.secrets(), routersvc.OpenOptions{}, routersvc.Deps{Transport: f.tr})
	must(t, err)
	snap := rt.Store.Snapshot()
	rt.Close()
	if len(snap.Incidents) != 0 && snap.Incidents["inc-1"] != 0 {
		t.Errorf("бюджет тронут: %v", snap.Incidents)
	}
	f.noLeaks()
}

func TestRoute401Halts(t *testing.T) {
	f := newFx(t)
	f.tr.post = func([]byte) (openrouter.Response, error) {
		return openrouter.Response{Status: 401, Body: []byte(`{}`)}, nil
	}
	f.serveOnce()
	code, out, errs := f.do(f.cfgArgs("route", "-operator", "alice", "-in", f.writeReq("hybrid"))...)
	t.Logf("route 401: код %d", code)
	if out == "" {
		t.Fatalf("нет вывода: %s", errs)
	}
	if st, _ := f.chainStats(); st.Records != 1 {
		t.Errorf("record не записан: %d", st.Records)
	}
	m := f.status()
	if m["halted"] != true || m["halt_reason"] != "auth" {
		t.Fatalf("%v", m)
	}
	f.noLeaks()
}

// ------------------------------------------------------------------ подпроцесс

func buildBin(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "aegis-llmrouter")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

func (f *fx) startProc(t *testing.T, bin string) (*exec.Cmd, *syncBuf) {
	t.Helper()
	cmd := exec.Command(bin, "serve", "-config", f.cfgPath)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	for k, v := range f.env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	var errb syncBuf
	cmd.Stderr = &errb
	must(t, cmd.Start())
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	waitFor(t, "llmrouter_opened", func() bool { return strings.Contains(errb.String(), "llmrouter_opened") })
	return cmd, &errb
}

func TestSubprocessSIGTERM(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	bin := buildBin(t)
	f := newFx(t)
	cmd, errb := f.startProc(t, bin)
	// status при работающем serve — 3
	if code, _, _ := f.do(f.cfgArgs("status")...); code != 3 {
		t.Errorf("status при serve: %d", code)
	}
	must(t, cmd.Process.Signal(syscall.SIGTERM))
	err := cmd.Wait()
	if err != nil {
		t.Fatalf("SIGTERM: %v\n%s", err, errb.String())
	}
	if !strings.Contains(errb.String(), `"shutdown"`) {
		t.Errorf("нет shutdown: %s", errb.String())
	}
	f.allOut.Write([]byte(errb.String()))
	if m := f.status(); m["halted"] != false {
		t.Errorf("%v", m)
	}
	f.noLeaks()
}

func TestSubprocessSIGINT(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	bin := buildBin(t)
	f := newFx(t)
	cmd, errb := f.startProc(t, bin)
	must(t, cmd.Process.Signal(syscall.SIGINT))
	if err := cmd.Wait(); err != nil {
		t.Fatalf("SIGINT: %v\n%s", err, errb.String())
	}
	if !strings.Contains(errb.String(), `"shutdown"`) {
		t.Errorf("нет shutdown")
	}
}

func TestSubprocessSIGKILL(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	bin := buildBin(t)
	f := newFx(t)
	cmd, _ := f.startProc(t, bin)
	must(t, cmd.Process.Signal(syscall.SIGKILL))
	cmd.Wait()
	// flock снимает ядро: status полон и успешен
	if m := f.status(); m["halted"] != false {
		t.Errorf("после SIGKILL: %v", m)
	}
	// и store/цепочка открываются
	rt, err := routersvc.Open(f.cfg, f.secrets(), routersvc.OpenOptions{}, routersvc.Deps{Transport: f.tr})
	must(t, err)
	rt.Close()
	_ = routerstate.ErrLocked
}
