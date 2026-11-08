package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/limpjungle/aegis3311/internal/audit"
	"github.com/limpjungle/aegis3311/internal/intake"
	"github.com/limpjungle/aegis3311/internal/routersvc"
)

type stack struct {
	cfgPath, chain string
	getenv         func(string) string
	keys           audit.Keyring
	tr             *stubTr
	cfg            map[string]any
}

func newStack(t *testing.T) *stack {
	t.Helper()
	tr := &stubTr{}
	cfgPath, getenv, chain, keys, _ := fakeStack(t, tr)
	var cfg map[string]any
	b, _ := os.ReadFile(cfgPath)
	json.Unmarshal(b, &cfg)
	return &stack{cfgPath, chain, getenv, keys, tr, cfg}
}

func (s *stack) env(out, errb *bytes.Buffer) env {
	return env{getenv: s.getenv, stdout: out, stderr: errb, deps: routersvc.Deps{Transport: s.tr}, live: newLive}
}

func (s *stack) records(t *testing.T) []audit.DecisionRecord {
	t.Helper()
	b, err := os.ReadFile(s.chain)
	if err != nil {
		return nil
	}
	var recs []audit.DecisionRecord
	if _, err := audit.Verify(bytes.NewReader(b), s.keys, audit.VerifyOptions{ChainID: "chain-test", OnRecord: func(_ uint64, r *audit.DecisionRecord) { recs = append(recs, *r) }}); err != nil {
		t.Fatalf("цепочка не проходит проверку: %v", err)
	}
	return recs
}

func (s *stack) intakeState() (closed map[string]any, incidents map[string]any) {
	b, err := os.ReadFile(s.cfg["state_path"].(string))
	if err != nil {
		return nil, nil
	}
	var d struct {
		Closed    map[string]any `json:"closed"`
		Incidents map[string]any `json:"incidents"`
	}
	json.Unmarshal(b, &d)
	return d.Closed, d.Incidents
}

func waitFor(t *testing.T, what string, d time.Duration, f func() bool) {
	t.Helper()
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		if f() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("не дождались: %s", what)
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee exitError
	if errors.As(err, &ee) {
		return ee.code
	}
	return classify(err)
}

type running struct {
	done   chan error
	cancel context.CancelFunc
	out    *bytes.Buffer
	errb   *bytes.Buffer
}

func (s *stack) start(t *testing.T, e func(env) env) *running {
	t.Helper()
	r := &running{done: make(chan error, 1), out: &bytes.Buffer{}, errb: &bytes.Buffer{}}
	var ctx context.Context
	ctx, r.cancel = context.WithCancel(context.Background())
	en := s.env(r.out, r.errb)
	if e != nil {
		en = e(en)
	}
	go func() { r.done <- run(ctx, []string{"serve", "-config", s.cfgPath}, en) }()
	t.Cleanup(func() {
		r.cancel()
		select {
		case <-r.done:
		case <-time.After(5 * time.Second):
		}
	})
	return r
}

func (r *running) stop(t *testing.T) error {
	t.Helper()
	r.cancel()
	select {
	case err := <-r.done:
		r.done <- err
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("serve не остановился")
		return nil
	}
}

// Алерт → одна запись → алерт пропал на close_after → инцидент закрыт (состояние intake и store роутера), повторной записи нет.
func TestServeResolvedClosesIncident(t *testing.T) {
	s := newStack(t)
	r := s.start(t, nil)
	waitFor(t, "запись shadow", 5*time.Second, func() bool { return len(s.records(t)) == 1 })
	recs := s.records(t)
	id := recs[0].Incident.ID
	if recs[0].Intake == nil || recs[0].Intake.Outcome != "routed" || recs[0].Mode != audit.ModeShadow {
		t.Fatalf("запись: %+v", recs[0])
	}
	amGone.Store(true)
	waitFor(t, "инцидент закрыт", 5*time.Second, func() bool { c, inc := s.intakeState(); _, ok := c[id]; return ok && len(inc) == 0 })
	if err := r.stop(t); err != nil {
		t.Fatalf("serve: %v\n%s", err, r.errb.String())
	}
	if n := len(s.records(t)); n != 1 {
		t.Errorf("записей после закрытия %d", n)
	}
	rs, err := os.ReadFile(s.cfg["router_config"].(string))
	if err != nil {
		t.Fatal(err)
	}
	var rc struct {
		StatePath string `json:"state_path"`
	}
	json.Unmarshal(rs, &rc)
	st, err := os.ReadFile(rc.StatePath)
	if err != nil || !bytes.Contains(st, []byte("close_incident")) || !bytes.Contains(st, []byte(id)) {
		t.Errorf("в store роутера нет close_incident для %s (%v)", id, err)
	}
	if s.tr.posts != 1 {
		t.Errorf("запросов в модель %d", s.tr.posts)
	}
	for _, bad := range []string{"Bearer", "ignore previous", "p99 высокий"} {
		if strings.Contains(r.errb.String(), bad) {
			t.Errorf("в журнале есть %q", bad)
		}
	}
}

// SIGTERM → корректная остановка, код 0 (run возвращает nil).
func TestServeSIGTERM(t *testing.T) {
	s := newStack(t)
	r := s.start(t, func(e env) env { e.signals = []os.Signal{syscall.SIGTERM}; return e })
	waitFor(t, "запись", 5*time.Second, func() bool { return len(s.records(t)) == 1 })
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-r.done:
		r.done <- err // для t.Cleanup
		if exitCode(err) != 0 {
			t.Fatalf("код %d: %v\n%s", exitCode(err), err, r.errb.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve не завершился по SIGTERM")
	}
}

// Второй экземпляр aegis-intake и aegis-llmrouter serve на той же конфигурации → код 3 (файлы заняты).
func TestSecondInstanceBusy(t *testing.T) {
	s := newStack(t)
	r := s.start(t, nil)
	waitFor(t, "запись", 5*time.Second, func() bool { return len(s.records(t)) == 1 })
	var o, e bytes.Buffer
	err := run(context.Background(), []string{"serve", "-config", s.cfgPath}, s.env(&o, &e))
	if exitCode(err) != 3 {
		t.Errorf("второй aegis-intake: код %d: %v", exitCode(err), err)
	}
	// aegis-llmrouter serve открывает тот же routersvc.Runtime с той же конфигурацией роутера
	rcfg, lerr := routersvc.LoadConfig(s.cfg["router_config"].(string))
	if lerr != nil {
		t.Fatal(lerr)
	}
	sec, lerr := routersvc.LoadSecrets(s.getenv)
	if lerr != nil {
		t.Fatal(lerr)
	}
	rt, oerr := routersvc.Open(rcfg, sec, routersvc.OpenOptions{Create: true}, routersvc.Deps{Transport: s.tr})
	if rt != nil {
		rt.Close()
		t.Fatal("роутер открыт параллельно с работающим intake")
	}
	if routersvc.Classify(oerr) != routersvc.ClassBusy {
		t.Errorf("aegis-llmrouter serve: класс %v: %v", routersvc.Classify(oerr), oerr)
	}
	if err := r.stop(t); err != nil {
		t.Fatalf("первый экземпляр: %v", err)
	}
	// после остановки файлы свободны
	var o2, e2 bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	if err := run(ctx, []string{"serve", "-config", s.cfgPath}, s.env(&o2, &e2)); err != nil {
		t.Errorf("запуск после остановки: %v\n%s", err, e2.String())
	}
}

// Занятый только файл состояния intake (роутер свободен) → код 3; повреждённый → 1.
func TestStateBusyAndCorrupt(t *testing.T) {
	s := newStack(t)
	var o, e bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	run(ctx, []string{"serve", "-config", s.cfgPath}, s.env(&o, &e)) // создаёт store и цепочку
	cancel()
	statePath := s.cfg["state_path"].(string)
	// повреждённое состояние
	os.WriteFile(statePath, []byte(`{"schema":"x"`), 0o600)
	e.Reset()
	err := run(context.Background(), []string{"serve", "-config", s.cfgPath}, s.env(&o, &e))
	if exitCode(err) != 1 {
		t.Errorf("повреждённое состояние: код %d: %v", exitCode(err), err)
	}
	if h := hint(err); !strings.Contains(h, "состояния") {
		t.Errorf("подсказка: %q", h)
	}
	// занятое: открываем состояние отдельно
	os.Remove(statePath)
	// ErrStateLocked из intake.OpenState
	lk := lockState(t, statePath)
	defer lk()
	err = run(context.Background(), []string{"serve", "-config", s.cfgPath}, s.env(&o, &e))
	if exitCode(err) != 3 {
		t.Errorf("занятое состояние: код %d: %v", exitCode(err), err)
	}
}

// Ошибки аргументов и конфигурации → 2.
func TestUsageErrors(t *testing.T) {
	s := newStack(t)
	badCfg := filepath.Join(t.TempDir(), "bad.json")
	os.WriteFile(badCfg, []byte(`{"unknown_field":1}`), 0o600)
	for name, args := range map[string][]string{
		"без команды":                 {},
		"неизвестная команда":         {"bogus"},
		"serve без -config":           {"serve"},
		"лишние аргументы":            {"serve", "-config", s.cfgPath, "x"},
		"replay без -in":              {"replay", "-config", s.cfgPath},
		"collect без service":         {"collect", "-config", s.cfgPath, "-namespace", "shop"},
		"prepare-only у serve":        {"serve", "-config", s.cfgPath, "-prepare-only"},
		"print-input у serve":         {"serve", "-config", s.cfgPath, "-print-input"},
		"неизвестный флаг":            {"serve", "-config", s.cfgPath, "-nope"},
		"конфиг с лишним полем":       {"serve", "-config", badCfg},
		"нет файла конфигурации":      {"serve", "-config", filepath.Join(t.TempDir(), "none.json")},
		"collect: пары нет в реестре": {"collect", "-config", s.cfgPath, "-namespace", "shop", "-service", "nope"},
	} {
		var o, e bytes.Buffer
		if c := exitCode(run(context.Background(), args, s.env(&o, &e))); c != 2 {
			t.Errorf("%s: код %d", name, c)
		}
	}
	// нет обязательного токена kube → 2
	var o, e bytes.Buffer
	en := s.env(&o, &e)
	en.getenv = func(k string) string {
		if k == "AEGIS_KUBE_TOKEN_FILE" {
			return ""
		}
		return s.getenv(k)
	}
	if c := exitCode(run(context.Background(), []string{"serve", "-config", s.cfgPath}, en)); c != 2 {
		t.Errorf("без токена kube: код %d", c)
	}
}

const replayFixture = `{"t0":"2026-01-02T10:00:00Z",
"alert":{"fingerprint":"0123456789abcdef","name":"HighLatency","severity":"critical","namespace":"shop","service":"geo-svc","summary":"s","description":"","starts_at":"2026-01-02T09:55:00Z"},
"topology":{"service":"geo-svc","namespace":"shop","database":null,"insufficient_data_policy":null,"autoscaler":null,"pods":["geo-svc-1"],"namespace_labels":{"aegisops.io/managed":"true"},"target_labels":{}},
"metrics":[],"events":[],"deploys":[]}`

// replay: -prepare-only печатает хеши без записи и без обращения к модели; полный replay пишет shadow-запись.
func TestReplay(t *testing.T) {
	s := newStack(t)
	{ // инициализация роутера
		var o, e bytes.Buffer
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		run(ctx, []string{"serve", "-config", s.cfgPath}, s.env(&o, &e))
		cancel()
	}
	before := len(s.records(t))
	posts := s.tr.posts
	fx := filepath.Join(t.TempDir(), "fx.json")
	os.WriteFile(fx, []byte(replayFixture), 0o600)
	var o, e bytes.Buffer
	if err := run(context.Background(), []string{"replay", "-config", s.cfgPath, "-in", fx, "-prepare-only"}, s.env(&o, &e)); err != nil {
		t.Fatalf("prepare-only: %v\n%s", err, e.String())
	}
	var res map[string]any
	if err := json.Unmarshal(o.Bytes(), &res); err != nil || res["request_sha256"] == nil || res["input_sha256"] == nil {
		t.Fatalf("вывод prepare-only: %v %s", err, o.String())
	}
	if len(s.records(t)) != before || s.tr.posts != posts {
		t.Error("prepare-only записал или вызвал модель")
	}
	o.Reset()
	if err := run(context.Background(), []string{"replay", "-config", s.cfgPath, "-in", fx}, s.env(&o, &e)); err != nil {
		t.Fatalf("replay: %v\n%s", err, e.String())
	}
	recs := s.records(t)
	if len(recs) != before+1 {
		t.Fatalf("записей %d, ожидалось %d", len(recs), before+1)
	}
	if r := recs[len(recs)-1]; r.Intake == nil || r.Intake.Outcome != "routed" || r.Mode != audit.ModeShadow {
		t.Errorf("запись: %+v", r.Intake)
	}
	// фикстура с лишним полем отвергается (2), без записи
	bad := filepath.Join(t.TempDir(), "bad.json")
	os.WriteFile(bad, []byte(strings.Replace(replayFixture, `"deploys":[]`, `"deploys":[],"extra":1`, 1)), 0o600)
	if c := exitCode(run(context.Background(), []string{"replay", "-config", s.cfgPath, "-in", bad}, s.env(&o, &e))); c != 2 {
		t.Errorf("фикстура с лишним полем: код %d", c)
	}
}

// Исключаем зависимость от форматирования: lockState держит flock файла состояния intake до вызова возвращённой функции.
func lockState(t *testing.T, path string) func() {
	t.Helper()
	st, err := openIntakeState(path)
	if err != nil {
		t.Fatal(err)
	}
	return func() { st.Close() }
}

func openIntakeState(path string) (*intake.State, error) { return intake.OpenState(path) }
