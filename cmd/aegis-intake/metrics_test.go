package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// withMetrics переписывает конфигурацию стека: metrics_listen = addr.
func (s *stack) withMetrics(t *testing.T, addr string) {
	t.Helper()
	s.cfg["metrics_listen"] = addr
	b, _ := json.Marshal(s.cfg)
	if err := os.WriteFile(s.cfgPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

type lnCapture struct {
	mu    sync.Mutex
	calls int
	addr  string
}

func (c *lnCapture) listen(network, addr string) (net.Listener, error) {
	ln, err := net.Listen(network, addr)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if err == nil {
		c.addr = ln.Addr().String()
	}
	return ln, err
}

func (c *lnCapture) get() (string, int) { c.mu.Lock(); defer c.mu.Unlock(); return c.addr, c.calls }

func scrape(t *testing.T, addr, path string) (int, string) {
	t.Helper()
	resp, err := http.Get("http://" + addr + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func metricValue(body, series string) (string, bool) {
	re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(series) + ` (\S+)$`)
	m := re.FindStringSubmatch(body)
	if m == nil {
		return "", false
	}
	return m[1], true
}

func sumRecords(body string) float64 {
	var sum float64
	for _, m := range regexp.MustCompile(`(?m)^aegis_intake_records_total\{[^}]*\} (\S+)$`).FindAllStringSubmatch(body, -1) {
		var f float64
		json.Unmarshal([]byte(m[1]), &f)
		sum += f
	}
	return sum
}

func TestServeMetricsEndToEnd(t *testing.T) {
	s := newStack(t)
	s.withMetrics(t, "127.0.0.1:0")
	amGone.Store(true)
	cap := &lnCapture{}
	r := s.start(t, func(e env) env { e.listen = cap.listen; return e })
	waitFor(t, "listener метрик", 5*time.Second, func() bool { a, _ := cap.get(); return a != "" })
	addr, _ := cap.get()
	waitFor(t, "событие bootstrap", 5*time.Second, func() bool {
		for _, ev := range s.killSwitchEvents(t) {
			if ev.Bootstrap {
				return true
			}
		}
		return false
	})
	// после старта без истории: остановлен, ждём release
	var body string
	waitFor(t, "метрики bootstrap", 5*time.Second, func() bool {
		_, body = scrape(t, addr, "/metrics")
		v, ok := metricValue(body, "aegis_intake_killswitch_bootstrap_awaiting_release")
		return ok && v == "1"
	})
	if v, _ := metricValue(body, `aegis_intake_killswitch_stopped{cluster="prod-eu-1"}`); v != "1" {
		t.Errorf("stopped = %q\n%s", v, body)
	}
	if v, _ := metricValue(body, "aegis_intake_killswitch_bootstrap_pending"); v != "0" {
		t.Errorf("bootstrap_pending = %q", v)
	}
	if code, hz := scrape(t, addr, "/healthz"); code != 200 || hz != "ok\n" {
		t.Errorf("/healthz при остановке: %d %q", code, hz)
	}
	// утечек нет
	for _, bad := range []string{"oncall-ivanov", "oncall-petrov", "geo-svc", "sha256", "intake-test", "Bearer"} {
		if strings.Contains(body, bad) {
			t.Errorf("в /metrics утекло %q", bad)
		}
	}
	// release двумя дежурными
	lastKS.setRun(t)
	waitFor(t, "released в метриках", 8*time.Second, func() bool {
		_, body = scrape(t, addr, "/metrics")
		v, _ := metricValue(body, `aegis_intake_killswitch_events_total{kind="released"}`)
		return v == "1"
	})
	for series, want := range map[string]string{`aegis_intake_killswitch_stopped{cluster="prod-eu-1"}`: "0", "aegis_intake_killswitch_liveness_confirmed": "1",
		"aegis_intake_killswitch_bootstrap_awaiting_release": "0", `aegis_intake_killswitch_reason{reason="none"}`: "1"} {
		if v, _ := metricValue(body, series); v != want {
			t.Errorf("%s = %q, ожидалось %s", series, v, want)
		}
	}
	before := sumRecords(body)
	amGone.Store(false)
	waitFor(t, "запись", 8*time.Second, func() bool { return len(s.records(t)) == 1 })
	waitFor(t, "records_total вырос", 5*time.Second, func() bool {
		_, body = scrape(t, addr, "/metrics")
		return sumRecords(body) > before
	})
	if v, _ := metricValue(body, `aegis_intake_alert_polls_total{result="ok"}`); v == "0" || v == "" {
		t.Errorf("alert_polls ok = %q", v)
	}
	if v, _ := metricValue(body, `aegis_intake_incidents{status="recorded"}`); v != "1" {
		t.Errorf("incidents recorded = %q", v)
	}
	for _, bad := range []string{"geo-svc", s.records(t)[0].Incident.ID} {
		if strings.Contains(body, bad) {
			t.Errorf("в /metrics утекло %q", bad)
		}
	}
	// завершение: serve без ошибки, порт закрыт
	start := time.Now()
	if err := r.stop(t); err != nil {
		t.Fatalf("serve: %v\n%s", err, r.errb.String())
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("остановка заняла %s", d)
	}
	if c, err := net.DialTimeout("tcp", addr, 500*time.Millisecond); err == nil {
		c.Close()
		t.Error("порт метрик открыт после остановки")
	}
}

func TestServeMetricsPortBusy(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	s := newStack(t)
	s.withMetrics(t, busy.Addr().String())
	amGone.Store(false)
	var out, errb bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = run(ctx, []string{"serve", "-config", s.cfgPath}, s.env(&out, &errb))
	if err == nil || exitCode(err) != 2 || !strings.Contains(err.Error(), "metrics_listen") {
		t.Fatalf("занятый порт: код %d, ошибка %v", exitCode(err), err)
	}
	if n := len(s.records(t)); n != 0 {
		t.Errorf("до приёма инцидентов записей быть не должно: %d", n)
	}
	if _, inc := s.intakeState(); len(inc) != 0 {
		t.Errorf("инциденты приняты: %v", inc)
	}
	if evs := s.killSwitchEvents(t); len(evs) != 0 {
		t.Errorf("kill switch опрошен до ошибки listener: %d событий", len(evs))
	}
}

func TestServeWithoutMetricsListenDoesNotListen(t *testing.T) {
	s := newStack(t)
	cap := &lnCapture{}
	r := s.startReleased(t, func(e env) env { e.listen = cap.listen; return e })
	waitFor(t, "запись", 8*time.Second, func() bool { return len(s.records(t)) == 1 })
	if err := r.stop(t); err != nil {
		t.Fatalf("serve: %v\n%s", err, r.errb.String())
	}
	if _, calls := cap.get(); calls != 0 {
		t.Errorf("env.listen вызван %d раз без metrics_listen", calls)
	}
}

func TestInvalidMetricsListenIsUsageError(t *testing.T) {
	s := newStack(t)
	s.withMetrics(t, "9464")
	var out, errb bytes.Buffer
	err := run(context.Background(), []string{"serve", "-config", s.cfgPath}, s.env(&out, &errb))
	var ee exitError
	if !errors.As(err, &ee) || ee.code != 2 {
		t.Errorf("код %d: %v", exitCode(err), err)
	}
}

// brokenListener: Accept падает сразу — сервер метрик «умирает» после старта.
type brokenListener struct{ net.Listener }

func (b brokenListener) Accept() (net.Conn, error) { return nil, errors.New("accept: сломан") }

// Сбой HTTP-сервера метрик после старта не фатален: serve продолжает работать (intake_metrics_failed в журнале).
func TestServeMetricsFailureIsNotFatal(t *testing.T) {
	s := newStack(t)
	s.withMetrics(t, "127.0.0.1:0")
	amGone.Store(true)
	r := s.start(t, func(e env) env {
		e.listen = func(network, addr string) (net.Listener, error) {
			ln, err := net.Listen(network, addr)
			return brokenListener{ln}, err
		}
		return e
	})
	select {
	case err := <-r.done:
		r.done <- err
		t.Fatalf("serve завершился из-за сбоя метрик (err=%v, код %d):\n%s", err, exitCode(err), r.errb.String())
	case <-time.After(2 * time.Second):
	}
	if !strings.Contains(r.errb.String(), "intake_metrics_failed") {
		t.Errorf("нет intake_metrics_failed:\n%s", r.errb.String())
	}
	r.stop(t)
}

// После сбоя метрик intake продолжает принимать инциденты и штатно завершается по ctx (nil, serve_error пуст).
func TestServeContinuesAfterMetricsFailure(t *testing.T) {
	s := newStack(t)
	s.withMetrics(t, "127.0.0.1:0")
	r := s.startReleased(t, func(e env) env {
		e.listen = func(network, addr string) (net.Listener, error) {
			ln, err := net.Listen(network, addr)
			return brokenListener{ln}, err
		}
		return e
	})
	waitFor(t, "запись после сбоя метрик", 8*time.Second, func() bool { return len(s.records(t)) == 1 })
	if err := r.stop(t); err != nil {
		t.Fatalf("serve: %v", err)
	}
	if !strings.Contains(r.errb.String(), "intake_metrics_failed") || !strings.Contains(r.errb.String(), `"serve_error":"<nil>"`) && !strings.Contains(r.errb.String(), `"serve_error":"<nil>"`) {
		t.Errorf("журнал:\n%s", r.errb.String())
	}
}
