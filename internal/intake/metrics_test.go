package intake

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/limpjungle/aegis3311/internal/audit"
	"github.com/limpjungle/aegis3311/internal/killswitch"
	"github.com/limpjungle/aegis3311/internal/llmrouter"
	"github.com/limpjungle/aegis3311/internal/promtext"
)

type fakeKS struct {
	mu sync.Mutex
	o  killswitch.Observation
}

func (f *fakeKS) Observe() killswitch.Observation { f.mu.Lock(); defer f.mu.Unlock(); return f.o }
func (f *fakeKS) set(o killswitch.Observation)    { f.mu.Lock(); f.o = o; f.mu.Unlock() }

// PollOnce фейкового монитора: меняет наблюдаемое состояние, как это делал бы настоящий.
func (f *fakeKS) PollOnce(i int) {
	f.mu.Lock()
	f.o.LastPoll = time.Unix(int64(1000+i), 0)
	f.o.Events = map[string]uint64{"kill_switch_engaged": uint64(i)}
	f.mu.Unlock()
}

type fakeRouter struct{ s llmrouter.State }

func (f fakeRouter) State() llmrouter.State { return f.s }

type fakeChain struct{ seq uint64 }

func (f fakeChain) Head() audit.Head { return audit.Head{ChainID: "secret-chain", Seq: f.seq} }

const (
	secretIncident = "inc-7f3a9c-geo-svc"
	secretIssuer   = "oncall-ivanov"
	secretSHA      = "sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
)

// stoppedObs — остановленный kill switch с «чувствительным» содержимым в наблюдении.
func stoppedObs() killswitch.Observation {
	var st killswitch.State
	st.Stopped, st.Reason, st.Global = true, "global", true
	st.Actions = []string{"workload.restart"}
	st.Triggers = []string{secretSHA}
	st.TriggerSigners = []string{secretIssuer}
	st.Marks = killswitch.Marks{Stop: time.Unix(1_700_000_000, 0), Release: time.Unix(1_699_999_000, 0)}
	st.Channels = []audit.KillSwitchChannel{
		{Channel: "configmap", Status: "fresh", Error: "partial_signatures", Signers: []string{secretIssuer}, DocSHA256: secretSHA, IssuedAt: "2023-11-14T22:13:20Z"},
		{Channel: "oob", Status: "absent", Error: "http_403", Signers: []string{}}}
	lat := int64(1234)
	return killswitch.Observation{State: st, BootstrapAwaitingRelease: true, LastPoll: time.Unix(1_700_000_100, 0),
		ChannelLastOK: map[string]time.Time{"configmap": time.Unix(1_700_000_090, 0)},
		Events:        map[string]uint64{"kill_switch_engaged": 2, "kill_switch_released": 1}, LastEngagedLatencyMs: &lat}
}

func testMetrics(t testing.TB, ks KillSwitchObserver) (*Metrics, *State) {
	t.Helper()
	st, err := OpenState("")
	if err != nil {
		t.Fatal(err)
	}
	st.Do(func(d *Data) {
		d.Incidents[secretIncident] = &Incident{ID: secretIncident, Status: StatusOpen}
		d.Incidents["inc-2"] = &Incident{ID: "inc-2", Status: StatusRecorded}
		d.Incidents["inc-3"] = &Incident{ID: "inc-3", Status: "weird-" + secretIncident}
	})
	return NewMetrics("prod-eu-1", ks, fakeRouter{llmrouter.State{Halted: true, HaltReason: "audit_failed"}}, fakeChain{42}, st,
		func() time.Time { return time.Unix(1_700_000_000, 0) }), st
}

func get(t testing.TB, h http.Handler, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

func TestMetricsHandlerRouting(t *testing.T) {
	ks := &fakeKS{o: stoppedObs()}
	m, _ := testMetrics(t, ks)
	h := m.Handler()
	r := get(t, h, "GET", "/metrics")
	if r.Code != 200 || r.Header().Get("Content-Type") != promtext.ContentType || r.Body.Len() == 0 {
		t.Fatalf("GET /metrics: %d %q len=%d", r.Code, r.Header().Get("Content-Type"), r.Body.Len())
	}
	hd := get(t, h, "HEAD", "/metrics")
	if hd.Code != 200 || hd.Body.Len() != 0 || hd.Header().Get("Content-Type") != promtext.ContentType {
		t.Errorf("HEAD /metrics: %d len=%d", hd.Code, hd.Body.Len())
	}
	for _, p := range []string{"/metrics", "/healthz"} {
		for _, meth := range []string{"POST", "PUT", "DELETE", "PATCH"} {
			rr := get(t, h, meth, p)
			if rr.Code != 405 || !strings.Contains(rr.Header().Get("Allow"), "GET") || !strings.Contains(rr.Header().Get("Allow"), "HEAD") {
				t.Errorf("%s %s: %d Allow=%q", meth, p, rr.Code, rr.Header().Get("Allow"))
			}
		}
	}
	for _, p := range []string{"/other", "/", "/metrics/", "/healthz/x", "/debug/pprof/"} {
		if rr := get(t, h, "GET", p); rr.Code != 404 {
			t.Errorf("GET %s: %d", p, rr.Code)
		}
	}
	// /healthz — 200 ok даже при остановленном kill switch
	if hz := get(t, h, "GET", "/healthz"); hz.Code != 200 || hz.Body.String() != "ok\n" {
		t.Errorf("/healthz при остановке: %d %q", hz.Code, hz.Body)
	}
	if hz := get(t, h, "HEAD", "/healthz"); hz.Code != 200 || hz.Body.Len() != 0 {
		t.Errorf("HEAD /healthz: %d", hz.Code)
	}
	// nil-наблюдатели не роняют скрейп
	empty := NewMetrics("c", nil, nil, nil, nil, nil)
	if rr := get(t, empty.Handler(), "GET", "/metrics"); rr.Code != 200 {
		t.Errorf("пустые наблюдатели: %d", rr.Code)
	}
}

var (
	typeRe   = regexp.MustCompile(`^# TYPE (\S+) (gauge|counter)$`)
	helpRe   = regexp.MustCompile(`^# HELP (\S+) .*$`)
	sampleRe = regexp.MustCompile(`^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{([a-zA-Z_][a-zA-Z0-9_]*="[^"\\\n]*"(,[a-zA-Z_][a-zA-Z0-9_]*="[^"\\\n]*")*)?\})? (-?[0-9.]+(e[+-][0-9]+)?|NaN|\+Inf|-Inf)$`)
	labelRe  = regexp.MustCompile(`([a-zA-Z_][a-zA-Z0-9_]*)="([^"]*)"`)
)

type series struct {
	name   string
	labels map[string]string
	value  string
}

// parseExposition разбирает тело строго: у каждого семейства есть # TYPE до рядов, ряды соответствуют формату 0.0.4.
func parseExposition(t testing.TB, body string) (map[string]string, []series) {
	t.Helper()
	types := map[string]string{}
	var out []series
	if !strings.HasSuffix(body, "\n") {
		t.Fatal("тело не заканчивается переводом строки")
	}
	for _, ln := range strings.Split(strings.TrimSuffix(body, "\n"), "\n") {
		switch {
		case helpRe.MatchString(ln):
		case typeRe.MatchString(ln):
			m := typeRe.FindStringSubmatch(ln)
			if _, dup := types[m[1]]; dup {
				t.Errorf("семейство %s выведено дважды", m[1])
			}
			types[m[1]] = m[2]
		case sampleRe.MatchString(ln):
			m := sampleRe.FindStringSubmatch(ln)
			if types[m[1]] == "" {
				t.Errorf("ряд без # TYPE: %s", ln)
			}
			s := series{name: m[1], labels: map[string]string{}, value: m[5]}
			for _, l := range labelRe.FindAllStringSubmatch(m[3], -1) {
				s.labels[l[1]] = l[2]
			}
			out = append(out, s)
		default:
			t.Errorf("строка не по формату 0.0.4: %q", ln)
		}
	}
	return types, out
}

func find(ss []series, name string, kv ...string) (series, bool) {
next:
	for _, s := range ss {
		if s.name != name {
			continue
		}
		for i := 0; i < len(kv); i += 2 {
			if s.labels[kv[i]] != kv[i+1] {
				continue next
			}
		}
		return s, true
	}
	return series{}, false
}

func val(t testing.TB, ss []series, name string, kv ...string) string {
	t.Helper()
	s, ok := find(ss, name, kv...)
	if !ok {
		t.Fatalf("нет ряда %s %v", name, kv)
	}
	return s.value
}

var allowedLabels = map[string]bool{"cluster": true, "reason": true, "channel": true, "kind": true, "result": true, "outcome": true,
	"mode": true, "status": true}

func TestMetricsExposition(t *testing.T) {
	ks := &fakeKS{o: stoppedObs()}
	m, _ := testMetrics(t, ks)
	body, err := m.Render()
	if err != nil {
		t.Fatal(err)
	}
	types, ss := parseExposition(t, string(body))
	wantFamilies := []string{"killswitch_stopped", "killswitch_reason", "killswitch_liveness_confirmed", "killswitch_actions_restricted",
		"killswitch_confirmed_until_timestamp_seconds", "killswitch_stop_watermark_timestamp_seconds", "killswitch_release_watermark_timestamp_seconds",
		"killswitch_bootstrap_pending", "killswitch_bootstrap_awaiting_release", "killswitch_last_poll_timestamp_seconds", "killswitch_channel_ok",
		"killswitch_channel_cached", "killswitch_channel_doc_issued_timestamp_seconds", "killswitch_channel_last_success_timestamp_seconds",
		"killswitch_last_engaged_latency_ms", "killswitch_events_total", "alert_polls_total", "records_total", "records_llm_mode_total",
		"records_kill_switch_stopped_total", "incidents", "router_halted", "router_halt_reason", "audit_chain_seq", "start_timestamp_seconds"}
	for _, f := range wantFamilies {
		if types["aegis_intake_"+f] == "" {
			t.Errorf("нет семейства aegis_intake_%s", f)
		}
	}
	for name, typ := range types {
		if strings.HasSuffix(name, "_total") != (typ == "counter") {
			t.Errorf("%s: тип %s не согласован с суффиксом _total", name, typ)
		}
		if !strings.HasPrefix(name, "aegis_intake_") {
			t.Errorf("семейство вне префикса: %s", name)
		}
	}
	for _, s := range ss {
		for l := range s.labels {
			if !allowedLabels[l] {
				t.Errorf("недопустимая метка %s в %s", l, s.name)
			}
		}
	}
	// значения
	for name, want := range map[string]string{
		"aegis_intake_killswitch_stopped":                             "1",
		"aegis_intake_killswitch_actions_restricted":                  "1",
		"aegis_intake_killswitch_bootstrap_pending":                   "0",
		"aegis_intake_killswitch_bootstrap_awaiting_release":          "1",
		"aegis_intake_killswitch_liveness_confirmed":                  "0",
		"aegis_intake_killswitch_last_engaged_latency_ms":             "1234",
		"aegis_intake_router_halted":                                  "1",
		"aegis_intake_audit_chain_seq":                                "42",
		"aegis_intake_killswitch_stop_watermark_timestamp_seconds":    "1.7e+09",
		"aegis_intake_killswitch_release_watermark_timestamp_seconds": "1.699999e+09",
	} {
		if got := val(t, ss, name); got != want {
			t.Errorf("%s = %s, ожидалось %s", name, got, want)
		}
	}
	if v := val(t, ss, "aegis_intake_killswitch_stopped", "cluster", "prod-eu-1"); v != "1" {
		t.Errorf("stopped{cluster}: %s", v)
	}
	if v := val(t, ss, "aegis_intake_killswitch_events_total", "kind", "engaged"); v != "2" {
		t.Errorf("events engaged: %s", v)
	}
	if v := val(t, ss, "aegis_intake_killswitch_events_total", "kind", "released"); v != "1" {
		t.Errorf("events released: %s", v)
	}
	if val(t, ss, "aegis_intake_killswitch_channel_ok", "channel", "configmap") != "0" || val(t, ss, "aegis_intake_killswitch_channel_ok", "channel", "oob") != "0" {
		t.Error("channel_ok с ошибкой должен быть 0")
	}
	if v := val(t, ss, "aegis_intake_killswitch_channel_last_success_timestamp_seconds", "channel", "configmap"); v != "1.70000009e+09" {
		t.Errorf("channel_last_success: %s", v)
	}
	if v := val(t, ss, "aegis_intake_killswitch_channel_last_success_timestamp_seconds", "channel", "oob"); v != "0" {
		t.Errorf("channel_last_success oob: %s", v)
	}
	if v := val(t, ss, "aegis_intake_router_halt_reason", "reason", "audit_failed"); v != "1" {
		t.Errorf("halt_reason: %s", v)
	}
	// инциденты: неизвестный статус сворачивается в other
	if val(t, ss, "aegis_intake_incidents", "status", "open") != "1" || val(t, ss, "aegis_intake_incidents", "status", "recorded") != "1" ||
		val(t, ss, "aegis_intake_incidents", "status", "other") != "1" {
		t.Errorf("incidents: %s", body)
	}
	// one-hot: суммы равны 1
	for _, fam := range []string{"aegis_intake_killswitch_reason", "aegis_intake_router_halt_reason"} {
		sum := 0
		for _, s := range ss {
			if s.name == fam {
				if s.value != "0" && s.value != "1" {
					t.Errorf("%s: значение %s", fam, s.value)
				}
				if s.value == "1" {
					sum++
				}
			}
		}
		if sum != 1 {
			t.Errorf("%s: единиц %d, ожидалась 1", fam, sum)
		}
	}
	// ряды заранее заполнены нулями
	for _, want := range [][]string{{"aegis_intake_alert_polls_total", "result", "ok"}, {"aegis_intake_alert_polls_total", "result", "error"},
		{"aegis_intake_records_total", "outcome", "routed"}, {"aegis_intake_records_total", "outcome", "not_routed", "reason", "source_unavailable"},
		{"aegis_intake_records_llm_mode_total", "mode", "hybrid"}, {"aegis_intake_records_llm_mode_total", "mode", "off"},
		{"aegis_intake_killswitch_events_total", "kind", "updated"}} {
		if s, ok := find(ss, want[0], want[1:]...); !ok || s.value != "0" {
			t.Errorf("нулевой ряд %v: %v %v", want, s, ok)
		}
	}
	if _, ok := find(ss, "aegis_intake_records_kill_switch_stopped_total"); !ok {
		t.Error("нет records_kill_switch_stopped_total")
	}
}

func TestMetricsNoLeak(t *testing.T) {
	ks := &fakeKS{o: stoppedObs()}
	m, _ := testMetrics(t, ks)
	// записи с чувствительными значениями: неизвестный reason/mode не должен попасть в метки
	m.Record(&audit.DecisionRecord{Incident: audit.IncidentRef{ID: secretIncident, Service: "geo-svc"}, Initiator: audit.Actor{ID: "intake-secret"},
		Intake: &audit.IntakeInfo{Outcome: "not_routed", Reason: "geo-svc/shop/" + secretIncident}})
	m.Record(&audit.DecisionRecord{Intake: &audit.IntakeInfo{Outcome: "routed"}, LLM: &audit.LLMInfo{Mode: "shop-" + secretIssuer}})
	body, err := m.Render()
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"geo-svc", "shop", secretIncident, secretIssuer, "oncall-", "deadbeef", "sha256", "intake-secret", "secret-chain",
		"partial_signatures", "http_403", "workload.restart", "weird"} {
		if strings.Contains(string(body), bad) {
			t.Errorf("в /metrics утекло %q", bad)
		}
	}
	_, ss := parseExposition(t, string(body))
	if v := val(t, ss, "aegis_intake_records_total", "outcome", "not_routed", "reason", "other"); v != "1" {
		t.Errorf("неизвестный reason должен быть other: %s", v)
	}
	if v := val(t, ss, "aegis_intake_records_llm_mode_total", "mode", "other"); v != "1" {
		t.Errorf("неизвестный mode должен быть other: %s", v)
	}
}

func TestMetricsCounters(t *testing.T) {
	ks := &fakeKS{}
	m, _ := testMetrics(t, ks)
	m.AlertPoll(true)
	m.AlertPoll(true)
	m.AlertPoll(false)
	routed := func(mode string, stopped bool) *audit.DecisionRecord {
		return &audit.DecisionRecord{Intake: &audit.IntakeInfo{Outcome: "routed"}, LLM: &audit.LLMInfo{Mode: mode},
			KillSwitch: &audit.KillSwitchInfo{State: audit.KillSwitchState{Stopped: stopped}}}
	}
	m.Record(routed("hybrid", false))
	m.Record(routed("off", true))
	m.Record(&audit.DecisionRecord{Intake: &audit.IntakeInfo{Outcome: "not_routed", Reason: "rate_limited"}})
	m.Record(&audit.DecisionRecord{}) // без intake — игнор
	m.Record(nil)
	body, _ := m.Render()
	_, ss := parseExposition(t, string(body))
	for _, c := range []struct {
		want string
		name string
		kv   []string
	}{
		{"2", "aegis_intake_alert_polls_total", []string{"result", "ok"}},
		{"1", "aegis_intake_alert_polls_total", []string{"result", "error"}},
		{"2", "aegis_intake_records_total", []string{"outcome", "routed", "reason", "none"}},
		{"1", "aegis_intake_records_total", []string{"outcome", "not_routed", "reason", "rate_limited"}},
		{"1", "aegis_intake_records_llm_mode_total", []string{"mode", "hybrid"}},
		{"1", "aegis_intake_records_llm_mode_total", []string{"mode", "off"}},
		{"1", "aegis_intake_records_kill_switch_stopped_total", nil},
	} {
		if got := val(t, ss, c.name, c.kv...); got != c.want {
			t.Errorf("%s %v = %s, ожидалось %s", c.name, c.kv, got, c.want)
		}
	}
	// nil-безопасность
	var nm *Metrics
	nm.AlertPoll(true)
	nm.Record(routed("off", false))
}

func TestMetricsRace(t *testing.T) {
	ks := &fakeKS{o: stoppedObs()}
	m, _ := testMetrics(t, ks)
	h := m.Handler()
	var wg sync.WaitGroup
	stop := make(chan struct{})
	rec := &audit.DecisionRecord{Intake: &audit.IntakeInfo{Outcome: "routed"}, LLM: &audit.LLMInfo{Mode: "hybrid"}}
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				rr := httptest.NewRecorder()
				h.ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))
				if rr.Code != 200 {
					t.Errorf("скрейп: %d", rr.Code)
					return
				}
			}
		}()
	}
	wg.Add(3)
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			m.Record(rec)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			m.AlertPoll(i%2 == 0)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			ks.PollOnce(i)
		}
	}()
	time.Sleep(200 * time.Millisecond)
	close(stop)
	wg.Wait()
}

func TestServeMetricsLifecycle(t *testing.T) {
	ks := &fakeKS{o: stoppedObs()}
	m, _ := testMetrics(t, ks)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ServeMetrics(ctx, ln, m.Handler(), nil) }()
	resp, err := http.Get("http://" + addr + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != promtext.ContentType || !bytes.Contains(b, []byte("aegis_intake_killswitch_stopped")) {
		t.Fatalf("GET: %d %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	start := time.Now()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("ServeMetrics вернул %v", err)
		}
		if d := time.Since(start); d > time.Second {
			t.Errorf("остановка заняла %s", d)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("ServeMetrics не вернулся после отмены ctx")
	}
	if c, err := net.DialTimeout("tcp", addr, 500*time.Millisecond); err == nil {
		c.Close()
		t.Error("порт открыт после остановки")
	}
}

func TestServeMetricsClosedListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()
	var buf bytes.Buffer
	lg := slog.New(slog.NewTextHandler(&buf, nil))
	m, _ := testMetrics(t, &fakeKS{})
	done := make(chan error, 1)
	go func() { done <- ServeMetrics(context.Background(), ln, m.Handler(), lg) }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("ожидался nil, получено %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ServeMetrics завис на закрытом listener")
	}
	if !strings.Contains(buf.String(), "intake_metrics_failed") {
		t.Errorf("нет лога intake_metrics_failed: %s", buf.String())
	}
}
