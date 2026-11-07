package llmrouter

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/limpjungle/aegis3311/internal/audit"
	"github.com/limpjungle/aegis3311/internal/openrouter"
	"github.com/limpjungle/aegis3311/internal/pyjson"
	"github.com/limpjungle/aegis3311/internal/routerstate"
)

func pj(t testing.TB, s string) *pyjson.Value {
	t.Helper()
	v, err := pyjson.Parse([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func frag(t testing.TB, id, src string, req bool, rel int, js string) Fragment {
	return Fragment{ID: id, Source: src, Kind: KindGeneric, Required: req, Relevance: rel, Value: pj(t, js)}
}

func simpleReq(t testing.TB, secs ...Section) Request {
	return Request{IncidentID: "inc-1", Service: "geo-svc", Mode: ModeHybrid, Sections: secs}
}

func one(key string, f Fragment) Section { return Section{Key: key, Fragments: []Fragment{f}} }
func list(key string, fs ...Fragment) Section {
	return Section{Key: key, List: true, Fragments: fs}
}

func inputOf(t *testing.T, p *Prepared) *pyjson.Value {
	t.Helper()
	return pj(t, userContent(t, p.Body))
}

func TestNewFailClosed(t *testing.T) {
	a := loadAssets(t)
	tr := &stubTransport{}
	cl, _ := openrouter.NewClient(&a.Config, testKey(t, "k-1"), tr)
	base := Options{Assets: a, Client: cl, Masker: &identityMasker{}, Events: &memSink{}, Clock: newFakeClock(), Budgets: DefaultBudgets(), Failover: DefaultFailover(), RouterID: "r1",
		State: routerstate.NewMemory(routerstate.Identity{RouterID: "r1", Primary: a.Primary.Name, Fallback: a.Fallback.Name})}
	if _, err := New(base); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(o *Options){
		"nil маскировщик":  func(o *Options) { o.Masker = nil },
		"typed-nil":        func(o *Options) { o.Masker = (*identityMasker)(nil) },
		"nil Events":       func(o *Options) { o.Events = nil },
		"nil State":        func(o *Options) { o.State = nil },
		"nil Clock":        func(o *Options) { o.Clock = nil },
		"бюджет 0":         func(o *Options) { o.Budgets.IncidentTokens = 0 },
		"порог failover 0": func(o *Options) { o.Failover.FailThreshold = 0 },
	} {
		o := base
		mut(&o)
		_, err := New(o)
		if err == nil {
			t.Errorf("%s: принято", name)
		}
		if strings.HasPrefix(name, "nil мас") || name == "typed-nil" {
			if !errors.Is(err, ErrNoMasker) {
				t.Errorf("%s: %v", name, err)
			}
		}
	}
}

func TestPrepareGates(t *testing.T) {
	ctx := context.Background()
	t.Run("источник логов не доходит до маскировщика", func(t *testing.T) {
		m := &identityMasker{}
		rg := newRig(t, m, &stubTransport{}, "", nil)
		req := simpleReq(t, one("alert", frag(t, "a", "alerts.alertmanager", true, 1, `{"n":1}`)),
			list("logs", frag(t, "l1", "logs.loki", false, 1, `"x"`)), list("unk", frag(t, "u1", "no.such", false, 1, `"x"`)))
		p, err := rg.r.Prepare(ctx, req, RolePrimary)
		if err != nil || p.NotSent != "" {
			t.Fatal(err, p)
		}
		if m.calls.Load() != 1 || len(p.Excluded) != 2 || p.Excluded[0].Reason != "source_class" || p.Excluded[1].Reason != "unknown_source" ||
			p.Excluded[1].Class.String() != "restricted" {
			t.Fatalf("calls=%d %+v", m.calls.Load(), p.Excluded)
		}
		in := inputOf(t, p)
		if l := in.Get("logs"); l == nil || len(l.Items) != 0 {
			t.Error("исключённый список должен быть []")
		}
	})
	t.Run("ПДн: необязательный исключён, обязательный — нет запроса", func(t *testing.T) {
		m := &pdMasker{hit: map[string]bool{"k": true}}
		rg := newRig(t, m, &stubTransport{}, "", nil)
		req := simpleReq(t, one("alert", frag(t, "a", "alerts.alertmanager", true, 1, `1`)), one("k", frag(t, "k", "k8s.events", false, 1, `"zzz"`)))
		p, _ := rg.r.Prepare(ctx, req, RolePrimary)
		if p.NotSent != "" || len(p.Excluded) != 1 || p.Excluded[0].Reason != "personal_data" || inputOf(t, p).Get("k") != nil || strings.Contains(string(p.Body), "zzz") {
			t.Fatalf("%+v", p)
		}
		req.Sections[1].Fragments[0].Required = true
		if p, _ := rg.r.Prepare(ctx, req, RolePrimary); p.NotSent != "required_excluded" || p.Body != nil {
			t.Fatalf("%+v", p)
		}
	})
	for _, mode := range []string{"failed", "error", "panic", "nil", "hang"} {
		t.Run("сбой маскировщика "+mode, func(t *testing.T) {
			rg := newRig(t, &failMasker{mode: mode}, &stubTransport{}, "", nil)
			rg.r.maskTimeout = 50 * time.Millisecond
			req := simpleReq(t, one("k", frag(t, "k", "k8s.events", false, 1, `"x"`)))
			p, err := rg.r.Prepare(ctx, req, RolePrimary)
			if err != nil || len(p.Excluded) != 1 || p.Excluded[0].Reason != "masker_failure" {
				t.Fatalf("%v %+v", err, p)
			}
			req.Sections[0].Fragments[0].Required = true
			if p, _ := rg.r.Prepare(ctx, req, RolePrimary); p.NotSent != "required_excluded" {
				t.Fatal(p.NotSent)
			}
		})
	}
	t.Run("секрет: отправлен замаскированным", func(t *testing.T) {
		rg := newRig(t, &secretMasker{}, &stubTransport{}, "", nil)
		p, _ := rg.r.Prepare(ctx, simpleReq(t, one("k", frag(t, "k", "manifests.k8s", false, 1, `"orig"`))), RolePrimary)
		if len(p.Excluded) != 0 || p.DataClass.String() != "internal" || inputOf(t, p).Get("k").S != "<removed>" {
			t.Fatalf("%+v", p)
		}
	})
	t.Run("маскировщик не портит исходный запрос", func(t *testing.T) {
		rg := newRig(t, &mutatingMasker{}, &stubTransport{}, "", nil)
		req := simpleReq(t, one("k", frag(t, "k", "manifests.k8s", false, 1, `{"a":[1,2]}`)))
		rg.r.Prepare(ctx, req, RolePrimary)
		if got := string(pyjson.Marshal(req.Sections[0].Fragments[0].Value, pyjson.Canonical)); got != `{"a":[1,2]}` {
			t.Fatal(got)
		}
	})
	t.Run("метки метрик", func(t *testing.T) {
		rg := newRig(t, &identityMasker{}, &stubTransport{}, "", nil)
		f := Fragment{ID: "m", Source: "metrics.prometheus", Kind: KindMetricSeries, Relevance: 1, Value: pj(t, `{"labels":{"service":"a","user":"bob"}}`)}
		p, _ := rg.r.Prepare(ctx, simpleReq(t, list("metrics", f)), RolePrimary)
		if p.LabelsDropped != 1 || strings.Contains(string(p.Body), "bob") {
			t.Fatalf("%+v", p)
		}
		f.Value = pj(t, `{"labels":3}`)
		p, _ = rg.r.Prepare(ctx, simpleReq(t, list("metrics", f)), RolePrimary)
		if len(p.Excluded) != 1 || p.Excluded[0].Reason != "malformed" {
			t.Fatalf("%+v", p.Excluded)
		}
	})
}

func TestContextCeiling(t *testing.T) {
	ctx := context.Background()
	rg := newRig(t, &identityMasker{}, &stubTransport{}, "", nil)
	big := func(n int) string { return `"` + strings.Repeat("x", n) + `"` }
	mk := func(a, b, c int) Request {
		return simpleReq(t,
			one("must", frag(t, "must", "platform.topology", true, 100, `1`)),
			list("l", frag(t, "f1", "k8s.events", false, 10, big(a)), frag(t, "f2", "k8s.events", false, 10, big(b)), frag(t, "f3", "k8s.events", false, 5, big(c))))
	}
	// Суммарно > потолка: отбрасываются f3 (меньшая релевантность), затем поздний из равных — f2.
	p, err := rg.r.Prepare(ctx, mk(100000, 100000, 100000), RolePrimary)
	if err != nil || p.NotSent != "" {
		t.Fatal(err, p.NotSent)
	}
	var ids []string
	for _, d := range p.Dropped {
		ids = append(ids, d.ID)
	}
	if fmt.Sprint(ids) != "[f3 f2]" || p.EstInputTokens+p.MaxTokens > rg.assets.Config.ContextCeiling {
		t.Fatalf("%v est=%d", ids, p.EstInputTokens)
	}
	p2, _ := rg.r.Prepare(ctx, mk(100000, 100000, 100000), RolePrimary)
	if p2.RequestSHA256 != p.RequestSHA256 {
		t.Error("недетерминированно")
	}
	// Граница: наибольший размер без отбрасывания укладывается в потолок, на единицу больше — отбрасывает.
	fits := func(n int) *Prepared {
		q, err := rg.r.Prepare(ctx, mk(n, 10, 10), RolePrimary)
		if err != nil {
			t.Fatal(err)
		}
		return q
	}
	lo, hi := 10, 200000
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if len(fits(mid).Dropped) == 0 {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	if q := fits(lo); len(q.Dropped) != 0 || q.EstInputTokens+q.MaxTokens > rg.assets.Config.ContextCeiling {
		t.Fatalf("граница: %d", lo)
	}
	if len(fits(lo+1).Dropped) == 0 {
		t.Fatal("за границей ничего не отброшено")
	}
	// Обязательный фрагмент не помещается.
	req := mk(10, 10, 10)
	req.Sections[0].Fragments[0].Value = pj(t, big(200000))
	if p, _ := rg.r.Prepare(ctx, req, RolePrimary); p.NotSent != "context_ceiling" || len(p.Dropped) != 3 {
		t.Fatalf("%s %d", p.NotSent, len(p.Dropped))
	}
}

func TestRequestValidate(t *testing.T) {
	f := func(id string) Fragment {
		return Fragment{ID: id, Source: "k8s.events", Kind: KindGeneric, Value: pyjson.NewNull()}
	}
	bad := map[string]Request{
		"дубль ID":      {IncidentID: "i", Service: "s", Mode: ModeHybrid, Sections: []Section{list("a", f("x"), f("x"))}},
		"дубль ключа":   {IncidentID: "i", Service: "s", Mode: ModeHybrid, Sections: []Section{list("a", f("x")), list("a", f("y"))}},
		"value с двумя": {IncidentID: "i", Service: "s", Mode: ModeHybrid, Sections: []Section{{Key: "a", Fragments: []Fragment{f("x"), f("y")}}}},
		"nil значение":  {IncidentID: "i", Service: "s", Mode: ModeHybrid, Sections: []Section{list("a", Fragment{ID: "x", Kind: KindGeneric})}},
		"режим":         {IncidentID: "i", Service: "s", Mode: "x"},
		"incident":      {IncidentID: "", Service: "s", Mode: ModeHybrid},
	}
	for name, r := range bad {
		if err := r.validate(); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
	var many []Fragment
	for i := 0; i <= MaxFragments; i++ {
		many = append(many, f(fmt.Sprint("f", i)))
	}
	if err := (&Request{IncidentID: "i", Service: "s", Mode: ModeHybrid, Sections: []Section{list("a", many...)}}).validate(); err == nil {
		t.Error("больше MaxFragments")
	}
}

// ---------------------------------------------------------------- Route

const goodAnswer = `{"incident_class":"RB-006","root_cause":"load_growth","action":{"type":"workload.scale_out","params":{"scope":null,"pod_name":null,"reason":null,"parameter":null}},"confidence":0.9,"evidence":["a"],"summary":"s"}`

func reply(provider string, prompt, completion int) openrouter.Response {
	c, _ := pyjsonString(goodAnswer)
	return openrouter.Response{Status: 200, Body: []byte(fmt.Sprintf(`{"id":"g1","model":"m","provider":%q,"choices":[{"finish_reason":"stop","message":{"content":%s}}],"usage":{"prompt_tokens":%d,"completion_tokens":%d,"total_tokens":%d}}`,
		provider, c, prompt, completion, prompt+completion))}
}

func pyjsonString(s string) (string, error) {
	return string(pyjson.Marshal(pyjson.NewString(s), pyjson.Canonical)), nil
}

func routeReq(t testing.TB) Request {
	return simpleReq(t, one("alert", frag(t, "a", "alerts.alertmanager", true, 100, `{"n":1}`)))
}

func providerOf(body []byte) string {
	v, _ := pyjson.Parse(body)
	return v.Get("provider").Get("only").Items[0].S
}

func applyOK(t *testing.T, res *Result) {
	t.Helper()
	rec := &audit.DecisionRecord{Schema: audit.RecordSchema, RecordID: audit.NewRecordID(), RecordedAt: audit.Timestamp(time.Now()), Mode: audit.ModeShadow,
		Incident: audit.IncidentRef{ID: "inc-1", Service: "geo-svc", Environment: "staging"}, Initiator: audit.Actor{Kind: "agent", ID: "a1"},
		RetrievedDocs: []string{}, AutonomyLevel: "L0"}
	res.Apply(rec)
	if err := rec.Validate(); err != nil {
		t.Fatalf("decision record: %v\n%+v", err, rec.LLM)
	}
}

func TestRouteOffAndBudget(t *testing.T) {
	ctx := context.Background()
	m := &identityMasker{}
	tr := &stubTransport{post: func([]byte) (openrouter.Response, error) { return reply("Inceptron", 100, 50), nil }}
	rg := newRig(t, m, tr, "", nil)
	req := routeReq(t)
	req.Mode = ModeOff
	res, err := rg.r.Route(ctx, req)
	if err != nil || res.Reason != "mode_off" || m.calls.Load() != 0 || tr.calls != 0 || res.DegradeL1 {
		t.Fatal(err, res)
	}
	applyOK(t, res)

	req = routeReq(t)
	rg.r.bud.cfg.IncidentTokens = 1000
	res, _ = rg.r.Route(ctx, req)
	if res.Reason != "budget_incident" || !res.DegradeL1 || tr.calls != 0 {
		t.Fatalf("%+v", res)
	}
	applyOK(t, res)
	rg.r.bud.cfg.IncidentTokens = 1 << 40
	rg.r.bud.cfg.ServiceDayTokens = 8200
	res, _ = rg.r.Route(ctx, req)
	if res.Outcome != "sent" {
		t.Fatalf("%+v", res)
	}
	applyOK(t, res)
	req.IncidentID = "inc-2"
	if res, _ = rg.r.Route(ctx, req); res.Reason != "budget_service_day" {
		t.Fatalf("%+v", res)
	}
	rg.clock.Advance(24 * time.Hour)
	if res, _ = rg.r.Route(ctx, req); res.Outcome != "sent" {
		t.Fatalf("после смены суток: %+v", res)
	}
}

func TestRouteConcurrentBudget(t *testing.T) {
	tr := &stubTransport{post: func([]byte) (openrouter.Response, error) { return reply("Inceptron", 100, 50), nil }}
	rg := newRig(t, &identityMasker{}, tr, "", nil)
	rg.r.bud.cfg.ServiceDayTokens = 30000
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := routeReq(t)
			req.IncidentID = fmt.Sprint("inc-", i)
			rg.r.Route(context.Background(), req)
		}(i)
	}
	wg.Wait()
	if d := rg.r.bud.days["geo-svc"]; d.spent+d.held > 30000 || d.held != 0 {
		t.Fatalf("%+v", d)
	}
}

func TestFailover(t *testing.T) {
	ctx := context.Background()
	var mu sync.Mutex
	failPrimary := true
	tr := &stubTransport{post: func(b []byte) (openrouter.Response, error) {
		mu.Lock()
		defer mu.Unlock()
		if providerOf(b) == "inceptron" {
			if failPrimary {
				return openrouter.Response{}, &openrouter.TransportError{Kind: "timeout"}
			}
			return reply("Inceptron", 100, 50), nil
		}
		return reply("Wafer", 100, 50), nil
	}}
	rg := newRig(t, &identityMasker{}, tr, "", nil)
	res, err := rg.r.Route(ctx, routeReq(t))
	if err != nil || res.Outcome != "sent" || res.Role != RoleFallback || res.Parsed == nil || res.Parsed.Status != "ok" {
		t.Fatalf("%v %+v", err, res)
	}
	if fmt.Sprint(rg.sink.kinds()) != "[endpoint_down active_changed]" || tr.calls != 4 {
		t.Fatalf("%v calls=%d", rg.sink.kinds(), tr.calls)
	}
	if e := rg.sink.events[0]; e.Reason != "consecutive_failures" || e.ConsecutiveFailures != 3 {
		t.Errorf("%+v", e)
	}
	applyOK(t, res)
	st := rg.r.State()
	if st.Active != "wafer-nvfp4" || st.Endpoints["inceptron-fp8"] != "down" {
		t.Fatalf("%+v", st)
	}

	// Гистерезис: health-check'и primary.
	mu.Lock()
	failPrimary = false
	mu.Unlock()
	healthy := true
	tr.get = func() (openrouter.Response, error) {
		if !healthy {
			return openrouter.Response{Status: 500}, nil
		}
		return openrouter.Response{Status: 200, Body: []byte(`{"data":{"endpoints":[{"provider_name":"Inceptron","quantization":"fp8","tag":"t","supported_parameters":["response_format","structured_outputs","seed"]},` +
			`{"provider_name":"Wafer","quantization":"nvfp4","tag":"w","supported_parameters":["response_format","structured_outputs","seed"]}]}}`)}, nil
	}
	check := func(wantState string) {
		t.Helper()
		if err := rg.r.CheckHealth(ctx); err != nil {
			t.Fatal(err)
		}
		if s := rg.r.State().Endpoints["inceptron-fp8"]; s != wantState {
			t.Fatalf("после проверки: %s, ожидается %s", s, wantState)
		}
	}
	check("down") // t=0: серия началась
	rg.clock.Advance(5 * time.Minute)
	check("down")
	healthy = false
	rg.clock.Advance(2 * time.Minute)
	check("down") // неудача на 7 минуте сбрасывает серию
	healthy = true
	rg.clock.Advance(time.Minute)
	check("down") // новая серия с t=8
	rg.clock.Advance(9*time.Minute + 59*time.Second)
	check("down")
	rg.clock.Advance(time.Second)
	check("up")
	n := len(rg.sink.events)
	if last, prev := rg.sink.events[n-1], rg.sink.events[n-2]; last.Kind != "active_changed" || last.To != "inceptron-fp8" || prev.Kind != "endpoint_up" || prev.StableForS != 600 {
		t.Fatalf("%+v %+v", prev, last)
	}

	// Закрепление: инцидент на Wafer остаётся там, пока Wafer up.
	mu.Lock()
	failPrimary = true
	mu.Unlock()
	req := routeReq(t)
	req.IncidentID = "inc-pin"
	rg.r.Route(ctx, req) // три таймаута primary → Wafer; инцидент закреплён за Wafer
	mu.Lock()
	failPrimary = false
	mu.Unlock()
	healthy = true
	for i := 0; i < 3; i++ {
		rg.r.CheckHealth(ctx)
		rg.clock.Advance(5 * time.Minute)
	}
	if rg.r.State().Active != "inceptron-fp8" {
		t.Fatalf("primary не вернулся: %+v", rg.r.State())
	}
	if res, _ := rg.r.Route(ctx, req); res.Role != RoleFallback {
		t.Errorf("закреплённый инцидент ушёл с Wafer: %s", res.Role)
	}
	req.IncidentID = "inc-new"
	if res, _ := rg.r.Route(ctx, req); res.Role != RolePrimary {
		t.Errorf("новый инцидент: %s", res.Role)
	}
}

func TestBothDownHaltAuditAndQuarantine(t *testing.T) {
	ctx := context.Background()
	fail := func([]byte) (openrouter.Response, error) { return openrouter.Response{Status: 503}, nil }
	tr := &stubTransport{post: fail}
	rg := newRig(t, &identityMasker{}, tr, "", nil)
	rg.r.Route(ctx, routeReq(t)) // primary down → fallback: 3 попытки → down
	res, _ := rg.r.Route(ctx, routeReq(t))
	if res.Reason != "unavailable" || !res.DegradeL1 {
		t.Fatalf("%+v", res)
	}
	applyOK(t, res)
	calls := tr.calls
	rg.r.Route(ctx, routeReq(t))
	if tr.calls != calls || rg.r.State().Active != "none" {
		t.Fatal("транспорт вызван при недоступных endpoint'ах")
	}

	// 401 → halt, Resume снимает.
	leak := runtimeSecret(t)
	tr2 := &stubTransport{post: func([]byte) (openrouter.Response, error) {
		return openrouter.Response{Status: 401, Body: []byte(leak)}, nil
	}}
	rg2 := newRig(t, &identityMasker{}, tr2, "", nil)
	res, err := rg2.r.Route(ctx, routeReq(t))
	if err != nil || res.ErrorKind != "auth" || !rg2.r.State().Halted {
		t.Fatal(err, res)
	}
	applyOK(t, res)
	if res, _ = rg2.r.Route(ctx, routeReq(t)); res.Reason != "halted" {
		t.Fatalf("%+v", res)
	}
	if err := rg2.r.Resume(ctx, "sre-1"); err != nil || rg2.r.State().Halted {
		t.Fatal(err)
	}
	if k := rg2.sink.kinds(); fmt.Sprint(k) != "[router_halted router_resumed]" {
		t.Fatal(k)
	}

	// provider_mismatch → quarantine; health-check не возвращает; Resume → down.
	tr3 := &stubTransport{post: func([]byte) (openrouter.Response, error) { return reply("Other", 10, 10), nil }}
	rg3 := newRig(t, &identityMasker{}, tr3, "", nil)
	res, _ = rg3.r.Route(ctx, routeReq(t))
	if res.Parsed.Status != "provider_mismatch" || rg3.r.State().Endpoints["inceptron-fp8"] != "quarantined" {
		t.Fatalf("%+v", rg3.r.State())
	}
	applyOK(t, res)
	rg3.r.Resume(ctx, "sre-1")
	if rg3.r.State().Endpoints["inceptron-fp8"] != "down" {
		t.Fatal("Resume не снял карантин")
	}

	// 404 → down сразу; usage выше потолка → halt estimator.
	tr4 := &stubTransport{post: func([]byte) (openrouter.Response, error) { return openrouter.Response{Status: 404}, nil }}
	rg4 := newRig(t, &identityMasker{}, tr4, "", nil)
	res, _ = rg4.r.Route(ctx, routeReq(t))
	if res.ErrorKind != "no_endpoint" || rg4.r.State().Endpoints["inceptron-fp8"] != "down" || rg4.sink.events[0].Reason != "no_endpoint" {
		t.Fatalf("%+v", rg4.sink.events)
	}
	tr5 := &stubTransport{post: func([]byte) (openrouter.Response, error) { return reply("Inceptron", 70000, 10), nil }}
	rg5 := newRig(t, &identityMasker{}, tr5, "", nil)
	res, _ = rg5.r.Route(ctx, routeReq(t))
	if res.ErrorKind != "context_ceiling_actual" || res.Parsed.Answer != nil || rg5.r.State().HaltReason != "estimator" {
		t.Fatalf("%+v", res)
	}
	applyOK(t, res)
}

func TestAuditFailureHalts(t *testing.T) {
	ctx := context.Background()
	tr := &stubTransport{post: func([]byte) (openrouter.Response, error) { return openrouter.Response{Status: 503}, nil }}
	sink := &memSink{failOn: "endpoint_down"}
	rg := newRig(t, &identityMasker{}, tr, "", sink)
	res, err := rg.r.Route(ctx, routeReq(t))
	if !errors.Is(err, ErrAuditFailed) || res == nil {
		t.Fatalf("%v", err)
	}
	if st := rg.r.State(); !st.Halted || st.HaltReason != "audit_failed" {
		t.Fatalf("%+v", st)
	}
	calls := tr.calls
	if res, err = rg.r.Route(ctx, routeReq(t)); err != nil || res.Reason != "halted" || tr.calls != calls {
		t.Fatalf("%v %+v", err, res)
	}
	sink.failOn = "*"
	if err := rg.r.Resume(ctx, "sre-1"); !errors.Is(err, ErrAuditFailed) || !rg.r.State().Halted {
		t.Fatalf("Resume при сбое записи: %v", err)
	}
	sink.failOn = ""
	if err := rg.r.Resume(ctx, "sre-1"); err != nil || rg.r.State().Halted {
		t.Fatalf("Resume при рабочем аудите: %v %+v", err, rg.r.State())
	}
}
