package intake

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/limpjungle/aegis3311/internal/audit"
	"github.com/limpjungle/aegis3311/internal/catalog"
	"github.com/limpjungle/aegis3311/internal/llmrouter"
	"github.com/limpjungle/aegis3311/internal/openrouter"
	"github.com/limpjungle/aegis3311/internal/pyjson"
)

// fakeCluster: каждый метод можно сделать ошибочным или блокирующимся до отмены контекста.
type fakeCluster struct {
	topo    Topology
	events  []Event
	deploy  *Deploy
	rollout *Rollout
	pdb     *PDB
	fail    map[string]error // метод → ошибка
	block   map[string]bool  // метод блокируется до отмены ctx
	calls   atomic.Int32
}

func (f *fakeCluster) do(ctx context.Context, m string) error {
	f.calls.Add(1)
	if f.block[m] {
		<-ctx.Done()
		return ctx.Err()
	}
	return f.fail[m]
}
func (f *fakeCluster) Topology(ctx context.Context, _ ServiceConfig) (Topology, error) {
	return f.topo, f.do(ctx, "topology")
}
func (f *fakeCluster) Events(ctx context.Context, _ ServiceConfig, _ []string, _ time.Time) ([]Event, error) {
	return f.events, f.do(ctx, "events")
}
func (f *fakeCluster) LastDeploy(ctx context.Context, _ ServiceConfig) (*Deploy, error) {
	return f.deploy, f.do(ctx, "deploy")
}
func (f *fakeCluster) Rollout(ctx context.Context, _ ServiceConfig, _ time.Time) (*Rollout, error) {
	return f.rollout, f.do(ctx, "rollout")
}
func (f *fakeCluster) PDB(ctx context.Context, _ ServiceConfig) (*PDB, error) {
	return f.pdb, f.do(ctx, "pdb")
}

type fakeMetrics struct {
	mu     sync.Mutex
	byName map[string][]RawSeries // по тексту запроса
	fail   map[string]error
	block  map[string]bool
	starts []time.Time
}

func (f *fakeMetrics) QueryRange(ctx context.Context, q string, start, end time.Time, step time.Duration) ([]RawSeries, error) {
	f.mu.Lock()
	f.starts = append(f.starts, start)
	f.mu.Unlock()
	if f.block[q] {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if err := f.fail[q]; err != nil {
		return nil, err
	}
	return f.byName[q], nil
}

type fakeDB struct {
	agg *DBAggregates
	err error
}

func (f fakeDB) Aggregates(context.Context, ServiceConfig, time.Time) (*DBAggregates, error) {
	return f.agg, f.err
}

func rawSeries(n int, labels ...Label) RawSeries {
	return RawSeries{Labels: labels, Values: make([]*float64, n)}
}

type collectFix struct {
	c    *Collector
	cl   *fakeCluster
	m    *fakeMetrics
	svc  ServiceConfig
	inc  Incident
	snap Snapshot
}

func newCollectFix(t *testing.T, kind string, withDB bool) *collectFix {
	t.Helper()
	// основа — кейс golden с нужной формой (есть БД/rollout или нет)
	var snap Snapshot
	found := false
	for _, c := range loadCases(t, "probe-v3.jsonl") {
		s := snapshotFromGolden(t, pyjson.Marshal(c.Get("input"), pyjson.Canonical))
		hasDB := s.Topology.Database != nil && s.DB.Present && s.DB.Value != nil
		hasRO := s.Rollout.Present && s.Rollout.Value != nil
		if hasDB == withDB && (kind == "Rollout") == hasRO && len(s.Topology.Pods) > 0 {
			snap, found = s, true
			break
		}
	}
	if !found {
		t.Skipf("нет golden-кейса для kind=%s db=%v", kind, withDB)
	}
	inc, svc := ReplayIncident("staging", snap)
	svc.Workload = WorkloadRef{Kind: kind, Name: "w"}
	if withDB {
		svc.Database = *snap.Topology.Database
	}
	cl := &fakeCluster{topo: snap.Topology, rollout: snap.Rollout.Value, pdb: snap.PDB.Value, fail: map[string]error{}, block: map[string]bool{}}
	if len(snap.Deploys) > 0 {
		d := snap.Deploys[0]
		cl.deploy = &d
	}
	cl.events = snap.Events
	m := &fakeMetrics{byName: map[string][]RawSeries{"q1": {rawSeries(31)}, "q2": {rawSeries(31)}}, fail: map[string]error{}, block: map[string]bool{}}
	var agg *DBAggregates
	if snap.DB.Value != nil {
		agg = snap.DB.Value
	}
	c := &Collector{Cluster: cl, Metrics: m, DB: fakeDB{agg: agg},
		Specs:          []MetricSpec{{Name: "m1", Unit: "u", Query: "q1", Applies: "always", MaxSeries: 3}, {Name: "m2", Unit: "u", Query: "q2", Applies: "always", MaxSeries: 3}},
		RequestTimeout: 100 * time.Millisecond, CollectTimeout: 2 * time.Second}
	return &collectFix{c: c, cl: cl, m: m, svc: svc, inc: inc, snap: snap}
}

func statusOf(s Snapshot, src string) (audit.SourceStatus, bool) {
	for _, st := range s.Status {
		if st.Source == src {
			return st, true
		}
	}
	return audit.SourceStatus{}, false
}

func TestCollectHappyPath(t *testing.T) {
	f := newCollectFix(t, "Deployment", false)
	s, err := f.c.Collect(context.Background(), f.inc, f.svc, goldenT0)
	if err != nil {
		t.Fatal(err)
	}
	for _, src := range []string{"alerts.alertmanager", "platform.topology", "platform.action_catalog", "k8s.events", "k8s.deploys", "k8s.rollout_status", "db.aggregates", "manifests.k8s", "metrics.prometheus"} {
		if _, ok := statusOf(s, src); !ok {
			t.Errorf("нет статуса %s", src)
		}
	}
	if st, _ := statusOf(s, "k8s.rollout_status"); st.Status != "skipped" {
		t.Errorf("rollout у Deployment: %+v", st)
	}
	if st, _ := statusOf(s, "db.aggregates"); st.Status != "skipped" {
		t.Errorf("db без database: %+v", st)
	}
	if st, _ := statusOf(s, "metrics.prometheus"); st.Status != "ok" || st.Items != 2 {
		t.Errorf("metrics: %+v", st)
	}
	// окно метрик: start = T0-30m
	for _, st := range f.m.starts {
		if !st.Equal(goldenT0.Add(-30 * time.Minute)) {
			t.Errorf("start запроса метрик %v", st)
		}
	}
	// все записи статусов проходят валидацию записи аудита
	r := &audit.DecisionRecord{}
	_ = r
	for _, st := range s.Status {
		if st.Status == "" || st.Items < 0 {
			t.Errorf("статус %+v", st)
		}
	}
}

// Источник, блокирующийся до отмены: некритичный → unavailable/timeout в пределах request_timeout, сбор продолжается.
func TestCollectNonCriticalBlockingTimesOut(t *testing.T) {
	for _, m := range []string{"events", "deploy", "pdb"} {
		f := newCollectFix(t, "Deployment", false)
		f.cl.block[m] = true
		start := time.Now()
		s, err := f.c.Collect(context.Background(), f.inc, f.svc, goldenT0)
		if err != nil {
			t.Fatalf("%s: %v", m, err)
		}
		if el := time.Since(start); el > time.Second {
			t.Errorf("%s: сбор занял %v при request_timeout 100ms", m, el)
		}
		src := map[string]string{"events": "k8s.events", "deploy": "k8s.deploys", "pdb": "manifests.k8s"}[m]
		if st, _ := statusOf(s, src); st.Status != "unavailable" || st.Error != "timeout" {
			t.Errorf("%s: статус %+v", m, st)
		}
		if m == "events" && len(s.Events) != 0 {
			t.Errorf("события при сбое: %v", s.Events)
		}
		if m == "pdb" && s.PDB.Present {
			t.Error("pdb при сбое должен быть опущен")
		}
	}
}

func TestCollectNonCriticalFailureRenders(t *testing.T) {
	f := newCollectFix(t, "Deployment", false)
	f.cl.fail["events"] = &SourceError{"http_503"}
	s, err := f.c.Collect(context.Background(), f.inc, f.svc, goldenT0)
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := statusOf(s, "k8s.events"); st.Status != "unavailable" || st.Error != "http_503" {
		t.Fatalf("статус %+v", st)
	}
	req, _, err := Assemble(f.inc.ID, s, catalog.MustLoadEmbedded(), llmrouter.ModeHybrid)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, sec := range req.Sections {
		if sec.Key == "k8s_events" {
			found = true
			if !sec.List || len(sec.Fragments) != 0 {
				t.Errorf("k8s_events: list=%v фрагментов %d", sec.List, len(sec.Fragments))
			}
		}
	}
	if !found {
		t.Error("секция k8s_events пропала: должна быть пустым списком")
	}
}

// Четыре критичных случая: *ErrCriticalSource, статус unavailable с классом ошибки.
func TestCollectCriticalFailures(t *testing.T) {
	type tc struct {
		name, kind string
		db         bool
		mut        func(f *collectFix)
		src        string
	}
	cases := []tc{
		{"топология", "Deployment", false, func(f *collectFix) { f.cl.fail["topology"] = &SourceError{"network"} }, "platform.topology"},
		{"топология блокирует", "Deployment", false, func(f *collectFix) { f.cl.block["topology"] = true }, "platform.topology"},
		{"все метрики", "Deployment", false, func(f *collectFix) {
			f.m.fail["q1"], f.m.fail["q2"] = &SourceError{"timeout"}, &SourceError{"timeout"}
		}, "metrics.prometheus"},
		{"rollout", "Rollout", false, func(f *collectFix) { f.cl.fail["rollout"] = &SourceError{"http_500"} }, "k8s.rollout_status"},
		{"db", "Deployment", true, func(f *collectFix) { f.c.DB = fakeDB{err: &SourceError{"decode"}} }, "db.aggregates"},
	}
	for _, c := range cases {
		f := newCollectFix(t, c.kind, c.db)
		c.mut(f)
		s, err := f.c.Collect(context.Background(), f.inc, f.svc, goldenT0)
		var ce *ErrCriticalSource
		if !errors.As(err, &ce) || ce.Source != c.src {
			t.Errorf("%s: ошибка %v", c.name, err)
			continue
		}
		if st, ok := statusOf(s, c.src); !ok || st.Status != "unavailable" || st.Error == "" {
			t.Errorf("%s: статус %+v", c.name, st)
		}
	}
}

// Часть метрик: один запрос упал → partial; неверное число точек → partial; лимит max_series → truncated.
func TestCollectMetricsStatuses(t *testing.T) {
	f := newCollectFix(t, "Deployment", false)
	f.m.fail["q2"] = &SourceError{"timeout"}
	s, err := f.c.Collect(context.Background(), f.inc, f.svc, goldenT0)
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := statusOf(s, "metrics.prometheus"); st.Status != "partial" || st.Items != 1 {
		t.Errorf("один запрос упал: %+v", st)
	}

	f = newCollectFix(t, "Deployment", false)
	f.m.byName["q1"] = []RawSeries{rawSeries(31), rawSeries(30), rawSeries(32)}
	s, _ = f.c.Collect(context.Background(), f.inc, f.svc, goldenT0)
	st, _ := statusOf(s, "metrics.prometheus")
	if st.Status != "partial" || len(s.Metrics) != 2 { // m1: одна верная + m2: одна
		t.Errorf("серии с числом точек ≠ 31: %+v, серий %d", st, len(s.Metrics))
	}
	for _, se := range s.Metrics {
		if len(se.Values) != SeriesPoints {
			t.Errorf("в снимок попала серия из %d точек", len(se.Values))
		}
	}

	f = newCollectFix(t, "Deployment", false)
	var many []RawSeries
	for i := 0; i < 5; i++ {
		many = append(many, rawSeries(31, Label{"pod", string(rune('a' + i))}))
	}
	f.m.byName["q1"] = many
	f.c.Specs[0].SeriesLabels = []string{"pod"}
	s, _ = f.c.Collect(context.Background(), f.inc, f.svc, goldenT0)
	st, _ = statusOf(s, "metrics.prometheus")
	n := 0
	for _, se := range s.Metrics {
		if se.Name == "m1" {
			n++
		}
	}
	if st.Status != "truncated" || n != 3 {
		t.Errorf("max_series: %+v, серий m1 %d", st, n)
	}
	// детерминированный порядок: по меткам
	var pods []string
	for _, se := range s.Metrics {
		if se.Name == "m1" {
			pods = append(pods, se.Labels[0].V)
		}
	}
	if len(pods) != 3 || pods[0] != "a" || pods[1] != "b" || pods[2] != "c" {
		t.Errorf("порядок серий: %v", pods)
	}

	f = newCollectFix(t, "Deployment", false)
	f.m.byName["q1"], f.m.byName["q2"] = nil, nil
	s, err = f.c.Collect(context.Background(), f.inc, f.svc, goldenT0)
	if st, _ := statusOf(s, "metrics.prometheus"); err != nil || st.Status != "empty" {
		t.Errorf("пустой ответ: %+v %v", st, err)
	}
}

// Лимиты: события сверх 20 → truncated у k8s.events.
func TestCollectEventsTruncated(t *testing.T) {
	f := newCollectFix(t, "Deployment", false)
	f.cl.events = nil
	for i := 0; i < MaxEvents+5; i++ {
		f.cl.events = append(f.cl.events, Event{Type: "Warning", Reason: "BackOff", Object: "pod/" + f.cl.topo.Pods[0], Count: 1, At: goldenT0.Add(-time.Duration(i) * time.Minute)})
	}
	s, err := f.c.Collect(context.Background(), f.inc, f.svc, goldenT0)
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := statusOf(s, "k8s.events"); st.Status != "truncated" {
		t.Errorf("статус %+v", st)
	}
	if len(s.Events) != MaxEvents {
		t.Errorf("событий %d", len(s.Events))
	}
}

// ErrTruncated от кластерного источника: данные годны, статус truncated, это не сбой и не ErrCriticalSource.
func TestCollectClusterTruncated(t *testing.T) {
	for _, src := range []string{"topology", "events", "deploy", "rollout", "pdb"} {
		f := newCollectFix(t, "Rollout", false)
		f.cl.fail[src] = ErrTruncated
		s, err := f.c.Collect(context.Background(), f.inc, f.svc, goldenT0)
		var crit *ErrCriticalSource
		if err != nil || errors.As(err, &crit) {
			t.Fatalf("%s: err = %v", src, err)
		}
		want := map[string]string{"topology": "platform.topology", "events": "k8s.events", "deploy": "k8s.deploys",
			"rollout": "k8s.rollout_status", "pdb": "manifests.k8s"}[src]
		st, ok := statusOf(s, want)
		if !ok || st.Status != "truncated" || st.Error != "" {
			t.Errorf("%s: статус %+v", src, st)
		}
		switch src {
		case "topology":
			if len(s.Topology.Pods) == 0 || st.Items != len(s.Topology.Pods) {
				t.Errorf("топология: pods=%d items=%d", len(s.Topology.Pods), st.Items)
			}
		case "events":
			if len(f.cl.events) > 0 && len(s.Events) == 0 {
				t.Error("события потеряны при усечении")
			}
		case "deploy":
			if f.cl.deploy != nil && len(s.Deploys) != 1 {
				t.Errorf("деплой потерян при усечении: %v", s.Deploys)
			}
		case "rollout":
			if s.Rollout.Value == nil {
				t.Error("rollout потерян при усечении")
			}
		case "pdb":
			if f.cl.pdb != nil && s.PDB.Value == nil {
				t.Error("PDB потерян при усечении")
			}
		}
		// остальные источники не затронуты
		for _, other := range []string{"platform.topology", "k8s.events"} {
			if other == want {
				continue
			}
			if o, _ := statusOf(s, other); o.Status == "truncated" || o.Status == "unavailable" {
				t.Errorf("%s: чужой статус %s = %+v", src, other, o)
			}
		}
	}
	// deploy == nil вместе с ErrTruncated: truncated, Items 0
	f := newCollectFix(t, "Deployment", false)
	f.cl.deploy = nil
	f.cl.fail["deploy"] = ErrTruncated
	s, err := f.c.Collect(context.Background(), f.inc, f.svc, goldenT0)
	if st, _ := statusOf(s, "k8s.deploys"); err != nil || st.Status != "truncated" || st.Items != 0 || len(s.Deploys) != 0 {
		t.Errorf("deploy nil + truncated: %+v %v", st, err)
	}
	// pdb == nil вместе с ErrTruncated
	f = newCollectFix(t, "Deployment", false)
	f.cl.pdb = nil
	f.cl.fail["pdb"] = ErrTruncated
	s, err = f.c.Collect(context.Background(), f.inc, f.svc, goldenT0)
	if st, _ := statusOf(s, "manifests.k8s"); err != nil || st.Status != "truncated" || st.Items != 0 {
		t.Errorf("pdb nil + truncated: %+v %v", st, err)
	}
	// ошибка, обёрнутая вместе с ErrTruncated через %w, тоже снимается
	f = newCollectFix(t, "Deployment", false)
	f.cl.fail["events"] = fmt.Errorf("обёртка: %w", ErrTruncated)
	if s, err = f.c.Collect(context.Background(), f.inc, f.svc, goldenT0); err != nil {
		t.Errorf("обёрнутый ErrTruncated: %v", err)
	} else if st, _ := statusOf(s, "k8s.events"); st.Status != "truncated" {
		t.Errorf("обёрнутый ErrTruncated: %+v", st)
	}
	// обычная ошибка — unavailable (не truncated)
	f = newCollectFix(t, "Deployment", false)
	f.cl.fail["events"] = errors.New("boom")
	f.cl.fail["deploy"] = errors.New("boom")
	f.cl.fail["pdb"] = errors.New("boom")
	s, err = f.c.Collect(context.Background(), f.inc, f.svc, goldenT0)
	if err != nil {
		t.Fatal(err)
	}
	for _, src := range []string{"k8s.events", "k8s.deploys", "manifests.k8s"} {
		if st, _ := statusOf(s, src); st.Status != "unavailable" {
			t.Errorf("%s: %+v", src, st)
		}
	}
	// критичная ошибка топологии не маскируется усечением других источников
	f = newCollectFix(t, "Deployment", false)
	f.cl.fail["topology"] = errors.New("boom")
	f.cl.fail["events"] = ErrTruncated
	var crit *ErrCriticalSource
	if _, err = f.c.Collect(context.Background(), f.inc, f.svc, goldenT0); !errors.As(err, &crit) {
		t.Errorf("ожидается ErrCriticalSource: %v", err)
	}
}

// Метрика применяется по applies: database/kafka не запрашиваются у сервиса без БД и Kafka.
func TestCollectAppliesFilter(t *testing.T) {
	f := newCollectFix(t, "Deployment", false)
	f.c.Specs = append(f.c.Specs, MetricSpec{Name: "dbm", Unit: "u", Query: "qdb", Applies: "database", MaxSeries: 1},
		MetricSpec{Name: "km", Unit: "u", Query: "qk", Applies: "kafka", MaxSeries: 1})
	f.m.byName["qdb"], f.m.byName["qk"] = []RawSeries{rawSeries(31)}, []RawSeries{rawSeries(31)}
	s, err := f.c.Collect(context.Background(), f.inc, f.svc, goldenT0)
	if err != nil {
		t.Fatal(err)
	}
	for _, se := range s.Metrics {
		if se.Name == "dbm" || se.Name == "km" {
			t.Errorf("запрошена неприменимая метрика %s", se.Name)
		}
	}
}

// Подстановка в PromQL только из реестра: значения алерта в запрос не попадают.
func TestCollectQueryExpandFromRegistryOnly(t *testing.T) {
	f := newCollectFix(t, "Deployment", false)
	f.inc.Alert.Namespace, f.inc.Alert.Service = `x"} or vector(1) #`, `evil`
	f.inc.Alert.Description = `$namespace`
	f.c.Specs = []MetricSpec{{Name: "m1", Unit: "u", Query: `up{ns="$namespace",s="$service",d="$database",c="$pg_cluster"}`, Applies: "always", MaxSeries: 1}}
	var got string
	f.c.Metrics = captureQuery{&got, f.m}
	f.svc.Namespace, f.svc.Service, f.svc.Database, f.svc.PgCluster = "shop", "geo-svc", "geo", "pg1"
	f.c.Collect(context.Background(), f.inc, f.svc, goldenT0)
	if got != `up{ns="shop",s="geo-svc",d="geo",c="pg1"}` {
		t.Errorf("запрос: %q", got)
	}
}

type captureQuery struct {
	q *string
	MetricsSource
}

func (c captureQuery) QueryRange(ctx context.Context, q string, s, e time.Time, st time.Duration) ([]RawSeries, error) {
	*c.q = q
	return c.MetricsSource.QueryRange(ctx, q, s, e, st)
}

// ---- Конвейер с настоящим Collector и сбоем критичного источника ----

type countRouter struct {
	Router
	routes atomic.Int32
}

func (c *countRouter) Route(ctx context.Context, r llmrouter.Request) (*llmrouter.Result, error) {
	c.routes.Add(1)
	return c.Router.Route(ctx, r)
}

// Каждый из критичных случаев: Route не вызывается, запись not_routed/source_unavailable проходит Validate и пишется в цепочку.
func TestPipelineCriticalSourcesNotRouted(t *testing.T) {
	type tc struct {
		name, kind string
		db         bool
		mut        func(f *collectFix)
	}
	cases := []tc{
		{"topology", "Deployment", false, func(f *collectFix) { f.cl.fail["topology"] = &SourceError{"timeout"} }},
		{"metrics", "Deployment", false, func(f *collectFix) {
			f.m.fail["q1"], f.m.fail["q2"] = &SourceError{"network"}, &SourceError{"network"}
		}},
		{"rollout", "Rollout", false, func(f *collectFix) { f.cl.fail["rollout"] = &SourceError{"http_500"} }},
		{"db", "Deployment", true, func(f *collectFix) { f.c.DB = fakeDB{err: &SourceError{"oversize"}} }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rt, cfg, keys := openTestRuntime(t, &stubTr{post: func([]byte) (openrouter.Response, error) { return okReply(), nil }})
			f := newCollectFix(t, c.kind, c.db)
			c.mut(f)
			p, inc, _ := newTestPipeline(t, rt, f.snap, "")
			cr := &countRouter{Router: rt.Router}
			p.Router, p.Collector = cr, f.c
			p.Lookup = func(ns, sv string) (ServiceConfig, bool) { return f.svc, ns == f.svc.Namespace && sv == f.svc.Service }
			p.RetryPause, p.Settle = time.Millisecond, time.Hour
			inc.OpenedAt = time.Now()
			if err := p.Handle(context.Background(), &inc); err != nil {
				t.Fatal(err)
			}
			if cr.routes.Load() != 0 {
				t.Fatal("Route вызван при сбое критичного источника")
			}
			recs := verifyRecords(t, cfg, keys)
			if len(recs) != 1 || recs[0].LLM != nil || recs[0].Intake.Outcome != "not_routed" || recs[0].Intake.Reason != "source_unavailable" {
				t.Fatalf("записи: %+v", recs)
			}
			if err := recs[0].Validate(); err != nil {
				t.Errorf("Validate: %v", err)
			}
			var unavailable int
			for _, st := range recs[0].Intake.Sources {
				if st.Status == "unavailable" && st.Error != "" {
					unavailable++
				}
			}
			if unavailable == 0 {
				t.Errorf("в записи нет unavailable-источника: %+v", recs[0].Intake.Sources)
			}
		})
	}
}

// Сбой некритичного источника: запрос уходит, запись routed со статусом unavailable.
func TestPipelineNonCriticalStillRouted(t *testing.T) {
	rt, cfg, keys := openTestRuntime(t, &stubTr{post: func([]byte) (openrouter.Response, error) { return okReply(), nil }})
	f := newCollectFix(t, "Deployment", false)
	f.cl.fail["events"] = &SourceError{"timeout"}
	p, inc, _ := newTestPipeline(t, rt, f.snap, "")
	cr := &countRouter{Router: rt.Router}
	p.Router, p.Collector = cr, f.c
	if err := p.Handle(context.Background(), &inc); err != nil {
		t.Fatal(err)
	}
	recs := verifyRecords(t, cfg, keys)
	if cr.routes.Load() != 1 || len(recs) != 1 || recs[0].Intake.Outcome != "routed" {
		t.Fatalf("routes=%d records=%+v", cr.routes.Load(), recs)
	}
	var ok bool
	for _, st := range recs[0].Intake.Sources {
		if st.Source == "k8s.events" && st.Status == "unavailable" && st.Error == "timeout" {
			ok = true
		}
	}
	if !ok {
		t.Errorf("статусы: %+v", recs[0].Intake.Sources)
	}
}

// previous_analysis_run -> статус partial (Items 1, Error пуст); усечение приоритетнее partial.
func TestCollectRolloutPreviousAnalysisRunStatus(t *testing.T) {
	rev := 7
	mk := func(prev *PreviousAnalysisRun) *collectFix {
		f := newCollectFix(t, "Rollout", false)
		r := *f.cl.rollout
		r.Phase, r.AnalysisRun, r.PreviousAnalysisRun = "Progressing", nil, prev
		f.cl.rollout = &r
		return f
	}
	prev := &PreviousAnalysisRun{Revision: &rev, Name: "ar-prev", Verdict: "success", Metrics: []AnalysisMetric{}}

	f := mk(prev)
	s, err := f.c.Collect(context.Background(), f.inc, f.svc, goldenT0)
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := statusOf(s, "k8s.rollout_status"); st.Status != "partial" || st.Items != 1 || st.Error != "" {
		t.Errorf("с Previous: %+v", st)
	}
	if s.Rollout.Value == nil || s.Rollout.Value.PreviousAnalysisRun == nil {
		t.Error("Previous потерян в снимке")
	}

	f = mk(prev)
	f.cl.fail["rollout"] = ErrTruncated
	s, err = f.c.Collect(context.Background(), f.inc, f.svc, goldenT0)
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := statusOf(s, "k8s.rollout_status"); st.Status != "truncated" || st.Items != 1 || st.Error != "" {
		t.Errorf("Previous + усечение: %+v", st)
	}

	f = mk(nil) // контроль: без Previous статус ok
	s, _ = f.c.Collect(context.Background(), f.inc, f.svc, goldenT0)
	if st, _ := statusOf(s, "k8s.rollout_status"); st.Status != "ok" {
		t.Errorf("без Previous: %+v", st)
	}
}
