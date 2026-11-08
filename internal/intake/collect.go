package intake

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/limpjungle/aegis3311/internal/audit"
)

// Collector собирает снимок инцидента из источников параллельно. Критичные источники (топология; метрики, если
// провалились все запросы; rollout, если workload.kind=Rollout; db, если у сервиса задан database) — их сбой даёт
// *ErrCriticalSource, и Route не вызывается. Остальные: статус unavailable, список-секция пуста, одиночная опущена.
type Collector struct {
	Cluster        ClusterSource
	Metrics        MetricsSource
	DB             DBSource
	Specs          []MetricSpec
	RequestTimeout time.Duration
	CollectTimeout time.Duration
}

// sourceClass — класс ошибки источника для audit.SourceStatus.Error.
func sourceClass(err error) string {
	var k interface{ ErrKind() string } // SourceError и httpget.Error
	switch {
	case errors.As(err, &k):
		return k.ErrKind()
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	}
	return "network"
}

func status(src, st string, items int, err error) audit.SourceStatus {
	s := audit.SourceStatus{Source: src, Status: st, Items: items}
	if err != nil {
		s.Error = sourceClass(err)
	}
	return s
}

// Collect строит снимок на момент t0 (кратен минуте). Status в снимке заполнен и при ошибке.
func (c *Collector) Collect(ctx context.Context, inc Incident, svc ServiceConfig, t0 time.Time) (Snapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, c.CollectTimeout)
	defer cancel()
	req := func() (context.Context, context.CancelFunc) { return context.WithTimeout(ctx, c.RequestTimeout) }

	s := Snapshot{T0: t0, Alert: inc.Alert}
	s.Status = append(s.Status, status("alerts.alertmanager", "ok", len(inc.Alerts), nil))

	rc, rcancel := req()
	topo, err := c.Cluster.Topology(rc, svc)
	rcancel()
	topoTrunc, err := cutTrunc(err)
	if err != nil {
		s.Status = append(s.Status, status("platform.topology", "unavailable", 0, err))
		return s, &ErrCriticalSource{"platform.topology", err}
	}
	topo.Service, topo.Namespace = svc.Service, svc.Namespace
	if svc.Database != "" {
		d := svc.Database
		topo.Database = &d
	}
	if svc.InsufficientDataPolicy != "" {
		p := svc.InsufficientDataPolicy
		topo.InsufficientDataPolicy = &p
	}
	if a := topo.Autoscaler; a != nil {
		a.DeclaredMin = a.CurrentMin
		if svc.DeclaredMin > 0 {
			a.DeclaredMin = svc.DeclaredMin
		}
	}
	s.Topology = topo
	s.Status = append(s.Status, status("platform.topology", truncOr(topoTrunc, "ok"), len(topo.Pods), nil),
		status("platform.action_catalog", "ok", 0, nil))

	var (
		wg     sync.WaitGroup
		evs    []Event
		evErr  error
		dep    *Deploy
		depErr error
		ro     *Rollout
		roErr  error
		pdb    *PDB
		pdbErr error
		db     *DBAggregates
		dbErr  error
		series []Series
		mst    audit.SourceStatus
	)
	run := func(f func(context.Context)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rc, cancel := req()
			defer cancel()
			f(rc)
		}()
	}
	run(func(ctx context.Context) {
		evs, evErr = c.Cluster.Events(ctx, svc, topo.Pods, t0.Add(-30*time.Minute))
	})
	run(func(ctx context.Context) { dep, depErr = c.Cluster.LastDeploy(ctx, svc) })
	run(func(ctx context.Context) { pdb, pdbErr = c.Cluster.PDB(ctx, svc) })
	if svc.Workload.Kind == "Rollout" {
		run(func(ctx context.Context) { ro, roErr = c.Cluster.Rollout(ctx, svc, t0) })
	}
	if svc.Database != "" {
		run(func(ctx context.Context) { db, dbErr = c.DB.Aggregates(ctx, svc, t0) })
	}
	wg.Add(1)
	go func() { defer wg.Done(); series, mst = c.metrics(ctx, svc, t0) }()
	wg.Wait()
	evTr, evErr := cutTrunc(evErr)
	depTr, depErr := cutTrunc(depErr)
	roTr, roErr := cutTrunc(roErr)
	pdbTr, pdbErr := cutTrunc(pdbErr)

	// Статусы в фиксированном порядке.
	if evErr != nil {
		s.Status = append(s.Status, status("k8s.events", "unavailable", 0, evErr))
	} else {
		s.Status = append(s.Status, status("k8s.events", truncOr(evTr, okOrEmpty(len(evs))), len(evs), nil))
		s.Events = evs
	}
	if depErr != nil {
		s.Status = append(s.Status, status("k8s.deploys", "unavailable", 0, depErr))
	} else if dep == nil {
		s.Status = append(s.Status, status("k8s.deploys", truncOr(depTr, "empty"), 0, nil))
	} else {
		s.Status = append(s.Status, status("k8s.deploys", truncOr(depTr, "ok"), 1, nil))
		s.Deploys = []Deploy{*dep}
	}
	switch {
	case svc.Workload.Kind != "Rollout":
		s.Rollout = Some[Rollout](nil)
		s.Status = append(s.Status, status("k8s.rollout_status", "skipped", 0, nil))
	case roErr != nil:
		s.Status = append(s.Status, status("k8s.rollout_status", "unavailable", 0, roErr))
		return s, &ErrCriticalSource{"k8s.rollout_status", roErr}
	default:
		s.Rollout = Some(ro)
		// partial — подставлен анализ предыдущей ревизии (previous_analysis_run), у текущей анализа ещё нет.
		st := okOrEmpty(b2i(ro != nil))
		if ro != nil && ro.PreviousAnalysisRun != nil {
			st = "partial"
		}
		s.Status = append(s.Status, status("k8s.rollout_status", truncOr(roTr, st), b2i(ro != nil), nil))
	}
	switch {
	case svc.Database == "":
		s.DB = Some[DBAggregates](nil)
		s.Status = append(s.Status, status("db.aggregates", "skipped", 0, nil))
	case dbErr != nil:
		s.Status = append(s.Status, status("db.aggregates", "unavailable", 0, dbErr))
		return s, &ErrCriticalSource{"db.aggregates", dbErr}
	default:
		s.DB = Some(db)
		s.Status = append(s.Status, status("db.aggregates", okOrEmpty(b2i(db != nil)), b2i(db != nil), nil))
	}
	switch {
	case pdbErr != nil:
		s.Status = append(s.Status, status("manifests.k8s", "unavailable", 0, pdbErr))
	case pdb == nil:
		s.Status = append(s.Status, status("manifests.k8s", truncOr(pdbTr, "empty"), 0, nil))
	default:
		s.PDB = Some(pdb)
		s.Status = append(s.Status, status("manifests.k8s", truncOr(pdbTr, "ok"), 1, nil))
	}
	s.Status = append(s.Status, mst)
	s.Metrics = series
	if mst.Status == "unavailable" {
		return s, &ErrCriticalSource{"metrics.prometheus", errors.New("все запросы метрик провалились")}
	}

	var trunc map[string]bool
	s, trunc = Sanitize(s)
	for _, sp := range Sections {
		if !trunc[sp.Key] {
			continue
		}
		for i := range s.Status {
			if s.Status[i].Source == sp.Source && s.Status[i].Status != "unavailable" {
				s.Status[i].Status = "truncated"
			}
		}
	}
	return s, nil
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// cutTrunc снимает ErrTruncated: (true, nil) — данные годны, но усечены.
func cutTrunc(err error) (bool, error) {
	if errors.Is(err, ErrTruncated) {
		return true, nil
	}
	return false, err
}

func truncOr(t bool, st string) string {
	if t {
		return "truncated"
	}
	return st
}

func okOrEmpty(n int) string {
	if n == 0 {
		return "empty"
	}
	return "ok"
}

// metrics выполняет запросы подходящих метрик параллельно. Статус: unavailable — провалились все запросы
// (или подходящих метрик нет вовсе), partial — часть запросов или серий; truncated — сработал max_series.
func (c *Collector) metrics(ctx context.Context, svc ServiceConfig, t0 time.Time) ([]Series, audit.SourceStatus) {
	type res struct {
		raw []RawSeries
		err error
	}
	var specs []MetricSpec
	for _, sp := range c.Specs {
		if sp.Applies == "always" || (sp.Applies == "database" && svc.Database != "") || (sp.Applies == "kafka" && svc.Kafka) {
			specs = append(specs, sp)
		}
	}
	out := make([]res, len(specs))
	var wg sync.WaitGroup
	for i, sp := range specs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rc, cancel := context.WithTimeout(ctx, c.RequestTimeout)
			defer cancel()
			raw, err := c.Metrics.QueryRange(rc, svc.Expand(sp.Query), t0.Add(SeriesStartMn*time.Minute), t0, SeriesStepS*time.Second)
			out[i] = res{raw, err}
		}()
	}
	wg.Wait()
	var series []Series
	failed, truncated, dropped := 0, false, false
	var lastErr error
	for i, sp := range specs {
		if out[i].err != nil {
			failed, lastErr = failed+1, out[i].err
			continue
		}
		raw := out[i].raw
		sort.SliceStable(raw, func(a, b int) bool { return labelKey(raw[a].Labels) < labelKey(raw[b].Labels) })
		n := 0
		for _, r := range raw {
			if len(r.Values) != SeriesPoints {
				dropped = true
				continue
			}
			if n == sp.MaxSeries {
				truncated = true
				break
			}
			n++
			se := Series{Name: sp.Name, Unit: sp.Unit, Values: r.Values}
			for _, l := range r.Labels {
				for _, want := range sp.SeriesLabels {
					if l.K == want {
						se.Labels = append(se.Labels, l)
					}
				}
			}
			for k, v := range sp.StaticLabels {
				se.Labels = append(se.Labels, Label{k, svc.Expand(v)})
			}
			if sp.SelfReported {
				se.Labels = append(se.Labels, Label{"source", "self_reported"})
			}
			series = append(series, se)
		}
	}
	const src = "metrics.prometheus"
	switch {
	case len(specs) == 0 || failed == len(specs):
		if lastErr == nil {
			lastErr = errors.New("нет применимых метрик")
		}
		return nil, status(src, "unavailable", 0, lastErr)
	case failed > 0 || dropped:
		return series, status(src, "partial", len(series), lastErr)
	case truncated:
		return series, status(src, "truncated", len(series), nil)
	}
	return series, status(src, okOrEmpty(len(series)), len(series), nil)
}

func labelKey(ls []Label) string {
	ss := make([]string, 0, len(ls))
	for _, l := range ls {
		ss = append(ss, l.K+"="+strconv.Quote(l.V))
	}
	sort.Strings(ss)
	k := ""
	for _, s := range ss {
		k += s + ","
	}
	return k
}
