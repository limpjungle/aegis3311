package intake

import (
	"math"
	"sort"
	"time"

	"github.com/limpjungle/aegis3311/internal/pyjson"
)

// Окно метрик: 31 точка с шагом 60 с, T0-30m…T0 (форма golden v3).
const (
	SeriesPoints  = 31
	SeriesStartMn = -30
	SeriesStepS   = 60
)

// offset — смещение момента t от T0 в целых минутах (усечение к нулю): раньше T0 — отрицательное.
func offset(t0, t time.Time) int64 { return -int64(t0.Sub(t) / time.Minute) }

func str(s string) *pyjson.Value { return pyjson.NewString(s) }
func num(i int) *pyjson.Value    { return pyjson.NewInt(int64(i)) }
func obj(ms ...pyjson.Member) *pyjson.Value {
	return pyjson.NewObject(ms...)
}

func optStr(p *string) *pyjson.Value {
	if p == nil {
		return pyjson.NewNull()
	}
	return str(*p)
}

func optInt(p *int) *pyjson.Value {
	if p == nil {
		return pyjson.NewNull()
	}
	return num(*p)
}

func optNum(n *Num) *pyjson.Value {
	switch {
	case n == nil:
		return pyjson.NewNull()
	case n.Int:
		return pyjson.NewInt(int64(n.F))
	}
	return pyjson.NewFloat(n.F)
}

// roundValue округляет значение серии: достаточно, чтобы не раздувать вход шумом разрядов, но без потери
// малых величин (доли 0.0034). Значения golden v3 проходят без изменений.
func roundValue(v float64) float64 {
	if v == 0 || math.IsNaN(v) || math.IsInf(v, 0) {
		return v
	}
	d := 3 - int(math.Floor(math.Log10(math.Abs(v)))) // 4 значащие цифры
	d = max(d, 2)
	d = min(d, 8)
	p := math.Pow(10, float64(d))
	return math.Round(v*p) / p
}

func renderAlert(t0 time.Time, a Alert) *pyjson.Value {
	ann := obj(pyjson.M("summary", str(a.Summary)))
	if a.Description != "" {
		ann.Members = append(ann.Members, pyjson.M("description", str(a.Description)))
	}
	return obj(pyjson.M("name", str(a.Name)), pyjson.M("severity", str(a.Severity)),
		pyjson.M("labels", obj(pyjson.M("namespace", str(a.Namespace)), pyjson.M("service", str(a.Service)))),
		pyjson.M("annotations", ann), pyjson.M("starts_at_offset_min", pyjson.NewInt(offset(t0, a.StartsAt))))
}

func renderService(t Topology) *pyjson.Value {
	pods := pyjson.NewArray()
	for _, p := range t.Pods {
		pods.Items = append(pods.Items, str(p))
	}
	as := pyjson.NewNull()
	if a := t.Autoscaler; a != nil {
		as = obj(pyjson.M("kind", str(a.Kind)), pyjson.M("declared_min", num(a.DeclaredMin)), pyjson.M("current_min", num(a.CurrentMin)),
			pyjson.M("max", num(a.Max)), pyjson.M("replicas", num(a.Replicas)))
	}
	v := obj(pyjson.M("name", str(t.Service)), pyjson.M("namespace", str(t.Namespace)), pyjson.M("database", optStr(t.Database)),
		pyjson.M("autoscaler", as), pyjson.M("pods", pods))
	if t.InsufficientDataPolicy != nil {
		v.Members = append(v.Members, pyjson.M("insufficient_data_policy", str(*t.InsufficientDataPolicy)))
	}
	return v
}

func renderRollout(t0 time.Time, r *Rollout) *pyjson.Value {
	if r == nil {
		return pyjson.NewNull()
	}
	ar := pyjson.NewNull()
	if a := r.AnalysisRun; a != nil {
		ar = obj(pyjson.M("name", str(a.Name)), pyjson.M("verdict", str(a.Verdict)), pyjson.M("metrics", renderAnalysisMetrics(a.Metrics)))
	}
	v := obj(pyjson.M("name", optStr(r.Name)), pyjson.M("phase", str(r.Phase)), pyjson.M("canary_revision", optInt(r.CanaryRevision)),
		pyjson.M("stable_revision", optInt(r.StableRevision)), pyjson.M("canary_weight_pct", num(r.CanaryWeightPct)), pyjson.M("analysis_run", ar))
	if p := r.PreviousAnalysisRun; r.AnalysisRun == nil && p != nil {
		v.Members = append(v.Members, pyjson.M("previous_analysis_run", obj(pyjson.M("revision", optInt(p.Revision)),
			pyjson.M("name", str(p.Name)), pyjson.M("verdict", str(p.Verdict)), pyjson.M("metrics", renderAnalysisMetrics(p.Metrics)))))
	}
	return v
}

func renderAnalysisMetrics(ms []AnalysisMetric) *pyjson.Value {
	out := pyjson.NewArray()
	for _, m := range ms {
		mv := obj(pyjson.M("name", str(m.Name)), pyjson.M("test", str(m.Test)), pyjson.M("baseline", optNum(m.Baseline)),
			pyjson.M("canary", optNum(m.Canary)), pyjson.M("p_value", optNum(m.PValue)), pyjson.M("holm_significant", pyjson.NewBool(m.HolmSignificant)))
		if m.Samples != nil {
			mv.Members = append(mv.Members, pyjson.M("samples", num(*m.Samples)))
		}
		if m.MinSamples != nil {
			mv.Members = append(mv.Members, pyjson.M("min_samples", num(*m.MinSamples)))
		}
		out.Items = append(out.Items, mv)
	}
	return out
}

func renderDB(d *DBAggregates) *pyjson.Value {
	if d == nil {
		return pyjson.NewNull()
	}
	ss, sp := pyjson.NewArray(), pyjson.NewArray()
	for _, r := range d.SessionsByState {
		ss.Items = append(ss.Items, obj(pyjson.M("state", str(r.State)), pyjson.M("sessions", num(r.Sessions)), pyjson.M("over_60s", num(r.Over60s))))
	}
	for _, r := range d.ShowPools {
		sp.Items = append(sp.Items, obj(pyjson.M("database", str(r.Database)), pyjson.M("cl_active", num(r.ClActive)), pyjson.M("cl_waiting", num(r.ClWaiting)),
			pyjson.M("sv_active", num(r.SvActive)), pyjson.M("sv_idle", num(r.SvIdle)), pyjson.M("maxwait_s", pyjson.NewFloat(r.MaxWaitS))))
	}
	pg, pp := d.PgBouncer, d.Postgres
	return obj(pyjson.M("pgbouncer", obj(pyjson.M("database", str(pg.Database)), pyjson.M("pool_size", num(pg.PoolSize)))),
		pyjson.M("postgres", obj(pyjson.M("max_connections", num(pp.MaxConnections)), pyjson.M("superuser_reserved_connections", num(pp.SuperuserReserved)),
			pyjson.M("other_pools_total", num(pp.OtherPoolsTotal)), pyjson.M("headroom", num(pp.Headroom)))),
		pyjson.M("sessions_by_state", ss), pyjson.M("show_pools", sp))
}

func renderPDB(p *PDB) *pyjson.Value {
	if p == nil {
		return pyjson.NewNull()
	}
	v := obj()
	for _, m := range []struct {
		k string
		v any
	}{{"min_available", p.MinAvailable}, {"max_unavailable", p.MaxUnavailable}} {
		switch x := m.v.(type) {
		case nil:
		case int:
			v.Members = append(v.Members, pyjson.M(m.k, num(x)))
		case float64: // из JSON-фикстуры
			v.Members = append(v.Members, pyjson.M(m.k, pyjson.NewInt(int64(x))))
		case string:
			v.Members = append(v.Members, pyjson.M(m.k, str(x)))
		}
	}
	return v
}

func renderSeries(s Series) *pyjson.Value {
	lbl := obj()
	ls := append([]Label(nil), s.Labels...)
	sort.Slice(ls, func(i, j int) bool { return ls[i].K < ls[j].K })
	for _, l := range ls {
		lbl.Members = append(lbl.Members, pyjson.M(l.K, str(l.V)))
	}
	vals := pyjson.NewArray()
	for _, p := range s.Values {
		if p == nil {
			vals.Items = append(vals.Items, pyjson.NewNull())
		} else {
			vals.Items = append(vals.Items, pyjson.NewFloat(roundValue(*p)))
		}
	}
	return obj(pyjson.M("name", str(s.Name)), pyjson.M("unit", str(s.Unit)), pyjson.M("labels", lbl),
		pyjson.M("start_offset_min", num(SeriesStartMn)), pyjson.M("step_s", num(SeriesStepS)), pyjson.M("values", vals))
}

func renderEvent(t0 time.Time, e Event) *pyjson.Value {
	return obj(pyjson.M("type", str(e.Type)), pyjson.M("reason", str(e.Reason)), pyjson.M("object", str(e.Object)),
		pyjson.M("count", num(e.Count)), pyjson.M("offset_min", pyjson.NewInt(offset(t0, e.At))))
}

func renderDeploy(t0 time.Time, d Deploy) *pyjson.Value {
	return obj(pyjson.M("revision", num(d.Revision)), pyjson.M("image_digest", str(d.ImageDigest)),
		pyjson.M("offset_min", pyjson.NewInt(offset(t0, d.At))), pyjson.M("author_id", str(d.AuthorID)))
}
