// Package prom — read-only источник метрик и агрегатов СУБД: GET /api/v1/query_range и /api/v1/query Prometheus
// (заголовки tenant для Mimir/Cortex — через headers конфигурации). PromQL целиком приходит из конфигурации.
package prom

import (
	"context"
	"fmt"
	"math"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/limpjungle/aegis3311/internal/intake"
	"github.com/limpjungle/aegis3311/internal/intake/httpget"
)

type Client struct {
	c         *httpget.Client
	dbQueries map[string]string
}

// New: src — адрес, CA и заголовки из конфигурации; tokenFile — AEGIS_PROMETHEUS_TOKEN_FILE (может быть пуст);
// dbQueries — db_queries конфигурации.
func New(src intake.HTTPSource, tokenFile string, dbQueries map[string]string, timeout time.Duration) (*Client, error) {
	c, err := httpget.New(src.URL, src.CAFile, tokenFile, src.Headers, httpget.MaxBytesMetrics, timeout)
	if err != nil {
		return nil, err
	}
	return &Client{c: c, dbQueries: dbQueries}, nil
}

type matrixResp struct {
	Status string `json:"status"`
	Data   struct {
		ResultType string `json:"resultType"`
		Result     []struct {
			Metric map[string]string `json:"metric"`
			Values [][2]any          `json:"values"`
			Value  [2]any            `json:"value"`
		} `json:"result"`
	} `json:"data"`
}

func unix(t time.Time) string { return strconv.FormatInt(t.Unix(), 10) }

// QueryRange: окно [start, end] с шагом step; точки выравниваются по сетке start+i·step. Значение без отсчёта в узле
// сетки, NaN и ±Inf — nil. Серии с числом узлов, отличным от ожидаемого, не возвращаются.
func (c *Client) QueryRange(ctx context.Context, q string, start, end time.Time, step time.Duration) ([]intake.RawSeries, error) {
	var r matrixResp
	err := c.c.GetJSON(ctx, "/api/v1/query_range", url.Values{"query": {q}, "start": {unix(start)}, "end": {unix(end)},
		"step": {strconv.Itoa(int(step / time.Second))}}, &r)
	if err != nil {
		return nil, err
	}
	if r.Status != "success" || r.Data.ResultType != "matrix" {
		return nil, &httpget.Error{Kind: "decode"}
	}
	n := int(end.Sub(start)/step) + 1
	var out []intake.RawSeries
	for _, s := range r.Data.Result {
		vals := make([]*float64, n)
		for _, p := range s.Values {
			ts, ok1 := p[0].(float64)
			str, ok2 := p[1].(string)
			if !ok1 || !ok2 {
				return nil, &httpget.Error{Kind: "decode"}
			}
			idx := int(math.Round((ts - float64(start.Unix())) / step.Seconds()))
			if idx < 0 || idx >= n {
				continue
			}
			v, err := strconv.ParseFloat(str, 64)
			if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
				continue
			}
			vals[idx] = &v
		}
		rs := intake.RawSeries{Values: vals}
		for k, v := range s.Metric {
			rs.Labels = append(rs.Labels, intake.Label{K: k, V: v})
		}
		out = append(out, rs)
	}
	return out, nil
}

// scalar — один instant-запрос: первое значение вектора. Пустой вектор или нечисло — ошибка decode.
func (c *Client) scalar(ctx context.Context, q string, at time.Time) (float64, error) {
	var r matrixResp
	if err := c.c.GetJSON(ctx, "/api/v1/query", url.Values{"query": {q}, "time": {unix(at)}}, &r); err != nil {
		return 0, err
	}
	if r.Status != "success" || r.Data.ResultType != "vector" || len(r.Data.Result) == 0 {
		return 0, &httpget.Error{Kind: "decode"}
	}
	s, ok := r.Data.Result[0].Value[1].(string)
	if !ok {
		return 0, &httpget.Error{Kind: "decode"}
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
		return 0, &httpget.Error{Kind: "decode"}
	}
	return v, nil
}

// Aggregates выполняет db_queries (по одному скаляру на ключ, параллельно) и собирает агрегаты СУБД. headroom =
// ceil(0.1·max_connections) (action-catalog.md). Нет значения любого ключа — ошибка: агрегаты неполны.
func (c *Client) Aggregates(ctx context.Context, svc intake.ServiceConfig, t0 time.Time) (*intake.DBAggregates, error) {
	vals := map[string]float64{}
	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		firstErr error
	)
	for _, k := range intake.DBQueryKeys {
		q, ok := c.dbQueries[k]
		if !ok {
			return nil, fmt.Errorf("prom: нет db_queries[%s]", k)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, err := c.scalar(ctx, svc.Expand(q), t0)
			mu.Lock()
			defer mu.Unlock()
			if err != nil && firstErr == nil {
				firstErr = err
			}
			vals[k] = v
		}()
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	i := func(k string) int { return int(math.Round(vals[k])) }
	maxConn := i("max_connections")
	d := &intake.DBAggregates{}
	d.PgBouncer.Database, d.PgBouncer.PoolSize = svc.Database, i("pool_size")
	d.Postgres.MaxConnections, d.Postgres.SuperuserReserved = maxConn, i("superuser_reserved_connections")
	d.Postgres.OtherPoolsTotal, d.Postgres.Headroom = i("other_pools_total"), int(math.Ceil(0.1*float64(maxConn)))
	for _, st := range []struct{ name, key string }{{"active", "sessions_active"}, {"idle", "sessions_idle"}, {"idle in transaction", "sessions_idle_in_transaction"}} {
		d.SessionsByState = append(d.SessionsByState, intake.SessionRow{State: st.name, Sessions: i(st.key), Over60s: i(st.key + "_over_60s")})
	}
	d.ShowPools = []intake.PoolRow{{Database: svc.Database, ClActive: i("cl_active"), ClWaiting: i("cl_waiting"), SvActive: i("sv_active"),
		SvIdle: i("sv_idle"), MaxWaitS: vals["maxwait_s"]}}
	return d, nil
}
