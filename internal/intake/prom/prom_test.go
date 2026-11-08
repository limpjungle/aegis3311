package prom

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/limpjungle/aegis3311/internal/intake"
)

func fixture(t *testing.T, h http.HandlerFunc) intake.HTTPSource {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600)
	return intake.HTTPSource{URL: srv.URL, CAFile: ca}
}

func matrix(series ...map[string]any) []byte {
	b, _ := json.Marshal(map[string]any{"status": "success", "data": map[string]any{"resultType": "matrix", "result": series}})
	return b
}

var t0 = time.Date(2026, 1, 2, 10, 0, 0, 0, time.UTC)

func TestQueryRangeGridNaNGaps(t *testing.T) {
	start, end := t0.Add(-30*time.Minute), t0
	var got map[string][]string
	var method string
	// узлы 0..30; отсутствуют 5 и 6; NaN в 7; +Inf в 8; значение со сдвигом в долю секунды в 9; вне окна — -1 и 31
	var vals [][2]any
	for i := 0; i <= 30; i++ {
		if i == 5 || i == 6 {
			continue
		}
		v := strconv.Itoa(i) + ".5"
		switch i {
		case 7:
			v = "NaN"
		case 8:
			v = "+Inf"
		case 10:
			v = "-Inf"
		}
		ts := float64(start.Unix()) + float64(i*60)
		if i == 9 {
			ts += 0.4 // Prometheus может вернуть дробную метку
		}
		vals = append(vals, [2]any{ts, v})
	}
	vals = append(vals, [2]any{float64(start.Unix() - 60), "99"}, [2]any{float64(end.Unix() + 60), "99"})
	src := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		method, got = r.Method, r.URL.Query()
		w.Write(matrix(map[string]any{"metric": map[string]string{"pod": "p1", "__name__": "x"}, "values": vals}))
	})
	c, err := New(src, "", nil, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	out, err := c.QueryRange(context.Background(), `up{a="1"}`, start, end, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if method != "GET" || got["query"][0] != `up{a="1"}` || got["start"][0] != strconv.FormatInt(start.Unix(), 10) ||
		got["end"][0] != strconv.FormatInt(end.Unix(), 10) || got["step"][0] != "60" {
		t.Errorf("запрос: %s %v", method, got)
	}
	if len(out) != 1 || len(out[0].Values) != 31 {
		t.Fatalf("серий %d / точек %d", len(out), len(out[0].Values))
	}
	v := out[0].Values
	for i := range v {
		switch i {
		case 5, 6, 7, 8, 10:
			if v[i] != nil {
				t.Errorf("узел %d должен быть nil, а %v", i, *v[i])
			}
		default:
			if v[i] == nil || *v[i] != float64(i)+0.5 {
				t.Errorf("узел %d: %v", i, v[i])
			}
		}
	}
	// метки возвращаются как есть (фильтрация — в сборщике и роутере)
	if len(out[0].Labels) != 2 {
		t.Errorf("метки: %v", out[0].Labels)
	}
}

func TestQueryRangeErrors(t *testing.T) {
	bodies := map[string]string{
		"vector вместо matrix": `{"status":"success","data":{"resultType":"vector","result":[]}}`,
		"status error":         `{"status":"error","errorType":"bad_data","error":"parse error"}`,
		"точка не пара":        `{"status":"success","data":{"resultType":"matrix","result":[{"metric":{},"values":[[1,2]]}]}}`,
		"не JSON":              `<html>`,
	}
	for name, b := range bodies {
		src := fixture(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(b)) })
		c, _ := New(src, "", nil, 2*time.Second)
		_, err := c.QueryRange(context.Background(), "q", t0.Add(-30*time.Minute), t0, time.Minute)
		if err == nil || !strings.Contains(err.Error(), "decode") {
			t.Errorf("%s: %v", name, err)
		}
	}
	src := fixture(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(422); w.Write([]byte("tsdb-body-marker")) })
	c, _ := New(src, "", nil, 2*time.Second)
	if _, err := c.QueryRange(context.Background(), "q", t0.Add(-30*time.Minute), t0, time.Minute); err == nil ||
		!strings.Contains(err.Error(), "http_422") || strings.Contains(err.Error(), "marker") {
		t.Errorf("422: %v", err)
	}
	// пустой результат — не ошибка
	src = fixture(t, func(w http.ResponseWriter, r *http.Request) { w.Write(matrix()) })
	c, _ = New(src, "", nil, 2*time.Second)
	if out, err := c.QueryRange(context.Background(), "q", t0.Add(-30*time.Minute), t0, time.Minute); err != nil || len(out) != 0 {
		t.Errorf("пустой matrix: %v %v", out, err)
	}
}

func dbSvc() intake.ServiceConfig {
	return intake.ServiceConfig{Namespace: "shop", Service: "geo-svc", Database: "geo", PgCluster: "pg1"}
}

func dbQueries() map[string]string {
	m := map[string]string{}
	for _, k := range intake.DBQueryKeys {
		m[k] = "k_" + k + `{db="$database",c="$pg_cluster"}`
	}
	return m
}

func vector(v string) []byte {
	b, _ := json.Marshal(map[string]any{"status": "success", "data": map[string]any{"resultType": "vector",
		"result": []any{map[string]any{"metric": map[string]string{}, "value": []any{1.0, v}}}}})
	return b
}

func TestAggregates(t *testing.T) {
	vals := map[string]string{"pool_size": "20", "max_connections": "101", "superuser_reserved_connections": "3", "other_pools_total": "40",
		"sessions_active": "7", "sessions_active_over_60s": "1", "sessions_idle": "30", "sessions_idle_over_60s": "10",
		"sessions_idle_in_transaction": "2", "sessions_idle_in_transaction_over_60s": "2", "cl_active": "5", "cl_waiting": "4", "sv_active": "6", "sv_idle": "14", "maxwait_s": "1.5"}
	var mu sync.Mutex
	seen := map[string]bool{}
	var methods []string
	src := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		methods = append(methods, r.Method)
		q := r.URL.Query().Get("query")
		for k, v := range vals {
			if q == "k_"+k+`{db="geo",c="pg1"}` {
				seen[k] = true
				if r.URL.Path != "/api/v1/query" || r.URL.Query().Get("time") != strconv.FormatInt(t0.Unix(), 10) {
					t.Errorf("запрос %s: %s %v", k, r.URL.Path, r.URL.Query())
				}
				w.Write(vector(v))
				return
			}
		}
		t.Errorf("неожиданный запрос: %q", q)
		w.WriteHeader(400)
	})
	c, _ := New(src, "", dbQueries(), 2*time.Second)
	d, err := c.Aggregates(context.Background(), dbSvc(), t0)
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != len(intake.DBQueryKeys) {
		t.Errorf("выполнено %d запросов из %d", len(seen), len(intake.DBQueryKeys))
	}
	for _, m := range methods {
		if m != "GET" {
			t.Errorf("метод %s", m)
		}
	}
	if d.PgBouncer.Database != "geo" || d.PgBouncer.PoolSize != 20 || d.Postgres.MaxConnections != 101 || d.Postgres.SuperuserReserved != 3 ||
		d.Postgres.OtherPoolsTotal != 40 || d.Postgres.Headroom != 11 { // ceil(10.1)
		t.Errorf("агрегаты: %+v", d)
	}
	want := []intake.SessionRow{{State: "active", Sessions: 7, Over60s: 1}, {State: "idle", Sessions: 30, Over60s: 10}, {State: "idle in transaction", Sessions: 2, Over60s: 2}}
	if len(d.SessionsByState) != 3 {
		t.Fatalf("sessions: %+v", d.SessionsByState)
	}
	for i, w := range want {
		if d.SessionsByState[i] != w {
			t.Errorf("sessions[%d] = %+v, ожидается %+v", i, d.SessionsByState[i], w)
		}
	}
	if len(d.ShowPools) != 1 || d.ShowPools[0] != (intake.PoolRow{Database: "geo", ClActive: 5, ClWaiting: 4, SvActive: 6, SvIdle: 14, MaxWaitS: 1.5}) {
		t.Errorf("pools: %+v", d.ShowPools)
	}
}

func TestAggregatesFailures(t *testing.T) {
	// отсутствует ключ db_queries
	src := fixture(t, func(w http.ResponseWriter, r *http.Request) { w.Write(vector("1")) })
	q := dbQueries()
	delete(q, "pool_size")
	c, _ := New(src, "", q, 2*time.Second)
	if _, err := c.Aggregates(context.Background(), dbSvc(), t0); err == nil {
		t.Error("нет ключа pool_size: ошибка не возвращена")
	}
	// плохие значения: пустой вектор, NaN, Inf, отрицательное, не число
	for name, body := range map[string][]byte{
		"пустой вектор": []byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`),
		"NaN":           vector("NaN"), "Inf": vector("+Inf"), "отрицательное": vector("-1"), "текст": vector("abc"),
		"matrix": matrix(),
	} {
		src := fixture(t, func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Query().Get("query"), "max_connections") {
				w.Write(body)
				return
			}
			w.Write(vector("1"))
		})
		c, _ := New(src, "", dbQueries(), 2*time.Second)
		if _, err := c.Aggregates(context.Background(), dbSvc(), t0); err == nil {
			t.Errorf("%s: ошибка не возвращена", name)
		}
	}
	// HTTP-ошибка одного запроса
	src = fixture(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("query"), "k_sv_idle") {
			w.WriteHeader(503)
			return
		}
		w.Write(vector("1"))
	})
	c, _ = New(src, "", dbQueries(), 2*time.Second)
	if _, err := c.Aggregates(context.Background(), dbSvc(), t0); err == nil || !strings.Contains(err.Error(), "http_503") {
		t.Errorf("503: %v", err)
	}
}

// Токен Prometheus необязателен; с токеном — только по https и из файла.
func TestOptionalToken(t *testing.T) {
	var auth []string
	var mu sync.Mutex
	src := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		auth = append(auth, r.Header.Get("Authorization"))
		mu.Unlock()
		w.Write(matrix())
	})
	c, _ := New(src, "", nil, 2*time.Second)
	c.QueryRange(context.Background(), "q", t0.Add(-30*time.Minute), t0, time.Minute)
	tf := filepath.Join(t.TempDir(), "t")
	tok := fmt.Sprintf("p%x", time.Now().UnixNano())
	os.WriteFile(tf, []byte(tok), 0o600)
	c, _ = New(src, tf, nil, 2*time.Second)
	c.QueryRange(context.Background(), "q", t0.Add(-30*time.Minute), t0, time.Minute)
	if auth[0] != "" || auth[1] != "Bearer "+tok {
		t.Errorf("Authorization: %q", auth)
	}
}
