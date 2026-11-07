package pep_test

import (
	"context"
	"encoding/json"
	"math"
	"sync"
	"testing"

	"github.com/limpjungle/aegis3311/internal/pep"
)

// Проверки на обход PEP: нестрогий разбор, отрицательные счётчики, переполнения, гонки, паники.

const validParamsJSON = `"params":{"scope":null,"pod_name":null,"reason":null,"parameter":null}`

func TestParseProposal_RejectsTrailingGarbage(t *testing.T) {
	base := `{"type":"none",` + validParamsJSON + `}`
	for _, in := range []string{base + "}", base + "]", base + "}}}", base + " ]"} {
		if _, err := pep.ParseProposal([]byte(in)); err == nil {
			t.Errorf("хвост %q принят как валидный JSON; ожидалась ошибка разбора", in[len(base):])
		}
	}
}

func TestEvaluate_NegativeHistoryIsContextInvalid(t *testing.T) {
	eng := newEngine(t)
	p := pep.Proposal{Type: "workload.scale_out"}
	cases := map[string]func(*pep.Context){
		"actions_last_hour < 0":  func(c *pep.Context) { c.History.ActionsLastHour = ip(-1000) },
		"seconds_since_last < 0": func(c *pep.Context) { c.History.SecondsSinceLast = ip(-1) },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			c := permissive(richState())
			mut(&c)
			v := eng.Evaluate(context.Background(), p, c)
			if v.Decision != "deny" || v.EffectiveLevel != "L0" || !hasReason(v.Reasons, "deny:context_invalid") {
				t.Errorf("decision=%s level=%s reasons=%+v; ожидался deny/L0 с context_invalid", v.Decision, v.EffectiveLevel, v.Reasons)
			}
		})
	}
}

func TestEvaluate_HugeNumbersNoBogusAllow(t *testing.T) {
	eng := newEngine(t)
	huge := []struct {
		name string
		typ  string
		mut  func(*pep.Context)
	}{
		{"pool_size близко к MaxInt64", "pgbouncer.resize_pool", func(c *pep.Context) {
			c.State.DB.PgBouncer.PoolSize = math.MaxInt64 - 1
		}},
		{"max_connections близко к MaxInt64", "postgres.set_restart_param", func(c *pep.Context) {
			c.State.DB.Postgres.MaxConnections = math.MaxInt64/2 + 10
		}},
		{"autoscaler current_min близко к MaxInt64", "workload.scale_out", func(c *pep.Context) {
			c.State.Autoscaler.CurrentMin = math.MaxInt64 - 1
			c.State.Autoscaler.Max = math.MaxInt64
		}},
	}
	for _, h := range huge {
		t.Run(h.name, func(t *testing.T) {
			c := permissive(richState())
			h.mut(&c)
			p := pep.Proposal{Type: h.typ}
			if h.typ == "postgres.set_restart_param" {
				p.Params.Parameter = sp("max_connections")
			}
			v := eng.Evaluate(context.Background(), p, c)
			// Допустимо: deny (любой код). Недопустимо: allow/downgrade с вычисленным значением,
			// которое выходит за пределы int64-арифметики (отрицательное или обёрнутое).
			if v.Decision == "allow" || v.Decision == "downgrade" {
				for k, val := range v.Action.Computed {
					if n, ok := val.(int); ok && n < 0 {
						t.Errorf("%s=%d: отрицательная величина при %s", k, n, v.Decision)
					}
					if m, ok := val.(map[string]int); ok {
						for kk, nn := range m {
							if nn < 0 {
								t.Errorf("%s.%s=%d: отрицательная величина при %s", k, kk, nn, v.Decision)
							}
						}
					}
				}
			}
		})
	}
}

// Параллельные вызовы Evaluate не дают разных вердиктов (запуск с -race ловит гонки).
func TestEvaluate_ConcurrentSafe(t *testing.T) {
	eng := newEngine(t)
	p := pep.Proposal{Type: "workload.restart", Params: params(sp("pod"), sp("geo-svc-aaa-11111"), nil, nil)}
	mk := func() pep.Context {
		c := permissive(richState())
		c.Flags.HumanEngaged = bp(true)
		return c
	}
	want, err := json.Marshal(eng.Evaluate(context.Background(), p, mk()))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan string, 64)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				got, _ := json.Marshal(eng.Evaluate(context.Background(), p, mk()))
				if string(got) != string(want) {
					select {
					case errs <- string(got):
					default:
					}
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Errorf("вердикт в параллельном вызове отличается: %s", e)
	}
}

// FuzzEvaluateRaw: произвольный action и контекст не должны вызывать панику, а вердикт обязан
// соблюдать инварианты PEP. В обычном go test выполняются только seed-кейсы.
func FuzzEvaluateRaw(f *testing.F) {
	eng := newEngine(f)
	seedCtx, _ := json.Marshal(permissive(richState()))
	l0 := permissive(richState())
	l0.Level.Level = sp("L0")
	l0Ctx, _ := json.Marshal(l0)
	seeds := []struct{ prop, ctx string }{
		{`{"type":"workload.scale_out",` + validParamsJSON + `}`, string(l0Ctx)},
		{`{"type":"workload.scale_out",` + validParamsJSON + `}`, string(seedCtx)},
		{`{"type":"workload.restart","params":{"scope":"pod","pod_name":"geo-svc-aaa-11111","reason":null,"parameter":null}}`, string(seedCtx)},
		{`{"type":"postgres.set_restart_param","params":{"scope":null,"pod_name":null,"reason":null,"parameter":"shared_buffers"}}`, string(seedCtx)},
		{`{"type":"none",` + validParamsJSON + `}`, `{}`},
		{`{"type":"","params":null}`, `null`},
		{`{"type":"pgbouncer.resize_pool",` + validParamsJSON + `}`, `{"state":{"db":{"pgbouncer":{"pool_size":-1}}}}`},
	}
	for _, s := range seeds {
		f.Add([]byte(s.prop), []byte(s.ctx))
	}
	levels := map[string]bool{"L0": true, "L1": true, "L2": true, "L3": true}
	rank := map[string]int{"L0": 0, "L1": 1, "L2": 2, "L3": 3}
	f.Fuzz(func(t *testing.T, prop, ctxJSON []byte) {
		var c pep.Context
		if err := json.Unmarshal(ctxJSON, &c); err != nil {
			return
		}
		v := eng.EvaluateRaw(context.Background(), prop, c)
		if !levels[v.EffectiveLevel] || (v.Ceiling != "" && !levels[v.Ceiling]) {
			t.Fatalf("неизвестный уровень: %+v", v)
		}
		if v.Reasons == nil {
			t.Fatal("Reasons == nil")
		}
		if _, err := json.Marshal(v); err != nil {
			t.Fatalf("вердикт не сериализуется: %v", err)
		}
		switch v.Decision {
		case "deny":
			if v.EffectiveLevel != "L0" {
				t.Fatalf("deny с уровнем %s", v.EffectiveLevel)
			}
		case "allow":
			if v.EffectiveLevel != v.RequestedLevel || v.EffectiveLevel == "L0" || hasDenyReason(v.Reasons) {
				t.Fatalf("allow нарушает инвариант: %+v", v)
			}
		case "downgrade":
			if v.EffectiveLevel == "L0" || hasDenyReason(v.Reasons) || rank[v.EffectiveLevel] >= rank[v.RequestedLevel] {
				t.Fatalf("downgrade нарушает инвариант: %+v", v)
			}
		case "noop":
			if v.EffectiveLevel != "L0" || hasDenyReason(v.Reasons) {
				t.Fatalf("noop нарушает инвариант: %+v", v)
			}
		default:
			t.Fatalf("неизвестное решение %q", v.Decision)
		}
		if len(c.Validate()) > 0 {
			if v.Decision == "allow" || v.Decision == "downgrade" {
				t.Fatalf("allow/downgrade при невалидном контексте: %+v", v)
			}
		}
	})
}

func hasReason(rs []pep.Reason, key string) bool {
	for _, r := range rs {
		if r.Effect+":"+r.Code == key {
			return true
		}
	}
	return false
}

func hasDenyReason(rs []pep.Reason) bool {
	for _, r := range rs {
		if r.Effect == "deny" {
			return true
		}
	}
	return false
}

// Пустые строки в обязательных идентификаторах контекста — неполный контекст (fail-closed).
func TestEvaluate_EmptyIdentifiersAreContextInvalid(t *testing.T) {
	eng := newEngine(t)
	p := pep.Proposal{Type: "workload.scale_out"}
	cases := map[string]func(*pep.Context){
		"namespace пуст":   func(c *pep.Context) { c.Namespace = sp("") },
		"environment пуст": func(c *pep.Context) { c.Environment = sp("") },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			c := permissive(richState())
			mut(&c)
			v := eng.Evaluate(context.Background(), p, c)
			if v.Decision != "deny" || v.EffectiveLevel != "L0" {
				t.Errorf("decision=%s level=%s reasons=%+v; ожидался deny/L0", v.Decision, v.EffectiveLevel, v.Reasons)
			}
		})
	}
}

// Пустой контекст для noop не должен паниковать: вердикт формируется без разыменования указателей.
func TestEvaluate_EmptyContextNoPanic(t *testing.T) {
	eng := newEngine(t)
	for _, typ := range []string{"recommend", "none", "workload.scale_out", "pgbouncer.resize_pool", "unknown.x"} {
		v := eng.Evaluate(context.Background(), pep.Proposal{Type: typ}, pep.Context{})
		if _, err := json.Marshal(v); err != nil {
			t.Fatalf("%s: %v", typ, err)
		}
		if v.Decision == "allow" || v.Decision == "downgrade" {
			t.Errorf("%s: %s при пустом контексте", typ, v.Decision)
		}
	}
}
