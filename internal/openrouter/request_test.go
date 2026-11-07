package openrouter

import (
	"errors"
	"strings"
	"testing"

	"github.com/limpjungle/aegis3311/internal/pyjson"
)

func testInput(t *testing.T) *pyjson.Value {
	return parseF(t, `{"service":{"name":"геo-svc"},"metrics":[{"v":416.0}]}`)
}

func TestBuildRequest(t *testing.T) {
	a := loadReal(t)
	body := BuildRequest(testInput(t), a, a.Primary)
	b := string(BodyBytes(body))
	for _, want := range []string{`"max_tokens":4096`, `"temperature":0,`, `"seed":20261105`, `"usage":{"include":true}`, `"strict":true`,
		`"name":"aegisops_answer_v1"`, `416.0`, `геo-svc`} {
		if !strings.Contains(b, want) {
			t.Errorf("в теле нет %s", want)
		}
	}
	if strings.Contains(b, `"$schema"`) || strings.Contains(b, `"$id"`) {
		t.Error("$schema/$id в теле")
	}
	if err := AssertRequestSafe([]byte(b), &a.Config, a.Primary); err != nil {
		t.Fatal(err)
	}
	if est := EstimateInputTokens(body, &a.Config); est < 1000 {
		t.Errorf("est %d", est)
	}
}

func TestAssertRequestSafeTampered(t *testing.T) {
	a := loadReal(t)
	good := string(BodyBytes(BuildRequest(testInput(t), a, a.Primary)))
	cases := map[string]string{
		"лишний ключ":     strings.Replace(good, `{"max_tokens"`, `{"stop":[],"max_tokens"`, 1),
		"zdr false":       strings.Replace(good, `"zdr":true`, `"zdr":false`, 1),
		"другой provider": strings.Replace(good, `"inceptron"`, `"other"`, 1),
		"другая модель":   strings.Replace(good, `"model":"z-ai`, `"model":"x-ai`, 1),
		"temperature":     strings.Replace(good, `"temperature":0`, `"temperature":0.7`, 1),
		"strict false":    strings.Replace(good, `"strict":true`, `"strict":false`, 1),
		"не json":         "{",
	}
	for name, b := range cases {
		err := AssertRequestSafe([]byte(b), &a.Config, a.Primary)
		var se *SafetyError
		if !errors.As(err, &se) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// seed без send_seed.
	p := *a.Primary
	p.SendSeed = false
	if err := AssertRequestSafe([]byte(good), &a.Config, &p); err == nil {
		t.Error("seed без send_seed принят")
	}
}

func TestOverCeilingBoundary(t *testing.T) {
	a := loadReal(t)
	c := &a.Config
	if OverCeiling(c.ContextCeiling-4096, 4096, c) || !OverCeiling(c.ContextCeiling-4095, 4096, c) {
		t.Error("граница потолка")
	}
}

func TestEstimateHandExample(t *testing.T) {
	// 3 байта system + 3 user (кириллица: 2 байта на букву) + схема: ceil(n/2.5)+64.
	cfg := &Config{CharsPerToken: 2.5}
	body := parseF(t, `{"messages":[{"content":"abc"},{"content":"аб"}],"response_format":{"json_schema":{"schema":{"k":"я"}}}}`)
	// схема: {"k": "я"} = 15 байт; 3+4+15 = 22 → ceil(8.8)=9 → 73
	if got := EstimateInputTokens(body, cfg); got != 73 {
		t.Errorf("got %d", got)
	}
}
