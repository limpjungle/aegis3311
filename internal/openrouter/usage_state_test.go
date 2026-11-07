package openrouter

import (
	"context"
	"testing"
)

// Usage из ответа провайдера (проверка после итерации 2): отрицательные, нецелые, сверхбольшие и нечисловые значения —
// не usage, списывается весь резерв; целые в пределах 2^53 учитываются по факту.
func TestUsageNumbersChargeByFact(t *testing.T) {
	cases := []struct {
		name  string
		usage string
		want  int64
	}{
		{"целые", `,"usage":{"prompt_tokens":100,"completion_tokens":50}`, 150},
		{"граница 2^53", `,"usage":{"prompt_tokens":9007199254740992,"completion_tokens":0}`, 1 << 53},
		{"отрицательный prompt", `,"usage":{"prompt_tokens":-100000,"completion_tokens":50}`, res1.Tokens},
		{"отрицательный completion", `,"usage":{"prompt_tokens":100,"completion_tokens":-50}`, res1.Tokens},
		{"дробный", `,"usage":{"prompt_tokens":10.5,"completion_tokens":50}`, res1.Tokens},
		{"выше 2^53", `,"usage":{"prompt_tokens":9007199254740994,"completion_tokens":1}`, res1.Tokens},
		{"строка вместо числа", `,"usage":{"prompt_tokens":"100","completion_tokens":50}`, res1.Tokens},
		{"без usage", ``, res1.Tokens},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tr := &fakeTr{resp: []any{okResp(c.usage)}}
			b := &fakeBudget{max: 1 << 62}
			cr, err := testClient(t, tr, nil).Call(context.Background(), nil, b, res1, nil)
			if err != nil || cr.Kind != CallOK {
				t.Fatalf("%v %v", err, cr.Kind)
			}
			if len(b.settled) != 1 || b.settled[0] != c.want || cr.Tokens != c.want {
				t.Errorf("учтено %v (в результате %d), ожидается %d", b.settled, cr.Tokens, c.want)
			}
			if b.held != 0 {
				t.Errorf("held после расчёта: %d", b.held)
			}
		})
	}
}

// Отрицательная цена в usage.cost не уменьшает расход: берётся расчёт по токенам.
func TestNegativeReportedCostIgnored(t *testing.T) {
	tr := &fakeTr{resp: []any{okResp(`,"usage":{"prompt_tokens":100,"completion_tokens":50,"cost":-5}`)}}
	cr, err := testClient(t, tr, nil).Call(context.Background(), nil, &fakeBudget{max: 1 << 62}, res1, nil)
	if err != nil || cr.Kind != CallOK {
		t.Fatalf("%v %v", err, cr.Kind)
	}
	if cr.Tokens != 150 || cr.CostUSD <= 0 {
		t.Errorf("токены %d, стоимость %v: ожидается 150 и положительная стоимость по токенам", cr.Tokens, cr.CostUSD)
	}
}
