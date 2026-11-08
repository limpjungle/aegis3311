package dataclass

import (
	"testing"

	"github.com/limpjungle/aegis3311/internal/pyjson"
)

// Шаблон метки якорится целиком: «a|b» не пропускает «a-x» и «xb».
func TestLabelPolicyPatternAnchored(t *testing.T) {
	p, err := NewLabelPolicy(map[string]string{"service": "a|b"})
	if err != nil {
		t.Fatal(err)
	}
	in := parse(t, `{"labels":{"service":"a-x"}}`)
	out, dropped, err := p.FilterSeries(in)
	if err != nil || dropped != 1 || out.Get("labels").Kind != pyjson.Object || len(out.Get("labels").Members) != 0 {
		t.Errorf("a-x не должна проходить: dropped=%d err=%v", dropped, err)
	}
	for _, s := range []string{`{"labels":{"service":"xb"}}`, `{"labels":{"service":"b"}}`} {
		_, d, _ := p.FilterSeries(parse(t, s))
		want := 1
		if s == `{"labels":{"service":"b"}}` {
			want = 0
		}
		if d != want {
			t.Errorf("%s: dropped=%d, ожидается %d", s, d, want)
		}
	}
}

// Метка с нестроковым значением, даже если имя разрешено, удаляется.
func TestLabelNonStringDropped(t *testing.T) {
	p := MVPLabelPolicy()
	_, d, err := p.FilterSeries(parse(t, `{"labels":{"service":1,"limit_mb":true,"pod":null}}`))
	if err != nil || d != 3 {
		t.Errorf("dropped=%d err=%v, ожидается 3", d, err)
	}
}
