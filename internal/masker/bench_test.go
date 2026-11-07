package masker

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/limpjungle/aegis3311/internal/dataclass"
	"github.com/limpjungle/aegis3311/internal/pyjson"
)

// probeCases читает первые n кейсов probe-v3.
func probeCases(tb testing.TB, n int) []*pyjson.Value {
	raw, err := os.ReadFile("../../eval/golden-synthetic/data/probe-v3.jsonl")
	if err != nil {
		tb.Fatal(err)
	}
	var out []*pyjson.Value
	for _, ln := range bytes.Split(raw, []byte("\n")) {
		if len(bytes.TrimSpace(ln)) == 0 {
			continue
		}
		c, err := pyjson.Parse(ln)
		if err != nil {
			tb.Fatal(err)
		}
		out = append(out, c.Get("input"))
		if len(out) == n {
			break
		}
	}
	return out
}

func BenchmarkMaskProbeCase(b *testing.B) {
	m := newMasker(b)
	cases := probeCases(b, 50)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := m.Mask(ctxOK, meta("bench"), cases[i%len(cases)]); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMaskString256KiB(b *testing.B) {
	m := newMasker(b)
	var sb strings.Builder
	for sb.Len() < 256<<10 {
		sb.WriteString("error in handler, retry later; token=" + alnum(b, 18) + " user p" + lowerHex(b, 6) + "@example.org from " + publicIPv4(b) + "\n")
	}
	v := pyjson.NewString(sb.String())
	b.SetBytes(int64(sb.Len()))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := m.Mask(ctxOK, meta("bench"), v); err != nil {
			b.Fatal(err)
		}
	}
}

// Целевой бюджет: кейс probe заметно быстрее MaskTimeout (2 с на фрагмент); тест держит запас на медленные CI.
func TestMaskProbeCaseBudget(t *testing.T) {
	m := newMasker(t)
	cases := probeCases(t, 480)
	var worst time.Duration
	for _, c := range cases {
		start := time.Now()
		if _, _, err := m.Mask(ctxOK, meta("budget"), c); err != nil {
			t.Fatal(err)
		}
		if d := time.Since(start); d > worst {
			worst = d
		}
	}
	if worst > 200*time.Millisecond && !raceEnabled {
		t.Errorf("самый медленный кейс probe: %v, цель < 50 мс (предел 200 мс)", worst)
	}
	t.Logf("самый медленный кейс probe: %v", worst)
}

// 256 KiB плотного текста укладывается в MaskTimeout с запасом.
func TestMaskLargeStringBudget(t *testing.T) {
	m := newMasker(t)
	var sb strings.Builder
	for sb.Len() < 256<<10 {
		sb.WriteString("error in handler, retry later; token=" + alnum(t, 18) + " user p" + lowerHex(t, 6) + "@example.org from " + publicIPv4(t) + "\n")
	}
	start := time.Now()
	_, rep := maskStr(t, m, sb.String())
	d := time.Since(start)
	if rep.Removed == 0 {
		t.Error("находок нет")
	}
	if d > time.Second && !raceEnabled { // MaskTimeout = 2 с; запас на -race и медленные CI
		t.Errorf("256 KiB: %v, слишком близко к MaskTimeout 2 с", d)
	}
	t.Logf("256 KiB: %v, находок %d", d, rep.Removed)
	_ = dataclass.Internal
}
