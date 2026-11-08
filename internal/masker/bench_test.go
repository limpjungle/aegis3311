package masker

import (
	"bytes"
	"math"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

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

// maskTimeout — llmrouter.MaskTimeout (импорт дал бы цикл); менять синхронно.
const maskTimeout = 2 * time.Second

// bestOf — минимальное время из n прогонов f: конкуренция за CPU (параллельные пакеты go test ./...) только
// добавляет время, минимум её отсекает.
func bestOf(n int, f func()) time.Duration {
	best := time.Duration(1<<63 - 1)
	for i := 0; i < n; i++ {
		start := time.Now()
		f()
		best = min(best, time.Since(start))
	}
	return best
}

// denseText — плотный текст размером не меньше size байт: в каждой строке токен, e-mail и публичный IPv4.
func denseText(tb testing.TB, size int) string {
	var sb strings.Builder
	for sb.Len() < size {
		sb.WriteString("error in handler, retry later; token=" + alnum(tb, 18) + " user p" + lowerHex(tb, 6) + "@example.org from " + publicIPv4(tb) + "\n")
	}
	return sb.String()
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
	text := denseText(b, 256<<10)
	v := pyjson.NewString(text)
	b.SetBytes(int64(len(text)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := m.Mask(ctxOK, meta("bench"), v); err != nil {
			b.Fatal(err)
		}
	}
}

// Целевой бюджет: кейс probe заметно быстрее MaskTimeout (2 с на фрагмент); тест держит запас на медленные CI.
// Берётся минимум из 3 прогонов на кейс — максимум по 480 одиночным замерам ловил бы паузы планировщика и GC.
func TestMaskProbeCaseBudget(t *testing.T) {
	m := newMasker(t)
	cases := probeCases(t, 480)
	var worst time.Duration
	for _, c := range cases {
		d := bestOf(3, func() {
			if _, _, err := m.Mask(ctxOK, meta("budget"), c); err != nil {
				t.Fatal(err)
			}
		})
		worst = max(worst, d)
	}
	if worst > 200*time.Millisecond && !raceEnabled {
		t.Errorf("самый медленный кейс probe: %v, цель < 50 мс (предел 200 мс)", worst)
	}
	t.Logf("самый медленный кейс probe: %v", worst)
}

// 256 KiB плотного текста укладывается в MaskTimeout (лучший из 3 настенных прогонов; рост времени проверяет
// TestMaskScalesLinearly).
func TestMaskLargeStringBudget(t *testing.T) {
	const n = 3
	m := newMasker(t)
	s256 := denseText(t, 256<<10)
	removed := 0
	best256 := bestOf(n, func() {
		_, rep := maskStr(t, m, s256)
		removed = rep.Removed
	})
	if removed == 0 {
		t.Error("находок нет")
	}
	if best256 >= maskTimeout && !raceEnabled {
		t.Errorf("256 KiB: лучший из %d прогонов %v ≥ MaskTimeout", n, best256)
	}
	t.Logf("256 KiB: %v, находок %d", best256, removed)
}

// maxScalingExp — предел показателя степени t ~ n^p между соседними размерами: линейно ≈ 1,0–1,06; слабая
// квадратичность (лишний проход по строке на находку) на 256K→1M ≈ 1,6, на 64K→256K ≈ 1,2 (не отделяется от шума).
const maxScalingExp = 1.25

// scalingExp — показатель степени роста v по n; n — фактические длины текстов.
func scalingExp(n0, n1 int, v0, v1 float64) float64 {
	return math.Log(v1/v0) / math.Log(float64(n1)/float64(n0))
}

// TestMaskScalesLinearly ловит слабую квадратичность в Mask на плотном тексте (находка каждые ~90 байт).
// Меряется CPU-время потока (CLOCK_THREAD_CPUTIME_ID под LockOSThread): оно стабильно под нагрузкой (±3% при
// 8 копиях теста на 4 CPU), настенное время плавает на 6–28%. Точка 1 MiB обязательна: пара 64→256 KiB слабую
// квадратичность не отделяет (показатель 1,19–1,24 против линейных 1,0–1,06), 256→1024 даёт ≈ 1,6.
// Минимум по 3 раундам отсекает паузы. Проверка аллокаций (TestMaskAllocScalesLinearly) дополняет: она
// детерминирована и ловит квадратичность по копированию (показатель ≈ 14), но не ловит лишний CPU без аллокаций.
func TestMaskScalesLinearly(t *testing.T) {
	if raceEnabled {
		t.Skip("race-детектор искажает время")
	}
	if testing.Short() {
		t.Skip("1 MiB плотного текста — около секунды")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if _, ok := threadCPUTime(); !ok {
		t.Skip("нет CPU-времени потока на этой платформе")
	}
	m := newMasker(t)
	sizes := []int{64 << 10, 256 << 10, 1 << 20}
	texts := make([]string, len(sizes))
	for i, sz := range sizes {
		texts[i] = denseText(t, sz)
	}
	best := make([]time.Duration, len(sizes))
	for round := 0; round < 3; round++ {
		for i, text := range texts {
			runtime.GC()
			c0, _ := threadCPUTime()
			maskStr(t, m, text)
			c1, _ := threadCPUTime()
			d := c1 - c0
			if round == 0 || d < best[i] {
				best[i] = d
			}
			if round == 0 && i == 1 && d > maskTimeout {
				t.Fatalf("256 KiB: CPU %v > MaskTimeout, 1 MiB не меряется", d)
			}
		}
	}
	var exps [2]float64
	for i := range exps {
		exps[i] = scalingExp(len(texts[i]), len(texts[i+1]), float64(best[i]), float64(best[i+1]))
	}
	t.Logf("CPU: 64K %v, 256K %v, 1M %v; показатели 64→256 %.2f, 256→1024 %.2f (предел %.2f)",
		best[0], best[1], best[2], exps[0], exps[1], maxScalingExp)
	for i, e := range exps {
		if e > maxScalingExp {
			t.Errorf("нелинейный рост %d→%d KiB: показатель %.2f > %.2f (CPU: 64K %v, 256K %v, 1M %v; показатели %.2f, %.2f)",
				len(texts[i])>>10, len(texts[i+1])>>10, e, maxScalingExp, best[0], best[1], best[2], exps[0], exps[1])
		}
	}
}

// TestMaskAllocScalesLinearly — детерминированная проверка: байты аллокаций растут линейно (16/64/256 KiB).
// Ловит квадратичность по копированию (s[:a]+repl+s[b:] на находку: показатель ≈ 14–16), не ловит лишние вычисления
// без аллокаций (strings.Count на находку: 4,25). Работает и под -race.
func TestMaskAllocScalesLinearly(t *testing.T) {
	m := newMasker(t)
	sizes := []int{16 << 10, 64 << 10, 256 << 10}
	texts := make([]string, len(sizes))
	alloc := make([]float64, len(sizes))
	for i, sz := range sizes {
		texts[i] = denseText(t, sz)
		best := uint64(math.MaxUint64)
		for run := 0; run < 2; run++ {
			runtime.GC()
			var a, b runtime.MemStats
			runtime.ReadMemStats(&a)
			maskStr(t, m, texts[i])
			runtime.ReadMemStats(&b)
			best = min(best, b.TotalAlloc-a.TotalAlloc)
		}
		alloc[i] = float64(best)
		t.Logf("%d KiB: %d байт аллокаций, %.1f на байт входа", len(texts[i])>>10, best, alloc[i]/float64(len(texts[i])))
	}
	for i := 0; i < len(sizes)-1; i++ {
		if e := scalingExp(len(texts[i]), len(texts[i+1]), alloc[i], alloc[i+1]); e > maxScalingExp {
			t.Errorf("аллокации %d→%d KiB: показатель %.2f > %.2f", len(texts[i])>>10, len(texts[i+1])>>10, e, maxScalingExp)
		}
	}
}
