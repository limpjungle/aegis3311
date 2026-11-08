package promtext

import (
	"math"
	"strings"
	"testing"
	"time"
)

func TestGoldenGaugeCounter(t *testing.T) {
	var w Writer
	w.Gauge("x_up", "Жив ли.", Sample{Value: 1})
	w.Gauge("x_status", "Статус.",
		Sample{Labels: []Label{{"status", "ok"}}, Value: 1},
		Sample{Labels: []Label{{"status", "bad"}}, Value: 0})
	w.Counter("x_events_total", "События.", Sample{Labels: []Label{{"kind", "a"}, {"result", "ok"}}, Value: 42})
	b, err := w.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	want := "# HELP x_up Жив ли.\n# TYPE x_up gauge\nx_up 1\n" +
		"# HELP x_status Статус.\n# TYPE x_status gauge\nx_status{status=\"ok\"} 1\nx_status{status=\"bad\"} 0\n" +
		"# HELP x_events_total События.\n# TYPE x_events_total counter\nx_events_total{kind=\"a\",result=\"ok\"} 42\n"
	if string(b) != want {
		t.Errorf("получено:\n%s\nожидалось:\n%s", b, want)
	}
}

func TestEscaping(t *testing.T) {
	var w Writer
	w.Gauge("x", "a\\b\nc \"q\"", Sample{Labels: []Label{{"l", "a\\b\"c\nd"}}, Value: 1})
	b, err := w.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	want := "# HELP x a\\\\b\\nc \"q\"\n# TYPE x gauge\nx{l=\"a\\\\b\\\"c\\nd\"} 1\n"
	if string(b) != want {
		t.Errorf("получено %q, ожидалось %q", b, want)
	}
}

func TestSpecialValues(t *testing.T) {
	var w Writer
	w.Gauge("x", "h",
		Sample{Labels: []Label{{"v", "nan"}}, Value: math.NaN()},
		Sample{Labels: []Label{{"v", "pinf"}}, Value: math.Inf(1)},
		Sample{Labels: []Label{{"v", "ninf"}}, Value: math.Inf(-1)},
		Sample{Labels: []Label{{"v", "frac"}}, Value: 0.5},
		Sample{Labels: []Label{{"v", "ts"}}, Value: Unix(time.Date(2026, 11, 8, 10, 0, 0, 123_000_000, time.UTC))},
		Sample{Labels: []Label{{"v", "zero"}}, Value: Unix(time.Time{})})
	b, err := w.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{`x{v="nan"} NaN`, `x{v="pinf"} +Inf`, `x{v="ninf"} -Inf`, `x{v="frac"} 0.5`, `x{v="zero"} 0`, `x{v="ts"} 1.794132000123e+09`} {
		if !strings.Contains(s, want+"\n") {
			t.Errorf("нет %q в:\n%s", want, s)
		}
	}
}

func TestUnixKeepsMilliseconds(t *testing.T) {
	tm := time.Date(2026, 11, 8, 10, 0, 0, 987_000_000, time.UTC)
	if got := Unix(tm); got != float64(tm.UnixMilli())/1000 {
		t.Errorf("Unix = %v", got)
	}
	// строка, выведенная FormatFloat, обратимо хранит миллисекунды
	if s := formatFloat(Unix(tm)); !strings.HasSuffix(s, "e+09") || !strings.Contains(s, "987") {
		t.Errorf("потеря миллисекунд: %s", s)
	}
	if Unix(time.Time{}) != 0 || Bool(true) != 1 || Bool(false) != 0 {
		t.Error("Unix(zero) и Bool")
	}
}

func TestErrors(t *testing.T) {
	cases := map[string]func(w *Writer){
		"повтор семейства":     func(w *Writer) { w.Gauge("x", "h"); w.Gauge("x", "h") },
		"повтор gauge/counter": func(w *Writer) { w.Gauge("x_total", "h"); w.Counter("x_total", "h") },
		"имя с дефисом":        func(w *Writer) { w.Gauge("x-y", "h") },
		"имя с цифры":          func(w *Writer) { w.Gauge("1x", "h") },
		"пустое имя":           func(w *Writer) { w.Gauge("", "h") },
		"counter без _total":   func(w *Writer) { w.Counter("x", "h") },
		"метка __":             func(w *Writer) { w.Gauge("x", "h", Sample{Labels: []Label{{"__name", "v"}}}) },
		"метка с дефисом":      func(w *Writer) { w.Gauge("x", "h", Sample{Labels: []Label{{"a-b", "v"}}}) },
		"пустая метка":         func(w *Writer) { w.Gauge("x", "h", Sample{Labels: []Label{{"", "v"}}}) },
	}
	for name, f := range cases {
		var w Writer
		f(&w)
		if b, err := w.Bytes(); err == nil || b != nil {
			t.Errorf("%s: ожидалась ошибка, получено %q", name, b)
		}
	}
	// первая ошибка запоминается, последующие правильные вызовы её не стирают
	var w Writer
	w.Gauge("bad-name", "h")
	w.Gauge("ok", "h")
	if _, err := w.Bytes(); err == nil || !strings.Contains(err.Error(), "bad-name") {
		t.Errorf("первая ошибка потеряна: %v", err)
	}
	// пустой Writer — пустой вывод без ошибки
	var e Writer
	if b, err := e.Bytes(); err != nil || len(b) != 0 {
		t.Errorf("пустой: %q %v", b, err)
	}
}
