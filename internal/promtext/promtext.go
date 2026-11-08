// Package promtext — минимальная текстовая экспозиция Prometheus (формат 0.0.4) на stdlib: клиентская библиотека
// проекту не нужна, метрик немного, а зависимость расширила бы границу доверия.
package promtext

import (
	"bytes"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ContentType — Content-Type ответа /metrics.
const ContentType = "text/plain; version=0.0.4; charset=utf-8"

var (
	nameRe  = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*$`)
	labelRe = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
)

// Label — пара имя/значение метки.
type Label struct{ Name, Value string }

// Sample — один ряд семейства.
type Sample struct {
	Labels []Label
	Value  float64
}

// Writer собирает экспозицию. Семейства идут в порядке вызовов, каждое — не больше одного раза; первая ошибка
// запоминается и возвращается из Bytes.
type Writer struct {
	buf  bytes.Buffer
	seen map[string]bool
	err  error
}

// Gauge добавляет семейство gauge.
func (w *Writer) Gauge(name, help string, s ...Sample) { w.family("gauge", name, help, s) }

// Counter добавляет семейство counter; имя обязано оканчиваться на _total.
func (w *Writer) Counter(name, help string, s ...Sample) {
	if !strings.HasSuffix(name, "_total") {
		w.fail(fmt.Errorf("promtext: счётчик %q: имя должно оканчиваться на _total", name))
		return
	}
	w.family("counter", name, help, s)
}

// Bytes возвращает экспозицию или первую ошибку.
func (w *Writer) Bytes() ([]byte, error) {
	if w.err != nil {
		return nil, w.err
	}
	return w.buf.Bytes(), nil
}

func (w *Writer) fail(err error) {
	if w.err == nil {
		w.err = err
	}
}

func (w *Writer) family(typ, name, help string, samples []Sample) {
	if !nameRe.MatchString(name) {
		w.fail(fmt.Errorf("promtext: недопустимое имя семейства %q", name))
		return
	}
	if w.seen[name] {
		w.fail(fmt.Errorf("promtext: семейство %q уже выведено", name))
		return
	}
	if w.seen == nil {
		w.seen = map[string]bool{}
	}
	w.seen[name] = true
	fmt.Fprintf(&w.buf, "# HELP %s %s\n# TYPE %s %s\n", name, escape(help, false), name, typ)
	for _, s := range samples {
		w.buf.WriteString(name)
		if len(s.Labels) > 0 {
			w.buf.WriteByte('{')
			for i, l := range s.Labels {
				if !labelRe.MatchString(l.Name) || strings.HasPrefix(l.Name, "__") {
					w.fail(fmt.Errorf("promtext: недопустимое имя метки %q в %q", l.Name, name))
					return
				}
				if i > 0 {
					w.buf.WriteByte(',')
				}
				fmt.Fprintf(&w.buf, `%s="%s"`, l.Name, escape(l.Value, true))
			}
			w.buf.WriteByte('}')
		}
		w.buf.WriteByte(' ')
		w.buf.WriteString(formatFloat(s.Value))
		w.buf.WriteByte('\n')
	}
}

func escape(s string, quote bool) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	if quote {
		s = strings.ReplaceAll(s, `"`, `\"`)
	}
	return s
}

func formatFloat(v float64) string {
	switch {
	case math.IsNaN(v):
		return "NaN"
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// Unix — время в секундах Unix с долями (до миллисекунд); 0 для нулевого времени.
func Unix(t time.Time) float64 {
	if t.IsZero() {
		return 0
	}
	return float64(t.UnixMilli()) / 1000
}

// Bool — 1 для true, иначе 0.
func Bool(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
