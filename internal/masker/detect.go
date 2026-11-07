package masker

import (
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/limpjungle/aegis3311/internal/dataclass"
)

// span — найденный фрагмент строки [start, end) и его замена.
type span struct {
	start, end int
	prio       int // меньше — важнее: 0 секреты, 1 документы/карты, 2 контакты, 3 ФИО
	repl       string
	cat        dataclass.Category
}

// detector — строковый детектор. global — работает по всей строке, остальные — по окнам (см. scan).
type detector struct {
	name   string
	global bool
	find   func(st *state, w string) []span
}

// Большие строки сканируются окнами, чтобы ctx проверялся часто (regexp не прерывается).
const (
	windowThreshold = 32 << 10
	windowStep      = 16 << 10
	windowOverlap   = 2 << 10
	windowSnap      = 256
)

// scan — все детекторы → непересекающиеся находки по приоритету, упорядоченные по позиции.
func (st *state) scan(s string) ([]span, error) {
	if len(s) == 0 {
		return nil, nil
	}
	var all []span
	for _, d := range detectors {
		if !d.global {
			continue
		}
		if err := st.checkCtx(); err != nil {
			return nil, err
		}
		all = append(all, d.find(st, s)...)
	}
	if err := st.checkCtx(); err != nil {
		return nil, err
	}
	if len(s) <= windowThreshold {
		sp, err := st.runWindow(s, 0)
		if err != nil {
			return nil, err
		}
		all = append(all, sp...)
	} else {
		for start := 0; start < len(s); start += windowStep {
			a := snapForward(s, start)
			b := start + windowStep + windowOverlap
			if b >= len(s) {
				b = len(s)
			} else {
				b = snapBack(s, b)
			}
			sp, err := st.runWindow(s[a:b], a)
			if err != nil {
				return nil, err
			}
			all = append(all, sp...)
		}
	}
	return resolve(all), nil
}

// snapForward сдвигает начало окна к ближайшему пробельному разделителю (не больше windowSnap байт вперёд),
// иначе — к границе руны: окно не должно начинаться посреди токена или собственной заглушки.
func snapForward(s string, i int) int {
	for j := i; j < len(s) && j < i+windowSnap; j++ {
		if s[j] == ' ' || s[j] == '\n' {
			return j + 1
		}
	}
	for i < len(s) && !utf8.RuneStart(s[i]) {
		i++
	}
	return i
}

// snapBack — то же для конца окна (сдвиг назад).
func snapBack(s string, i int) int {
	for j := i; j > 0 && j > i-windowSnap; j-- {
		if s[j-1] == ' ' || s[j-1] == '\n' {
			return j
		}
	}
	for i > 0 && !utf8.RuneStart(s[i]) {
		i--
	}
	return i
}

func (st *state) runWindow(w string, off int) ([]span, error) {
	var out []span
	for _, d := range detectors {
		if d.global {
			continue
		}
		if err := st.checkCtx(); err != nil {
			return nil, err
		}
		for _, sp := range d.find(st, w) {
			if sp.end > sp.start {
				sp.start += off
				sp.end += off
				out = append(out, sp)
			}
		}
	}
	return out, nil
}

// resolve выбирает непересекающиеся находки: внутри группы пересекающихся — по (prio↑, длина↓, start↑).
func resolve(all []span) []span {
	if len(all) < 2 {
		return all
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].start != all[j].start {
			return all[i].start < all[j].start
		}
		return all[i].end > all[j].end
	})
	var out []span
	for i := 0; i < len(all); {
		j, end := i, all[i].end
		for j < len(all) && all[j].start < end {
			if all[j].end > end {
				end = all[j].end
			}
			j++
		}
		cl := append([]span(nil), all[i:j]...)
		sort.SliceStable(cl, func(a, b int) bool {
			if cl[a].prio != cl[b].prio {
				return cl[a].prio < cl[b].prio
			}
			if la, lb := cl[a].end-cl[a].start, cl[b].end-cl[b].start; la != lb {
				return la > lb
			}
			return cl[a].start < cl[b].start
		})
		var sel []span
		for _, c := range cl {
			ok := true
			for _, s := range sel {
				if c.start < s.end && s.start < c.end {
					ok = false
					break
				}
			}
			if ok {
				sel = append(sel, c)
			}
		}
		sort.Slice(sel, func(a, b int) bool { return sel[a].start < sel[b].start })
		out = append(out, sel...)
		i = j
	}
	return out
}

// apply заменяет находки (упорядочены, не пересекаются) и считает их по категориям.
func (st *state) apply(s string, sp []span) string {
	if len(sp) == 0 {
		return s
	}
	var b strings.Builder
	last := 0
	for _, x := range sp {
		b.WriteString(s[last:x.start])
		b.WriteString(x.repl)
		last = x.end
		if x.cat == dataclass.CategorySecret {
			st.secrets++
		} else {
			st.personal++
		}
	}
	b.WriteString(s[last:])
	return b.String()
}

// scanString — строка с заменёнными находками.
func (st *state) scanString(s string) (string, error) {
	sp, err := st.scan(s)
	if err != nil {
		return s, err
	}
	return st.apply(s, sp), nil
}

func prevRune(s string, i int) rune {
	if i <= 0 {
		return 0
	}
	r, _ := utf8.DecodeLastRuneInString(s[:i])
	return r
}

func nextRune(s string, i int) rune {
	if i >= len(s) {
		return 0
	}
	r, _ := utf8.DecodeRuneInString(s[i:])
	return r
}

// isWord — буква, цифра или '_' (\b в RE2 только ASCII, поэтому границы проверяются в коде).
func isWord(r rune) bool { return r == '_' || unicode.IsLetter(r) || unicode.IsNumber(r) }

// wordBounded — слева и справа от [a, b) нет «словесных» символов.
func wordBounded(s string, a, b int) bool { return !isWord(prevRune(s, a)) && !isWord(nextRune(s, b)) }

// leftWindow — до n байт слева от i по границе руны.
func leftWindow(s string, i, n int) string {
	a := i - n
	if a < 0 {
		a = 0
	}
	for a < i && !utf8.RuneStart(s[a]) {
		a++
	}
	return s[a:i]
}

func hasAny(s string, lits ...string) bool {
	for _, l := range lits {
		if strings.Contains(s, l) {
			return true
		}
	}
	return false
}

func hasCyrillic(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == 0xD0 || s[i] == 0xD1 {
			return true
		}
	}
	return false
}

// isPlaceholder — пусто, маска или шаблон подстановки, либо собственная заглушка маскировщика: находкой не считается.
func isPlaceholder(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return true
	}
	if strings.Trim(s, "*") == "" || strings.Trim(s, "x") == "" || strings.Trim(s, "X") == "" {
		return true
	}
	switch {
	case strings.HasPrefix(s, "${") && strings.HasSuffix(s, "}"),
		strings.HasPrefix(s, "{{") && strings.HasSuffix(s, "}}"),
		strings.HasPrefix(s, "$(") && strings.HasSuffix(s, ")"):
		return true
	}
	return ownPlaceholder.MatchString(s)
}
