package masker

import (
	"net/netip"
	"regexp"
	"strings"

	"github.com/limpjungle/aegis3311/internal/dataclass"
)

const (
	prioDoc     = 1 // документы и карты
	prioContact = 2 // email, телефон, IP
	prioPerson  = 3 // ФИО
)

func (st *state) pdSpan(a, b, prio int, kind, norm string) span {
	return span{start: a, end: b, prio: prio, repl: pseudonym(st.inc, kind, norm), cat: dataclass.CategoryPersonal}
}

func cardSpan(a, b int) span {
	return span{start: a, end: b, prio: prioDoc, repl: cardRepl, cat: dataclass.CategoryPersonal}
}

func hasDigit(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			return true
		}
	}
	return false
}

// digitRuns — максимальные последовательности ASCII-цифр, соседи которых не «словесные» символы.
func digitRuns(w string) [][2]int {
	var out [][2]int
	for i := 0; i < len(w); {
		if w[i] < '0' || w[i] > '9' {
			i++
			continue
		}
		j := i
		for j < len(w) && w[j] >= '0' && w[j] <= '9' {
			j++
		}
		if wordBounded(w, i, j) {
			out = append(out, [2]int{i, j})
		}
		i = j
	}
	return out
}

// --- email ---

var reEmail = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}`)

func findEmail(st *state, w string) []span {
	if !strings.Contains(w, "@") {
		return nil
	}
	var out []span
	for _, m := range reEmail.FindAllStringIndex(w, -1) {
		// scp-синтаксис git@host:org/repo — не адрес почты
		if m[1]+1 < len(w) && w[m[1]] == ':' && w[m[1]+1] != ' ' && w[m[1]+1] != '\n' {
			continue
		}
		out = append(out, st.pdSpan(m[0], m[1], prioContact, "PERSON", strings.ToLower(w[m[0]:m[1]])))
	}
	return out
}

// --- телефон ---

// normPhone — только цифры; ведущая 8 при 11 цифрах → 7.
func normPhone(s string) string {
	d := digitsOnly(s)
	if len(d) == 11 && d[0] == '8' {
		d = "7" + d[1:]
	}
	return d
}

var (
	rePhoneRU   = regexp.MustCompile(`(?:\+7|8)[ \t\x{a0}(-]*[0-9]{3}[ \t\x{a0})-]*[0-9]{3}[ \t\x{a0}-]*[0-9]{2}[ \t\x{a0}-]*[0-9]{2}`)
	rePhoneIntl = regexp.MustCompile(`\+[1-9][0-9 \t()-]{7,17}[0-9]`)
)

func findPhone(st *state, w string) []span {
	if !hasDigit(w) {
		return nil
	}
	var out []span
	for _, m := range rePhoneRU.FindAllStringIndex(w, -1) {
		t := w[m[0]:m[1]]
		p := prevRune(w, m[0])
		if isWord(p) || p == '+' || isWord(nextRune(w, m[1])) {
			continue
		}
		d := digitsOnly(t)
		if len(d) != 11 || (t[0] == '8' && d[1] != '9') {
			continue
		}
		out = append(out, st.pdSpan(m[0], m[1], prioContact, "PERSON", normPhone(t)))
	}
	if strings.Contains(w, "+") {
		for _, m := range rePhoneIntl.FindAllStringIndex(w, -1) {
			t := w[m[0]:m[1]]
			if isWord(prevRune(w, m[0])) || isWord(nextRune(w, m[1])) {
				continue
			}
			if n := len(digitsOnly(t)); n < 8 || n > 15 {
				continue
			}
			out = append(out, st.pdSpan(m[0], m[1], prioContact, "PERSON", normPhone(t)))
		}
	}
	return out
}

// --- карты ---

var reCardGroups = []*regexp.Regexp{
	regexp.MustCompile(`[0-9]{4}(?:[ -][0-9]{4}){2,3}(?:[ -][0-9]{1,3})?`),
	regexp.MustCompile(`[0-9]{4}[ -][0-9]{6}[ -][0-9]{5}`),
}

func cardNumber(d string) bool {
	return len(d) >= 13 && len(d) <= 19 && d[0] >= '2' && d[0] <= '6' && luhnValid(d)
}

func findCard(_ *state, w string) []span {
	if !hasDigit(w) {
		return nil
	}
	var out []span
	for _, r := range digitRuns(w) {
		if cardNumber(w[r[0]:r[1]]) {
			out = append(out, cardSpan(r[0], r[1]))
		}
	}
	for _, re := range reCardGroups {
		for _, m := range re.FindAllStringIndex(w, -1) {
			if wordBounded(w, m[0], m[1]) && cardNumber(digitsOnly(w[m[0]:m[1]])) {
				out = append(out, cardSpan(m[0], m[1]))
			}
		}
	}
	return out
}

// --- СНИЛС, ИНН, паспорт, IBAN ---

var (
	reSnilsFmt  = regexp.MustCompile(`[0-9]{3}-[0-9]{3}-[0-9]{3}[ -][0-9]{2}`)
	reSnilsCtx  = regexp.MustCompile(`(?i)(?:^|[^\p{L}])(?:снилс|snils)[^0-9]{0,24}$`)
	reInnCtx    = regexp.MustCompile(`(?i)(?:^|[^\p{L}])(?:инн|inn|tin)[^0-9]{0,24}$`)
	rePassCtx   = regexp.MustCompile(`(?i)(?:^|[^\p{L}])(?:паспорт\p{L}*|passport)[^0-9]{0,24}$`)
	rePassport  = regexp.MustCompile(`[0-9]{2}[ \t]?[0-9]{2}[ \t]?[0-9]{6}`)
	reIBAN      = regexp.MustCompile(`[A-Z]{2}[0-9]{2}[A-Z0-9 ]{11,30}`)
	docCtxBytes = 40
)

func ctxBefore(re *regexp.Regexp, w string, i int) bool {
	return re.MatchString(leftWindow(w, i, docCtxBytes))
}

func findDocs(st *state, w string) []span {
	if !hasDigit(w) {
		return nil
	}
	var out []span
	for _, m := range reSnilsFmt.FindAllStringIndex(w, -1) {
		if wordBounded(w, m[0], m[1]) && snilsValid(digitsOnly(w[m[0]:m[1]])) {
			out = append(out, st.pdSpan(m[0], m[1], prioDoc, "DOC", digitsOnly(w[m[0]:m[1]])))
		}
	}
	for _, r := range digitRuns(w) {
		d := w[r[0]:r[1]]
		switch len(d) {
		case 11:
			if snilsValid(d) && ctxBefore(reSnilsCtx, w, r[0]) {
				out = append(out, st.pdSpan(r[0], r[1], prioDoc, "DOC", d))
			}
		case 10, 12:
			if innValid(d) && ctxBefore(reInnCtx, w, r[0]) {
				out = append(out, st.pdSpan(r[0], r[1], prioDoc, "DOC", d))
			}
		}
	}
	if hasAny(strings.ToLower(w), "паспорт", "passport") {
		for _, m := range rePassport.FindAllStringIndex(w, -1) {
			if wordBounded(w, m[0], m[1]) && ctxBefore(rePassCtx, w, m[0]) {
				out = append(out, st.pdSpan(m[0], m[1], prioDoc, "DOC", digitsOnly(w[m[0]:m[1]])))
			}
		}
	}
	for _, m := range reIBAN.FindAllStringIndex(w, -1) {
		if isWord(prevRune(w, m[0])) {
			continue
		}
		// жадное совпадение может захватить следующие слова: укорачиваем по границам групп
		t := w[m[0]:m[1]]
		for {
			t = strings.TrimRight(t, " ")
			if ibanValid(t) {
				if e := m[0] + len(t); !isWord(nextRune(w, e)) {
					out = append(out, st.pdSpan(m[0], e, prioDoc, "DOC", strings.ReplaceAll(t, " ", "")))
				}
				break
			}
			i := strings.LastIndexByte(t, ' ')
			if i < 0 {
				break
			}
			t = t[:i]
		}
	}
	return out
}

// normDoc — нормализация номера документа для псевдонима: без пробелов и дефисов, верхний регистр.
func normDoc(s string) string {
	return strings.ToUpper(strings.NewReplacer(" ", "", "-", "", "\t", "").Replace(s))
}

// --- IP ---

var reIPv4 = regexp.MustCompile(`[0-9]{1,3}(?:\.[0-9]{1,3}){3}`)
var reIPv6 = regexp.MustCompile(`[0-9A-Fa-f:]{2,39}`)

// DefaultInternalNets — внутренние сети, адреса которых не маскируются.
func DefaultInternalNets() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8",
		"169.254.0.0/16", "fc00::/7", "fe80::/10", "::1/128"} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func (st *state) internalIP(a netip.Addr) bool {
	a = a.Unmap()
	if a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsUnspecified() || a.IsMulticast() {
		return true
	}
	for _, n := range st.m.nets {
		if n.Contains(a) {
			return true
		}
	}
	return false
}

func findIP(st *state, w string) []span {
	var out []span
	if strings.Contains(w, ".") {
		for _, m := range reIPv4.FindAllStringIndex(w, -1) {
			if p := prevRune(w, m[0]); isAlnum(p) || p == '.' {
				continue
			}
			if n := nextRune(w, m[1]); n >= '0' && n <= '9' {
				continue
			} else if n == '.' && m[1]+1 < len(w) && w[m[1]+1] >= '0' && w[m[1]+1] <= '9' {
				continue
			}
			a, err := netip.ParseAddr(w[m[0]:m[1]])
			if err != nil || st.internalIP(a) {
				continue
			}
			out = append(out, st.pdSpan(m[0], m[1], prioContact, "IP", a.String()))
		}
	}
	if strings.Count(w, ":") >= 2 {
		for _, m := range reIPv6.FindAllStringIndex(w, -1) {
			a0, b0 := m[0], m[1]
			if isWord(prevRune(w, a0)) || isAlnum(nextRune(w, b0)) || prevRune(w, a0) == '.' {
				continue
			}
			if strings.Count(w[a0:b0], ":") < 2 {
				continue
			}
			a, err := netip.ParseAddr(w[a0:b0])
			if err != nil && w[b0-1] == ':' && !strings.HasSuffix(w[a0:b0], "::") { // хвостовое двоеточие знака препинания
				b0--
				a, err = netip.ParseAddr(w[a0:b0])
			}
			if err != nil || st.internalIP(a) {
				continue
			}
			out = append(out, st.pdSpan(a0, b0, prioContact, "IP", a.String()))
		}
	}
	return out
}

// --- ФИО (кириллица, по отчеству и инициалам) ---

const (
	cWord = `[А-ЯЁ][а-яё]+`
	cPatr = `[А-ЯЁ][а-яё]+(?:ович|евич|ьич|овна|евна|ична)`
	cSp   = `[ \t\x{a0}]+`
)

var (
	rePersonPatr = regexp.MustCompile(`(?:` + cWord + `(?:-` + cWord + `)?` + cSp + `)?` + cWord + cSp + cPatr)
	rePersonInit = regexp.MustCompile(cWord + `(?:-` + cWord + `)?` + cSp + `[А-ЯЁ]\.[ \t]?[А-ЯЁ]\.`)
)

func normFIO(s string) string {
	s = strings.ReplaceAll(strings.ToLower(s), "ё", "е")
	return strings.ReplaceAll(strings.Join(strings.Fields(s), " "), ". ", ".")
}

func findPerson(st *state, w string) []span {
	if !hasCyrillic(w) {
		return nil
	}
	var out []span
	for _, re := range []*regexp.Regexp{rePersonPatr, rePersonInit} {
		for _, m := range re.FindAllStringIndex(w, -1) {
			if isWord(prevRune(w, m[0])) || isWord(nextRune(w, m[1])) {
				continue
			}
			out = append(out, st.pdSpan(m[0], m[1], prioPerson, "PERSON", normFIO(w[m[0]:m[1]])))
		}
	}
	return out
}

// detectors — порядок не влияет на результат (resolve по приоритету), global запускаются по всей строке.
var detectors = []detector{
	{"pem", true, findPEM},
	{"tokens", false, findTokens},
	{"auth", false, findAuthHeader},
	{"cookie", false, findCookie},
	{"bearer", false, findBearer},
	{"urlcred", false, findURLCred},
	{"assign", false, findAssign},
	{"entropy", false, findEntropy},
	{"email", false, findEmail},
	{"phone", false, findPhone},
	{"card", false, findCard},
	{"docs", false, findDocs},
	{"ip", false, findIP},
	{"person", false, findPerson},
}
