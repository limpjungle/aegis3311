package masker

import (
	"math"
	"regexp"
	"strings"

	"github.com/limpjungle/aegis3311/internal/dataclass"
)

var ownPlaceholder = regexp.MustCompile(`^<(?:SECRET_REMOVED|CARD|(?:PERSON|DOC|IP)_[0-9a-f]{8})>$`)

func secretSpan(a, b int) span {
	return span{start: a, end: b, prio: 0, repl: secretRepl, cat: dataclass.CategorySecret}
}

// tokenRule — токен с характерным префиксом; lits — быстрый префильтр, bound — слева не должно быть [A-Za-z0-9].
type tokenRule struct {
	re    *regexp.Regexp
	lits  []string
	bound bool
}

// Подмножество правил gitleaks; примеры в комментариях без реальных значений.
var tokenRules = []tokenRule{
	{regexp.MustCompile(`(?:AKIA|ASIA)[0-9A-Z]{16}`), []string{"AKIA", "ASIA"}, false},                            // AWS access key id
	{regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,}`), []string{"gh"}, false},                                     // GitHub: префикс ghp_ и т. п.
	{regexp.MustCompile(`github_pat_[A-Za-z0-9_]{22,}`), []string{"github_pat_"}, false},                          // GitHub fine-grained
	{regexp.MustCompile(`glpat-[A-Za-z0-9_-]{20,}`), []string{"glpat-"}, false},                                   // GitLab
	{regexp.MustCompile(`xox[abprs]-[A-Za-z0-9-]{10,}`), []string{"xox"}, false},                                  // Slack
	{regexp.MustCompile(`hooks\.slack\.com/services/[A-Za-z0-9/_-]+`), []string{"hooks.slack.com"}, false},        // Slack webhook
	{regexp.MustCompile(`sk-or-v1-[0-9a-f]{64}`), []string{"sk-or-v1-"}, false},                                   // OpenRouter
	{regexp.MustCompile(`sk-ant-[A-Za-z0-9_-]{20,}`), []string{"sk-ant-"}, false},                                 // Anthropic
	{regexp.MustCompile(`sk-(?:proj-)?[A-Za-z0-9_-]{20,}`), []string{"sk-"}, true},                                // OpenAI
	{regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`), []string{"AIza"}, false},                                        // Google API key
	{regexp.MustCompile(`(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}`), []string{"_live_", "_test_"}, true},          // Stripe
	{regexp.MustCompile(`hv[sbr]\.[A-Za-z0-9_-]{20,}`), []string{"hvs.", "hvb.", "hvr."}, true},                   // Vault
	{regexp.MustCompile(`y0_[A-Za-z0-9_-]{20,}`), []string{"y0_"}, true},                                          // Yandex Cloud OAuth/IAM
	{regexp.MustCompile(`t1\.[A-Za-z0-9_-]{20,}`), []string{"t1."}, true},                                         // Yandex Cloud IAM
	{regexp.MustCompile(`AQVN[A-Za-z0-9_-]{30,}`), []string{"AQVN"}, true},                                        // Yandex Cloud API key
	{regexp.MustCompile(`[0-9]{8,10}:[A-Za-z0-9_-]{35}`), []string{":"}, true},                                    // Telegram bot token
	{regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`), []string{"eyJ"}, false}, // JWT
}

func isAlnum(r rune) bool {
	return r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z'
}

func findTokens(_ *state, w string) []span {
	var out []span
	for _, r := range tokenRules {
		if !hasAny(w, r.lits...) {
			continue
		}
		for _, m := range r.re.FindAllStringIndex(w, -1) {
			if r.bound && isAlnum(prevRune(w, m[0])) {
				continue
			}
			out = append(out, secretSpan(m[0], m[1]))
		}
	}
	return out
}

// findPEM — блок приватного ключа целиком; без END — до конца строки. Поиск по литералу и ручной разбор маркера
// (линейно), ctx проверяется между итерациями: regexp по всей строке не прерывается.
func findPEM(st *state, s string) []span {
	var out []span
	from := 0
	for n := 0; from < len(s); n++ {
		if n&255 == 0 && st.ctx.Err() != nil {
			return nil // ошибку вернёт scan при следующей проверке ctx
		}
		i := strings.Index(s[from:], "-----BEGIN ")
		if i < 0 {
			break
		}
		a := from + i
		hdrEnd, ok := pemMarker(s, a+len("-----BEGIN "))
		if !ok {
			from = a + len("-----BEGIN ")
			continue
		}
		end := len(s)
		for pos, k := hdrEnd, 0; pos < len(s); k++ {
			if k&255 == 0 && st.ctx.Err() != nil {
				return nil
			}
			j := strings.Index(s[pos:], "-----END ")
			if j < 0 {
				break
			}
			if e, ok := pemMarker(s, pos+j+len("-----END ")); ok {
				end = e
				break
			}
			pos += j + len("-----END ")
		}
		out = append(out, secretSpan(a, end))
		from = end
	}
	return out
}

// pemMarker разбирает `[A-Z ]*PRIVATE KEY-----` с позиции i; возвращает конец маркера.
func pemMarker(s string, i int) (int, bool) {
	k := i
	for k < len(s) && (s[k] == ' ' || s[k] >= 'A' && s[k] <= 'Z') {
		k++
	}
	if !strings.HasSuffix(s[i:k], "PRIVATE KEY") || !strings.HasPrefix(s[k:], "-----") {
		return 0, false
	}
	return k + 5, true
}

// lineValue — значение с позиции from до конца строки или одной из stop-кавычек.
func lineValue(w string, from int, stop string) (int, int) {
	end := len(w)
	if i := strings.IndexAny(w[from:], stop); i >= 0 {
		end = from + i
	}
	for end > from && (w[end-1] == ' ' || w[end-1] == '\t') {
		end--
	}
	return from, end
}

// Authorization: …, Proxy-Authorization=… — значение до конца строки или кавычки.
var reAuth = regexp.MustCompile(`(?i)(?:proxy-)?authorization["']?[ \t]*[:=][ \t]*["']?`)

func findAuthHeader(_ *state, w string) []span {
	if !strings.Contains(strings.ToLower(w), "authorization") {
		return nil
	}
	var out []span
	for _, m := range reAuth.FindAllStringIndex(w, -1) {
		a, b := lineValue(w, m[1], "\r\n\"'")
		if b > a && !isPlaceholder(w[a:b]) {
			out = append(out, secretSpan(a, b))
		}
	}
	return out
}

// Set-Cookie: …, Cookie: … — значение до конца строки.
var reCookie = regexp.MustCompile(`(?i)(?:set-)?cookie[ \t]*:[ \t]*`)

func findCookie(_ *state, w string) []span {
	if !strings.Contains(strings.ToLower(w), "cookie") {
		return nil
	}
	var out []span
	for _, m := range reCookie.FindAllStringIndex(w, -1) {
		if p := prevRune(w, m[0]); isAlnum(p) || p == '-' {
			continue
		}
		a, b := lineValue(w, m[1], "\r\n")
		if b > a && !isPlaceholder(w[a:b]) {
			out = append(out, secretSpan(a, b))
		}
	}
	return out
}

// Bearer <токен>, Basic <токен>: вырезается токен. Слова вроде «basic configuration» не трогаются —
// токен обязан содержать цифру или (при длине ≥ 20) заглавные и строчные одновременно.
var reBearer = regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9])(?:bearer|basic)[ \t]+([A-Za-z0-9._~+/=-]{8,})`)

func findBearer(_ *state, w string) []span {
	lw := strings.ToLower(w)
	if !strings.Contains(lw, "bearer") && !strings.Contains(lw, "basic") {
		return nil
	}
	var out []span
	for _, m := range reBearer.FindAllStringSubmatchIndex(w, -1) {
		t := w[m[2]:m[3]]
		if isPlaceholder(t) || !tokenLike(t) {
			continue
		}
		out = append(out, secretSpan(m[2], m[3]))
	}
	return out
}

func tokenLike(t string) bool {
	var up, lo, dg bool
	for i := 0; i < len(t); i++ {
		switch c := t[i]; {
		case c >= 'A' && c <= 'Z':
			up = true
		case c >= 'a' && c <= 'z':
			lo = true
		case c >= '0' && c <= '9':
			dg = true
		}
	}
	return dg || (len(t) >= 20 && up && lo)
}

// scheme://user:pass@host → scheme://<SECRET_REMOVED>@host.
var reURLCred = regexp.MustCompile(`[a-z][a-z0-9+.-]*://([^\s/:@]+:[^\s/@]+)@`)

func findURLCred(_ *state, w string) []span {
	if !strings.Contains(w, "://") {
		return nil
	}
	var out []span
	for _, m := range reURLCred.FindAllStringSubmatchIndex(w, -1) {
		cred := w[m[2]:m[3]]
		if i := strings.IndexByte(cred, ':'); isPlaceholder(cred[i+1:]) {
			continue
		}
		out = append(out, secretSpan(m[2], m[3]))
	}
	return out
}

// Присваивания в тексте: password=…, "api_key": "…", ?token=…&sig=… — вырезается значение.
var reAssign = regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9])([A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|signature|sig))["']?[ \t]*[:=][ \t]*("[^"]*"|'[^']*'|[^\s&,;]+)`)

func findAssign(_ *state, w string) []span {
	lw := strings.ToLower(w)
	if !hasAny(lw, "pass", "pwd", "secret", "token", "key", "sig") {
		return nil
	}
	var out []span
	for _, m := range reAssign.FindAllStringSubmatchIndex(w, -1) {
		if strings.Contains(strings.ToLower(w[m[2]:m[3]]), "tokens") {
			continue // счётчики токенов LLM, не секрет
		}
		a, b := m[4], m[5]
		if q := w[a]; q == '"' || q == '\'' {
			a, b = a+1, b-1
		}
		if b <= a || isPlaceholder(w[a:b]) {
			continue
		}
		out = append(out, secretSpan(a, b))
	}
	return out
}

// entropyMin — порог энтропии Шеннона (бит/симв.) для энтропийного правила. 4.1, а не 4.0: CamelCase-идентификаторы
// (имена алертов, метрик, классов) набирают 4.1–4.4, но порогом их не отсечь — у случайного токена из 32 символов
// [A-Za-z0-9] 0.1-й перцентиль ≈ 4.08. Их отсекает looksLikeIdentifier; порог 4.1 теряет ≈ 0.15% случайных токенов
// длины 32 и ни одного — от 36 (замер на 20 000 токенов каждой длины).
const entropyMin = 4.1

// findEntropy — самостоятельный токен: ≥ 32 симв., заглавные+строчные+цифры, энтропия Шеннона ≥ entropyMin.
// Исключены только-hex строки (дайджесты, git SHA, хэши подов) и идентификаторы из слов (looksLikeIdentifier).
func findEntropy(_ *state, w string) []span {
	var out []span
	for i := 0; i < len(w); {
		if !entropyChar(w[i]) {
			i++
			continue
		}
		j := i
		for j < len(w) && entropyChar(w[j]) {
			j++
		}
		if j-i >= 32 && entropyToken(w[i:j]) {
			out = append(out, secretSpan(i, j))
		}
		i = j
	}
	return out
}

func entropyChar(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '+' || c == '/' || c == '_' || c == '=' || c == '-'
}

func entropyToken(t string) bool {
	var up, lo, dg, nonHex bool
	for i := 0; i < len(t); i++ {
		switch c := t[i]; {
		case c >= 'A' && c <= 'Z':
			up = true
			nonHex = nonHex || c > 'F'
		case c >= 'a' && c <= 'z':
			lo = true
			nonHex = nonHex || c > 'f'
		case c >= '0' && c <= '9':
			dg = true
		default:
			nonHex = true
		}
	}
	return up && lo && dg && nonHex && shannon(t) >= entropyMin && !looksLikeIdentifier(t)
}

// Идентификатор из слов: CamelCase/PascalCase, в том числе с разделителями _ - / и цифрами
// (ProductionDatabaseConnectionPoolExhausted2024Alert, HighRequestLatencyP99ThresholdExceeded5m,
// OrderService-HighErrorRate-5xx-Critical2). Части: слово [A-Z]?[a-z]{2,}, аббревиатура [A-Z]{2,5}, число с
// необязательной буквой спереди и единицей сзади (P99, 2024, 5xx, 30s).
var (
	reIdentifier = regexp.MustCompile(`^(?:[A-Z]?[a-z]{2,}|[A-Z]{2,5}|[A-Z]?[0-9]{1,4}[a-z]{0,3})` +
		`(?:[_/-]?(?:[A-Z]?[a-z]{2,}|[A-Z]{2,5}|[A-Z]?[0-9]{1,4}[a-z]{0,3}))+$`)
	reIdentWord  = regexp.MustCompile(`[A-Z]?[a-z]{2,}`)
	reIdentUnit  = regexp.MustCompile(`[0-9]+[a-z]{0,3}`)       // 5xx, 30s: не слова
	reConsonants = regexp.MustCompile(`[b-df-hj-np-tv-xz]{4,}`) // 4+ согласных подряд — не слово
)

// looksLikeIdentifier — токен разбирается на части reIdentifier и его слова похожи на слова естественного языка:
// не меньше 3 слов, слова покрывают ≥ 60% токена, в каждом есть гласная (aeiouy), нет 4+ согласных подряд,
// гласных ≥ 25% букв слов. Случайный токен [A-Za-z0-9] длины 32 проходит с вероятностью ≈ 6·10⁻⁵, длины 64 —
// не прошёл ни разу на 10⁶ (замер при выборе правила). Токены с известными префиксами ловят свои правила раньше.
func looksLikeIdentifier(t string) bool {
	if !reIdentifier.MatchString(t) {
		return false
	}
	words, cover, letters, vowels := 0, 0, 0, 0
	for _, w := range reIdentWord.FindAllString(reIdentUnit.ReplaceAllString(t, "0"), -1) {
		lw := strings.ToLower(w)
		if !strings.ContainsAny(lw, "aeiouy") || reConsonants.MatchString(lw) {
			return false
		}
		words++
		cover += len(w)
		letters += len(lw)
		for i := 0; i < len(lw); i++ {
			if strings.IndexByte("aeiouy", lw[i]) >= 0 {
				vowels++
			}
		}
	}
	return words >= 3 && cover*10 >= len(t)*6 && vowels*4 >= letters
}

// shannon — энтропия Шеннона в битах на символ (по байтам).
func shannon(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	h := 0.0
	n := float64(len(s))
	for _, c := range freq {
		if c > 0 {
			p := float64(c) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}
