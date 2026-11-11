package llmrouter

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/limpjungle/aegis3311/internal/openrouter"
	"github.com/limpjungle/aegis3311/internal/pyjson"
)

const canaryM1 = "canary-secret-0001" // 18 символов из допустимого набора

func mustCanary(t testing.TB, ms ...string) *CanarySet {
	t.Helper()
	c, err := NewCanarySet(ms)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNewCanarySetFormat(t *testing.T) {
	ok := []string{
		strings.Repeat("a", 12), strings.Repeat("a", 128), "AbC.dEf@ghi+jk-l_m", "user@example.org", "0123456789.-_+@",
	}
	for _, m := range ok {
		if _, err := NewCanarySet([]string{m}); err != nil {
			t.Errorf("%q: %v", m, err)
		}
	}
	bad := map[string]string{
		"11 символов":    strings.Repeat("a", 11),
		"129 символов":   strings.Repeat("a", 129),
		"пустой":         "",
		"пробел":         "canary secret 01",
		"пробел в конце": canaryM1 + " ",
		"слэш":           "canary/secret-01",
		"кириллица":      "canary-секрет-0001",
		"кавычка":        `canary"secret-01`,
		"обратный слэш":  `canary\secret-01`,
		"перевод строки": "canary-secret\n-01",
		"таб":            "canary\tsecret-01",
		"NUL":            "canary\x00secret-01",
		"неASCII 0x7f":   "canary-secret\x7f-01",
		"двоеточие":      "canary:secret-01",
		"CR в конце":     canaryM1 + "\r",
	}
	for name, m := range bad {
		_, err := NewCanarySet([]string{m})
		if err == nil {
			t.Errorf("%s: принято", name)
			continue
		}
		if m != "" && strings.Contains(err.Error(), m) {
			t.Errorf("%s: значение маркера попало в ошибку: %v", name, err)
		}
	}
}

func TestNewCanarySetDuplicatesAndLimit(t *testing.T) {
	_, err := NewCanarySet([]string{"Canary-Secret-0001", "canary-secret-0001"})
	if err == nil {
		t.Fatal("дубль другого регистра принят")
	}
	if strings.Contains(strings.ToLower(err.Error()), "canary-secret-0001") {
		t.Errorf("маркер в ошибке: %v", err)
	}
	if _, err := NewCanarySet([]string{canaryM1, canaryM1}); err == nil {
		t.Error("точный дубль принят")
	}
	gen := func(n int) []string {
		var out []string
		for i := 0; i < n; i++ {
			out = append(out, fmt.Sprintf("canary-marker-%05d", i))
		}
		return out
	}
	c, err := NewCanarySet(gen(MaxCanaryMarkers))
	if err != nil || c.Len() != MaxCanaryMarkers {
		t.Fatalf("256: %v %d", err, c.Len())
	}
	if _, err := NewCanarySet(gen(MaxCanaryMarkers + 1)); err == nil {
		t.Fatal("257 маркеров приняты")
	}
	// Пустой список — набор с нулём маркеров (проверка выключена), не ошибка конструктора.
	if c, err := NewCanarySet(nil); err != nil || c.Len() != 0 {
		t.Errorf("nil: %v %v", c, err)
	}
	if _, ok := mustCanary(t).Find([]byte(canaryM1)); ok {
		t.Error("пустой набор нашёл маркер")
	}
}

func writeCanaryFile(t testing.TB, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "markers.txt")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadCanaryFile(t *testing.T) {
	good := map[string]struct {
		content string
		n       int
	}{
		"простой":                {canaryM1 + "\n", 1},
		"без перевода в конце":   {canaryM1, 1},
		"комментарии и пустые":   {"# комментарий\n\n" + canaryM1 + "\n\n   \n#ещё\ncanary-secret-0002\n", 2},
		"CRLF":                   {"canary-secret-0001\r\ncanary-secret-0002\r\n", 2},
		"только CR в конце CRLF": {"# c\r\ncanary-secret-0001\r\n", 1},
	}
	for name, c := range good {
		cs, err := LoadCanaryFile(writeCanaryFile(t, c.content))
		if err != nil || cs.Len() != c.n {
			t.Errorf("%s: n=%d err=%v", name, cs.Len(), err)
			continue
		}
		if _, ok := cs.Find([]byte("xx " + strings.ToUpper(canaryM1) + " yy")); !ok {
			t.Errorf("%s: маркер из файла не найден", name)
		}
	}
	bad := map[string]string{
		"только комментарии":     "# a\n# b\n",
		"пустой файл":            "",
		"только пустые строки":   "\n\n  \n",
		"пробел в конце маркера": canaryM1 + " \n",
		"пробел в начале":        " " + canaryM1 + "\n",
		"отступ перед #":         " # коммент\n" + canaryM1 + "\n",
		"слишком короткий":       "short\n",
		"дубль":                  canaryM1 + "\n" + strings.ToUpper(canaryM1) + "\n",
		"два маркера в строке":   canaryM1 + " canary-secret-0002\n",
		"BOM":                    "\xef\xbb\xbf" + canaryM1 + "\n",
		"маркер с кириллицей":    "canary-секрет-0001\n",
		"NUL":                    "canary-secret\x00-0001\n",
	}
	for name, content := range bad {
		cs, err := LoadCanaryFile(writeCanaryFile(t, content))
		if err == nil {
			t.Errorf("%s: принято (n=%d)", name, cs.Len())
			continue
		}
		if strings.Contains(err.Error(), "canary-secret") || strings.Contains(err.Error(), "canary-секрет") {
			t.Errorf("%s: значение маркера в ошибке: %v", name, err)
		}
	}
	if _, err := LoadCanaryFile(filepath.Join(t.TempDir(), "нет-такого")); err == nil {
		t.Error("несуществующий файл принят")
	}
	if _, err := LoadCanaryFile(t.TempDir()); err == nil {
		t.Error("каталог принят")
	}
}

func TestLoadCanaryFileSizeLimit(t *testing.T) {
	line := func(n int) string { return "#" + strings.Repeat("x", n-2) + "\n" } // ровно n байт
	pad := func(total int) string {
		var b strings.Builder
		for b.Len()+1000 <= total {
			b.WriteString(line(1000))
		}
		b.WriteString(line(total - b.Len()))
		return b.String()
	}
	// Ровно 64 KiB (комментарии + маркер) допустимы; на байт больше — ошибка.
	body := pad(maxCanaryFileBytes-len(canaryM1)-1) + canaryM1 + "\n"
	if len(body) != maxCanaryFileBytes {
		t.Fatalf("тест: размер %d", len(body))
	}
	if cs, err := LoadCanaryFile(writeCanaryFile(t, body)); err != nil || cs.Len() != 1 {
		t.Fatalf("ровно 64 KiB: %v", err)
	}
	if _, err := LoadCanaryFile(writeCanaryFile(t, body+"\n")); err == nil {
		t.Fatal("64 KiB + 1 байт принято")
	}
	if _, err := LoadCanaryFile(writeCanaryFile(t, strings.Repeat("a", 1<<20))); err == nil {
		t.Fatal("1 MiB принят")
	}
}

func TestCanaryFind(t *testing.T) {
	m := "Canary-Secret-0001"
	c := mustCanary(t, "first-marker-0000", m, "tail-marker-9999")
	cases := []struct {
		name string
		body string
		idx  int
		ok   bool
	}{
		{"начало", strings.ToLower(m) + " tail", 1, true},
		{"конец", "head " + strings.ToLower(m), 1, true},
		{"вся строка", m, 1, true},
		{"верхний регистр", "x " + strings.ToUpper(m) + " x", 1, true},
		{"смешанный регистр", "x cAnArY-sEcReT-0001 x", 1, true},
		{"нет", "canary-secret-0002", 0, false},
		{"префикс маркера", "canary-secret-000", 0, false},
		{"первый маркер", "xx FIRST-MARKER-0000", 0, true},
		{"последний маркер", "xx tail-marker-9999", 2, true},
		{"кириллица рядом", "Секрет: " + m + " — конец", 1, true},
		{"пустое тело", "", 0, false},
		{"разорванный", "canary-secret-" + "\n" + "0001", 0, false},
		{"юникод-подобие (K-Kelvin)", "Kanary-secret-0001", 0, false},
	}
	for _, tc := range cases {
		idx, ok := c.Find([]byte(tc.body))
		if ok != tc.ok || (ok && idx != tc.idx) {
			t.Errorf("%s: idx=%d ok=%v, ожидается %d %v", tc.name, idx, ok, tc.idx, tc.ok)
		}
	}
	if _, ok := c.Find(nil); ok {
		t.Error("nil тело")
	}
	// Тело не изменяется.
	body := []byte("PREFIX " + m)
	cp := string(body)
	c.Find(body)
	if string(body) != cp {
		t.Error("Find изменил тело")
	}
}

func TestCanaryNilSafe(t *testing.T) {
	var c *CanarySet
	if c.Len() != 0 {
		t.Error("Len")
	}
	if i, ok := c.Find([]byte(canaryM1)); ok || i != 0 {
		t.Error("Find на nil нашёл")
	}
	if _, ok := (&CanarySet{}).Find([]byte(canaryM1)); ok {
		t.Error("zero-value нашёл")
	}
}

// Маркер из допустимого набора лежит в теле запроса теми же байтами, что в тексте фрагмента:
// кириллица и перевод строки вокруг него экранируются/кодируются, а сам маркер — нет.
func TestCanaryFindInBodyBytes(t *testing.T) {
	m := "Canary-Secret-0001"
	c := mustCanary(t, m)
	text := "Ошибка: пользователь\n" + m + "\nтаб\t«кавычки» \"q\" \\ ✓"
	for name, body := range map[string][]byte{
		"BodyBytes":         openrouter.BodyBytes(pyjson.NewString(text)),
		"Marshal canonical": pyjson.Marshal(pyjson.NewString(text), pyjson.Canonical),
	} {
		if _, ok := c.Find(body); !ok {
			t.Errorf("%s: маркер не найден в %q", name, body)
		}
	}
	// В ключе объекта.
	obj := pyjson.NewObject()
	obj.Set(m, pyjson.NewString("значение"))
	if _, ok := c.Find(openrouter.BodyBytes(obj)); !ok {
		t.Error("маркер в ключе не найден")
	}
}

func naiveFind(markers []string, body []byte) (int, bool) {
	fold := func(b byte) byte {
		if 'A' <= b && b <= 'Z' {
			return b + 32
		}
		return b
	}
	for mi, m := range markers {
		for i := 0; i+len(m) <= len(body); i++ {
			match := true
			for j := 0; j < len(m); j++ {
				if fold(body[i+j]) != fold(m[j]) {
					match = false
					break
				}
			}
			if match {
				return mi, true
			}
		}
	}
	return 0, false
}

func FuzzCanaryFind(f *testing.F) {
	markers := []string{"Canary-Secret-0001", "user@example.org", "AAAAAAAAAAAA", "tok.en_+-valu3"}
	c := mustCanary(f, markers...)
	for _, s := range []string{"", "x", "canary-secret-0001", "pre CANARY-SECRET-0001 post", "USER@EXAMPLE.ORG",
		"aaaaaaaaaaa", "AAAAAAAAAAAAA", "tok.en_+-valu", "Kanary", "Секрет canary-secret-0001\n", "\x00\xff\xfe"} {
		f.Add([]byte(s), uint8(0))
	}
	f.Fuzz(func(t *testing.T, body []byte, pick uint8) {
		// Часть входов: тело с вклеенным маркером в случайном регистре.
		if pick%3 == 1 {
			m := markers[int(pick)%len(markers)]
			var mixed strings.Builder
			for i := 0; i < len(m); i++ {
				ch := m[i]
				if (int(pick)+i)%2 == 0 && 'a' <= ch && ch <= 'z' {
					ch -= 32
				}
				mixed.WriteByte(ch)
			}
			cut := int(pick) % (len(body) + 1)
			body = append(append(append([]byte(nil), body[:cut]...), mixed.String()...), body[cut:]...)
		}
		orig := append([]byte(nil), body...)
		gi, gok := c.Find(body)
		wi, wok := naiveFind(markers, body)
		// Порядок маркеров: Find возвращает первый маркер набора, naive — тоже первый по маркерам.
		if gok != wok || (gok && gi != wi) {
			t.Fatalf("Find=(%d,%v) naive=(%d,%v) body=%q", gi, gok, wi, wok, body)
		}
		if string(body) != string(orig) {
			t.Fatal("тело изменено")
		}
	})
}
