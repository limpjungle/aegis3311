package masker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/netip"
	"strings"
	"testing"

	"github.com/limpjungle/aegis3311/internal/dataclass"
	"github.com/limpjungle/aegis3311/internal/pyjson"
)

// Все секреты, ключи и «валидные» номера в тестах строятся в рантайме: в исходниках нет токеноподобных литералов.

const alnumSet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func randInt(t testing.TB, n int) int {
	t.Helper()
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		t.Fatal(err)
	}
	return int(v.Int64())
}

func randFrom(t testing.TB, set string, n int) string {
	t.Helper()
	b := make([]byte, n)
	for i := range b {
		b[i] = set[randInt(t, len(set))]
	}
	return string(b)
}

func alnum(t testing.TB, n int) string  { return randFrom(t, alnumSet, n) }
func digits(t testing.TB, n int) string { return randFrom(t, "0123456789", n) }
func lowerHex(t testing.TB, n int) string {
	t.Helper()
	return randFrom(t, "0123456789abcdef", n)
}

// testKey — мастер-ключ псевдонимов (32 случайных байта).
func testKey(t testing.TB) []byte {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func newMasker(t testing.TB) *Masker {
	t.Helper()
	m, err := New(Config{PseudonymKey: testKey(t)})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func newMaskerKey(t testing.TB, key []byte) *Masker {
	t.Helper()
	m, err := New(Config{PseudonymKey: key})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func meta(inc string) dataclass.FragmentMeta {
	return dataclass.FragmentMeta{IncidentID: inc, FragmentID: "f1", Source: "alerts.alertmanager", Class: dataclass.Internal}
}

func pj(t testing.TB, js string) *pyjson.Value {
	t.Helper()
	v, err := pyjson.Parse([]byte(js))
	if err != nil {
		t.Fatalf("pyjson.Parse(%q): %v", js, err)
	}
	return v
}

func canon(v *pyjson.Value) string { return string(pyjson.Marshal(v, pyjson.Canonical)) }

// maskJSON — Mask над JSON-текстом; возвращает канонический JSON результата и отчёт.
func maskJSON(t testing.TB, m *Masker, js string) (string, dataclass.MaskReport) {
	t.Helper()
	out, rep, err := m.Mask(context.Background(), meta("inc-1"), pj(t, js))
	if err != nil {
		t.Fatalf("Mask(%.80q): %v", js, err)
	}
	return canon(out), rep
}

// maskStr — Mask над одной строкой; возвращает результирующую строку и отчёт.
func maskStr(t testing.TB, m *Masker, s string) (string, dataclass.MaskReport) {
	t.Helper()
	out, rep, err := m.Mask(context.Background(), meta("inc-1"), pyjson.NewString(s))
	if err != nil {
		t.Fatalf("Mask(%.80q): %v", s, err)
	}
	if out.Kind != pyjson.String {
		t.Fatalf("Mask строки вернул вид %d", out.Kind)
	}
	return out.S, rep
}

func count(rep dataclass.MaskReport, c dataclass.Category) int {
	n := 0
	for _, f := range rep.Findings {
		if f.Category == c {
			n += f.Count
		}
	}
	return n
}

// jstr — JSON-строка.
func jstr(s string) string { return string(pyjson.Marshal(pyjson.NewString(s), pyjson.Canonical)) }

// --- генераторы валидных номеров ---

// withLuhn дописывает контрольную цифру Луна к строке цифр.
func withLuhn(prefix string) string {
	for d := byte('0'); d <= '9'; d++ {
		if luhnValid(prefix + string(d)) {
			return prefix + string(d)
		}
	}
	panic("не найдена контрольная цифра Луна")
}

// card — номер карты из n цифр с Luhn, первая цифра first.
func card(t testing.TB, first byte, n int) string {
	return withLuhn(string(first) + digits(t, n-2))
}

// snils — 11 цифр СНИЛС с верной контрольной суммой (номер заведомо выше 001-001-998).
func snils(t testing.TB) string {
	t.Helper()
	for {
		base := string(byte('1'+randInt(t, 9))) + digits(t, 8)
		sum := 0
		for i := 0; i < 9; i++ {
			sum += int(base[i]-'0') * (9 - i)
		}
		if sum > 101 {
			sum %= 101
		}
		if sum >= 100 {
			sum = 0
		}
		return base + fmt.Sprintf("%02d", sum)
	}
}

func innCheck(d string, w []int) byte { return byte('0' + innDigit(d, w)) }

func inn10Gen(t testing.TB) string {
	b := string(byte('1'+randInt(t, 9))) + digits(t, 8)
	return b + string(innCheck(b, inn10))
}

func inn12Gen(t testing.TB) string {
	b := string(byte('1'+randInt(t, 9))) + digits(t, 9)
	b += string(innCheck(b, inn11))
	return b + string(innCheck(b, inn12))
}

// ibanGen — IBAN с верными контрольными цифрами: страна + 2 цифры + bban.
func ibanGen(country, bban string) string {
	rem := 0
	r := bban + country + "00"
	for i := 0; i < len(r); i++ {
		c := r[i]
		if c >= 'A' {
			rem = (rem*100 + int(c-'A') + 10) % 97
		} else {
			rem = (rem*10 + int(c-'0')) % 97
		}
	}
	return fmt.Sprintf("%s%02d%s", country, 98-rem, bban)
}

// groups4 разбивает строку на группы по 4 через sep.
func groups4(s, sep string) string {
	var parts []string
	for len(s) > 4 {
		parts = append(parts, s[:4])
		s = s[4:]
	}
	parts = append(parts, s)
	return strings.Join(parts, sep)
}

// mutateDigit меняет цифру на позиции i (в строке цифр) так, чтобы проверка, как правило, сломалась.
func mutateDigit(s string, i int) string {
	b := []byte(s)
	if b[i] == '9' {
		b[i] = '0'
	} else {
		b[i]++
	}
	return string(b)
}

func publicIPv4(t testing.TB) string {
	first := []string{"5", "8", "45", "185", "93", "151"}[randInt(t, 6)]
	return fmt.Sprintf("%s.%d.%d.%d", first, randInt(t, 254)+1, randInt(t, 254)+1, randInt(t, 254)+1)
}

// ctxOK — контекст без дедлайна.
var ctxOK = context.Background()

var _ = hex.EncodeToString

type netipPrefix = netip.Prefix

func mustPrefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }
