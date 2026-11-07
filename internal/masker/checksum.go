package masker

import "strings"

// digitsOnly оставляет в строке только ASCII-цифры.
func digitsOnly(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// luhnValid — проверка Луна для строки из цифр (длина ≥ 2).
func luhnValid(d string) bool {
	if len(d) < 2 || !allDigits(d) {
		return false
	}
	sum, alt := 0, false
	for i := len(d) - 1; i >= 0; i-- {
		n := int(d[i] - '0')
		if alt {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}
	return sum%10 == 0
}

// snilsValid — контрольная сумма СНИЛС (11 цифр). Номера ≤ 001-001-998 по методике ПФР сумму не проверяют, но считаются СНИЛС.
func snilsValid(d string) bool {
	if len(d) != 11 || !allDigits(d) {
		return false
	}
	if d[:9] <= "001001998" {
		return true
	}
	sum := 0
	for i := 0; i < 9; i++ {
		sum += int(d[i]-'0') * (9 - i)
	}
	if sum > 101 {
		sum %= 101
	}
	if sum >= 100 {
		sum = 0
	}
	return sum == int(d[9]-'0')*10+int(d[10]-'0')
}

var (
	inn10 = []int{2, 4, 10, 3, 5, 9, 4, 6, 8}
	inn11 = []int{7, 2, 4, 10, 3, 5, 9, 4, 6, 8}
	inn12 = []int{3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8}
)

func innDigit(d string, w []int) int {
	sum := 0
	for i, k := range w {
		sum += int(d[i]-'0') * k
	}
	return sum % 11 % 10
}

// innValid — контрольные суммы ИНН юрлица (10 цифр) и физлица (12 цифр).
func innValid(d string) bool {
	if !allDigits(d) {
		return false
	}
	switch len(d) {
	case 10:
		return innDigit(d, inn10) == int(d[9]-'0')
	case 12:
		return innDigit(d, inn11) == int(d[10]-'0') && innDigit(d, inn12) == int(d[11]-'0')
	}
	return false
}

// ibanValid — IBAN (пробелы допускаются): длина 15–34, страна, mod-97 == 1.
func ibanValid(s string) bool {
	s = strings.ReplaceAll(s, " ", "")
	if len(s) < 15 || len(s) > 34 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case i < 2 && (c < 'A' || c > 'Z'):
			return false
		case i >= 2 && i < 4 && (c < '0' || c > '9'):
			return false
		case !(c >= '0' && c <= '9' || c >= 'A' && c <= 'Z'):
			return false
		}
	}
	r := s[4:] + s[:4]
	rem := 0
	for i := 0; i < len(r); i++ {
		c := r[i]
		if c >= 'A' {
			rem = (rem*100 + int(c-'A') + 10) % 97
		} else {
			rem = (rem*10 + int(c-'0')) % 97
		}
	}
	return rem == 1
}
