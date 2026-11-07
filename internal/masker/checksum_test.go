package masker

import "testing"

func TestLuhnValid(t *testing.T) {
	for i := 0; i < 50; i++ {
		v := card(t, byte('2'+i%5), 13+i%7)
		if !luhnValid(v) {
			t.Errorf("сгенерированный номер %q (len %d) не прошёл Luhn", v, len(v))
		}
		if bad := mutateDigit(v, len(v)-1); luhnValid(bad) {
			t.Errorf("номер с испорченной контрольной цифрой прошёл Luhn: %q", bad)
		}
	}
	for _, c := range []struct{ in, name string }{{"", "пусто"}, {"7", "одна цифра"}, {"12a4", "не цифры"}, {"12 34", "пробел"}} {
		if luhnValid(c.in) {
			t.Errorf("%s: %q прошёл Luhn", c.name, c.in)
		}
	}
}

func TestSnilsValid(t *testing.T) {
	for i := 0; i < 50; i++ {
		v := snils(t)
		if !snilsValid(v) {
			t.Fatalf("сгенерированный СНИЛС %q невалиден", v)
		}
		// одна изменённая цифра контрольной суммы (последняя) всегда ломает проверку
		if bad := mutateDigit(v, 10); snilsValid(bad) {
			t.Errorf("СНИЛС с испорченной суммой валиден: %q", bad)
		}
		if snilsValid(v[:10]) || snilsValid(v+"0") {
			t.Errorf("СНИЛС неверной длины валиден: %q", v)
		}
	}
	// малые номера по методике не проверяются
	if !snilsValid("00100199800") || !snilsValid("00000000099") {
		t.Error("номер не выше 001001998 должен считаться СНИЛС независимо от суммы")
	}
	if snilsValid("12345678a01") {
		t.Error("нецифровой СНИЛС валиден")
	}
}

func TestInnValid(t *testing.T) {
	for i := 0; i < 50; i++ {
		v10, v12 := inn10Gen(t), inn12Gen(t)
		if !innValid(v10) {
			t.Fatalf("ИНН-10 %q невалиден", v10)
		}
		if !innValid(v12) {
			t.Fatalf("ИНН-12 %q невалиден", v12)
		}
		if innValid(mutateDigit(v10, 9)) {
			t.Errorf("ИНН-10 с испорченной суммой валиден: %q", v10)
		}
		if innValid(mutateDigit(v12, 10)) || innValid(mutateDigit(v12, 11)) {
			t.Errorf("ИНН-12 с испорченной суммой валиден: %q", v12)
		}
		if innValid(v10[:9]) || innValid(v12[:11]) || innValid(v12+"0") {
			t.Errorf("ИНН неверной длины валиден")
		}
	}
	if innValid("") || innValid("12345abcde") {
		t.Error("пустой или нецифровой ИНН валиден")
	}
}

func TestIbanValid(t *testing.T) {
	for _, c := range []struct{ cc, bban string }{
		{"DE", "5" + "00000000" + "0000000001"[:9]},
		{"GB", "WEST" + "12345698765432"},
		{"FR", "3000" + "6000" + "0112" + "3456" + "789"},
	} {
		v := ibanGen(c.cc, c.bban)
		if !ibanValid(v) {
			t.Errorf("IBAN %q невалиден", v)
		}
		if !ibanValid(groups4(v, " ")) {
			t.Errorf("IBAN с пробелами невалиден: %q", groups4(v, " "))
		}
		if ibanValid(mutateDigit(v, len(v)-1)) {
			t.Errorf("IBAN с испорченной цифрой валиден: %q", v)
		}
		if ibanValid(v[:12]) {
			t.Errorf("слишком короткий IBAN валиден: %q", v[:12])
		}
		if ibanValid(v + "0000000000000000000000") {
			t.Errorf("слишком длинный IBAN валиден")
		}
		if ibanValid(lowerStr(v)) {
			t.Errorf("IBAN в нижнем регистре валиден: %q", lowerStr(v))
		}
	}
	if ibanValid("") || ibanValid("1234567890123456") {
		t.Error("мусор прошёл как IBAN")
	}
}

func lowerStr(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

func TestDigitsOnly(t *testing.T) {
	if got := digitsOnly("+7 (916) 123-45-67 абв"); got != "79161234567" {
		t.Errorf("digitsOnly = %q", got)
	}
}
