package masker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/limpjungle/aegis3311/internal/dataclass"
	"github.com/limpjungle/aegis3311/internal/pyjson"
)

const secRepl = "<SECRET_REMOVED>"

// escalates проверяет влияние отчёта на класс: секрет класс не меняет, ПДн → restricted/personal_data.
func checkEscalate(t *testing.T, rep dataclass.MaskReport, wantPersonal bool) {
	t.Helper()
	cls, reason := dataclass.Escalate(dataclass.Internal, rep)
	if wantPersonal {
		if cls != dataclass.Restricted || reason != "personal_data" {
			t.Errorf("Escalate = %s/%q, ожидается restricted/personal_data (отчёт %+v)", cls, reason, rep)
		}
		return
	}
	if cls != dataclass.Internal || reason != "" {
		t.Errorf("Escalate = %s/%q, ожидается internal без причины (отчёт %+v)", cls, reason, rep)
	}
}

// --- секреты (строки) ---

type secretCase struct {
	name string
	gen  func(t testing.TB) (in, want string, markers []string, n int)
}

// around строит «до секрет после» → «до заглушка после».
func around(pre, secret, post string) (string, string, []string, int) {
	return pre + secret + post, pre + secRepl + post, []string{secret}, 1
}

func secretCases() []secretCase {
	return []secretCase{
		{"aws AKIA", func(t testing.TB) (string, string, []string, int) {
			return around("key ", "AKIA"+randFrom(t, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16), " end")
		}},
		{"aws ASIA", func(t testing.TB) (string, string, []string, int) {
			return around("key ", "ASIA"+randFrom(t, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16), " end")
		}},
		{"github ghp", func(t testing.TB) (string, string, []string, int) {
			return around("clone with ", "ghp_"+alnum(t, 36), " done")
		}},
		{"github gho", func(t testing.TB) (string, string, []string, int) {
			return around("clone with ", "gho_"+alnum(t, 40), " done")
		}},
		{"github pat", func(t testing.TB) (string, string, []string, int) {
			return around("used ", "github_pat_"+alnum(t, 40), " ok")
		}},
		{"gitlab", func(t testing.TB) (string, string, []string, int) {
			return around("used ", "glpat-"+alnum(t, 24), " ok")
		}},
		{"slack bot", func(t testing.TB) (string, string, []string, int) {
			return around("posted ", "xoxb-"+digits(t, 11)+"-"+alnum(t, 24), " ok")
		}},
		{"slack webhook", func(t testing.TB) (string, string, []string, int) {
			return around("see https://", "hooks.slack.com/services/T"+alnum(t, 8)+"/B"+alnum(t, 8)+"/"+alnum(t, 24), " now")
		}},
		{"openrouter", func(t testing.TB) (string, string, []string, int) {
			return around("with ", "sk-or-v1-"+lowerHex(t, 64), " here")
		}},
		{"anthropic", func(t testing.TB) (string, string, []string, int) {
			return around("with ", "sk-ant-api03-"+alnum(t, 40), " here")
		}},
		{"openai proj", func(t testing.TB) (string, string, []string, int) {
			return around("with ", "sk-proj-"+alnum(t, 40), " here")
		}},
		{"openai", func(t testing.TB) (string, string, []string, int) {
			return around("with ", "sk-"+alnum(t, 40), " here")
		}},
		{"google", func(t testing.TB) (string, string, []string, int) {
			return around("with ", "AIza"+alnum(t, 35), " here")
		}},
		{"stripe live", func(t testing.TB) (string, string, []string, int) {
			return around("with ", "sk_live_"+alnum(t, 24), " here")
		}},
		{"stripe rk test", func(t testing.TB) (string, string, []string, int) {
			return around("with ", "rk_test_"+alnum(t, 24), " here")
		}},
		{"vault hvs", func(t testing.TB) (string, string, []string, int) {
			return around("with ", "hvs."+alnum(t, 26), " here")
		}},
		{"yandex y0_", func(t testing.TB) (string, string, []string, int) {
			return around("with ", "y0_"+alnum(t, 30), " here")
		}},
		{"yandex t1.", func(t testing.TB) (string, string, []string, int) {
			return around("with ", "t1."+alnum(t, 30), " here")
		}},
		{"yandex AQVN", func(t testing.TB) (string, string, []string, int) {
			return around("with ", "AQVN"+alnum(t, 40), " here")
		}},
		{"telegram", func(t testing.TB) (string, string, []string, int) {
			return around("bot ", digits(t, 9)+":"+alnum(t, 35), " here")
		}},
		{"jwt", func(t testing.TB) (string, string, []string, int) {
			return around("with ", "eyJ"+alnum(t, 14)+".eyJ"+alnum(t, 14)+"."+alnum(t, 20), " here")
		}},
		{"pem", func(t testing.TB) (string, string, []string, int) {
			body := alnum(t, 64) + "\n" + alnum(t, 64) + "\n" + alnum(t, 20)
			return around("dump ", "-----BEGIN RSA PRIVATE KEY-----\n"+body+"\n-----END RSA PRIVATE KEY-----", " tail")
		}},
		{"authorization bearer", func(t testing.TB) (string, string, []string, int) {
			tok := alnum(t, 30) + digits(t, 4)
			return "GET / HTTP/1.1\nAuthorization: Bearer " + tok + "\nHost: svc.internal",
				"GET / HTTP/1.1\nAuthorization: " + secRepl + "\nHost: svc.internal", []string{tok}, 1
		}},
		{"proxy-authorization basic", func(t testing.TB) (string, string, []string, int) {
			tok := alnum(t, 24) + digits(t, 4)
			return "Proxy-Authorization: Basic " + tok + "\nX: y", "Proxy-Authorization: " + secRepl + "\nX: y", []string{tok}, 1
		}},
		{"bearer в тексте", func(t testing.TB) (string, string, []string, int) {
			tok := alnum(t, 30) + digits(t, 4)
			return around("got Bearer ", tok, " from gateway")
		}},
		{"basic в тексте", func(t testing.TB) (string, string, []string, int) {
			tok := alnum(t, 22) + digits(t, 4)
			return around("sent Basic ", tok, " to gateway")
		}},
		{"cookie", func(t testing.TB) (string, string, []string, int) {
			v := "sid=" + lowerHex(t, 24) + "; theme=dark"
			return "Cookie: " + v + "\nA: b", "Cookie: " + secRepl + "\nA: b", []string{v[4:28]}, 1
		}},
		{"set-cookie", func(t testing.TB) (string, string, []string, int) {
			v := "sid=" + lowerHex(t, 24) + "; Path=/"
			return "Set-Cookie: " + v + "\nA: b", "Set-Cookie: " + secRepl + "\nA: b", []string{v[4:28]}, 1
		}},
		{"url user:pass@", func(t testing.TB) (string, string, []string, int) {
			u, p := "u"+lowerHex(t, 6), alnum(t, 16)
			return "dial postgres://" + u + ":" + p + "@db.internal:5432/app ok",
				"dial postgres://" + secRepl + "@db.internal:5432/app ok", []string{p, u + ":" + p}, 1
		}},
		{"query token и sig", func(t testing.TB) (string, string, []string, int) {
			tok, sig := alnum(t, 20), alnum(t, 20)
			return "GET https://api.example.org/v1?token=" + tok + "&sig=" + sig + "&x=1",
				"GET https://api.example.org/v1?token=" + secRepl + "&sig=" + secRepl + "&x=1", []string{tok, sig}, 2
		}},
		{"присваивание password=", func(t testing.TB) (string, string, []string, int) {
			return around("login failed, password=", alnum(t, 14), " retry")
		}},
		{"присваивание json-стиля", func(t testing.TB) (string, string, []string, int) {
			v := alnum(t, 18)
			return `cfg {"api_key": "` + v + `"} end`, `cfg {"api_key": "` + secRepl + `"} end`, []string{v}, 1
		}},
		{"присваивание client_secret:", func(t testing.TB) (string, string, []string, int) {
			return around("client_secret: ", alnum(t, 20), " ok")
		}},
		{"энтропийный токен", func(t testing.TB) (string, string, []string, int) {
			var tok string
			for {
				tok = alnum(t, 44)
				if strings.IndexFunc(tok, func(r rune) bool { return r >= 'A' && r <= 'Z' }) >= 0 &&
					strings.IndexFunc(tok, func(r rune) bool { return r >= 'a' && r <= 'z' }) >= 0 &&
					strings.IndexFunc(tok, func(r rune) bool { return r >= '0' && r <= '9' }) >= 0 {
					break
				}
			}
			return around("value ", tok, " end")
		}},
	}
}

func TestMaskDetectSecrets(t *testing.T) {
	m := newMasker(t)
	for _, c := range secretCases() {
		t.Run(c.name, func(t *testing.T) {
			in, want, markers, n := c.gen(t)
			out, rep := maskStr(t, m, in)
			if out != want {
				t.Errorf("выход %q, ожидается %q", out, want)
			}
			for _, mk := range markers {
				if mk != "" && strings.Contains(out, mk) {
					t.Errorf("секрет остался в выходе: %q", mk)
				}
			}
			if got := count(rep, dataclass.CategorySecret); got != n {
				t.Errorf("Count(secret) = %d, ожидается %d", got, n)
			}
			if len(rep.Findings) != 1 || rep.Findings[0].Category != dataclass.CategorySecret {
				t.Errorf("Findings = %+v, ожидается только secret", rep.Findings)
			}
			if rep.Removed != n || rep.Failed {
				t.Errorf("Removed=%d Failed=%v, ожидается %d/false", rep.Removed, rep.Failed, n)
			}
			checkEscalate(t, rep, false)
		})
	}
}

// --- секреты по имени поля и структуре ---

func TestMaskDetectSecretFields(t *testing.T) {
	m := newMasker(t)
	v := func() string { return alnum(t, 14) }
	type tc struct {
		name, in, want string
		n              int
		leaked         []string
	}
	var cases []tc
	add := func(name string, mk func(a, b string) (in, want string), n int) {
		a, b := v(), v()
		in, want := mk(a, b)
		cases = append(cases, tc{name, in, want, n, []string{a, b}})
	}
	add("db_password", func(a, _ string) (string, string) {
		return `{"db_password":` + jstr(a) + `}`, `{"db_password":` + jstr(secRepl) + `}`
	}, 1)
	add("X-Api-Key", func(a, _ string) (string, string) {
		return `{"headers":{"Accept":"json","X-Api-Key":` + jstr(a) + `}}`, `{"headers":{"Accept":"json","X-Api-Key":` + jstr(secRepl) + `}}`
	}, 1)
	add("clientSecret camelCase", func(a, _ string) (string, string) {
		return `{"clientSecret":` + jstr(a) + `}`, `{"clientSecret":` + jstr(secRepl) + `}`
	}, 1)
	add("суффикс token", func(a, _ string) (string, string) {
		return `{"github_token":` + jstr(a) + `}`, `{"github_token":` + jstr(secRepl) + `}`
	}, 1)
	add("k8s Secret.data", func(a, b string) (string, string) {
		return `{"kind":"Secret","metadata":{"name":"s1"},"data":{"a":` + jstr(a) + `,"b":` + jstr(b) + `}}`,
			`{"data":{"a":` + jstr(secRepl) + `,"b":` + jstr(secRepl) + `},"kind":"Secret","metadata":{"name":"s1"}}`
	}, 2)
	add("k8s Secret.stringData", func(a, _ string) (string, string) {
		return `{"kind":"Secret","stringData":{"cfg":` + jstr(a) + `}}`, `{"kind":"Secret","stringData":{"cfg":` + jstr(secRepl) + `}}`
	}, 1)
	add("env name/value", func(a, _ string) (string, string) {
		return `{"env":[{"name":"DB_PASSWORD","value":` + jstr(a) + `},{"name":"LOG_LEVEL","value":"debug"}]}`,
			`{"env":[{"name":"DB_PASSWORD","value":` + jstr(secRepl) + `},{"name":"LOG_LEVEL","value":"debug"}]}`
	}, 1)
	add("объект под секретным ключом", func(a, b string) (string, string) {
		return `{"credentials":{"n":5,"user":` + jstr(a) + `,"list":[` + jstr(b) + `]}}`,
			`{"credentials":{"list":[` + jstr(secRepl) + `],"n":5,"user":` + jstr(secRepl) + `}}`
	}, 2)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, rep := maskJSON(t, m, c.in)
			if out != c.want {
				t.Errorf("выход %s, ожидается %s", out, c.want)
			}
			for _, l := range c.leaked {
				if strings.Contains(out, l) {
					t.Errorf("секрет %q остался в выходе", l)
				}
			}
			if got := count(rep, dataclass.CategorySecret); got != c.n || rep.Removed != c.n || len(rep.Findings) != 1 {
				t.Errorf("отчёт %+v, ожидается secret=%d", rep, c.n)
			}
			checkEscalate(t, rep, false)
		})
	}
}

// Число, bool, null, пустая строка, плейсхолдеры и собственная заглушка под секретным ключом — не находки.
func TestMaskSecretKeyNonSecretValues(t *testing.T) {
	m := newMasker(t)
	in := `{"api_key":"<SECRET_REMOVED>","pass":"${DB_PASS}","password":null,"pwd":"","secret":true,"token":123,"tpl":"{{ .Values.x }}","x":"*****"}`
	// ключи tpl/x обычные; остальные секретные
	out, rep := maskJSON(t, m, in)
	if out != in || len(rep.Findings) != 0 || rep.Removed != 0 {
		t.Errorf("выход %s, отчёт %+v: ожидается без изменений", out, rep)
	}
}

// --- ПДн ---

type pdCase struct {
	name, pre, val, post string
	kind                 string // PERSON, DOC, IP или CARD
	leak                 []string
}

func personalCases(t testing.TB) []pdCase {
	var cs []pdCase
	add := func(name, pre, val, post, kind string, leak ...string) {
		if leak == nil {
			leak = []string{val}
		}
		cs = append(cs, pdCase{name, pre, val, post, kind, leak})
	}
	em := "u" + lowerHex(t, 8) + "@example.org"
	add("email", "contact ", em, " today", "PERSON")
	add("email в верхнем регистре", "contact ", strings.ToUpper(em), " today", "PERSON", em, strings.ToUpper(em))
	ph := "9" + digits(t, 9)
	g := func(sep1, sep2 string) string { return ph[:3] + sep1 + ph[3:6] + sep2 + ph[6:8] + sep2 + ph[8:] }
	add("телефон +7 (xxx) xxx-xx-xx", "звонил ", "+7 ("+ph[:3]+") "+ph[3:6]+"-"+ph[6:8]+"-"+ph[8:], " вчера", "PERSON", ph[3:6]+"-"+ph[6:8])
	add("телефон +7 слитно", "звонил ", "+7"+ph, " вчера", "PERSON")
	add("телефон 8 слитно", "звонил ", "8"+ph, " вчера", "PERSON")
	add("телефон 8 с пробелами", "звонил ", "8 "+g(" ", " "), " вчера", "PERSON")
	add("телефон +7 с дефисами", "звонил ", "+7-"+g("-", "-"), " вчера", "PERSON")
	add("телефон международный", "call ", "+49 "+digits(t, 3)+" "+digits(t, 7), " now", "PERSON")
	add("карта слитно 16", "card ", card(t, '4', 16), " paid", "CARD")
	c16 := card(t, '5', 16)
	add("карта пробелы", "card ", groups4(c16, " "), " paid", "CARD", c16, groups4(c16, " "))
	c16b := card(t, '2', 16)
	add("карта дефисы", "card ", groups4(c16b, "-"), " paid", "CARD", c16b, groups4(c16b, "-"))
	c15 := card(t, '3', 15)
	add("карта 4-6-5", "card ", c15[:4]+" "+c15[4:10]+" "+c15[10:], " paid", "CARD", c15, c15[4:10])
	add("карта 19", "card ", card(t, '6', 19), " paid", "CARD")
	add("карта 13", "card ", card(t, '4', 13), " paid", "CARD")
	s := snils(t)
	add("СНИЛС с разделителями без контекста", "поле ", s[:3]+"-"+s[3:6]+"-"+s[6:9]+" "+s[9:], " в анкете", "DOC", s[:3]+"-"+s[3:6])
	add("СНИЛС голый с контекстом", "СНИЛС: ", s, " в анкете", "DOC")
	add("snils latin ctx", "snils=", s, " in form", "DOC")
	add("ИНН-10 с контекстом", "ИНН ", inn10Gen(t), " организации", "DOC")
	add("ИНН-12 с контекстом", "ИНН: ", inn12Gen(t), " физлица", "DOC")
	add("inn latin ctx", "inn=", inn12Gen(t), " x", "DOC")
	add("паспорт РФ", "паспорт: ", digits(t, 2)+" "+digits(t, 2)+" "+digits(t, 6), " выдан", "DOC")
	add("passport слитно", "passport ", digits(t, 10), " issued", "DOC")
	ib := ibanGen("DE", digits(t, 18))
	add("IBAN слитно", "счёт ", ib, " закрыт", "DOC")
	add("IBAN группами", "счёт ", groups4(ib, " "), " закрыт", "DOC", ib, groups4(ib, " "))
	ip4 := publicIPv4(t)
	add("IPv4 публичный", "from ", ip4, " port", "IP")
	ip6 := fmt.Sprintf("2a02:%s:%s::%s", lowerHex(t, 4), lowerHex(t, 4), lowerHex(t, 3))
	add("IPv6 публичный", "from ", ip6, " port", "IP")
	for _, f := range []struct{ name, v string }{
		{"ФИО полное", "Иванов Иван Иванович"},
		{"ФИО женское", "Петрова Анна Сергеевна"},
		{"ФИО имя+отчество", "Иван Иванович"},
		{"ФИО инициалы", "Иванов И. И."},
		{"ФИО инициалы слитно", "Иванов И.И."},
		{"ФИО двойная фамилия", "Иванов-Петров Иван Игоревич"},
	} {
		add(f.name, "заявитель ", f.v, " обратился", "PERSON")
	}
	return cs
}

func TestMaskDetectPersonal(t *testing.T) {
	m := newMasker(t)
	for _, c := range personalCases(t) {
		t.Run(c.name, func(t *testing.T) {
			out, rep := maskStr(t, m, c.pre+c.val+c.post)
			var re *regexp.Regexp
			if c.kind == "CARD" {
				re = regexp.MustCompile("^" + regexp.QuoteMeta(c.pre) + "<CARD>" + regexp.QuoteMeta(c.post) + "$")
			} else {
				re = regexp.MustCompile("^" + regexp.QuoteMeta(c.pre) + "<" + c.kind + "_[0-9a-f]{8}>" + regexp.QuoteMeta(c.post) + "$")
			}
			if !re.MatchString(out) {
				t.Errorf("выход %q не соответствует %s", out, re)
			}
			for _, l := range c.leak {
				if strings.Contains(out, l) {
					t.Errorf("ПДн %q осталось в выходе", l)
				}
			}
			if count(rep, dataclass.CategoryPersonal) != 1 || count(rep, dataclass.CategorySecret) != 0 || len(rep.Findings) != 1 || rep.Removed != 1 {
				t.Errorf("отчёт %+v, ожидается ровно одна находка personal_data", rep)
			}
			checkEscalate(t, rep, true)
		})
	}
}

// Правила по имени поля.
func TestMaskDetectFieldNames(t *testing.T) {
	m := newMasker(t)
	pseudo := regexp.MustCompile(`^<(PERSON|DOC)_[0-9a-f]{8}>$`)
	cases := []struct {
		name, in, key, kind, leak string
	}{
		{"phone строка", `{"phone":` + jstr("x"+digits(t, 7)) + `}`, "phone", "PERSON", ""},
		{"phone число", `{"phone":` + "9" + digits(t, 9) + `}`, "phone", "PERSON", ""},
		{"inn", `{"inn":` + jstr(digits(t, 10)) + `}`, "inn", "DOC", ""},
		{"email", `{"email":` + jstr("a"+lowerHex(t, 6)+"@example.org") + `}`, "email", "PERSON", ""},
		{"вложенный в массив", `{"rows":[{"Email":` + jstr("b"+lowerHex(t, 6)+"@example.org") + `}]}`, "", "PERSON", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, rep := maskJSON(t, m, c.in)
			if c.leak != "" && strings.Contains(out, c.leak) {
				t.Errorf("значение %q осталось в %s", c.leak, out)
			}
			v := pj(t, out)
			var val *pyjson.Value
			if c.key != "" {
				val = v.Get(c.key)
			} else {
				val = v.Get("rows").Items[0].Get("Email")
			}
			if val == nil || val.Kind != pyjson.String || !pseudo.MatchString(val.S) || !strings.HasPrefix(val.S, "<"+c.kind+"_") {
				t.Errorf("значение поля = %+v, ожидается псевдоним %s", val, c.kind)
			}
			if count(rep, dataclass.CategoryPersonal) != 1 || rep.Removed != 1 {
				t.Errorf("отчёт %+v", rep)
			}
			checkEscalate(t, rep, true)
		})
	}
	// плейсхолдер под ПДн-ключом не находка
	out, rep := maskJSON(t, m, `{"email":"${EMAIL}","phone":""}`)
	if out != `{"email":"${EMAIL}","phone":""}` || rep.Removed != 0 {
		t.Errorf("плейсхолдеры: %s %+v", out, rep)
	}
}

// Число из 13–19 цифр с Luhn и первой цифрой 2–6 → строка <CARD>; прочие числа не трогаются.
func TestMaskNumbers(t *testing.T) {
	m := newMasker(t)
	c := card(t, '4', 16)
	out, rep := maskJSON(t, m, `{"n":`+c+`}`)
	if out != `{"n":"<CARD>"}` || count(rep, dataclass.CategoryPersonal) != 1 {
		t.Errorf("карта-число: %s %+v", out, rep)
	}
	bad := mutateDigit(c, 15)
	in := `{"a":` + bad + `,"b":1.5,"c":true,"d":null,"e":4096,"f":1731000000,"g":-12,"h":1e3}`
	want := pj(t, in)
	out, rep = maskJSON(t, m, in)
	if out != canon(want) || rep.Removed != 0 || len(rep.Findings) != 0 {
		t.Errorf("числа: %s %+v", out, rep)
	}
}

// ПДн в ключе объекта → ключ заменён псевдонимом; секрет в ключе → ошибка; дубль после замены → ошибка.
func TestMaskObjectKeys(t *testing.T) {
	m := newMasker(t)
	em := "k" + lowerHex(t, 8) + "@example.org"
	out, rep := maskJSON(t, m, `{`+jstr(em)+`:1,"b":2}`)
	v := pj(t, out)
	if len(v.Members) != 2 || v.Get("b") == nil || strings.Contains(out, em) {
		t.Fatalf("ключ не заменён: %s", out)
	}
	if !regexp.MustCompile(`^<PERSON_[0-9a-f]{8}>$`).MatchString(v.Members[0].Key) && !regexp.MustCompile(`^<PERSON_[0-9a-f]{8}>$`).MatchString(v.Members[1].Key) {
		t.Errorf("ключи %v", v.Members)
	}
	if count(rep, dataclass.CategoryPersonal) != 1 {
		t.Errorf("отчёт %+v", rep)
	}

	// секрет в ключе
	_, _, err := m.Mask(ctxOK, meta("inc-1"), pj(t, `{`+jstr("ghp_"+alnum(t, 36))+`:1}`))
	if err == nil {
		t.Error("секрет в ключе объекта должен давать ошибку")
	}

	// два ключа с одним псевдонимом (регистр email нормализуется)
	_, _, err = m.Mask(ctxOK, meta("inc-1"), pj(t, `{`+jstr(em)+`:1,`+jstr(strings.ToUpper(em))+`:2}`))
	if err == nil {
		t.Error("дубль ключей после замены должен давать ошибку")
	}
}

// --- ложные срабатывания ---

func noFalsePositiveInputs(t testing.TB) []string {
	hex := func(n int) string { return lowerHex(t, n) }
	invalidCard := mutateDigit(card(t, '4', 16), 15)
	epoch := "1" + digits(t, 9)
	var in11 string
	for {
		in11 = snils(t)
		if in11[0] != '8' && in11[0] != '7' {
			break
		}
	}
	return []string{
		"svc-" + hex(9) + "-" + hex(5),
		"pod/geo-svc-" + hex(9) + "-" + hex(5),
		"sha256:" + hex(64),
		"sha256:" + hex(16),
		hex(40),
		hex(64),
		"ar-" + hex(8),
		hex(8) + "-" + hex(4) + "-" + hex(4) + "-" + hex(4) + "-" + hex(12),
		"v1.2.3.4",
		"released v2.10.3 yesterday",
		"10.1.2.3", "connect to 10.0.0.5:8080", "192.168.1.5", "172.20.1.1", "127.0.0.1", "::1", "fe80::1", "100.64.1.2",
		"12:30:45", "at 2026-11-07T12:30:45Z",
		"ts " + epoch,
		invalidCard,
		groups4(invalidCard, " "),
		"значение " + inn10Gen(t),
		"значение " + inn12Gen(t),
		"id " + in11,
		"max_tokens=4096", "new_pool_size=50", "prompt_tokens: 120", "tokens=123456",
		"git@github.com:org/repo", "git clone git@github.com:org/repo.git",
		"Иван", "Привет, Иван", "Иван Петров", "Иванов Иван",
		"Deployment rolled back after canary failed with error rate 5xx",
		"image registry.example.org/team/app:1.4.2",
		// CamelCase-идентификаторы с цифрами: энтропия ≥ 4.1, но это имена, а не ключи (правила 1.1.0).
		"ProductionDatabaseConnectionPoolExhausted2024Alert",
		"alert KubePodCrashLoopingWarning2024 fired",
		"HighRequestLatencyP99ThresholdExceeded5m",
		"PaymentGatewayTimeoutErrorRate5xxCritical",
		"HTTPServerRequestDurationSecondsBucket2",
		"OrderService-HighErrorRate-5xx-Critical2",
		"rule team/OrderService/HighErrorRate5xxCritical2",
	}
}

func TestMaskNoFalsePositives(t *testing.T) {
	m := newMasker(t)
	for _, s := range noFalsePositiveInputs(t) {
		for _, wrap := range []string{"%s", `{"k":%s}`, `["a",%s]`, `{"annotations":{"summary":%s}}`} {
			js := fmt.Sprintf(wrap, jstr(s))
			if wrap == "%s" {
				js = jstr(s)
			}
			in := pj(t, js)
			out, rep, err := m.Mask(ctxOK, meta("inc-1"), in)
			if err != nil {
				t.Fatalf("%q: %v", js, err)
			}
			if len(rep.Findings) != 0 || rep.Removed != 0 {
				t.Errorf("ложная находка в %q: %+v", js, rep)
			}
			if !bytes.Equal(pyjson.Marshal(out, pyjson.Canonical), pyjson.Marshal(in, pyjson.Canonical)) {
				t.Errorf("выход изменился: %s -> %s", js, canon(out))
			}
		}
	}
}

// --- корпус eval ---

func TestMaskEvalCorpusUntouched(t *testing.T) {
	m := newMasker(t)
	files, _ := filepath.Glob("../../eval/golden-synthetic/data/*-v[123].jsonl")
	if len(files) != 6 {
		t.Fatalf("найдено %d файлов корпуса, ожидается 6: %v", len(files), files)
	}
	total := 0
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, ln := range bytes.Split(raw, []byte("\n")) {
			if len(bytes.TrimSpace(ln)) == 0 {
				continue
			}
			c, err := pyjson.Parse(ln)
			if err != nil {
				t.Fatalf("%s:%d: %v", f, i+1, err)
			}
			in := c.Get("input")
			if in == nil {
				t.Fatalf("%s:%d: нет input", f, i+1)
			}
			check := func(what string, v *pyjson.Value) {
				before := canon(v)
				out, rep, err := m.Mask(ctxOK, meta("corpus"), v)
				if err != nil {
					t.Fatalf("%s:%d %s: %v", f, i+1, what, err)
				}
				if len(rep.Findings) != 0 || rep.Removed != 0 {
					t.Errorf("%s:%d %s: находки %+v", filepath.Base(f), i+1, what, rep)
				}
				if canon(out) != before {
					t.Errorf("%s:%d %s: выход отличается от входа", filepath.Base(f), i+1, what)
				}
			}
			check("input", in)
			for _, mem := range in.Members {
				check(mem.Key, mem.Value)
			}
			total++
		}
	}
	if total < 480 {
		t.Errorf("проверено кейсов %d, ожидается не меньше 480", total)
	}
}

// --- свойства ---

// mixedDoc — документ с секретами и ПДн; возвращает JSON и список исходных значений для проверки утечек.
func mixedDoc(t testing.TB) (string, []string) {
	gh := "ghp_" + alnum(t, 36)
	em := "p" + lowerHex(t, 8) + "@example.org"
	ph := "9" + digits(t, 9)
	cd := card(t, '4', 16)
	ip := publicIPv4(t)
	sid := "s" + lowerHex(t, 8)
	pw := alnum(t, 14)
	js := `{"summary":` + jstr("token leaked "+gh+" by "+em+" phone +7"+ph+" card "+cd+" from "+ip) +
		`,"session_id":` + jstr(sid) + `,"user_id":"u-1042","db_password":` + jstr(pw) + `,"fio":` + jstr("Сидоров Пётр Петрович") +
		`,"n":[1,2.5,true,null]}`
	return js, []string{gh, em, ph, cd, ip, sid, pw, "Сидоров"}
}

func TestMaskInputUnchanged(t *testing.T) {
	m := newMasker(t)
	js, _ := mixedDoc(t)
	v := pj(t, js)
	before := v.Clone()
	out, _, err := m.Mask(ctxOK, meta("inc-1"), v)
	if err != nil {
		t.Fatal(err)
	}
	if canon(v) != canon(before) || canon(v) != canon(pj(t, js)) {
		t.Error("Mask изменил входное значение")
	}
	if out == v {
		t.Error("Mask вернул тот же указатель")
	}
	// правка результата не должна влиять на вход
	out.Set("zzz", pyjson.NewString("x"))
	if v.Get("zzz") != nil {
		t.Error("результат разделяет память со входом")
	}
}

func TestMaskDeterministicAndNoLeak(t *testing.T) {
	m := newMasker(t)
	js, leaks := mixedDoc(t)
	o1, r1 := maskJSON(t, m, js)
	o2, r2 := maskJSON(t, m, js)
	if o1 != o2 || fmt.Sprint(r1) != fmt.Sprint(r2) {
		t.Error("Mask недетерминирован")
	}
	for _, l := range leaks {
		if strings.Contains(o1, l) {
			t.Errorf("в выходе остались исходные данные %q", l)
		}
	}
	if count(r1, dataclass.CategorySecret) < 3 || count(r1, dataclass.CategoryPersonal) < 5 { // session_id — секрет, user_id — не ПДн
		t.Errorf("отчёт неполон: %+v", r1)
	}
}

func TestMaskReportShape(t *testing.T) {
	m := newMasker(t)
	js, _ := mixedDoc(t)
	_, rep := maskJSON(t, m, js)
	if len(rep.Findings) != 2 || rep.Findings[0].Category != dataclass.CategorySecret || rep.Findings[1].Category != dataclass.CategoryPersonal {
		t.Fatalf("порядок или состав Findings: %+v", rep.Findings)
	}
	sum := 0
	for _, f := range rep.Findings {
		if f.Count <= 0 {
			t.Errorf("нулевой Count: %+v", f)
		}
		sum += f.Count
	}
	if rep.Removed != sum || rep.Failed {
		t.Errorf("Removed=%d, сумма Count=%d, Failed=%v", rep.Removed, sum, rep.Failed)
	}
	// без находок — пустой отчёт
	_, rep = maskJSON(t, m, `{"a":"plain"}`)
	if len(rep.Findings) != 0 || rep.Removed != 0 {
		t.Errorf("пустой отчёт: %+v", rep)
	}
}

func TestMaskPseudonymProperties(t *testing.T) {
	key := testKey(t)
	m := newMaskerKey(t, key)
	em := "a" + lowerHex(t, 8) + "@example.org"
	mask := func(m *Masker, inc, s string) string {
		out, _, err := m.Mask(ctxOK, meta(inc), pyjson.NewString(s))
		if err != nil {
			t.Fatal(err)
		}
		return out.S
	}
	a := mask(m, "inc-1", "mail "+em)
	if b := mask(m, "inc-1", "mail "+em); a != b {
		t.Error("один инцидент, один ключ: псевдонимы должны совпадать")
	}
	if b := mask(m, "inc-1", "mail "+strings.ToUpper(em)); a != b {
		t.Error("email в другом регистре даёт другой псевдоним")
	}
	if b := mask(m, "inc-2", "mail "+em); a == b {
		t.Error("другой IncidentID дал тот же псевдоним")
	}
	other := make([]byte, 32)
	copy(other, key)
	other[0] ^= 0xff
	if b := mask(newMaskerKey(t, other), "inc-1", "mail "+em); a == b {
		t.Error("другой ключ дал тот же псевдоним")
	}
	// разные значения — разные псевдонимы
	if b := mask(m, "inc-1", "mail x"+em); a == b {
		t.Error("разные адреса дали один псевдоним")
	}
	// один телефон в разных форматах
	d := "9" + digits(t, 9)
	p1 := mask(m, "inc-1", "+7 ("+d[:3]+") "+d[3:6]+"-"+d[6:8]+"-"+d[8:])
	p2 := mask(m, "inc-1", "8"+d)
	p3 := mask(m, "inc-1", "+7"+d)
	if p1 != p2 || p2 != p3 || !strings.HasPrefix(p1, "<PERSON_") {
		t.Errorf("форматы телефона: %q %q %q", p1, p2, p3)
	}
	// одно ФИО в разном регистре и ё/е
	f1 := mask(m, "inc-1", "Фёдоров Пётр Петрович")
	f2 := mask(m, "inc-1", "Федоров  Петр Петрович")
	if f1 != f2 {
		t.Errorf("нормализация ФИО: %q != %q", f1, f2)
	}
	// псевдоним в поле и в тексте — один и тот же вид, ключ поля и текст одного e-mail совпадают
	out, _, _ := m.Mask(ctxOK, meta("inc-1"), pj(t, `{"email":`+jstr(em)+`,"t":`+jstr(em)+`}`))
	if out.Get("email").S != out.Get("t").S {
		t.Errorf("поле и текст дали разные псевдонимы: %q %q", out.Get("email").S, out.Get("t").S)
	}
}

func TestMaskIdempotent(t *testing.T) {
	m := newMasker(t)
	js, _ := mixedDoc(t)
	o1, _, err := m.Mask(ctxOK, meta("inc-1"), pj(t, js))
	if err != nil {
		t.Fatal(err)
	}
	o2, rep, err := m.Mask(ctxOK, meta("inc-1"), o1)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Removed != 0 || len(rep.Findings) != 0 || canon(o1) != canon(o2) {
		t.Errorf("повторный Mask: %+v\n%s\n%s", rep, canon(o1), canon(o2))
	}
}

// Идемпотентность на большой строке (сканирование окнами).
func TestMaskIdempotentLargeString(t *testing.T) {
	m := newMasker(t)
	var b strings.Builder
	for b.Len() < 256<<10 {
		b.WriteString("error in handler, retry later; ")
		switch randInt(t, 6) {
		case 0:
			b.WriteString("token=" + alnum(t, 18) + " ")
		case 1:
			b.WriteString("user p" + lowerHex(t, 6) + "@example.org ")
		case 2:
			b.WriteString("card " + card(t, '4', 16) + " ")
		case 3:
			b.WriteString("ghp_" + alnum(t, 36) + " ")
		case 4:
			b.WriteString("from " + publicIPv4(t) + " ")
		case 5:
			b.WriteString("Иванов Иван Иванович ")
		}
		b.WriteString("\n")
	}
	o1, rep1 := maskStr(t, m, b.String())
	if rep1.Removed == 0 {
		t.Fatal("в большой строке ничего не найдено")
	}
	o2, rep2 := maskStr(t, m, o1)
	if rep2.Removed != 0 || o1 != o2 {
		t.Errorf("повторный Mask большой строки: %+v", rep2)
	}
}

// Находка на границе окон (около 16 KiB и 32 KiB) не теряется.
func TestMaskLargeStringBoundaries(t *testing.T) {
	m := newMasker(t)
	for _, off := range []int{16<<10 - 40, 16<<10 - 1, 16 << 10, 16<<10 + 100, 18<<10 - 10, 32<<10 - 20, 32<<10 + 5} {
		gh := "ghp_" + alnum(t, 36)
		em := "q" + lowerHex(t, 8) + "@example.org"
		filler := strings.Repeat("lorem ipsum dolor sit amet ", 4<<10)[:70<<10]
		s := filler[:off] + " " + gh + " " + em + " " + filler[off:]
		out, rep := maskStr(t, m, s)
		if strings.Contains(out, gh) || strings.Contains(out, em) {
			t.Errorf("off=%d: находка на границе окна потеряна", off)
		}
		if count(rep, dataclass.CategorySecret) != 1 || count(rep, dataclass.CategoryPersonal) != 1 {
			t.Errorf("off=%d: отчёт %+v", off, rep)
		}
	}
}

// --- ограничения и контекст ---

func TestMaskErrors(t *testing.T) {
	m := newMasker(t)
	ok := pj(t, `{"a":"b"}`)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if out, _, err := m.Mask(ctx, meta("i"), ok); err == nil || out != nil || !errors.Is(err, context.Canceled) {
		t.Errorf("отменённый ctx: out=%v err=%v", out, err)
	}
	if out, _, err := m.Mask(ctxOK, meta(""), ok); err == nil || out != nil {
		t.Error("пустой IncidentID должен давать ошибку")
	}
	if out, _, err := m.Mask(ctxOK, meta("i"), nil); err == nil || out != nil {
		t.Error("nil значение должно давать ошибку")
	}
	if out, _, err := m.Mask(ctxOK, meta("i"), &pyjson.Value{Kind: pyjson.Kind(99)}); err == nil || out != nil {
		t.Error("неизвестный Kind должен давать ошибку")
	}
	if out, rep, err := m.Mask(ctxOK, meta("i"), pyjson.NewObject(pyjson.M("x", &pyjson.Value{Kind: pyjson.Kind(99)}))); err == nil || out != nil || rep.Removed != 0 {
		t.Error("неизвестный Kind во вложенном узле должен давать ошибку")
	}
}

func nested(depth int) *pyjson.Value {
	v := pyjson.NewString("leaf")
	for i := 0; i < depth; i++ {
		v = pyjson.NewArray(v)
	}
	return v
}

func TestMaskDepthLimit(t *testing.T) {
	m := newMasker(t)
	if _, _, err := m.Mask(ctxOK, meta("i"), nested(400)); err != nil {
		t.Errorf("глубина 400: %v", err)
	}
	if _, _, err := m.Mask(ctxOK, meta("i"), nested(600)); err == nil {
		t.Error("глубина 600 должна давать ошибку")
	}
	// объекты
	v := pyjson.NewString("leaf")
	for i := 0; i < 600; i++ {
		v = pyjson.NewObject(pyjson.M("k", v))
	}
	if _, _, err := m.Mask(ctxOK, meta("i"), v); err == nil {
		t.Error("глубина объектов 600 должна давать ошибку")
	}
}

func TestMaskSizeLimit(t *testing.T) {
	m := newMasker(t)
	big := pyjson.NewString(strings.Repeat("a", MaxScanBytes+1))
	start := time.Now()
	if out, _, err := m.Mask(ctxOK, meta("i"), big); err == nil || out != nil {
		t.Error("строка больше MaxScanBytes должна давать ошибку")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("отказ по размеру занял %v", d)
	}
	// суммарно по нескольким строкам и ключам
	half := strings.Repeat("a", MaxScanBytes/2+1)
	if _, _, err := m.Mask(ctxOK, meta("i"), pyjson.NewArray(pyjson.NewString(half), pyjson.NewString(half))); err == nil {
		t.Error("суммарный размер больше MaxScanBytes должен давать ошибку")
	}
	if _, _, err := m.Mask(ctxOK, meta("i"), pyjson.NewObject(pyjson.M(half, pyjson.NewString(half)))); err == nil {
		t.Error("ключи учитываются в MaxScanBytes")
	}
}

// Дедлайн на большой строке: Mask обязан сам выйти по ctx в разумный срок.
func TestMaskDeadlineLargeString(t *testing.T) {
	m := newMasker(t)
	var b strings.Builder
	for b.Len() < 7<<20 {
		b.WriteString("error in handler retry later; ")
		b.WriteString("token=" + alnum(t, 18) + " user p" + lowerHex(t, 6) + "@example.org\n")
	}
	const limit = 50 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	start := time.Now()
	out, _, err := m.Mask(ctx, meta("i"), pyjson.NewString(b.String()))
	el := time.Since(start)
	if err == nil {
		t.Fatalf("7 MiB обработаны за %v при дедлайне %v: ожидалась ошибка ctx (или машина слишком быстра)", el, limit)
	}
	if out != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("out=%v err=%v", out, err)
	}
	if el > limit+150*time.Millisecond {
		t.Errorf("возврат через %v после старта, дедлайн %v: Mask не выходит по ctx", el, limit)
	}
}

// Много мелких узлов: ctx проверяется по счётчику узлов.
func TestMaskDeadlineManyNodes(t *testing.T) {
	m := newMasker(t)
	items := make([]*pyjson.Value, 400000)
	for i := range items {
		items[i] = pyjson.NewString("x")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	time.Sleep(3 * time.Millisecond)
	if _, _, err := m.Mask(ctx, meta("i"), pyjson.NewArray(items...)); err == nil {
		t.Error("истёкший ctx на массиве узлов должен давать ошибку")
	}
}

func TestNewConfig(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Error("пустой ключ должен давать ошибку")
	}
	if _, err := New(Config{PseudonymKey: make([]byte, 31)}); err == nil {
		t.Error("ключ 31 байт должен давать ошибку")
	}
	if _, err := New(Config{PseudonymKey: make([]byte, 32)}); err != nil {
		t.Errorf("ключ 32 байта: %v", err)
	}
	if _, err := New(Config{PseudonymKey: testKey(t), InternalNets: []netipPrefix{{}}}); err == nil {
		t.Error("невалидная сеть должна давать ошибку")
	}
}

func TestVersion(t *testing.T) {
	key := testKey(t)
	m1 := newMaskerKey(t, key)
	m2 := newMasker(t)
	re := regexp.MustCompile(`^aegis-rules/` + regexp.QuoteMeta(RulesVersion) + `\+cfg\.[0-9a-f]{8}$`)
	if !re.MatchString(m1.Version()) {
		t.Errorf("Version = %q", m1.Version())
	}
	if m1.Version() != m2.Version() {
		t.Error("версия зависит от ключа")
	}
	if RulesVersion != "1.2.0" {
		t.Errorf("RulesVersion = %q", RulesVersion)
	}
	nets := DefaultInternalNets()
	rev := make([]netipPrefix, len(nets))
	for i, n := range nets {
		rev[len(nets)-1-i] = n
	}
	mr, err := New(Config{PseudonymKey: key, InternalNets: rev})
	if err != nil {
		t.Fatal(err)
	}
	if mr.Version() != m1.Version() {
		t.Error("порядок сетей влияет на версию")
	}
	mo, err := New(Config{PseudonymKey: key, InternalNets: nets[:3]})
	if err != nil {
		t.Fatal(err)
	}
	if mo.Version() == m1.Version() {
		t.Error("другой набор сетей не изменил версию")
	}
	// ключ не в версии
	if strings.Contains(m1.Version(), fmt.Sprintf("%x", key[:4])) {
		t.Error("ключ просочился в версию")
	}
}

// New копирует ключ и сети: правка исходных срезов не влияет на маскировщик.
func TestNewCopiesConfig(t *testing.T) {
	key := testKey(t)
	nets := DefaultInternalNets()
	m, err := New(Config{PseudonymKey: key, InternalNets: nets})
	if err != nil {
		t.Fatal(err)
	}
	ver := m.Version()
	before, _ := maskStr(t, m, "mail a"+"x@example.org")
	for i := range key {
		key[i] = 0
	}
	nets[0] = netipPrefix{}
	after, _ := maskStr(t, m, "mail a"+"x@example.org")
	if before != after || m.Version() != ver {
		t.Error("маскировщик зависит от исходных срезов конфигурации")
	}
	// IP из пользовательской сети не маскируется, остальной публичный — маскируется
	custom, err := New(Config{PseudonymKey: testKey(t), InternalNets: []netipPrefix{mustPrefix("203.0.113.0/24")}})
	if err != nil {
		t.Fatal(err)
	}
	if out, rep := maskStr(t, custom, "from 203.0.113.7 ok"); out != "from 203.0.113.7 ok" || rep.Removed != 0 {
		t.Errorf("пользовательская внутренняя сеть: %q %+v", out, rep)
	}
}

func TestMaskConcurrent(t *testing.T) {
	m := newMasker(t)
	js, leaks := mixedDoc(t)
	want, _ := maskJSON(t, m, js)
	in := pj(t, js)
	errc := make(chan string, 32)
	done := make(chan struct{})
	for g := 0; g < 32; g++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for i := 0; i < 20; i++ {
				out, rep, err := m.Mask(ctxOK, meta("inc-1"), in)
				if err != nil {
					errc <- err.Error()
					return
				}
				if canon(out) != want || rep.Removed == 0 {
					errc <- "результат отличается при конкурентном вызове"
					return
				}
				for _, l := range leaks {
					if strings.Contains(canon(out), l) {
						errc <- "утечка " + l
						return
					}
				}
			}
		}()
	}
	for g := 0; g < 32; g++ {
		<-done
	}
	close(errc)
	for e := range errc {
		t.Error(e)
	}
	if canon(in) != canon(pj(t, js)) {
		t.Error("вход изменён конкурентными вызовами")
	}
}

// --- LoadKey ---

func TestLoadKey(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	env := func(p string) func(string) string {
		return func(k string) string {
			if k == "AEGIS_MASKER_KEY_FILE" {
				return p
			}
			return ""
		}
	}
	good := lowerHex(t, 64)
	if k, err := LoadKey(env(write("ok", " "+good+"\n"))); err != nil || len(k) != 32 {
		t.Errorf("валидный ключ: %v len=%d", err, len(k))
	}
	if k, err := LoadKey(env(write("long", lowerHex(t, 96)))); err != nil || len(k) != 48 {
		t.Errorf("ключ 48 байт: %v len=%d", err, len(k))
	}
	notHex := "zz" + alnum(t, 62)
	cases := []struct {
		name string
		p    string
		leak string
	}{
		{"переменная не задана", "", ""},
		{"нет файла", filepath.Join(dir, "missing-"+lowerHex(t, 6)), ""},
		{"пустой файл", write("empty", "  \n"), ""},
		{"не hex", write("nothex", notHex), notHex},
		{"короткий", write("short", lowerHex(t, 62)), ""},
		{"слишком большой", write("huge", strings.Repeat("a", 1<<20)), ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			k, err := LoadKey(env(c.p))
			if err == nil || k != nil {
				t.Fatalf("ожидалась ошибка, получено key=%v err=%v", k, err)
			}
			msg := err.Error()
			if c.p != "" && (strings.Contains(msg, c.p) || strings.Contains(msg, dir)) {
				t.Errorf("ошибка содержит путь: %q", msg)
			}
			if c.leak != "" && (strings.Contains(msg, c.leak) || strings.Contains(msg, c.leak[:2]+" ")) {
				t.Errorf("ошибка содержит содержимое файла: %q", msg)
			}
		})
	}
}

// Строка, похожая на заголовок PEM: глобальный детектор PEM сканирует всю строку без проверки ctx.
func TestMaskDeadlinePEMLookalike(t *testing.T) {
	m := newMasker(t)
	s := strings.Repeat("-----BEGIN X-----\n", MaxScanBytes/len("-----BEGIN X-----\n"))
	const limit = 50 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	start := time.Now()
	_, _, err := m.Mask(ctx, meta("i"), pyjson.NewString(s))
	el := time.Since(start)
	if err == nil {
		t.Fatalf("ожидалась ошибка ctx, обработано за %v", el)
	}
	if el > limit+100*time.Millisecond {
		t.Errorf("возврат через %v при дедлайне %v: детектор PEM не прерывается по ctx", el, limit)
	}
}

// Граничные случаи ручного разбора PEM.
func TestMaskPEMEdgeCases(t *testing.T) {
	m := newMasker(t)
	b1, b2 := alnum(t, 48), alnum(t, 48)
	blk := func(typ, body string) string {
		return "-----BEGIN " + typ + "PRIVATE KEY-----\n" + body + "\n-----END " + typ + "PRIVATE KEY-----"
	}
	cases := []struct {
		name, in, want string
		leak           string
		n              int
	}{
		{"без типа", "a " + blk("", b1) + " z", "a " + secRepl + " z", b1, 1},
		{"RSA", "a " + blk("RSA ", b1) + " z", "a " + secRepl + " z", b1, 1},
		{"EC и ENCRYPTED", "a " + blk("ENCRYPTED ", b1) + " z", "a " + secRepl + " z", b1, 1},
		{"без END до конца строки", "a -----BEGIN RSA PRIVATE KEY-----\n" + b1, "a " + secRepl, b1, 1},
		{"END другого типа не закрывает", "a -----BEGIN RSA PRIVATE KEY-----\n" + b1 + "\n-----END CERTIFICATE-----\n" + b2, "a " + secRepl, b2, 1},
		{"два блока", blk("", b1) + " mid " + blk("EC ", b2), secRepl + " mid " + secRepl, b2, 2},
		{"повторный BEGIN внутри блока", "-----BEGIN PRIVATE KEY-----\n" + b1 + "\n-----BEGIN PRIVATE KEY-----\n" + b2 + "\n-----END PRIVATE KEY-----", secRepl, b2, 1},
		{"публичный ключ не трогается", "-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----", "", "", 0},
		{"сертификат не трогается", "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----", "", "", 0},
		{"нижний регистр не матчится", "-----BEGIN rsa private key-----\nabc\n-----END rsa private key-----", "", "", 0},
		{"цифры в типе не матчатся", "-----BEGIN RSA2 PRIVATE KEY-----\nabc\n-----END RSA2 PRIVATE KEY-----", "", "", 0},
		{"PRIVATE без KEY", "-----BEGIN PRIVATE-----\nabc\n-----END PRIVATE-----", "", "", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, rep := maskStr(t, m, c.in)
			want := c.want
			if c.n == 0 {
				want = c.in
			}
			if out != want {
				t.Errorf("выход %q, ожидается %q", out, want)
			}
			if c.leak != "" && strings.Contains(out, c.leak) {
				t.Error("тело ключа осталось в выходе")
			}
			if got := count(rep, dataclass.CategorySecret); got != c.n {
				t.Errorf("Count(secret)=%d, ожидается %d", got, c.n)
			}
		})
	}
}

// Отмена ctx посреди поиска END: много BEGIN без закрывающего маркера нужного типа.
func TestMaskPEMCancelMidSearch(t *testing.T) {
	m := newMasker(t)
	s := strings.Repeat("-----END X-----\n", (MaxScanBytes-100)/len("-----END X-----\n"))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	out, _, err := m.Mask(ctx, meta("i"), pyjson.NewString("-----BEGIN PRIVATE KEY-----\n"+s))
	if err == nil || out != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("out=%v err=%v", out != nil, err)
	}
	if el := time.Since(start); el > 130*time.Millisecond && !raceEnabled {
		t.Errorf("возврат через %v", el)
	}
}

// Энтропийное правило (1.1.0): идентификаторы из слов не вырезаются, а случайные токены той же формы — вырезаются.
func TestEntropyIdentifierFilter(t *testing.T) {
	for _, id := range []string{
		"ProductionDatabaseConnectionPoolExhausted2024Alert",
		"HighRequestLatencyP99ThresholdExceeded5m",
		"OrderService-HighErrorRate-5xx-Critical2",
	} {
		if shannon(id) < entropyMin {
			t.Errorf("%s: энтропия %.3f ниже порога — кейс не проверяет фильтр", id, shannon(id))
		}
		if !looksLikeIdentifier(id) || entropyToken(id) {
			t.Errorf("%s: принят за секрет", id)
		}
	}
	// Не идентификаторы: слова без гласных, согласные кластеры, мало слов.
	for _, s := range []string{
		"QwrtzXcvbnMnbvcPlkjhgDfgh2024Zxcvb",
		"Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv1W",
		"AlertXq9Zk2Vb7Np4Rt8Lm3Ws6Hj1Gf5Dc0",
	} {
		if looksLikeIdentifier(s) {
			t.Errorf("%s: принят за идентификатор", s)
		}
	}
	// Случайные токены длины 64: идентификатором не считаются (вероятность < 10⁻⁶ на токен).
	for i := 0; i < 2000; i++ {
		if tok := alnum(t, 64); looksLikeIdentifier(tok) {
			t.Fatalf("случайный токен принят за идентификатор: %s", tok)
		}
	}
	// Случайный токен в окружении идентификатора режется, идентификатор остаётся.
	m := newMasker(t)
	var tok string
	for tok == "" || !entropyToken(tok) {
		tok = alnum(t, 48)
	}
	in := pj(t, jstr("HighRequestLatencyP99ThresholdExceeded5m key "+tok))
	out, rep, err := m.Mask(ctxOK, meta("inc-1"), in)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := out.S, "HighRequestLatencyP99ThresholdExceeded5m key "+secRepl; got != want || rep.Removed != 1 {
		t.Errorf("выход %q removed=%d, ожидается %q", got, rep.Removed, want)
	}
}

// Идентификаторы — не ПДн (решение 07.11.2026): user_id, customer_id, login… не маскируются; ID сессии — секрет.
func TestMaskIdentifiersNotPersonal(t *testing.T) {
	m := newMasker(t)
	id := "u" + lowerHex(t, 8)
	num := "48" + digits(t, 6)
	for _, k := range []string{"user_id", "userId", "uid", "user", "customer_id", "account_id", "order_id", "subscriber_id", "login", "username", "author_id", "id"} {
		for _, v := range []string{jstr(id), num, jstr("ivan.petrov")} {
			in := `{` + jstr(k) + `:` + v + `}`
			out, rep := maskJSON(t, m, in)
			if out != canon(pj(t, in)) || rep.Removed != 0 || len(rep.Findings) != 0 {
				t.Errorf("%s: %s → %s %+v", k, in, out, rep)
			}
		}
	}
	// email в логине по-прежнему находит строковый детектор
	if _, rep := maskJSON(t, m, `{"login":`+jstr("a"+lowerHex(t, 6)+"@example.org")+`}`); count(rep, dataclass.CategoryPersonal) != 1 {
		t.Errorf("email в login: %+v", rep)
	}
	for _, k := range []string{"session", "session_id", "sessionId", "sid", "SID"} {
		in := `{` + jstr(k) + `:` + jstr(id) + `}`
		out, rep := maskJSON(t, m, in)
		if out != `{`+jstr(k)+`:`+jstr(secRepl)+`}` || count(rep, dataclass.CategorySecret) != 1 || count(rep, dataclass.CategoryPersonal) != 0 {
			t.Errorf("%s: %s %+v", k, out, rep)
		}
		checkEscalate(t, rep, false)
	}
}
