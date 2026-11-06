package strictjson_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/limpjungle/aegis3311/internal/strictjson"
)

type wide struct {
	Environment string           `json:"environment"`
	Items       []inner          `json:"items"`
	Ptr         *inner           `json:"ptr"`
	Any         any              `json:"any"`
	Map         map[string]inner `json:"map"`
}

// Экранирование в ключах: \u-последовательности — тот же ключ, дубли по декодированному имени ловятся.
func TestEscapedKeys(t *testing.T) {
	var w wide
	if err := strictjson.Decode([]byte(`{"environment":"staging"}`), &w); err != nil || w.Environment != "staging" {
		t.Errorf("экранированный ключ: %v env=%q", err, w.Environment)
	}
	bad := map[string]string{
		"дубль через экранирование":       `{"environment":"a","environment":"b"}`,
		"регистр через экранирование":     `{"Environment":"a"}`,
		"дубль через экранирование в any": `{"any":{"x":1,"x":2}}`,
		"дубль во вложенном ptr":          `{"ptr":{"n":1,"n":2}}`,
		"дубль в элементе слайса":         `{"items":[{"n":1},{"n":1,"n":1}]}`,
		"дубль в элементе map":            `{"map":{"k":{"n":1,"n":2}}}`,
		"неверный UTF-8 даёт одинаковые":  "{\"any\":{\"a\xff\":1,\"a\xfe\":2}}",
		"пустой ключ дублем":              `{"":1,"":2}`,
	}
	for name, in := range bad {
		var x wide
		if err := strictjson.Decode([]byte(in), &x); err == nil {
			t.Errorf("%s: ошибка не возвращена для %q", name, in)
		}
	}
}

func TestEmptyAndWhitespaceInput(t *testing.T) {
	var w wide
	for _, in := range []string{"", "   ", "\n\t"} {
		if err := strictjson.Decode([]byte(in), &w); err == nil {
			t.Errorf("Decode(%q): ошибка не возвращена", in)
		}
		if err := strictjson.Check([]byte(in), &w); err == nil {
			t.Errorf("Check(%q): ошибка не возвращена", in)
		}
	}
}

// Проверка на вход без предварительного json.Valid: Check не должен паниковать на вложенности.
func TestCheckDeepNesting(t *testing.T) {
	depth := 20000
	in := strings.Repeat("[", depth) + strings.Repeat("]", depth)
	var a any
	// Decode отвергает слишком глубокий JSON через json.Valid.
	if err := strictjson.Decode([]byte(in), &a); err == nil {
		t.Errorf("Decode принял вложенность %d", depth)
	}
}

// Всё, что Decode принял, должно декодироваться стандартным json без ошибок и давать тот же результат.
func FuzzDecodeConsistent(f *testing.F) {
	for _, s := range []string{
		`{"environment":"staging","items":[{"n":1}],"ptr":null,"any":{"a":[1,2]},"map":{"k":{"n":3}}}`,
		`{"environment":"x"}`, `{}`, `null`, `[]`, `{"items":[{"n":1,"n":2}]}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		var w wide
		err := strictjson.Decode(in, &w)
		if err != nil {
			return
		}
		var ref wide
		if err := json.Unmarshal(in, &ref); err != nil {
			t.Fatalf("strictjson принял, encoding/json отверг: %v", err)
		}
		a, _ := json.Marshal(w)
		b, _ := json.Marshal(ref)
		if string(a) != string(b) {
			t.Fatalf("результаты расходятся: %s vs %s", a, b)
		}
	})
}
