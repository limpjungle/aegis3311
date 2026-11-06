package strictjson_test

import (
	"encoding/json"
	"testing"

	"github.com/limpjungle/aegis3311/internal/strictjson"
)

type inner struct {
	N *int `json:"n"`
}

type outer struct {
	Name  string            `json:"name"`
	In    *inner            `json:"in"`
	List  []inner           `json:"list"`
	Raw   json.RawMessage   `json:"raw"`
	Label map[string]string `json:"label"`
}

func TestDecode(t *testing.T) {
	ok := []string{
		`{}`,
		`{"name":"a","in":{"n":1},"list":[{"n":2}],"raw":{"Any":1},"label":{"A":"b","a":"c"}}`,
		` {"name":"a"} `,
	}
	for _, in := range ok {
		var o outer
		if err := strictjson.Decode([]byte(in), &o); err != nil {
			t.Errorf("%s: %v", in, err)
		}
	}
	bad := map[string]string{
		"дубль":              `{"name":"a","name":"b"}`,
		"дубль во вложенном": `{"in":{"n":1,"n":2}}`,
		"дубль в списке":     `{"list":[{"n":1,"n":2}]}`,
		"дубль в raw":        `{"raw":{"a":1,"a":2}}`,
		"дубль в map":        `{"label":{"a":"1","a":"2"}}`,
		"регистр":            `{"Name":"a"}`,
		"регистр вложенного": `{"in":{"N":1}}`,
		"неизвестное поле":   `{"zzz":1}`,
		"хвост }":            `{"name":"a"}}`,
		"хвост значения":     `{"name":"a"} {"name":"b"}`,
		"не JSON":            `{`,
		"тип":                `{"name":1}`,
	}
	for name, in := range bad {
		var o outer
		if err := strictjson.Decode([]byte(in), &o); err == nil {
			t.Errorf("%s: ошибка не возвращена", name)
		}
	}
}
