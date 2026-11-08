package masker

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/limpjungle/aegis3311/internal/pyjson"
)

// FuzzMask: Mask не паникует, не меняет вход, результат сериализуется и разбирается обратно,
// а повторный Mask выхода не находит ничего нового (идемпотентность).
func FuzzMask(f *testing.F) {
	// сиды: фрагменты eval
	if files, _ := filepath.Glob("../../eval/golden-synthetic/data/probe-v3.jsonl"); len(files) == 1 {
		raw, err := os.ReadFile(files[0])
		if err == nil {
			for i, ln := range bytes.Split(raw, []byte("\n")) {
				if i >= 6 || len(bytes.TrimSpace(ln)) == 0 {
					continue
				}
				if c, err := pyjson.Parse(ln); err == nil {
					for _, mem := range c.Get("input").Members {
						f.Add(pyjson.Marshal(mem.Value, pyjson.Canonical))
					}
				}
			}
		}
	}
	// сиды: строки табличных тестов (рантайм)
	for _, c := range secretCases() {
		in, _, _, _ := c.gen(f)
		f.Add(pyjson.Marshal(pyjson.NewString(in), pyjson.Canonical))
	}
	for _, c := range personalCases(f) {
		f.Add(pyjson.Marshal(pyjson.NewString(c.pre+c.val+c.post), pyjson.Canonical))
	}
	for _, s := range noFalsePositiveInputs(f) {
		f.Add(pyjson.Marshal(pyjson.NewString(s), pyjson.Canonical))
	}
	js, _ := mixedDoc(f)
	f.Add([]byte(js))
	f.Add([]byte(`{"kind":"Secret","data":{"a":"b"},"env":[{"name":"DB_PASSWORD","value":"x"}]}`))
	f.Add([]byte(`{"user_id":123,"phone":9161234567,"n":[1.5,true,null]}`))

	m := newMasker(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := pyjson.Parse(data)
		if err != nil {
			return
		}
		before := pyjson.Marshal(v, pyjson.Canonical)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		out, rep, err := m.Mask(ctx, meta("fuzz"), v)
		if !bytes.Equal(before, pyjson.Marshal(v, pyjson.Canonical)) {
			t.Fatal("Mask изменил вход")
		}
		if err != nil {
			if out != nil {
				t.Fatal("при ошибке значение должно быть nil")
			}
			return
		}
		if out == nil {
			t.Fatal("nil без ошибки")
		}
		if rep.Failed || rep.Removed < 0 {
			t.Fatalf("некорректный отчёт: %+v", rep)
		}
		for _, fd := range rep.Findings {
			if fd.Count <= 0 {
				t.Fatalf("нулевой Count: %+v", rep)
			}
		}
		ser := pyjson.Marshal(out, pyjson.Canonical)
		re, err := pyjson.Parse(ser)
		if err != nil {
			t.Fatalf("выход не разбирается: %v\n%s", err, ser)
		}
		out2, rep2, err := m.Mask(ctx, meta("fuzz"), re)
		if err != nil {
			t.Fatalf("повторный Mask: %v", err)
		}
		if rep2.Removed != 0 || len(rep2.Findings) != 0 {
			t.Fatalf("не идемпотентен: %+v\nвход:  %s\nвыход: %s\nповтор: %s", rep2, before, ser, pyjson.Marshal(out2, pyjson.Canonical))
		}
	})
}
