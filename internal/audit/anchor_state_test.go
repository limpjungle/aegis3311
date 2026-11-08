package audit

import (
	"path/filepath"
	"testing"
)

// Якорь state_created (проверка после итерации 2): допустимая форма и отказы при неверной форме.
func TestStateCreatedValidate(t *testing.T) {
	ok := func() *RouterEvent {
		e := validEvent("state_created")
		e.From, e.To, e.Reason = "inceptron-fp8", "wafer-nvfp4", "store_created"
		return e
	}
	if err := ok().Validate(); err != nil {
		t.Fatalf("допустимый якорь отвергнут: %v", err)
	}
	bad := map[string]func(e *RouterEvent){
		"причина не store_created": func(e *RouterEvent) { e.Reason = "x" },
		"пустой from":              func(e *RouterEvent) { e.From = "" },
		"пустой to":                func(e *RouterEvent) { e.To = "" },
		"задан endpoint":           func(e *RouterEvent) { e.Endpoint = "inceptron-fp8" },
		"задана role":              func(e *RouterEvent) { e.Role = "primary" },
	}
	for name, mut := range bad {
		e := ok()
		mut(e)
		if err := e.Validate(); err == nil {
			t.Errorf("%s: должен отвергаться", name)
		}
	}
}

// Повторный event_id не должен попадать в цепочку: Verify при следующем открытии отвергает цепочку целиком, и
// роутер на ней не стартует. Writer обязан отказать при записи.
func TestWriterRejectsDuplicateEventID(t *testing.T) {
	signer, keys := newSigner(t)
	path := filepath.Join(t.TempDir(), "chain.jsonl")
	w, err := OpenWriter(path, "chain-dup-test", signer, keys)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	ev := validEvent("endpoint_down")
	if _, err := w.AppendEvent(ev); err != nil {
		t.Fatal(err)
	}
	dup := validEvent("endpoint_down")
	dup.EventID = ev.EventID
	if _, err := w.AppendEvent(dup); err == nil {
		t.Fatal("повторный event_id принят: цепочка станет непроверяемой при следующем открытии")
	}
}
