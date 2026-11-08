package audit

import (
	"os"
	"path/filepath"
	"testing"
)

// TestWriterHasEventAndLast: HasEvent и LastRouterEvent учитывают только записанные события; после перезапуска
// множество и последнее событие восстанавливаются из цепочки (через Verify).
func TestWriterHasEventAndLast(t *testing.T) {
	signer, keys := newSigner(t)
	path := filepath.Join(t.TempDir(), "chain.jsonl")
	w, err := OpenWriter(path, "chain-state-test", signer, keys)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := w.LastRouterEvent(); ok {
		t.Fatal("в пустой цепочке событий быть не должно")
	}

	ev1 := validEvent("endpoint_down")
	if _, err := w.AppendEvent(ev1); err != nil {
		t.Fatal(err)
	}
	if !w.HasEvent(ev1.EventID) {
		t.Fatal("записанное событие не найдено")
	}
	if last, ok := w.LastRouterEvent(); !ok || last.Kind != "endpoint_down" || last.EventID != ev1.EventID {
		t.Fatalf("последнее событие: %+v, %v", last, ok)
	}

	bad := validEvent("router_halted")
	bad.Reason = "x"
	if _, err := w.AppendEvent(bad); err == nil {
		t.Fatal("недопустимое событие должно быть отвергнуто")
	}
	if w.HasEvent(bad.EventID) {
		t.Error("отвергнутое событие учтено в HasEvent")
	}
	if last, _ := w.LastRouterEvent(); last.EventID != ev1.EventID {
		t.Error("отвергнутое событие стало последним")
	}

	ev2 := validEvent("router_halted")
	ev2.Reason = "state_store"
	if _, err := w.AppendEvent(ev2); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	w2, err := OpenWriter(path, "chain-state-test", signer, keys)
	if err != nil {
		t.Fatal(err)
	}
	defer w2.Close()
	if !w2.HasEvent(ev1.EventID) || !w2.HasEvent(ev2.EventID) {
		t.Error("после перезапуска события не восстановлены")
	}
	if w2.HasEvent(bad.EventID) {
		t.Error("после перезапуска учтено отвергнутое событие")
	}
	if last, ok := w2.LastRouterEvent(); !ok || last.Kind != "router_halted" || last.Reason != "state_store" {
		t.Errorf("последнее событие после перезапуска: %+v, %v", last, ok)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var seen []string
	if _, err := Verify(f, keys, VerifyOptions{ChainID: "chain-state-test", OnRouterEvent: func(_ uint64, ev *RouterEvent) {
		seen = append(seen, ev.EventID)
	}}); err != nil {
		t.Fatalf("цепочка не проходит проверку: %v", err)
	}
	if len(seen) != 2 || seen[0] != ev1.EventID || seen[1] != ev2.EventID {
		t.Errorf("OnRouterEvent вызван для %v, ожидается два события по порядку", seen)
	}
}

// TestRouterHaltedNewReasons: причины state_store и state_lost допустимы только для router_halted.
func TestRouterHaltedNewReasons(t *testing.T) {
	for _, reason := range []string{"state_store", "state_lost"} {
		e := validEvent("router_halted")
		e.Reason = reason
		if err := e.Validate(); err != nil {
			t.Errorf("router_halted(%s): %v", reason, err)
		}
	}
	for _, reason := range []string{"x", ""} {
		e := validEvent("router_halted")
		e.Reason = reason
		if err := e.Validate(); err == nil {
			t.Errorf("router_halted(%q) должен отвергаться", reason)
		}
	}
	e := validEvent("endpoint_down")
	e.Reason = "state_store"
	if err := e.Validate(); err == nil {
		t.Error("endpoint_down с причиной state_store должен отвергаться")
	}
}
