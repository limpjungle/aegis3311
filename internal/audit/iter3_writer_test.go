package audit

import (
	"path/filepath"
	"testing"
)

// TestDuplicateRefusedWriterStaysUsable: отказ дубля event_id не переводит писатель в failed и не портит цепочку.
// После отказа следующее событие пишется, при переоткрытии цепочка проверяется (OpenWriter вызывает Verify),
// оба события известны по event_id, а в памяти нет лишней записи.
func TestDuplicateRefusedWriterStaysUsable(t *testing.T) {
	signer, keys := newSigner(t)
	path := filepath.Join(t.TempDir(), "chain.jsonl")
	w, err := OpenWriter(path, "chain-dup-usable", signer, keys)
	if err != nil {
		t.Fatal(err)
	}
	ev := validEvent("endpoint_down")
	if _, err := w.AppendEvent(ev); err != nil {
		t.Fatal(err)
	}
	dup := validEvent("endpoint_up")
	dup.EventID = ev.EventID
	if _, err := w.AppendEvent(dup); err == nil {
		t.Fatal("повторный event_id принят")
	}
	next := validEvent("endpoint_up")
	if _, err := w.AppendEvent(next); err != nil {
		t.Fatalf("писатель не работает после отказа дубля: %v", err)
	}
	if n := len(w.RouterEvents()); n != 2 {
		t.Errorf("событий в памяти %d, ожидается 2 (дубль не записан)", n)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	w2, err := OpenWriter(path, "chain-dup-usable", signer, keys)
	if err != nil {
		t.Fatalf("цепочка не открылась после отказа дубля: %v", err)
	}
	defer w2.Close()
	if !w2.HasEvent(ev.EventID) || !w2.HasEvent(next.EventID) {
		t.Errorf("после переоткрытия не найдены события по event_id")
	}
	if n := len(w2.RouterEvents()); n != 2 {
		t.Errorf("после переоткрытия событий %d, ожидается 2", n)
	}
}
