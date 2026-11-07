package audit

import (
	"errors"
	"path/filepath"
	"testing"
)

// TestOpenWriterLocked: второй писатель на тот же файл получает ErrLocked, первый остаётся рабочим,
// после его закрытия файл открывается снова.
func TestOpenWriterLocked(t *testing.T) {
	signer, keys := newSigner(t)
	path := filepath.Join(t.TempDir(), "chain.jsonl")
	w, err := OpenWriter(path, "chain-locked", signer, keys)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenWriter(path, "chain-locked", signer, keys); !errors.Is(err, ErrLocked) {
		t.Fatalf("второй писатель: %v, ожидается ErrLocked", err)
	}
	if _, err := w.AppendEvent(validEvent("endpoint_down")); err != nil {
		t.Fatalf("первый писатель сломан отказом второго: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	w2, err := OpenWriter(path, "chain-locked", signer, keys)
	if err != nil {
		t.Fatalf("после закрытия: %v", err)
	}
	w2.Close()
}
