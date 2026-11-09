package audit

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const anchorChain = "agent-staging-1"

func openWith(t *testing.T, path string, s Signer, k Keyring, cps ...Checkpoint) (*Writer, error) {
	t.Helper()
	return OpenWriterWith(path, anchorChain, s, k, WriterOptions{Checkpoints: cps})
}

func TestOpenWriterWithMatchingCheckpoint(t *testing.T) {
	path, s, k, w := writeChain(t, 4)
	cp, err := w.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	w.Close()
	w2, err := openWith(t, path, s, k, cp)
	if err != nil {
		t.Fatalf("совпадающий checkpoint: %v", err)
	}
	w2.Close()
}

func TestOpenWriterWithTruncatedBelowCheckpoint(t *testing.T) {
	path, s, k, w := writeChain(t, 4)
	cp, _ := w.Checkpoint()
	w.Close()
	ls := lines(t, path)
	if err := os.WriteFile(path, bytes.Join(ls[:3], nil), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := openWith(t, path, s, k, cp)
	if err == nil || !strings.Contains(err.Error(), "усечен") {
		t.Fatalf("ожидалась ошибка усечения: %v", err)
	}
	// без checkpoint усечённая цепочка открывается, как раньше
	w2, err := openWith(t, path, s, k)
	if err != nil {
		t.Fatalf("без checkpoint: %v", err)
	}
	w2.Close()
}

func TestOpenWriterWithRollbackToOldCopy(t *testing.T) {
	path, s, k, w := writeChain(t, 2)
	old, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := w.AppendEvent(validEvent("endpoint_down")); err != nil {
			t.Fatal(err)
		}
	}
	cp, _ := w.Checkpoint() // seq 5
	w.Close()
	if cp.Seq != 5 {
		t.Fatalf("seq %d", cp.Seq)
	}
	if err := os.WriteFile(path, old, 0o600); err != nil { // откат к копии seq 2
		t.Fatal(err)
	}
	if _, err := openWith(t, path, s, k, cp); err == nil || !strings.Contains(err.Error(), "усечен") {
		t.Fatalf("откат не обнаружен: %v", err)
	}
}

func TestOpenWriterWithRewrittenSameSeq(t *testing.T) {
	path, s, k, w := writeChain(t, 3)
	cp, _ := w.Checkpoint()
	w.Close()
	ls := lines(t, path)
	// Злоумышленник с ключом переписал запись seq 3 другой (подпись и цепь верны).
	rw := filepath.Join(t.TempDir(), "rw.jsonl")
	if err := os.WriteFile(rw, bytes.Join(ls[:2], nil), 0o600); err != nil {
		t.Fatal(err)
	}
	w2, err := OpenWriter(rw, anchorChain, s, k)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w2.Append(shadowRecord(t, "deny_restart_foreign_pod")); err != nil {
		t.Fatal(err)
	}
	w2.Close()
	if _, err := openWith(t, rw, s, k, cp); err == nil || !strings.Contains(err.Error(), "checkpoint") {
		t.Fatalf("переписывание не обнаружено: %v", err)
	}
}

func TestOpenWriterWithTwoVersionsOneForged(t *testing.T) {
	path, s, k, w := writeChain(t, 3)
	good, _ := w.Checkpoint()
	w.Close()
	// Поддельная версия того же seq с другим head_hash, подписана тем же ключом.
	forged := good
	forged.HeadHash = "sha256:" + strings.Repeat("0", 64)
	forged.CreatedAt = Timestamp(time.Now().Add(time.Second))
	forged.Sig = ""
	fc, err := SignCheckpoint(Head{ChainID: forged.ChainID, Seq: forged.Seq, Hash: forged.HeadHash}, time.Now(), s)
	if err != nil {
		t.Fatal(err)
	}
	for _, order := range [][]Checkpoint{{good, fc}, {fc, good}} {
		if _, err := openWith(t, path, s, k, order...); err == nil {
			t.Fatal("поддельная версия checkpoint принята")
		}
	}
}

func TestOpenWriterWithEmptyChainAndCheckpoints(t *testing.T) {
	_, s, k, w := writeChain(t, 2)
	cp, _ := w.Checkpoint()
	w.Close()
	empty := filepath.Join(t.TempDir(), "empty.jsonl")
	if _, err := openWith(t, empty, s, k, cp); err == nil {
		t.Fatal("пустая цепочка при непустых checkpoint'ах открыта")
	}
	// Ошибка не должна оставлять нечитаемый/залоченный файл: последующее открытие без cp работает.
	if w2, err := openWith(t, empty, s, k); err != nil {
		t.Fatalf("после отказа: %v", err)
	} else {
		w2.Close()
	}
}

func TestOpenWriterWithForeignChainCheckpoint(t *testing.T) {
	path, s, k, w := writeChain(t, 2)
	cp, _ := w.Checkpoint()
	w.Close()
	other2, err := SignCheckpoint(Head{ChainID: "other-chain", Seq: cp.Seq, Hash: cp.HeadHash}, time.Now(), s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openWith(t, path, s, k, other2); err == nil {
		t.Fatal("checkpoint чужой цепочки принят")
	}
}

func TestOpenWriterWithBadSignatureCheckpoint(t *testing.T) {
	path, s, k, w := writeChain(t, 2)
	cp, _ := w.Checkpoint()
	w.Close()
	cp.HeadHash = "sha256:" + strings.Repeat("1", 64) // подпись больше не сходится
	if _, err := openWith(t, path, s, k, cp); err == nil {
		t.Fatal("checkpoint с неверной подписью принят")
	}
}

func TestOpenWriterEqualsOpenWriterWithoutOptions(t *testing.T) {
	path, s, k, w := writeChain(t, 2)
	w.Close()
	w1, err := OpenWriter(path, anchorChain, s, k)
	if err != nil {
		t.Fatal(err)
	}
	if an, hd, _ := w1.AnchorState(); an != 0 || hd != 2 {
		t.Errorf("state %d %d", an, hd)
	}
	w1.Close()
}

func TestDirAnchorLatestCheckpoints(t *testing.T) {
	dir := t.TempDir()
	a := DirAnchor{Dir: dir}
	got, err := a.LatestCheckpoints(anchorChain)
	if err != nil || len(got) != 0 {
		t.Fatalf("пустой каталог: %v %v", got, err)
	}
	_, _, _, w := writeChain(t, 1)
	c1, _ := w.Checkpoint()
	appendEv(t, w)
	c2, _ := w.Checkpoint()
	appendEv(t, w)
	c3, _ := w.Checkpoint()
	for _, c := range []Checkpoint{c1, c2, c3} {
		if c.ChainID != anchorChain {
			t.Skip("chain id")
		}
		if err := a.Put(c); err != nil {
			t.Fatal(err)
		}
	}
	got, err = a.LatestCheckpoints(anchorChain)
	if err != nil || len(got) != 1 || got[0].Seq != 3 {
		t.Fatalf("latest: %+v %v", got, err)
	}
}
