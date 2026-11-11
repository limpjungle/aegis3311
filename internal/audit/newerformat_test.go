package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/limpjungle/aegis3311/internal/strictjson"
)

func TestKillSwitchEventValidateBootstrap(t *testing.T) {
	ok := validKSEvent("kill_switch_engaged")
	ok.From, ok.Bootstrap = "none", true
	if err := ok.Validate(); err != nil {
		t.Fatalf("корректный bootstrap: %v", err)
	}
	for name, mut := range map[string]func(e *KillSwitchEvent){
		"from=running": func(e *KillSwitchEvent) {
			e.From = "running"
			e.Kind = "kill_switch_updated"
			e.State = ksState(false, "")
		},
		"from=stopped":          func(e *KillSwitchEvent) { e.From = "stopped"; e.Kind = "kill_switch_updated" },
		"пустой stop_watermark": func(e *KillSwitchEvent) { e.StopWatermark = "" },
	} {
		e := validKSEvent("kill_switch_engaged")
		e.From, e.Bootstrap = "none", true
		mut(e)
		if err := e.Validate(); err == nil || !strings.Contains(err.Error(), "bootstrap") {
			t.Errorf("%s: ожидалась ошибка bootstrap, получено %v", name, err)
		}
	}
	// bootstrap=false с любым from — как раньше
	e := validKSEvent("kill_switch_engaged")
	if err := e.Validate(); err != nil {
		t.Error(err)
	}
}

func TestFormatConstants(t *testing.T) {
	if ChainFormat != 4 {
		t.Errorf("ChainFormat = %d", ChainFormat)
	}
	ks := KnownSchemas()
	want := []string{KillSwitchEventSchema, RecordSchema, RouterEventSchema}
	if len(ks) != 3 {
		t.Fatalf("KnownSchemas: %v", ks)
	}
	for i := 1; i < len(ks); i++ {
		if ks[i-1] >= ks[i] {
			t.Errorf("не отсортированы: %v", ks)
		}
	}
	for _, w := range want {
		found := false
		for _, s := range ks {
			found = found || s == w
		}
		if !found {
			t.Errorf("нет %s в %v", w, ks)
		}
	}
	for s, want := range map[string]bool{"aegisops/foo/v1": true, "aegisops/a-b9/v12": true, "aegisops/Foo/v1": false, "aegisops/foo/v": false,
		"aegisops/foo/v1x": false, "evil/foo/v1": false, "aegisops/foo": false, "xaegisops/foo/v1": false, "": false, "aegisops/foo/v1\n": false} {
		if SchemaFromProject(s) != want {
			t.Errorf("SchemaFromProject(%q) != %v", s, want)
		}
	}
}

// rawAppend дописывает в цепочку подписанную запись с произвольным телом: так выглядит запись более новой сборки.
func rawAppend(t *testing.T, w *Writer, body string) {
	t.Helper()
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, err := w.appendBodyLocked([]byte(body)); err != nil {
		t.Fatal(err)
	}
}

// newerChain: [rec, unknown aegisops/foo/v1, rec с лишним полем, unknown aegisops/bar/v2, unknown aegisops/foo/v1, rec].
func newerChain(t *testing.T) (path string, k Keyring, s *Ed25519Signer, w *Writer) {
	t.Helper()
	path, s, k, w = writeChain(t, 1)
	rawAppend(t, w, `{"schema":"aegisops/foo/v1","payload":"secret-new-thing"}`)
	b, _ := json.Marshal(shadowRecord(t, "cap_lease_missing"))
	rawAppend(t, w, string(b[:len(b)-1])+`,"zz_new_field":{"a":1}}`)
	rawAppend(t, w, `{"schema":"aegisops/bar/v2"}`)
	rawAppend(t, w, `{"schema":"aegisops/foo/v1"}`)
	if _, err := w.Append(shadowRecord(t, "deny_restart_foreign_pod")); err != nil {
		t.Fatal(err)
	}
	return path, k, s, w
}

func TestVerifyNewerFormatStrict(t *testing.T) {
	path, k, _, w := newerChain(t)
	w.Close()
	_, err := verifyFile(t, path, k, VerifyOptions{})
	if !errors.Is(err, ErrNewerFormat) {
		t.Fatalf("ожидался ErrNewerFormat, получено %v", err)
	}
	var ce *ChainError
	if !errors.As(err, &ce) || ce.Line != 2 || ce.Seq != 2 {
		t.Fatalf("ChainError: %+v", ce)
	}
	for _, want := range []string{`aegisops/foo/v1`, "aegis-audit", "-integrity-only", "формат цепочки 4"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("в тексте %q нет %q", err, want)
		}
	}
}

func TestVerifyExtraFieldIsNewerFormat(t *testing.T) {
	path, s, k, w := writeChain(t, 1)
	_ = s
	b, _ := json.Marshal(shadowRecord(t, "cap_lease_missing"))
	rawAppend(t, w, string(b[:len(b)-1])+`,"zz_new_field":1}`)
	w.Close()
	_, err := verifyFile(t, path, k, VerifyOptions{})
	if !errors.Is(err, ErrNewerFormat) || !strings.Contains(err.Error(), "zz_new_field") {
		t.Fatalf("лишнее поле: %v", err)
	}
	var st VerifyStats
	if _, err := verifyFile(t, path, k, VerifyOptions{IntegrityOnly: true, Stats: &st}); err != nil {
		t.Fatalf("integrity-only: %v", err)
	}
	if st.Unverified != 1 || st.Records != 1 || len(st.UnverifiedSchemas) != 1 || st.UnverifiedSchemas[0] != RecordSchema {
		t.Errorf("stats: %+v", st)
	}
}

func TestVerifyNonProjectSchemaStillFatal(t *testing.T) {
	for _, schema := range []string{"evil/foo/v1", "aegisops/Foo/v1", "aegisops/foo/v1x", "", "aegisops/foo", "decision-record"} {
		path, _, k, w := writeChain(t, 1)
		rawAppend(t, w, `{"schema":"`+schema+`"}`)
		w.Close()
		for _, io := range []bool{false, true} {
			_, err := verifyFile(t, path, k, VerifyOptions{IntegrityOnly: io})
			if err == nil || errors.Is(err, ErrNewerFormat) || !strings.Contains(err.Error(), "неизвестная схема") {
				t.Errorf("схема %q integrityOnly=%v: %v", schema, io, err)
			}
		}
	}
	// не объект
	path, _, k, w := writeChain(t, 1)
	rawAppend(t, w, `[1,2]`)
	w.Close()
	if _, err := verifyFile(t, path, k, VerifyOptions{IntegrityOnly: true}); err == nil || errors.Is(err, ErrNewerFormat) {
		t.Errorf("запись-массив: %v", err)
	}
}

func TestVerifyIntegrityOnly(t *testing.T) {
	path, k, _, w := newerChain(t)
	head := w.Head()
	cp, err := w.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	w.Close()
	var recs, seen int
	var st VerifyStats
	got, err := verifyFile(t, path, k, VerifyOptions{IntegrityOnly: true, Stats: &st, Checkpoints: []Checkpoint{cp},
		OnRecord:          func(uint64, *DecisionRecord) { recs++ },
		OnRouterEvent:     func(uint64, *RouterEvent) { seen++ },
		OnKillSwitchEvent: func(uint64, *KillSwitchEvent) { seen++ }})
	if err != nil {
		t.Fatalf("integrity-only: %v", err)
	}
	if got != head {
		t.Errorf("голова %+v, ожидалась %+v", got, head)
	}
	if st.Records != 2 || st.Unverified != 4 || strings.Join(st.UnverifiedSchemas, ",") != "aegisops/bar/v2,aegisops/decision-record/v1,aegisops/foo/v1" && strings.Join(st.UnverifiedSchemas, ",") != "aegisops/bar/v2,"+RecordSchema+",aegisops/foo/v1" {
		t.Errorf("stats: %+v", st)
	}
	if recs != 2 || seen != 0 {
		t.Errorf("колбэки: records=%d прочие=%d (для непонятых записей колбэков быть не должно)", recs, seen)
	}
	// без флага — отказ
	if _, err := verifyFile(t, path, k, VerifyOptions{}); !errors.Is(err, ErrNewerFormat) {
		t.Errorf("без IntegrityOnly: %v", err)
	}
}

func TestIntegrityOnlyCheckpointBehindUnknownRecord(t *testing.T) {
	path, s, k, w := writeChain(t, 1)
	rawAppend(t, w, `{"schema":"aegisops/foo/v1"}`) // seq 2
	cp, err := w.Checkpoint()                       // на непонятой записи
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(shadowRecord(t, "cap_lease_missing")); err != nil {
		t.Fatal(err)
	}
	w.Close()
	if cp.Seq != 2 {
		t.Fatalf("checkpoint seq %d", cp.Seq)
	}
	if _, err := verifyFile(t, path, k, VerifyOptions{IntegrityOnly: true, Checkpoints: []Checkpoint{cp}}); err != nil {
		t.Fatalf("верный checkpoint: %v", err)
	}
	// checkpoint с неверным хешем головы (но с верной подписью — ключ у атакующего «внутри»)
	bad := cp
	bad.HeadHash = h('f')
	bad.Sig = ""
	if re, err := SignCheckpoint(Head{ChainID: cp.ChainID, Seq: cp.Seq, Hash: bad.HeadHash}, mustTime(t, cp.CreatedAt), s); err == nil {
		bad = re
	}
	if _, err := verifyFile(t, path, k, VerifyOptions{IntegrityOnly: true, Checkpoints: []Checkpoint{bad}}); err == nil || !strings.Contains(err.Error(), "checkpoint") {
		t.Errorf("checkpoint с чужим хешем принят: %v", err)
	}
	// усечение: цепочка до seq 1, checkpoint на seq 2
	ls := lines(t, path)
	trunc := writeLines(t, ls[:1])
	if _, err := verifyFile(t, trunc, k, VerifyOptions{IntegrityOnly: true, Checkpoints: []Checkpoint{cp}}); err == nil {
		t.Error("усечение не замечено в integrity-only")
	}
	// усечение: непонятая запись вырезана вместе с хвостом, остался только seq 1 — то же
}

func TestIntegrityOnlyTamperDetected(t *testing.T) {
	path, k, _, w := newerChain(t)
	w.Close()
	orig := lines(t, path)
	mutate := func(i int, from, to string) string {
		ls := make([][]byte, len(orig))
		copy(ls, orig)
		if !bytes.Contains(ls[i], []byte(from)) {
			t.Fatalf("в строке %d нет %q: %s", i, from, ls[i])
		}
		ls[i] = bytes.Replace(ls[i], []byte(from), []byte(to), 1)
		return writeLines(t, ls)
	}
	opts := VerifyOptions{IntegrityOnly: true}
	if _, err := verifyFile(t, mutate(1, "secret-new-thing", "secret-new-thinG"), k, opts); err == nil {
		t.Error("подмена байта в непонятой записи принята")
	}
	// подмена записи вместе с её record_sha256: ломается hash/prev_hash следующей
	var e Entry
	if err := json.Unmarshal(orig[1], &e); err != nil {
		t.Fatal(err)
	}
	fake := []byte(`{"schema":"aegisops/foo/v1","payload":"forged"}`)
	ls := make([][]byte, len(orig))
	copy(ls, orig)
	e.Record, e.RecordSHA256 = fake, sha256Prefixed(fake)
	nb, _ := json.Marshal(e)
	ls[1] = append(nb, '\n')
	if _, err := verifyFile(t, writeLines(t, ls), k, opts); err == nil {
		t.Error("подмена тела вместе с record_sha256 принята")
	}
	// подмена подписи: берём подпись другой записи
	var e0 Entry
	json.Unmarshal(orig[0], &e0)
	e.Record = []byte(`{"schema":"aegisops/foo/v1","payload":"secret-new-thing"}`)
	json.Unmarshal(orig[1], &e)
	e.Sig = e0.Sig
	nb, _ = json.Marshal(e)
	copy(ls, orig)
	ls[1] = append(nb, '\n')
	if _, err := verifyFile(t, writeLines(t, ls), k, opts); err == nil {
		t.Error("подмена подписи принята")
	}
	// удаление непонятой записи из середины
	ls = append(append([][]byte{}, orig[:1]...), orig[2:]...)
	if _, err := verifyFile(t, writeLines(t, ls), k, opts); err == nil {
		t.Error("удаление записи принято")
	}
	// перестановка
	ls = append([][]byte{}, orig...)
	ls[1], ls[3] = ls[3], ls[1]
	if _, err := verifyFile(t, writeLines(t, ls), k, opts); err == nil {
		t.Error("перестановка записей принята")
	}
	// чужой ключ
	_, other := newSigner(t)
	if _, err := verifyFile(t, path, other, opts); err == nil {
		t.Error("цепочка принята с чужим ключом")
	}
}

func TestIntegrityOnlyInvalidKnownRecordFatal(t *testing.T) {
	// известная схема, неизвестных полей нет, но запись невалидна: это порча, а не «новее сборки»
	for name, body := range map[string]string{
		"decision record":   `{"schema":"` + RecordSchema + `"}`,
		"kill switch event": `{"schema":"` + KillSwitchEventSchema + `"}`,
		"router event":      `{"schema":"` + RouterEventSchema + `"}`,
	} {
		path, _, k, w := writeChain(t, 1)
		rawAppend(t, w, body)
		w.Close()
		_, err := verifyFile(t, path, k, VerifyOptions{IntegrityOnly: true})
		if err == nil || errors.Is(err, ErrNewerFormat) {
			t.Errorf("%s: невалидная известная запись принята: %v", name, err)
		}
	}
	// дубликат ключа в известной записи — тоже порча
	path, _, k, w := writeChain(t, 1)
	b, _ := json.Marshal(shadowRecord(t, "cap_lease_missing"))
	rawAppend(t, w, string(b[:len(b)-1])+`,"mode":"x"}`)
	w.Close()
	if _, err := verifyFile(t, path, k, VerifyOptions{IntegrityOnly: true}); err == nil || errors.Is(err, ErrNewerFormat) {
		t.Errorf("дубль ключа: %v", err)
	}
	// дубль record_id у понятых записей по-прежнему ловится (непонятые в проверку ID не входят)
	path, s, k, w := writeChain(t, 0)
	rec := shadowRecord(t, "cap_lease_missing")
	if _, err := w.Append(rec); err != nil {
		t.Fatal(err)
	}
	bb, _ := json.Marshal(rec)
	rawAppend(t, w, string(bb))
	w.Close()
	_ = s
	if _, err := verifyFile(t, path, k, VerifyOptions{IntegrityOnly: true}); err == nil {
		t.Error("дубль record_id принят в integrity-only")
	}
}

func TestOpenWriterRefusesNewerFormat(t *testing.T) {
	path, k, s, w := newerChain(t)
	w.Close()
	before, _ := os.ReadFile(path)
	if _, err := OpenWriter(path, "agent-staging-1", s, k); !errors.Is(err, ErrNewerFormat) {
		t.Fatalf("OpenWriter: %v", err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Error("OpenWriter изменил файл цепочки")
	}
}

func TestStrictJSONUnknownField(t *testing.T) {
	var v struct {
		A int `json:"a"`
	}
	err := strictjson.Decode([]byte(`{"a":1,"b":2}`), &v)
	var uf *strictjson.UnknownFieldError
	if !errors.As(err, &uf) || uf.Field != "b" {
		t.Fatalf("errors.As: %v", err)
	}
	if err.Error() != `неизвестное поле "b" (имена регистрозависимы)` {
		t.Errorf("текст изменился: %q", err)
	}
	// вложенный и регистр
	var n struct {
		In struct {
			X int `json:"x"`
		} `json:"in"`
	}
	if err := strictjson.Decode([]byte(`{"in":{"X":1}}`), &n); !errors.As(err, &uf) || uf.Field != "X" {
		t.Errorf("вложенное/регистр: %v", err)
	}
	// прочие ошибки — не UnknownFieldError
	if err := strictjson.Decode([]byte(`{"a":1,"a":2}`), &v); err == nil || errors.As(err, &uf) {
		t.Errorf("дубль ключа: %v", err)
	}
	if err := strictjson.Decode([]byte(`{"a":"s"}`), &v); err == nil || errors.As(err, &uf) {
		t.Errorf("тип: %v", err)
	}
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatal(err)
	}
	return tm
}

var _ = filepath.Join
