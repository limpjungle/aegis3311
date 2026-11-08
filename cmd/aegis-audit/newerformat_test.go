package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/limpjungle/aegis3311/internal/audit"
)

// appendRaw дописывает в файл цепочки подписанную запись с произвольным телом: так выглядит запись более новой сборки.
func appendRaw(t *testing.T, chain, privPath, body string) {
	t.Helper()
	sg, err := audit.LoadPrivateKey(privPath)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(chain)
	if err != nil {
		t.Fatal(err)
	}
	ls := bytes.Split(bytes.TrimSuffix(b, []byte("\n")), []byte("\n"))
	var last audit.Entry
	if err := json.Unmarshal(ls[len(ls)-1], &last); err != nil {
		t.Fatal(err)
	}
	sum := func(b []byte) string { s := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(s[:]) }
	e := audit.Entry{Schema: audit.EntrySchema, ChainID: last.ChainID, Seq: last.Seq + 1, PrevHash: last.Hash, RecordSHA256: sum([]byte(body)),
		KeyID: sg.KeyID(), Record: json.RawMessage(body)}
	hb, _ := json.Marshal(struct {
		Schema       string `json:"schema"`
		ChainID      string `json:"chain_id"`
		Seq          uint64 `json:"seq"`
		PrevHash     string `json:"prev_hash"`
		RecordSHA256 string `json:"record_sha256"`
	}{e.Schema, e.ChainID, e.Seq, e.PrevHash, e.RecordSHA256})
	e.Hash = sum(hb)
	sig, _ := sg.Sign([]byte(audit.EntrySchema + "\x00" + e.Hash))
	e.Sig = base64Std(sig)
	line, _ := json.Marshal(e)
	f, err := os.OpenFile(chain, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.Write(append(line, '\n'))
}

func TestCLINewerFormat(t *testing.T) {
	d := t.TempDir()
	priv, pub, chain := filepath.Join(d, "k.pem"), filepath.Join(d, "k.pub"), filepath.Join(d, "c.jsonl")
	var out bytes.Buffer
	if err := run([]string{"keygen", "-priv", priv, "-pub", pub}, nil, &out); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"dr-1", "dr-2"} {
		if err := run([]string{"append", "-chain", chain, "-id", "agent-1", "-key", priv}, bytes.NewReader(record(t, id)), &out); err != nil {
			t.Fatal(err)
		}
	}
	var errBuf bytes.Buffer
	stderr = &errBuf
	defer func() { stderr = os.Stderr }()

	// version
	out.Reset()
	if err := run([]string{"version"}, nil, &out); err != nil {
		t.Fatal(err)
	}
	var ver struct {
		ChainFormat int      `json:"chain_format"`
		Schemas     []string `json:"schemas"`
	}
	if err := json.Unmarshal(out.Bytes(), &ver); err != nil || ver.ChainFormat != 3 || len(ver.Schemas) != 3 {
		t.Fatalf("version: %v %s", err, out.String())
	}
	if c := code(run([]string{"version", "-integrity-only"}, nil, &out)); c != 2 {
		t.Errorf("version -integrity-only: код %d", c)
	}

	// обычная цепочка с -integrity-only: пустой список, не null, без предупреждения
	out.Reset()
	if err := run([]string{"verify", "-chain", chain, "-pub", pub, "-integrity-only"}, nil, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"unverified_schemas": []`) || !strings.Contains(out.String(), `"unverified_records": 0`) || errBuf.Len() != 0 {
		t.Errorf("чистая цепочка: %s stderr=%q", out.String(), errBuf.String())
	}

	// запись новее сборки
	appendRaw(t, chain, priv, `{"schema":"aegisops/foo/v1","x":1}`)
	out.Reset()
	err := run([]string{"verify", "-chain", chain, "-pub", pub}, nil, &out)
	if code(err) != 1 || !strings.Contains(err.Error(), "не поддерживается этой сборкой") || !strings.Contains(err.Error(), "aegisops/foo/v1") || !strings.Contains(err.Error(), "-integrity-only") {
		t.Fatalf("verify без флага: код %d err=%v", code(err), err)
	}
	if !errors.Is(err, audit.ErrNewerFormat) {
		t.Errorf("errors.Is(ErrNewerFormat) на уровне run(): %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("при ошибке в stdout не должно быть результата: %s", out.String())
	}
	out.Reset()
	errBuf.Reset()
	if err := run([]string{"verify", "-chain", chain, "-pub", pub, "-integrity-only"}, nil, &out); err != nil {
		t.Fatalf("verify -integrity-only: %v", err)
	}
	var res struct {
		Seq        int      `json:"seq"`
		Records    int      `json:"records"`
		Format     int      `json:"chain_format"`
		Unverified int      `json:"unverified_records"`
		Schemas    []string `json:"unverified_schemas"`
	}
	if err := json.Unmarshal(out.Bytes(), &res); err != nil || res.Seq != 3 || res.Records != 2 || res.Format != 3 || res.Unverified != 1 ||
		len(res.Schemas) != 1 || res.Schemas[0] != "aegisops/foo/v1" {
		t.Fatalf("verify -integrity-only: %v %s", err, out.String())
	}
	if !strings.Contains(errBuf.String(), "предупреждение") || !strings.Contains(errBuf.String(), "aegisops/foo/v1") {
		t.Errorf("stderr: %q", errBuf.String())
	}

	// подмена байта в непонятой записи — код 1 и с флагом
	b, _ := os.ReadFile(chain)
	os.WriteFile(chain, bytes.Replace(b, []byte(`\"x\":1`), []byte(`\"x\":2`), 1), 0o600)
	if bytes.Equal(b, mustRead(t, chain)) {
		// Record — вложенный JSON, а не строка: ищем без экранирования
		os.WriteFile(chain, bytes.Replace(b, []byte(`"x":1`), []byte(`"x":2`), 1), 0o600)
	}
	if c := code(run([]string{"verify", "-chain", chain, "-pub", pub, "-integrity-only"}, nil, &out)); c != 1 {
		t.Errorf("подмена в непонятой записи: код %d", c)
	}
	os.WriteFile(chain, b, 0o600)

	// append в чистую цепочку: неизвестная aegisops/* и лишнее поле — тот же текст, код 1; не-aegisops — прежняя ошибка
	clean := filepath.Join(d, "clean.jsonl")
	if err := run([]string{"append", "-chain", clean, "-id", "agent-1", "-key", priv}, bytes.NewReader(record(t, "dr-1")), &out); err != nil {
		t.Fatal(err)
	}
	size := len(mustRead(t, clean))
	err = run([]string{"append", "-chain", clean, "-id", "agent-1", "-key", priv}, strings.NewReader(`{"schema":"aegisops/foo/v1"}`), &out)
	if code(err) != 1 || !strings.Contains(err.Error(), audit.ErrNewerFormat.Error()) || !strings.Contains(err.Error(), "aegisops/foo/v1") {
		t.Errorf("append новой схемы: %v", err)
	}
	err = run([]string{"append", "-chain", clean, "-id", "agent-1", "-key", priv}, strings.NewReader(`{"schema":"x"}`), &out)
	if code(err) != 1 || strings.Contains(err.Error(), audit.ErrNewerFormat.Error()) || !strings.Contains(err.Error(), "неизвестная схема") {
		t.Errorf("append чужой схемы: %v", err)
	}
	if len(mustRead(t, clean)) != size {
		t.Error("цепочка изменилась после отказов")
	}
	// append в цепочку с записью новее сборки: OpenWriter строг
	err = run([]string{"append", "-chain", chain, "-id", "agent-1", "-key", priv}, bytes.NewReader(record(t, "dr-9")), &out)
	if code(err) != 1 && code(err) != 2 || !strings.Contains(err.Error(), "не поддерживается этой сборкой") {
		t.Errorf("append в цепочку новее сборки: код %d %v", code(err), err)
	}
	// лишнее поле в известной записи при append
	extra := bytes.Replace(record(t, "dr-5"), []byte(`{"answer"`), []byte(`{"zz_new":1,"answer"`), 1)
	d2 := t.TempDir()
	c2 := filepath.Join(d2, "c.jsonl")
	err = run([]string{"append", "-chain", c2, "-id", "agent-1", "-key", priv}, bytes.NewReader(extra), &out)
	if code(err) != 1 || !strings.Contains(err.Error(), audit.ErrNewerFormat.Error()) || !strings.Contains(err.Error(), "zz_new") {
		t.Errorf("append с лишним полем: %v", err)
	}
	// -integrity-only вне verify
	if c := code(run([]string{"append", "-chain", chain, "-id", "agent-1", "-key", priv, "-integrity-only"}, strings.NewReader("{}"), &out)); c != 2 {
		t.Errorf("append -integrity-only: код %d", c)
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func base64Std(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
