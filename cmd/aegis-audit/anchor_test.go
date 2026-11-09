package main

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/limpjungle/aegis3311/internal/killswitch/s3/s3test"
)

type anchorEnv struct {
	dir, priv, pub, chain, cfg string
	fk                         *s3test.Fake
}

// newAnchorEnv готовит ключи, цепочку из n записей и конфигурацию s3 на фейке; переменные окружения задаются через t.Setenv.
func newAnchorEnv(t *testing.T, n int) *anchorEnv {
	t.Helper()
	d := t.TempDir()
	e := &anchorEnv{dir: d, priv: filepath.Join(d, "k.pem"), pub: filepath.Join(d, "k.pub"), chain: filepath.Join(d, "c.jsonl"), cfg: filepath.Join(d, "anchor.json")}
	var out bytes.Buffer
	if err := run([]string{"keygen", "-priv", e.priv, "-pub", e.pub}, nil, &out); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if err := run([]string{"append", "-chain", e.chain, "-id", "agent-1", "-key", e.priv}, bytes.NewReader(record(t, fmt.Sprintf("dr-%d", i))), &out); err != nil {
			t.Fatal(err)
		}
	}
	fk, c := s3test.New(t)
	e.fk = fk
	ca := filepath.Join(d, "ca.pem")
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fk.Srv.Certificate().Raw}), 0o600)
	cfg := map[string]any{"kind": "s3", "s3": map[string]any{"endpoint": fk.Srv.URL, "region": s3test.Region, "bucket": s3test.Bucket,
		"prefix": "aud/", "ca_file": ca, "path_style": true, "retention": "24h", "timeout": "3s"}}
	b, _ := json.Marshal(cfg)
	os.WriteFile(e.cfg, b, 0o600)
	t.Setenv("AEGIS_AUDIT_S3_ACCESS_KEY_ID_FILE", c.Creds.AccessKeyIDFile)
	t.Setenv("AEGIS_AUDIT_S3_SECRET_KEY_FILE", c.Creds.SecretKeyFile)
	t.Setenv("AEGIS_AUDIT_S3_SESSION_TOKEN_FILE", "")
	return e
}

func (e *anchorEnv) checkpoint(t *testing.T) error {
	return run([]string{"checkpoint", "-chain", e.chain, "-id", "agent-1", "-key", e.priv, "-anchor-config", e.cfg}, nil, &bytes.Buffer{})
}

func (e *anchorEnv) verify(out *bytes.Buffer, extra ...string) error {
	args := append([]string{"verify", "-chain", e.chain, "-pub", e.pub, "-id", "agent-1"}, extra...)
	return run(args, nil, out)
}

func TestAnchorConfigCheckpointAndVerify(t *testing.T) {
	e := newAnchorEnv(t, 3)
	if err := e.checkpoint(t); err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	keys := e.fk.Keys()
	if len(keys) != 1 || keys[0] != "aud/agent-1/cp/00000000000000000003.json" {
		t.Fatalf("ключи: %v", keys)
	}
	if v := e.fk.Versions(keys[0])[0]; v.Lock.Get("x-amz-object-lock-mode") != "COMPLIANCE" {
		t.Errorf("lock %v", v.Lock)
	}
	var out bytes.Buffer
	if err := e.verify(&out, "-anchor-config", e.cfg); err != nil {
		t.Fatalf("verify: %v", err)
	}
	var res struct {
		Seq         int `json:"seq"`
		Checkpoints int `json:"checkpoints_checked"`
	}
	json.Unmarshal(out.Bytes(), &res)
	if res.Seq != 3 || res.Checkpoints != 1 {
		t.Fatalf("verify вывод (checkpoints_checked должен быть 1): %s", out.String())
	}
}

func TestAnchorConfigVerifyTruncatedChainCode1(t *testing.T) {
	e := newAnchorEnv(t, 3)
	if err := e.checkpoint(t); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(e.chain)
	ls := bytes.SplitAfter(b, []byte("\n"))
	os.WriteFile(e.chain, bytes.Join(ls[:2], nil), 0o600)
	if c := code(e.verify(&bytes.Buffer{}, "-anchor-config", e.cfg)); c != 1 {
		t.Fatalf("усечённая цепочка: код %d, ожидался 1", c)
	}
}

func TestAnchorConfigVerifyRewrittenChainCode1(t *testing.T) {
	e := newAnchorEnv(t, 3)
	if err := e.checkpoint(t); err != nil {
		t.Fatal(err)
	}
	// Полная замена цепочки той же длины другими записями (тем же ключом).
	os.Remove(e.chain)
	var out bytes.Buffer
	for i := 0; i < 3; i++ {
		if err := run([]string{"append", "-chain", e.chain, "-id", "agent-1", "-key", e.priv}, bytes.NewReader(record(t, fmt.Sprintf("other-%d", i))), &out); err != nil {
			t.Fatal(err)
		}
	}
	if c := code(e.verify(&bytes.Buffer{}, "-anchor-config", e.cfg)); c != 1 {
		t.Fatalf("переписанная цепочка: код %d, ожидался 1", c)
	}
}

func TestAnchorAndAnchorConfigMutuallyExclusive(t *testing.T) {
	e := newAnchorEnv(t, 1)
	dir := filepath.Join(e.dir, "a")
	os.Mkdir(dir, 0o755)
	for _, args := range [][]string{
		{"checkpoint", "-chain", e.chain, "-id", "agent-1", "-key", e.priv, "-anchor", dir, "-anchor-config", e.cfg},
		{"verify", "-chain", e.chain, "-pub", e.pub, "-id", "agent-1", "-anchor", dir, "-anchor-config", e.cfg},
	} {
		if c := code(run(args, nil, &bytes.Buffer{})); c != 2 {
			t.Errorf("%v: код %d, ожидался 2", args[0], c)
		}
	}
	if len(e.fk.Keys()) != 0 {
		t.Error("при ошибке аргументов что-то записано в S3")
	}
}

func TestAnchorConfigBadInputsCode2(t *testing.T) {
	e := newAnchorEnv(t, 1)
	write := func(s string) string {
		p := filepath.Join(e.dir, "bad.json")
		os.WriteFile(p, []byte(s), 0o600)
		return p
	}
	cases := map[string]string{
		"файла нет":        filepath.Join(e.dir, "nope.json"),
		"мусор":            write("{"),
		"неизвестное поле": write(`{"kind":"dir","dir":"/a","zzz":1}`),
		"kind неизвестный": write(`{"kind":"ftp"}`),
		"s3 без retention": write(`{"kind":"s3","s3":{"endpoint":"https://x","region":"r","bucket":"b"}}`),
	}
	for name, p := range cases {
		if c := code(run([]string{"checkpoint", "-chain", e.chain, "-id", "agent-1", "-key", e.priv, "-anchor-config", p}, nil, &bytes.Buffer{})); c != 2 {
			t.Errorf("%s: код %d, ожидался 2", name, c)
		}
	}
	// без ключей доступа к S3
	t.Setenv("AEGIS_AUDIT_S3_ACCESS_KEY_ID_FILE", "")
	if c := code(e.checkpoint(t)); c != 2 {
		t.Errorf("без ключей: код %d, ожидался 2", c)
	}
}

func TestAnchorConfigCheckpointStoreUnavailable(t *testing.T) {
	e := newAnchorEnv(t, 2)
	e.fk.FailNext(500)
	err := e.checkpoint(t)
	if err == nil {
		t.Fatal("ошибка ожидалась")
	}
	if strings.Contains(err.Error(), "секретное") {
		t.Error("тело ответа утекло в ошибку")
	}
	if c := code(err); c != 2 {
		t.Errorf("код %d, ожидался 2 (ошибка хранилища)", c)
	}
}

func TestAnchorConfigVerifyStoreUnavailableCode1(t *testing.T) {
	e := newAnchorEnv(t, 2)
	if err := e.checkpoint(t); err != nil {
		t.Fatal(err)
	}
	e.fk.FailNext(503)
	if c := code(e.verify(&bytes.Buffer{}, "-anchor-config", e.cfg)); c != 1 {
		t.Fatalf("код %d, ожидался 1 (ошибка загрузки checkpoint'ов при verify)", c)
	}
}

func TestAnchorConfigDirKind(t *testing.T) {
	e := newAnchorEnv(t, 2)
	ad := filepath.Join(e.dir, "adir")
	os.Mkdir(ad, 0o755)
	cfg := filepath.Join(e.dir, "dir.json")
	b, _ := json.Marshal(map[string]any{"kind": "dir", "dir": ad})
	os.WriteFile(cfg, b, 0o600)
	if err := run([]string{"checkpoint", "-chain", e.chain, "-id", "agent-1", "-key", e.priv, "-anchor-config", cfg}, nil, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := e.verify(&out, "-anchor-config", cfg); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"checkpoints_checked": 1`) {
		t.Fatalf("verify: %s", out.String())
	}
}

func TestVerifyAnchorConfigRequiresIDAndValidConfig(t *testing.T) {
	e := newAnchorEnv(t, 1)
	if err := e.checkpoint(t); err != nil {
		t.Fatal(err)
	}
	if c := code(run([]string{"verify", "-chain", e.chain, "-pub", e.pub, "-anchor-config", e.cfg}, nil, &bytes.Buffer{})); c != 2 {
		t.Errorf("без -id: код %d, ожидался 2", c)
	}
	bad := filepath.Join(e.dir, "bad.json")
	os.WriteFile(bad, []byte(`{"kind":"ftp"}`), 0o600)
	if c := code(e.verify(&bytes.Buffer{}, "-anchor-config", bad)); c != 2 {
		t.Errorf("плохая конфигурация: код %d, ожидался 2", c)
	}
	// -anchor DIR без -id по-прежнему код 2
	if c := code(run([]string{"verify", "-chain", e.chain, "-pub", e.pub, "-anchor", e.dir}, nil, &bytes.Buffer{})); c != 2 {
		t.Errorf("-anchor без -id: код %d", c)
	}
}
