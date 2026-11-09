package worm

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/limpjungle/aegis3311/internal/audit"
	"github.com/limpjungle/aegis3311/internal/killswitch/s3"
	"github.com/limpjungle/aegis3311/internal/killswitch/s3/s3test"
)

const chainID = "chain-worm"

var t0 = time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)

type env struct {
	f *s3test.Fake
	a *S3Anchor
	s *audit.Ed25519Signer
	k audit.Keyring
}

func newEnv(t *testing.T) *env {
	t.Helper()
	f, c := s3test.New(t)
	a := &S3Anchor{C: c, Prefix: "aud/", Retention: 24 * time.Hour, Timeout: 5 * time.Second, Now: func() time.Time { return t0 }}
	_, priv, err := ed25519Key()
	if err != nil {
		t.Fatal(err)
	}
	s := audit.NewEd25519Signer(priv)
	k := audit.Keyring{}
	k.Add(s.Public())
	return &env{f, a, s, k}
}

// chain строит цепочку из n событий и возвращает путь, writer и checkpoint'ы каждой головы 1..n.
func (e *env) chain(t *testing.T, n int) (string, []audit.Checkpoint) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "c.jsonl")
	w, err := audit.OpenWriter(path, chainID, e.s, e.k)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	var cps []audit.Checkpoint
	for i := 0; i < n; i++ {
		ev := &audit.RouterEvent{}
		*ev = mkEvent(i)
		if _, err := w.AppendEvent(ev); err != nil {
			t.Fatal(err)
		}
		cp, err := w.Checkpoint()
		if err != nil {
			t.Fatal(err)
		}
		cps = append(cps, cp)
	}
	return path, cps
}

func (e *env) verify(t *testing.T, path string, cps []audit.Checkpoint) error {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = audit.Verify(bytes.NewReader(b), e.k, audit.VerifyOptions{ChainID: chainID, Checkpoints: cps})
	return err
}

func key(seq uint64) string { return fmt.Sprintf("aud/%s/cp/%020d.json", chainID, seq) }

func TestPutSetsComplianceLockAndMD5(t *testing.T) {
	e := newEnv(t)
	e.f.RequireMD5 = true
	_, cps := e.chain(t, 2)
	if err := e.a.Put(cps[1]); err != nil {
		t.Fatal(err)
	}
	vs := e.f.Versions(key(2))
	if len(vs) != 1 {
		t.Fatalf("версий %d, ключи %v", len(vs), e.f.Keys())
	}
	v := vs[0]
	if v.Lock.Get("x-amz-object-lock-mode") != "COMPLIANCE" {
		t.Errorf("mode %q", v.Lock.Get("x-amz-object-lock-mode"))
	}
	if got, want := v.Lock.Get("x-amz-object-lock-retain-until-date"), t0.Add(24*time.Hour).Format(time.RFC3339); got != want {
		t.Errorf("retain-until %q, ожидалось %q", got, want)
	}
	if !bytes.HasSuffix(v.Body, []byte("}\n")) || bytes.Count(v.Body, []byte("\n")) != 1 {
		t.Errorf("тело: %q", v.Body)
	}
	sum := md5.Sum(v.Body)
	reqs := e.f.Requests()
	md := reqs[len(reqs)-1].Header.Get("Content-MD5")
	if md != base64.StdEncoding.EncodeToString(sum[:]) {
		t.Errorf("Content-MD5 %q", md)
	}
	if ct := reqs[len(reqs)-1].Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type %q", ct)
	}
}

func TestPutLoadVerify(t *testing.T) {
	e := newEnv(t)
	path, cps := e.chain(t, 3)
	for _, c := range cps {
		if err := e.a.Put(c); err != nil {
			t.Fatal(err)
		}
	}
	all, err := e.a.LoadCheckpoints(chainID)
	if err != nil || len(all) != 3 {
		t.Fatalf("load: %d %v", len(all), err)
	}
	if err := e.verify(t, path, all); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	for _, c := range all {
		if err := audit.VerifyCheckpoint(c, e.k); err != nil {
			t.Errorf("подпись после круга: %v", err)
		}
	}
}

func TestRepeatPutSameSeqTwoVersions(t *testing.T) {
	e := newEnv(t)
	path, cps := e.chain(t, 2)
	for i := 0; i < 2; i++ {
		if err := e.a.Put(cps[1]); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(e.f.Versions(key(2))); n != 2 {
		t.Fatalf("версий %d", n)
	}
	got, err := e.a.LatestCheckpoints(chainID)
	if err != nil || len(got) != 2 {
		t.Fatalf("latest: %d %v", len(got), err)
	}
	if err := e.verify(t, path, got); err != nil {
		t.Fatal(err)
	}
}

func TestLatestLoadsOnlyMaxSeq(t *testing.T) {
	e := newEnv(t)
	_, cps := e.chain(t, 3)
	for _, c := range cps {
		e.a.Put(c)
	}
	e.a.Put(cps[2])
	before := len(e.f.Requests())
	got, err := e.a.LatestCheckpoints(chainID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Seq != 3 || got[1].Seq != 3 {
		t.Fatalf("latest: %+v", got)
	}
	gets := 0
	for _, r := range e.f.Requests()[before:] {
		if r.Method == "GET" && strings.Contains(r.Query, "versionId=") {
			gets++
		}
	}
	if gets != 2 {
		t.Errorf("GET версий: %d, ожидалось 2 (только seq 3)", gets)
	}
}

func TestLatestEmptyIsNewChain(t *testing.T) {
	e := newEnv(t)
	got, err := e.a.LatestCheckpoints(chainID)
	if err != nil || len(got) != 0 {
		t.Fatalf("%v %v", got, err)
	}
}

func TestLatestPagination(t *testing.T) {
	e := newEnv(t)
	e.f.PageSize = 2
	_, cps := e.chain(t, 5)
	for _, c := range cps {
		if err := e.a.Put(c); err != nil {
			t.Fatal(err)
		}
	}
	all, err := e.a.LoadCheckpoints(chainID)
	if err != nil || len(all) != 5 {
		t.Fatalf("%d %v", len(all), err)
	}
	l, err := e.a.LatestCheckpoints(chainID)
	if err != nil || len(l) != 1 || l[0].Seq != 5 {
		t.Fatalf("%+v %v", l, err)
	}
}

func TestDeleteMarkerIsError(t *testing.T) {
	e := newEnv(t)
	_, cps := e.chain(t, 2)
	for _, c := range cps {
		e.a.Put(c)
	}
	e.f.AddDeleteMarker(key(2))
	if _, err := e.a.LatestCheckpoints(chainID); !errors.Is(err, ErrDeleteMarker) {
		t.Fatalf("latest: %v", err)
	}
	if _, err := e.a.LoadCheckpoints(chainID); !errors.Is(err, ErrDeleteMarker) {
		t.Fatalf("load: %v", err)
	}
}

func TestDeleteMarkerOnOlderSeqIsError(t *testing.T) {
	e := newEnv(t)
	_, cps := e.chain(t, 2)
	for _, c := range cps {
		e.a.Put(c)
	}
	e.f.AddDeleteMarker(key(1))
	if _, err := e.a.LatestCheckpoints(chainID); !errors.Is(err, ErrDeleteMarker) {
		t.Fatalf("latest: %v", err)
	}
}

func TestForeignKeyInTemplateDir(t *testing.T) {
	for _, k := range []string{
		"aud/" + chainID + "/cp/readme.txt",
		"aud/" + chainID + "/cp/1.json",
		"aud/" + chainID + "/cp/" + fmt.Sprintf("%020d", 1) + ".json.bak",
		"aud/" + chainID + "/cp/sub/" + fmt.Sprintf("%020d", 1) + ".json",
	} {
		t.Run(k, func(t *testing.T) {
			e := newEnv(t)
			if err := e.a.C.Put(t.Context(), k, []byte("{}"), "application/json"); err != nil {
				t.Fatal(err)
			}
			if _, err := e.a.LatestCheckpoints(chainID); err == nil {
				t.Fatal("ключ вне шаблона принят")
			}
		})
	}
}

func putRaw(t *testing.T, e *env, k string, c audit.Checkpoint) {
	t.Helper()
	b, err := jsonLine(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.a.C.Put(t.Context(), k, b, "application/json"); err != nil {
		t.Fatal(err)
	}
}

func TestSeqOrChainMismatch(t *testing.T) {
	e := newEnv(t)
	_, cps := e.chain(t, 2)
	putRaw(t, e, key(1), cps[1]) // тело seq 2 под ключом seq 1
	if _, err := e.a.LatestCheckpoints(chainID); err == nil {
		t.Fatal("несовпадение seq принято")
	}
	e2 := newEnv(t)
	_, cps2 := e2.chain(t, 1)
	c := cps2[0]
	c.ChainID = "other-chain"
	putRaw(t, e2, key(1), c)
	if _, err := e2.a.LatestCheckpoints(chainID); err == nil {
		t.Fatal("несовпадение chain_id принято")
	}
}

func TestGarbageBodyAndUnknownFields(t *testing.T) {
	for name, body := range map[string]string{
		"мусор":       "not json",
		"лишнее поле": `{"schema":"aegisops/audit-checkpoint/v1","chain_id":"chain-worm","seq":1,"head_hash":"x","created_at":"x","key_id":"x","sig":"x","extra":1}`,
		"дубль ключа": `{"seq":1,"seq":1}`,
		"пустое тело": "",
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			if err := e.a.C.Put(t.Context(), key(1), []byte(body), "application/json"); err != nil {
				t.Fatal(err)
			}
			if _, err := e.a.LatestCheckpoints(chainID); err == nil {
				t.Fatal("ошибка ожидалась")
			}
		})
	}
}

func TestPrefixIsolation(t *testing.T) {
	e := newEnv(t)
	_, cps := e.chain(t, 2)
	e.a.Prefix = "a/"
	if err := e.a.Put(cps[0]); err != nil {
		t.Fatal(err)
	}
	other := &S3Anchor{C: e.a.C, Prefix: "a-b/", Retention: time.Hour, Now: e.a.Now}
	if err := other.Put(cps[1]); err != nil {
		t.Fatal(err)
	}
	got, err := e.a.LatestCheckpoints(chainID)
	if err != nil || len(got) != 1 || got[0].Seq != 1 {
		t.Fatalf("a/ захватил чужое: %+v %v", got, err)
	}
	// чужая цепочка с общим началом chain_id тоже не мешает
	_, c2 := e.chain(t, 1)
	c2[0].ChainID = chainID + "-2"
	e.a.C.Put(t.Context(), "a/"+chainID+"-2/cp/"+fmt.Sprintf("%020d", 1)+".json", []byte("junk"), "application/json")
	if got, err := e.a.LatestCheckpoints(chainID); err != nil || len(got) != 1 {
		t.Fatalf("соседняя цепочка: %+v %v", got, err)
	}
}

func TestServerErrorsNoBodyLeak(t *testing.T) {
	e := newEnv(t)
	_, cps := e.chain(t, 1)
	e.f.FailNext(500)
	err := e.a.Put(cps[0])
	if err == nil || strings.Contains(err.Error(), "секрет") {
		t.Fatalf("put: %v", err)
	}
	e.f.FailNext(503)
	_, err = e.a.LatestCheckpoints(chainID)
	if err == nil || strings.Contains(err.Error(), "секрет") {
		t.Fatalf("list: %v", err)
	}
	// 500 на GET версии (второй запрос после листинга)
	if err := e.a.Put(cps[0]); err != nil {
		t.Fatal(err)
	}
	for _, st := range []int{500, 403} {
		e.f.RawList(nil)
		e.f.FailNext(st)
		if _, err := e.a.LatestCheckpoints(chainID); err == nil || strings.Contains(err.Error(), "секрет") {
			t.Fatalf("status %d: %v", st, err)
		}
	}
}

func TestTimeout(t *testing.T) {
	e := newEnv(t)
	_, cps := e.chain(t, 1)
	e.a.Timeout = 50 * time.Millisecond
	e.f.Delay = 500 * time.Millisecond
	start := time.Now()
	err := e.a.Put(cps[0])
	if err == nil {
		t.Fatal("таймаут ожидался")
	}
	if time.Since(start) > 400*time.Millisecond {
		t.Errorf("таймаут не сработал вовремя: %v", time.Since(start))
	}
	var se *s3.Error
	if !errors.As(err, &se) || se.Kind != "timeout" {
		t.Errorf("ожидался kind timeout: %v", err)
	}
}

func TestRetentionRequired(t *testing.T) {
	e := newEnv(t)
	_, cps := e.chain(t, 1)
	e.a.Retention = 0
	if err := e.a.Put(cps[0]); err == nil {
		t.Fatal("Put без retention")
	}
	if len(e.f.Keys()) != 0 {
		t.Fatal("объект записан без lock")
	}
}

func TestConfigValidate(t *testing.T) {
	ok := Config{Endpoint: "https://s3.example", Region: "r", Bucket: "b", Prefix: "a/b/", Retention: "8760h", Timeout: "5s"}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := map[string]func(*Config){
		"нет retention":    func(c *Config) { c.Retention = "" },
		"retention 0":      func(c *Config) { c.Retention = "0s" },
		"retention <0":     func(c *Config) { c.Retention = "-1h" },
		"retention мусор":  func(c *Config) { c.Retention = "год" },
		"prefix ..":        func(c *Config) { c.Prefix = "a/../b/" },
		"prefix ведущий /": func(c *Config) { c.Prefix = "/a/" },
		"prefix без /":     func(c *Config) { c.Prefix = "a" },
		"prefix //":        func(c *Config) { c.Prefix = "a//b/" },
		"prefix пробел":    func(c *Config) { c.Prefix = "a b/" },
		"prefix ../":       func(c *Config) { c.Prefix = "../" },
		"timeout 0":        func(c *Config) { c.Timeout = "0s" },
		"timeout мусор":    func(c *Config) { c.Timeout = "x" },
		"нет endpoint":     func(c *Config) { c.Endpoint = "" },
		"нет region":       func(c *Config) { c.Region = "" },
		"нет bucket":       func(c *Config) { c.Bucket = "" },
	}
	for name, mut := range bad {
		c := ok
		mut(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: принято", name)
		}
		if _, err := New(c, s3.CredFiles{}, nil); err == nil {
			t.Errorf("%s: New принял", name)
		}
	}
	empty := ok
	empty.Prefix = ""
	if err := empty.Validate(); err != nil {
		t.Errorf("пустой prefix: %v", err)
	}
}

func TestBadChainIDRejected(t *testing.T) {
	e := newEnv(t)
	for _, id := range []string{"", "../x", "a/b", "-x"} {
		if _, err := e.a.LatestCheckpoints(id); err == nil {
			t.Errorf("chain_id %q принят", id)
		}
	}
	e.a.Prefix = "../"
	if _, err := e.a.LatestCheckpoints(chainID); err == nil {
		t.Error("плохой prefix принят при чтении")
	}
}

func TestOpenWriterWithWormTruncationAndRollback(t *testing.T) {
	e := newEnv(t)
	path, cps := e.chain(t, 4)
	for _, c := range cps {
		e.a.Put(c)
	}
	latest, err := e.a.LatestCheckpoints(chainID)
	if err != nil {
		t.Fatal(err)
	}
	w, err := audit.OpenWriterWith(path, chainID, e.s, e.k, audit.WriterOptions{Checkpoints: latest})
	if err != nil {
		t.Fatal(err)
	}
	w.Close()
	b, _ := os.ReadFile(path)
	ls := bytes.SplitAfter(b, []byte("\n"))
	os.WriteFile(path, bytes.Join(ls[:2], nil), 0o600)
	if _, err := audit.OpenWriterWith(path, chainID, e.s, e.k, audit.WriterOptions{Checkpoints: latest}); err == nil {
		t.Fatal("откат цепочки не обнаружен")
	}
}

func TestSessionTokenSignedWhenPresent(t *testing.T) {
	// креды с session token: запрос должен содержать x-amz-security-token и быть подписан (фейк требует подписи x-amz-*).
	e := newEnv(t)
	dir := t.TempDir()
	tok := filepath.Join(dir, "tok")
	os.WriteFile(tok, []byte("token\n"), 0o600)
	e.a.C.Creds.SessionTokenFile = tok
	_, cps := e.chain(t, 1)
	if err := e.a.Put(cps[0]); err != nil {
		t.Fatalf("с session token: %v", err)
	}
	reqs := e.f.Requests()
	if reqs[len(reqs)-1].Header.Get("X-Amz-Security-Token") == "" {
		t.Error("session token не отправлен")
	}
}
