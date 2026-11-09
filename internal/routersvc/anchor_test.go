package routersvc

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/limpjungle/aegis3311/internal/audit"
	"github.com/limpjungle/aegis3311/internal/audit/worm"
	"github.com/limpjungle/aegis3311/internal/killswitch/s3/s3test"
)

// withS3 включает audit.anchor kind=s3 на фейке; возвращает фейк.
func (f *fixture) withS3(t *testing.T) *s3test.Fake {
	t.Helper()
	fk, c := s3test.New(t)
	ca := filepath.Join(f.dir, "ca.pem")
	must(t, os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fk.Srv.Certificate().Raw}), 0o600))
	f.cfg.Audit.Anchor = &AnchorConfig{Kind: "s3", Interval: "20ms", MaxLag: "1h", S3: worm.Config{
		Endpoint: fk.Srv.URL, Region: s3test.Region, Bucket: s3test.Bucket, Prefix: "aud/", CAFile: ca, PathStyle: true,
		Retention: "24h", Timeout: "2s"}}
	f.env[AnchorAccessKeyEnv] = c.Creds.AccessKeyIDFile
	f.env[AnchorSecretKeyEnv] = c.Creds.SecretKeyFile
	return fk
}

func (f *fixture) dataEntries(t *testing.T) []string {
	t.Helper()
	es, err := os.ReadDir(filepath.Join(f.dir, "data"))
	must(t, err)
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out
}

func TestOpenAnchorUnavailableFailClosedNoFiles(t *testing.T) {
	for name, brk := range map[string]func(*s3test.Fake){
		"http 500":      func(fk *s3test.Fake) { fk.FailNext(500) },
		"сервер закрыт": func(fk *s3test.Fake) { fk.Srv.Close() },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			fk := f.withS3(t)
			brk(fk)
			_, err := f.open(true)
			if !errors.Is(err, ErrAnchorUnavailable) {
				t.Fatalf("ожидался ErrAnchorUnavailable: %v", err)
			}
			if Classify(err) != ClassFailClosed {
				t.Errorf("класс %d", Classify(err))
			}
			if strings.Contains(err.Error(), "секретное") || strings.Contains(f.log.String(), "секретное") {
				t.Error("тело ответа попало в ошибку или лог")
			}
			if es := f.dataEntries(t); len(es) != 0 {
				t.Fatalf("созданы файлы: %v", es)
			}
			if Hint(err) == "" {
				t.Error("нет подсказки оператору")
			}
		})
	}
}

func TestServeAnchorsHeadAndReopens(t *testing.T) {
	f := newFixture(t)
	fk := f.withS3(t)
	rt := f.mustOpen(true)
	if rt.Anchorer == nil {
		t.Fatal("Anchorer не создан")
	}
	req, _, err := ParseRequest(requestJSON("hybrid"))
	must(t, err)
	if _, rerr := rt.Router.Route(context.Background(), req); rerr != nil {
		t.Fatal(rerr)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- rt.Serve(ctx) }()
	waitFor(t, "anchor", func() bool {
		return rt.Anchorer.Status().AnchoredSeq == rt.Writer.Head().Seq && rt.Writer.Head().Seq > 0
	})
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Serve: %v", err)
	}
	head := rt.Writer.Head().Seq
	must(t, rt.Close())
	if len(fk.Keys()) == 0 {
		t.Fatal("в S3 нет checkpoint'ов")
	}
	last := fk.Keys()[len(fk.Keys())-1]
	if !strings.HasSuffix(last, "/cp/"+pad(head)+".json") {
		t.Errorf("последний ключ %s, голова %d", last, head)
	}
	if !strings.Contains(f.log.String(), "audit_anchor_ok") {
		t.Errorf("нет audit_anchor_ok")
	}
	// Повторное открытие проходит сверку.
	rt2 := f.mustOpen(true)
	an, _, _ := rt2.Writer.AnchorState()
	if an != head {
		t.Errorf("anchoredSeq после открытия %d, ожидалось %d", an, head)
	}
	rt2.Close()
}

func pad(n uint64) string {
	s := []byte("00000000000000000000")
	for i := len(s) - 1; n > 0; i-- {
		s[i] = byte('0' + n%10)
		n /= 10
	}
	return string(s)
}

func anchoredFixture(t *testing.T) (*fixture, *s3test.Fake, []byte) {
	t.Helper()
	f := newFixture(t)
	fk := f.withS3(t)
	rt := f.mustOpen(true)
	old := fileBytes(t, f.cfg.Audit.Chain) // состояние сразу после создания
	for i := 0; i < 2; i++ {
		_, err := rt.Writer.AppendEvent(&audit.RouterEvent{Schema: audit.RouterEventSchema, EventID: audit.NewEventID(),
			RecordedAt: audit.Timestamp(time.Now()), Kind: "endpoint_down", Endpoint: "inceptron-fp8", Role: "primary",
			Reason: "consecutive_failures", ConsecutiveFailures: 3, Model: "z-ai/glm-5.3-flash-20260826",
			Initiator: audit.Actor{Kind: "system", ID: "llm-router-1"}})
		must(t, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- rt.Serve(ctx) }()
	waitFor(t, "anchor", func() bool { a, h, _ := rt.Writer.AnchorState(); return a == h && h > 0 })
	cancel()
	<-done
	must(t, rt.Close())
	return f, fk, old
}

func TestOpenRollbackRejected(t *testing.T) {
	f, _, old := anchoredFixture(t)
	if len(fileBytes(t, f.cfg.Audit.Chain)) <= len(old) {
		t.Skip("цепочка не выросла")
	}
	must(t, os.WriteFile(f.cfg.Audit.Chain, old, 0o600))
	_, err := f.open(true)
	if err == nil {
		t.Fatal("откат цепочки не обнаружен")
	}
	if Classify(err) != ClassFailClosed || !strings.Contains(err.Error(), "усечен") {
		t.Errorf("ошибка/класс: %v / %d", err, Classify(err))
	}
	// Офлайн-открытие (resume/status/route) тоже сверяется.
	if _, err := f.open(false); err == nil {
		t.Fatal("офлайн-открытие пропустило откат")
	}
}

func TestOpenChainRemovedWithAnchorRejected(t *testing.T) {
	f, _, _ := anchoredFixture(t)
	must(t, os.Remove(f.cfg.Audit.Chain))
	if _, err := f.open(true); err == nil {
		t.Fatal("пустая цепочка при существующих checkpoint'ах открыта (chain_lost не должен маскировать удаление)")
	}
}

func TestOpenRewrittenHeadRejected(t *testing.T) {
	f, fk, _ := anchoredFixture(t)
	// В S3 появляется вторая версия последнего seq с другим хешем (подпись валидна тем же ключом).
	keys := fk.Keys()
	last := keys[len(keys)-1]
	vs := fk.Versions(last)
	var cp audit.Checkpoint
	must(t, json.Unmarshal(bytes.TrimSpace(vs[len(vs)-1].Body), &cp))
	forged, err := audit.SignCheckpoint(audit.Head{ChainID: cp.ChainID, Seq: cp.Seq, Hash: "sha256:" + strings.Repeat("a", 64)}, time.Now(), f.secrets().Signer)
	must(t, err)
	a, err := f.cfg.Audit.Anchor.Store(f.secrets().AnchorCreds, nil)
	must(t, err)
	must(t, a.Put(forged))
	if _, err := f.open(true); err == nil {
		t.Fatal("поддельная версия checkpoint принята")
	}
}

func TestOpenDeleteMarkerRejected(t *testing.T) {
	f, fk, _ := anchoredFixture(t)
	keys := fk.Keys()
	fk.AddDeleteMarker(keys[len(keys)-1])
	_, err := f.open(true)
	if !errors.Is(err, ErrAnchorUnavailable) {
		t.Fatalf("delete marker: %v", err)
	}
}

func TestDirAnchorKind(t *testing.T) {
	f := newFixture(t)
	dir := filepath.Join(f.dir, "anchor")
	must(t, os.Mkdir(dir, 0o700))
	f.cfg.Audit.Anchor = &AnchorConfig{Kind: "dir", Dir: dir, Interval: "20ms"}
	rt := f.mustOpen(true)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- rt.Serve(ctx) }()
	waitFor(t, "anchor", func() bool { a, h, _ := rt.Writer.AnchorState(); return a == h && h > 0 })
	cancel()
	<-done
	rt.Close()
	cps, err := audit.DirAnchor{Dir: dir}.LoadCheckpoints(f.cfg.Audit.ChainID)
	if err != nil || len(cps) == 0 {
		t.Fatalf("checkpoint'ы: %v %v", cps, err)
	}
}

func TestAnchorDisabledKeepsOldBehavior(t *testing.T) {
	f := newFixture(t)
	rt := f.mustOpen(true)
	defer rt.Close()
	if rt.Anchorer != nil {
		t.Error("Anchorer при выключенном anchor")
	}
	if !strings.Contains(f.log.String(), "audit_anchor_disabled") {
		t.Errorf("нет audit_anchor_disabled: %s", f.log.String())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := rt.Serve(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestS3KindWithoutCredsIsConfigError(t *testing.T) {
	f := newFixture(t)
	f.withS3(t)
	delete(f.env, AnchorAccessKeyEnv)
	_, err := f.open(true)
	var ce *ConfigError
	if !errors.As(err, &ce) || Classify(err) != ClassUsage {
		t.Fatalf("%v", err)
	}
	if es := f.dataEntries(t); len(es) != 0 {
		t.Fatalf("созданы файлы: %v", es)
	}
}

func TestLoadAnchorCreds(t *testing.T) {
	env := map[string]string{AnchorAccessKeyEnv: "/a", AnchorSecretKeyEnv: "/s", AnchorSessionTokenEnv: "/t"}
	c := LoadAnchorCreds(func(k string) string { return env[k] })
	if c.AccessKeyIDFile != "/a" || c.SecretKeyFile != "/s" || c.SessionTokenFile != "/t" {
		t.Fatalf("%+v", c)
	}
	if AnchorAccessKeyEnv != "AEGIS_AUDIT_S3_ACCESS_KEY_ID_FILE" || AnchorSecretKeyEnv != "AEGIS_AUDIT_S3_SECRET_KEY_FILE" ||
		AnchorSessionTokenEnv != "AEGIS_AUDIT_S3_SESSION_TOKEN_FILE" {
		t.Error("имена переменных окружения изменились")
	}
}

func cfgWithAnchor(anchor string) string {
	return `{"router_id":"r-1","state_path":"/tmp/x/state","audit":{"chain":"/tmp/x/chain","chain_id":"c-1","anchor":` + anchor + `}}`
}

func TestConfigAnchorValidation(t *testing.T) {
	s3ok := `{"kind":"s3","s3":{"endpoint":"https://s3.example","region":"r","bucket":"b","prefix":"p/","retention":"8760h"}}`
	good := []string{
		s3ok,
		`{"kind":"dir","dir":"/var/anchor"}`,
		`{"kind":"dir","dir":"/var/anchor","interval":"1m","max_lag":"2h"}`,
		`null`,
	}
	for _, a := range good {
		if _, err := LoadConfig(writeCfg(t, cfgWithAnchor(a))); err != nil {
			t.Errorf("%s: %v", a, err)
		}
	}
	bad := map[string]string{
		"неизвестное поле":  `{"kind":"dir","dir":"/a","bogus":1}`,
		"неизвестное в s3":  `{"kind":"s3","s3":{"endpoint":"https://x","region":"r","bucket":"b","retention":"1h","zzz":1}}`,
		"дубль ключа":       `{"kind":"dir","kind":"dir","dir":"/a"}`,
		"kind пуст":         `{}`,
		"kind неизвестный":  `{"kind":"ftp"}`,
		"dir относительный": `{"kind":"dir","dir":"a/b"}`,
		"dir пуст":          `{"kind":"dir"}`,
		"dir + s3":          `{"kind":"dir","dir":"/a","s3":{"bucket":"b"}}`,
		"s3 + dir":          `{"kind":"s3","dir":"/a","s3":{"endpoint":"https://x","region":"r","bucket":"b","retention":"1h"}}`,
		"s3 без retention":  `{"kind":"s3","s3":{"endpoint":"https://x","region":"r","bucket":"b"}}`,
		"s3 пустой":         `{"kind":"s3"}`,
		"s3 плохой prefix":  `{"kind":"s3","s3":{"endpoint":"https://x","region":"r","bucket":"b","retention":"1h","prefix":"../x/"}}`,
		"interval мусор":    `{"kind":"dir","dir":"/a","interval":"5 минут"}`,
		"interval 0":        `{"kind":"dir","dir":"/a","interval":"0s"}`,
		"interval < 0":      `{"kind":"dir","dir":"/a","interval":"-1m"}`,
		"max_lag мусор":     `{"kind":"dir","dir":"/a","max_lag":"x"}`,
		"max_lag 0":         `{"kind":"dir","dir":"/a","max_lag":"0"}`,
		"anchor не объект":  `"s3"`,
	}
	for name, a := range bad {
		if _, err := LoadConfig(writeCfg(t, cfgWithAnchor(a))); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
}

func TestAnchorPolicyDefaults(t *testing.T) {
	p, err := AnchorConfig{Kind: "dir", Dir: "/a"}.Policy()
	if err != nil || p.Interval != 5*time.Minute || p.MaxLag != time.Hour {
		t.Fatalf("%+v %v", p, err)
	}
	p, err = AnchorConfig{Interval: "30s", MaxLag: "10m"}.Policy()
	if err != nil || p.Interval != 30*time.Second || p.MaxLag != 10*time.Minute {
		t.Fatalf("%+v %v", p, err)
	}
}
