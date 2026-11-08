package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/limpjungle/aegis3311/internal/audit"
	"github.com/limpjungle/aegis3311/internal/killswitch"
)

// fakeCloud — ConfigMap (PATCH/GET) и S3 (GET/PUT, формат SigV4) на одном TLS-сервере.
type fakeCloud struct {
	mu          sync.Mutex
	cm          string
	hasCM       bool
	objects     map[string][]byte
	patches     int
	puts        int
	failS3      bool
	garbleCMGet bool // GET ConfigMap отвечает 200 с телом, не являющимся JSON
	failS3Get   bool // GET объекта отвечает 500 (PUT работает)
}

func (f *fakeCloud) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	if r.URL.Path == "/api/v1/namespaces/aegisops-control/configmaps/kill-switch" {
		if r.Header.Get("Authorization") != "Bearer kube-token" {
			w.WriteHeader(401)
			return
		}
		switch r.Method {
		case "PATCH":
			var b struct{ Data map[string]string }
			json.Unmarshal(body, &b)
			f.cm, f.hasCM = b.Data["document"], true
			f.patches++
		case "GET":
			if f.garbleCMGet {
				w.Write([]byte("<html>gateway"))
				return
			}
			if !f.hasCM {
				json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{}})
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"document": f.cm}})
		}
		return
	}
	if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=AKIDW/") || f.failS3 {
		w.WriteHeader(403)
		return
	}
	if f.failS3Get && r.Method == "GET" {
		w.WriteHeader(500)
		return
	}
	switch r.Method {
	case "GET":
		b, ok := f.objects[r.URL.Path]
		if !ok {
			w.WriteHeader(404)
			return
		}
		w.Write(b)
	case "PUT":
		f.objects[r.URL.Path] = body
		f.puts++
	}
}

func (f *fakeCloud) oob() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return string(f.objects["/ks-bucket/kill-switch.json"])
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type rig struct {
	t     *testing.T
	cloud *fakeCloud
	cfg   string
	dir   string
	clk   *clock
	keys  map[string]string // имя → приватный ключ
}

func newRig(t *testing.T) *rig {
	d := t.TempDir()
	cloud := &fakeCloud{objects: map[string][]byte{}}
	srv := httptest.NewTLSServer(cloud)
	t.Cleanup(srv.Close)
	ca := filepath.Join(d, "ca.pem")
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600)
	r := &rig{t: t, cloud: cloud, dir: d, clk: &clock{t: time.Date(2026, 11, 8, 10, 20, 0, 0, time.UTC)}, keys: map[string]string{}}
	var keys []map[string]any
	for _, k := range []struct{ n, role string }{{"ivanov", "oncall"}, {"petrov", "oncall"}, {"sidorov", "oncall"}, {"renewer-a", "renewer"}, {"renewer-b", "renewer"}} {
		priv, pub := filepath.Join(d, k.n+".pem"), filepath.Join(d, k.n+".pub.pem")
		if _, err := audit.GenerateKey(priv, pub); err != nil {
			t.Fatal(err)
		}
		r.keys[k.n] = priv
		keys = append(keys, map[string]any{"path": pub, "issuer": k.n, "role": k.role})
	}
	cfg, _ := json.Marshal(map[string]any{"keys": keys,
		"configmap": map[string]any{"api_url": srv.URL, "ca_file": ca},
		"oob":       map[string]any{"endpoint": srv.URL, "region": "ru-central1", "bucket": "ks-bucket", "key": "kill-switch.json", "path_style": true, "ca_file": ca},
		"renew":     map[string]any{"slot": "1h", "ttl": "6h", "prefix": "renew/"}, "timeout": "5s"})
	r.cfg = filepath.Join(d, "ks.json")
	os.WriteFile(r.cfg, cfg, 0o600)
	return r
}

func (r *rig) run(args ...string) (stdout, stderr string, code int) {
	r.t.Helper()
	files := map[string]string{"AEGIS_KILLSWITCH_KUBE_TOKEN_FILE": "kube-token", "AEGIS_KILLSWITCH_S3_ACCESS_KEY_ID_FILE": "AKIDW", "AEGIS_KILLSWITCH_S3_SECRET_KEY_FILE": "secret"}
	env := map[string]string{}
	for k, v := range files {
		p := filepath.Join(r.dir, strings.ToLower(k))
		os.WriteFile(p, []byte(v+"\n"), 0o600)
		env[k] = p
	}
	var o, e bytes.Buffer
	err := run(context.Background(), append(args[:1:1], append([]string{"-config", r.cfg}, args[1:]...)...),
		env_{getenv: func(k string) string { return env[k] }, stdout: &o, stderr: &e, now: r.clk.now})
	code = 0
	if err != nil {
		code = 2
		if ee, ok := err.(exitError); ok {
			code = ee.code
		}
	}
	return o.String(), e.String(), code
}

type env_ = env

func (r *rig) key(n string) string { return r.keys[n] }

func TestStopPublishesIdenticalBytes(t *testing.T) {
	r := newRig(t)
	out, _, code := r.run("stop", "-key", r.key("ivanov"), "-cluster", "prod-eu-1")
	if code != 0 {
		t.Fatalf("код %d: %s", code, out)
	}
	if r.cloud.cm == "" || r.cloud.cm != r.cloud.oob() {
		t.Errorf("байты в каналах различаются:\n%s\n%s", r.cloud.cm, r.cloud.oob())
	}
	var res struct {
		Channels []chanResult `json:"channels"`
		Signers  []string     `json:"signers"`
	}
	json.Unmarshal([]byte(out), &res)
	if len(res.Channels) != 2 || !res.Channels[0].ReadBackMatch || !res.Channels[1].ReadBackMatch || len(res.Signers) != 1 || res.Signers[0] != "ivanov" {
		t.Errorf("итог: %s", out)
	}
	// только oob: ConfigMap не трогается
	before := r.cloud.patches
	if _, _, code := r.run("stop", "-key", r.key("petrov"), "-global", "-channels", "oob"); code != 0 || r.cloud.patches != before {
		t.Errorf("oob-only: код %d, patches %d→%d", code, before, r.cloud.patches)
	}
	if _, _, code := r.run("stop", "-key", r.key("ivanov")); code != 2 {
		t.Errorf("stop без эффекта: код %d", code)
	}
	if _, _, code := r.run("stop", "-key", r.key("ivanov"), "-action", "no.such"); code != 2 {
		t.Errorf("неизвестное действие: код %d", code)
	}
}

func TestStopOutIsOffline(t *testing.T) {
	r := newRig(t)
	r.cloud.failS3 = true
	f := filepath.Join(r.dir, "stop.json")
	if _, _, code := r.run("stop", "-key", r.key("ivanov"), "-global", "-out", f); code != 0 {
		t.Fatalf("код %d", code)
	}
	if b, err := os.ReadFile(f); err != nil || !bytes.Contains(b, []byte(`"global":true`)) || r.cloud.patches != 0 || r.cloud.puts != 0 {
		t.Errorf("файл %q %v, patches=%d puts=%d", b, err, r.cloud.patches, r.cloud.puts)
	}
}

func TestReleaseCosignPublish(t *testing.T) {
	r := newRig(t)
	rel := filepath.Join(r.dir, "release.json")
	if _, _, code := r.run("release", "-key", r.key("ivanov"), "-out", rel); code != 0 || r.cloud.patches != 0 || r.cloud.puts != 0 {
		t.Fatalf("release: код %d, публикаций %d/%d", code, r.cloud.patches, r.cloud.puts)
	}
	if _, _, code := r.run("release", "-key", r.key("renewer-a"), "-out", rel+"2"); code != 2 {
		t.Errorf("release ключом renewer: код %d", code)
	}
	// тем же ключом и publish с одной подписью отказывают
	if _, _, code := r.run("cosign", "-key", r.key("ivanov"), "-in", rel, "-publish"); code != 1 {
		t.Errorf("cosign тем же ключом: код %d", code)
	}
	if _, _, code := r.run("publish", "-in", rel); code != 1 {
		t.Errorf("publish с одной подписью: код %d", code)
	}
	// renewer как вторая подпись run не считается
	if _, _, code := r.run("cosign", "-key", r.key("renewer-a"), "-in", rel, "-publish"); code != 1 {
		t.Errorf("cosign renewer: код %d", code)
	}
	out, errs, code := r.run("cosign", "-key", r.key("petrov"), "-in", rel, "-publish")
	if code != 0 || r.cloud.cm == "" || r.cloud.cm != r.cloud.oob() {
		t.Fatalf("cosign -publish: код %d\n%s\n%s", code, out, errs)
	}
	if !strings.Contains(errs, "content_sha256") || !strings.Contains(errs, "ivanov") {
		t.Errorf("сводка: %s", errs)
	}
	st, _, code := r.run("status", "-cluster", "prod-eu-1")
	if code != 0 || !strings.Contains(st, `"stopped": false`) {
		t.Errorf("status: код %d\n%s", code, st)
	}
}

func TestPublishReleaseOlderThanStopAndTainted(t *testing.T) {
	r := newRig(t)
	rel := filepath.Join(r.dir, "release.json")
	r.run("release", "-key", r.key("ivanov"), "-out", rel)
	signed := filepath.Join(r.dir, "release2.json")
	if _, _, code := r.run("cosign", "-key", r.key("petrov"), "-in", rel, "-out", signed); code != 0 {
		t.Fatal("cosign -out")
	}
	r.clk.add(time.Second)
	if _, _, code := r.run("stop", "-key", r.key("sidorov"), "-global"); code != 0 {
		t.Fatal("stop")
	}
	if _, _, code := r.run("publish", "-in", signed); code != 1 {
		t.Errorf("release старше stop: код %d", code)
	}
	// запятнанный: добавляем подпись незнакомого ключа
	b, _ := os.ReadFile(signed)
	var d killswitch.Document
	json.Unmarshal(b, &d)
	other := filepath.Join(r.dir, "other.pem")
	audit.GenerateKey(other, other+".pub")
	sg, _ := audit.LoadPrivateKey(other)
	sig, _ := killswitch.SignatureFor(d, sg, "evil")
	d, _ = killswitch.AddSignature(d, sig)
	tainted := filepath.Join(r.dir, "tainted.json")
	os.WriteFile(tainted, killswitch.Marshal(d), 0o600)
	if _, _, code := r.run("publish", "-in", tainted); code != 1 {
		t.Errorf("publish запятнанного: код %d", code)
	}
	if _, _, code := r.run("cosign", "-key", r.key("sidorov"), "-in", tainted, "-publish"); code != 1 {
		t.Errorf("cosign запятнанного: код %d", code)
	}
}

func TestRenewFlow(t *testing.T) {
	r := newRig(t)
	rel := filepath.Join(r.dir, "release.json")
	r.run("release", "-key", r.key("ivanov"), "-out", rel)
	r.run("cosign", "-key", r.key("petrov"), "-in", rel, "-publish")
	r.clk.add(2 * time.Hour)
	out, _, code := r.run("renew", "-key", r.key("renewer-a"))
	if code != 0 || !strings.Contains(out, "waiting_peer") {
		t.Fatalf("первый renewer: код %d\n%s", code, out)
	}
	r.clk.add(time.Minute)
	out, _, code = r.run("renew", "-key", r.key("renewer-b"))
	if code != 0 || !strings.Contains(out, `"published"`) || r.cloud.cm != r.cloud.oob() {
		t.Fatalf("второй renewer: код %d\n%s", code, out)
	}
	if out, _, code = r.run("renew", "-key", r.key("renewer-a")); code != 0 || !strings.Contains(out, "up_to_date") {
		t.Errorf("повтор: код %d\n%s", code, out)
	}
	// stop блокирует продление
	r.clk.add(time.Second)
	r.run("stop", "-key", r.key("sidorov"), "-cluster", "prod-eu-1")
	r.clk.add(time.Hour)
	if _, _, code := r.run("renew", "-key", r.key("renewer-a")); code != 1 {
		t.Errorf("renew при stop: код %d", code)
	}
	if _, _, code := r.run("renew", "-key", r.key("ivanov")); code != 1 && code != 2 {
		t.Errorf("renew ключом oncall: код %d", code)
	}
}

func TestUsageErrors(t *testing.T) {
	r := newRig(t)
	for _, args := range [][]string{{"nope"}, {"stop"}, {"release", "-key", r.key("ivanov")}, {"cosign", "-key", r.key("ivanov")},
		{"stop", "-key", "/нет", "-global"}, {"status", "-channels", "x"}} {
		if _, _, code := r.run(args...); code != 2 {
			t.Errorf("%v: код %d", args, code)
		}
	}
	// ключ не из keyring → 2
	other := filepath.Join(r.dir, "x.pem")
	audit.GenerateKey(other, other+".pub")
	if _, _, code := r.run("stop", "-key", other, "-global"); code != 2 {
		t.Errorf("чужой ключ: код %d", code)
	}
	// сбой канала → 1
	r.cloud.failS3 = true
	if _, _, code := r.run("stop", "-key", r.key("ivanov"), "-global"); code != 1 {
		t.Errorf("сбой S3: код %d", code)
	}
}
