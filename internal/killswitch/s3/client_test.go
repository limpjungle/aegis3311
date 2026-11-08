package s3

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeS3 struct {
	mu      sync.Mutex
	objects map[string][]byte
	auths   []string
	t       *testing.T
	secret  string
	status  int
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	// пересчёт подписи отдельной реализацией (по эталонному алгоритму, независимо от sigv4.go)
	auth := r.Header.Get("Authorization")
	f.auths = append(f.auths, auth)
	host := r.Host
	date := r.Header.Get("x-amz-date")
	canon := strings.Join([]string{r.Method, r.URL.EscapedPath(), r.URL.RawQuery,
		"host:" + host + "\nx-amz-content-sha256:" + r.Header.Get("x-amz-content-sha256") + "\nx-amz-date:" + date + "\n",
		"host;x-amz-content-sha256;x-amz-date", r.Header.Get("x-amz-content-sha256")}, "\n")
	scope := date[:8] + "/ru-central1/s3/aws4_request"
	sts := "AWS4-HMAC-SHA256\n" + date + "\n" + scope + "\n" + sha256Hex([]byte(canon))
	want := "AWS4-HMAC-SHA256 Credential=" + "AK" + "/" + scope + ", SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=" +
		hexOf(hmacSHA256(signingKey(f.secret, date[:8], "ru-central1", "s3"), sts))
	if auth != want || r.Header.Get("x-amz-content-sha256") != sha256Hex(body) {
		w.WriteHeader(403)
		return
	}
	if f.status != 0 {
		w.WriteHeader(f.status)
		w.Write([]byte("секретное тело ответа"))
		return
	}
	key := r.URL.Path
	switch r.Method {
	case "GET":
		b, ok := f.objects[key]
		if !ok {
			w.WriteHeader(404)
			return
		}
		w.Write(b)
	case "PUT":
		if r.Header.Get("Cache-Control") != "no-store" || r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(400)
			return
		}
		f.objects[key] = body
	}
}

func hexOf(b []byte) string {
	const h = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, h[c>>4], h[c&15])
	}
	return string(out)
}

type s3env struct {
	f      *fakeS3
	c      *Client
	srv    *httptest.Server
	dir    string
	secret string
}

func newS3Env(t *testing.T, pathStyle bool) *s3env {
	f := &fakeS3{objects: map[string][]byte{}, t: t, secret: "S3CRET"}
	srv := httptest.NewTLSServer(f)
	t.Cleanup(srv.Close)
	d := t.TempDir()
	ca := filepath.Join(d, "ca.pem")
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600)
	os.WriteFile(filepath.Join(d, "id"), []byte("AK\n"), 0o600)
	os.WriteFile(filepath.Join(d, "sk"), []byte("S3CRET\n"), 0o600)
	var hc Doer
	if pathStyle {
		h, err := NewHTTPClient(ca, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		hc = h
	} else { // virtual-hosted: bucket.host.test → loopback сервера
		h, _ := NewHTTPClient(ca, 2*time.Second)
		tr := h.Transport.(*http.Transport)
		addr := srv.Listener.Addr().String()
		tr.DialContext = func(ctx context.Context, n, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, n, addr)
		}
		tr.TLSClientConfig.ServerName = "127.0.0.1"
		hc = h
	}
	_ = tls.VersionTLS12
	ep := srv.URL
	if !pathStyle {
		ep = "https://s3.test"
	}
	c := &Client{Cfg: Config{Endpoint: ep, Region: "ru-central1", Bucket: "bkt", Key: "kill switch/a.json", PathStyle: pathStyle},
		Creds: CredFiles{AccessKeyIDFile: filepath.Join(d, "id"), SecretKeyFile: filepath.Join(d, "sk")}, HTTP: hc, MaxBytes: 1024,
		Now: func() time.Time { return time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC) }}
	return &s3env{f, c, srv, d, "S3CRET"}
}

func TestClientPutGetPathStyle(t *testing.T) {
	e := newS3Env(t, true)
	ctx := context.Background()
	if _, err := e.c.Get(ctx, e.c.Cfg.Key); err == nil || err.(*Error).Kind != "http_404" {
		t.Fatalf("404: %v", err)
	}
	if err := e.c.Put(ctx, e.c.Cfg.Key, []byte(`{"a":1}`), "application/json"); err != nil {
		t.Fatal(err)
	}
	b, err := e.c.Get(ctx, e.c.Cfg.Key)
	if err != nil || string(b) != `{"a":1}` {
		t.Fatalf("%q %v", b, err)
	}
	if _, ok := e.f.objects["/bkt/kill switch/a.json"]; !ok {
		t.Errorf("объекты: %v", e.f.objects)
	}
}

func TestClientVirtualHosted(t *testing.T) {
	e := newS3Env(t, false)
	if err := e.c.Put(context.Background(), "k.json", []byte("x"), "application/json"); err != nil {
		t.Fatal(err)
	}
	if string(e.f.objects["/k.json"]) != "x" {
		t.Errorf("объекты: %v", e.f.objects)
	}
}

func TestClientErrors(t *testing.T) {
	e := newS3Env(t, true)
	ctx := context.Background()
	e.f.status = 403
	_, err := e.c.Get(ctx, "k")
	var se *Error
	if !errors.As(err, &se) || se.Kind != "http_403" || strings.Contains(err.Error(), "секрет") {
		t.Errorf("403: %v", err)
	}
	e.f.status = 302 // редирект не следуется
	if _, err := e.c.Get(ctx, "k"); !errors.As(err, &se) || se.Kind != "http_302" {
		t.Errorf("302: %v", err)
	}
	e.f.status = 0
	e.f.objects["/bkt/big"] = make([]byte, 2000)
	if _, err := e.c.Get(ctx, "big"); !errors.As(err, &se) || se.Kind != "oversize" {
		t.Errorf("oversize: %v", err)
	}
	cctx, cancel := context.WithTimeout(ctx, time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond)
	if _, err := e.c.Get(cctx, "k"); !errors.As(err, &se) || se.Kind != "timeout" {
		t.Errorf("timeout: %v", err)
	}
	e.c.Cfg.Endpoint = "http://x"
	if _, err := e.c.Get(ctx, "k"); err == nil {
		t.Error("http endpoint принят")
	}
}

func TestClientRereadsCreds(t *testing.T) {
	e := newS3Env(t, true)
	e.f.objects["/bkt/k"] = []byte("v")
	if _, err := e.c.Get(context.Background(), "k"); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(e.dir, "sk"), []byte("ROTATED\n"), 0o600)
	if _, err := e.c.Get(context.Background(), "k"); err == nil {
		t.Error("ротация ключа не подхвачена (ожидался отказ фейка с новым секретом)")
	}
	e.f.secret = "ROTATED"
	if _, err := e.c.Get(context.Background(), "k"); err != nil {
		t.Errorf("после ротации: %v", err)
	}
}
