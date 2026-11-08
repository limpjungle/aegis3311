package killswitch

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/limpjungle/aegis3311/internal/killswitch/s3"
)

func TestFuncSource(t *testing.T) {
	want := errors.New("boom")
	s := FuncSource{Name: "configmap", F: func(context.Context) ([]byte, error) { return []byte("x"), want }}
	if s.Channel() != "configmap" {
		t.Error(s.Channel())
	}
	b, err := s.Fetch(context.Background())
	if string(b) != "x" || !errors.Is(err, want) {
		t.Errorf("%q %v", b, err)
	}
}

func TestStaticGuardAndState(t *testing.T) {
	st := Static{S: State{}}
	st.S.Stopped = true
	if !st.Stopped() || !st.State().Stopped {
		t.Error("Static: Stopped")
	}
	ctx, cancel := st.Guard(context.Background())
	if ctx.Err() != nil {
		t.Error("Static.Guard не должен отменяться сам")
	}
	cancel()
	if ctx.Err() == nil {
		t.Error("cancel Static.Guard не отменил контекст")
	}
	parent, pc := context.WithCancel(context.Background())
	g, gc := st.Guard(parent)
	defer gc()
	pc()
	if g.Err() == nil {
		t.Error("Static.Guard не наследует отмену родителя")
	}
}

func s3Fixture(t *testing.T, h http.HandlerFunc) *s3.Client {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	write := func(n, v string) string {
		p := filepath.Join(dir, n)
		os.WriteFile(p, []byte(v+"\n"), 0o600)
		return p
	}
	hc := srv.Client()
	hc.Transport.(*http.Transport).TLSClientConfig.MinVersion = tls.VersionTLS12
	return &s3.Client{Cfg: s3.Config{Endpoint: srv.URL, Region: "us-east-1", Bucket: "b", Key: "ks.json", PathStyle: true},
		Creds: s3.CredFiles{AccessKeyIDFile: write("id", "AK"), SecretKeyFile: write("sk", "SK")}, HTTP: hc,
		Now: func() time.Time { return t0 }, MaxBytes: MaxDocBytes}
}

func TestS3SourceAndPublisher(t *testing.T) {
	var stored []byte
	var gotPaths []string
	c := s3Fixture(t, func(w http.ResponseWriter, r *http.Request) {
		gotPaths = append(gotPaths, r.Method+" "+r.URL.Path)
		switch r.Method {
		case "GET":
			if stored == nil {
				w.WriteHeader(404)
				return
			}
			w.Write(stored)
		case "PUT":
			stored, _ = io.ReadAll(r.Body)
		}
	})
	src := S3Source(c)
	if src.Channel() != "oob" {
		t.Error(src.Channel())
	}
	_, err := src.Fetch(context.Background())
	var k interface{ ErrKind() string }
	if !errors.As(err, &k) || k.ErrKind() != "http_404" {
		t.Fatalf("404: %v", err)
	}
	if transportClass("http_404") {
		t.Error("404 не транспортная ошибка: кэш должен сбрасываться")
	}
	p := S3Publisher{C: c}
	if p.Name() != "oob" {
		t.Error(p.Name())
	}
	if err := p.Publish(context.Background(), []byte("doc")); err != nil {
		t.Fatal(err)
	}
	b, err := src.Fetch(context.Background())
	if err != nil || string(b) != "doc" {
		t.Fatalf("%q %v", b, err)
	}
	for _, p := range gotPaths {
		if !strings.HasSuffix(p, " /b/ks.json") {
			t.Errorf("путь %q", p)
		}
	}
}

func TestTransportClassTable(t *testing.T) {
	for c, want := range map[string]bool{"timeout": true, "network": true, "http_429": true, "http_500": true, "http_503": true, "http_599": true,
		"http_404": false, "http_401": false, "http_403": false, "http_400": false, "http_301": false, "oversize": false, "decode": false,
		"invalid": false, "http_5000": false, "": false} {
		if transportClass(c) != want {
			t.Errorf("transportClass(%q) != %v", c, want)
		}
	}
}
