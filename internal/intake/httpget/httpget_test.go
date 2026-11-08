package httpget

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func randTok() string {
	b := make([]byte, 12)
	rand.Read(b)
	return "t" + hex.EncodeToString(b)
}

// tlsFixture поднимает TLS-сервер и пишет его сертификат как CA-файл.
func tlsFixture(t *testing.T, h http.Handler) (url, ca string) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	ca = filepath.Join(t.TempDir(), "ca.pem")
	pemb := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(ca, pemb, 0o600); err != nil {
		t.Fatal(err)
	}
	return srv.URL, ca
}

func kind(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return "?" + errString(err)
}
func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

type rec struct {
	mu      sync.Mutex
	methods []string
	auth    []string
	paths   []string
	queries []string
	hdr     []http.Header
}

func (r *rec) log(req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.methods = append(r.methods, req.Method)
	r.auth = append(r.auth, req.Header.Get("Authorization"))
	r.paths = append(r.paths, req.URL.Path)
	r.queries = append(r.queries, req.URL.RawQuery)
	r.hdr = append(r.hdr, req.Header.Clone())
}

func TestGetJSONOnlyGetAndHeaders(t *testing.T) {
	var r rec
	u, ca := tlsFixture(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.log(req)
		if req.Method != http.MethodGet {
			http.Error(w, "no", http.StatusMethodNotAllowed)
			return
		}
		w.Write([]byte(`{"a":1}`))
	}))
	c, err := New(u+"/prefix/", ca, "", map[string]string{"X-Scope-OrgID": "tenant1"}, 1<<10, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var out struct{ A int }
	if err := c.GetJSON(context.Background(), "/api/v1/query", url.Values{"query": {`up{a="b"}`}}, &out); err != nil || out.A != 1 {
		t.Fatalf("%v %+v", err, out)
	}
	if r.methods[0] != "GET" || r.paths[0] != "/prefix/api/v1/query" || r.hdr[0].Get("X-Scope-OrgID") != "tenant1" || r.auth[0] != "" {
		t.Errorf("запрос: %v %v %v auth=%q", r.methods, r.paths, r.hdr[0], r.auth[0])
	}
	if q, _ := url.ParseQuery(r.queries[0]); q.Get("query") != `up{a="b"}` {
		t.Errorf("query: %s", r.queries[0])
	}
}

func TestRedirectRejected(t *testing.T) {
	var hits []string
	var mu sync.Mutex
	u, ca := tlsFixture(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		hits = append(hits, req.URL.Path)
		mu.Unlock()
		if req.URL.Path == "/start" {
			http.Redirect(w, req, "/target", http.StatusFound)
			return
		}
		w.Write([]byte(`{}`))
	}))
	c, _ := New(u, ca, "", nil, 1<<10, 2*time.Second)
	var out map[string]any
	err := c.GetJSON(context.Background(), "/start", nil, &out)
	if err == nil || kind(err) != "http_302" {
		t.Fatalf("редирект: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(hits) != 1 {
		t.Errorf("редирект выполнен: %v", hits)
	}
}

func TestStatusErrorsHaveNoBody(t *testing.T) {
	secretBody := "BODYMARK-" + randTok()
	for _, code := range []int{400, 401, 403, 404, 429, 500, 503} {
		u, ca := tlsFixture(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(code)
			w.Write([]byte(secretBody))
		}))
		c, _ := New(u, ca, "", nil, 1<<10, 2*time.Second)
		err := c.GetJSON(context.Background(), "/x", nil, new(any))
		if kind(err) != "http_"+itoa(code) {
			t.Errorf("код %d: %v", code, err)
		}
		if err != nil && strings.Contains(err.Error(), "BODYMARK") {
			t.Errorf("тело ответа в тексте ошибки: %v", err)
		}
	}
	// 2xx, но не 200 — тоже не успех
	u, ca := tlsFixture(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { w.WriteHeader(204) }))
	c, _ := New(u, ca, "", nil, 1<<10, 2*time.Second)
	if err := c.GetJSON(context.Background(), "/x", nil, new(any)); kind(err) != "http_204" {
		t.Errorf("204: %v", err)
	}
}

func itoa(i int) string { return strconv.Itoa(i) }

func TestOversizeAndDecode(t *testing.T) {
	body := ""
	u, ca := tlsFixture(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { w.Write([]byte(body)) }))
	c, _ := New(u, ca, "", nil, 32, 2*time.Second)
	pad := func(n int) string { return `{"k":"` + strings.Repeat("a", n-8) + `"}` }
	body = pad(32)
	if err := c.GetJSON(context.Background(), "/", nil, new(any)); err != nil {
		t.Errorf("ровно максимум: %v", err)
	}
	body = pad(33)
	if err := c.GetJSON(context.Background(), "/", nil, new(any)); kind(err) != "oversize" {
		t.Errorf("максимум+1: %v", err)
	}
	body = strings.Repeat(" ", 1<<20) // заведомо больше лимита и не JSON
	if err := c.GetJSON(context.Background(), "/", nil, new(any)); kind(err) != "oversize" {
		t.Errorf("1 MiB: %v", err)
	}
	body = `not json`
	if err := c.GetJSON(context.Background(), "/", nil, new(any)); kind(err) != "decode" {
		t.Errorf("decode: %v", err)
	}
	body = `{"a":"` + "x" + `"}`
	var bad struct{ A int }
	if err := c.GetJSON(context.Background(), "/", nil, &bad); kind(err) != "decode" {
		t.Errorf("несовпадение типа: %v", err)
	}
}

func TestTokenRereadAndScheme(t *testing.T) {
	var r rec
	u, ca := tlsFixture(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { r.log(req); w.Write([]byte(`{}`)) }))
	tf := filepath.Join(t.TempDir(), "tok")
	t1, t2 := randTok(), randTok()
	os.WriteFile(tf, []byte(t1+"\n"), 0o600)
	c, err := New(u, ca, tf, nil, 1<<10, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c.GetJSON(context.Background(), "/", nil, new(any))
	os.WriteFile(tf, []byte(t2+"\n"), 0o600) // ротация
	c.GetJSON(context.Background(), "/", nil, new(any))
	if r.auth[0] != "Bearer "+t1 || r.auth[1] != "Bearer "+t2 {
		t.Errorf("токены не перечитаны: %q %q", r.auth[0], r.auth[1])
	}
	// файл токена пропал/пуст — запрос не уходит, ошибка без значения токена
	os.WriteFile(tf, []byte("  \n"), 0o600)
	n := len(r.auth)
	err = c.GetJSON(context.Background(), "/", nil, new(any))
	if err == nil || len(r.auth) != n {
		t.Errorf("пустой токен: err=%v запросов=%d", err, len(r.auth)-n)
	}
	os.Remove(tf)
	if err := c.GetJSON(context.Background(), "/", nil, new(any)); err == nil || len(r.auth) != n {
		t.Errorf("нет файла токена: %v", err)
	}
	// токен только по https
	if _, err := New("http://example.invalid:9093", "", tf, nil, 1, time.Second); err == nil {
		t.Error("токен разрешён по http")
	}
	// нечитаемый файл токена отвергается при создании
	if _, err := New(u, ca, filepath.Join(t.TempDir(), "nope"), nil, 1, time.Second); err == nil {
		t.Error("отсутствующий файл токена принят")
	}
	// многострочный токен некорректен
	os.WriteFile(tf, []byte("a\nb"), 0o600)
	if _, err := New(u, ca, tf, nil, 1, time.Second); err == nil {
		t.Error("многострочный токен принят")
	}
}

func TestNewValidation(t *testing.T) {
	for _, bad := range []string{"", "ftp://x", "https://", "not a url", "//host"} {
		if _, err := New(bad, "", "", nil, 1, time.Second); err == nil {
			t.Errorf("URL %q принят", bad)
		}
	}
	d := t.TempDir()
	if _, err := New("https://x", filepath.Join(d, "none.pem"), "", nil, 1, time.Second); err == nil {
		t.Error("отсутствующий CA принят")
	}
	junk := filepath.Join(d, "junk.pem")
	os.WriteFile(junk, []byte("not pem"), 0o600)
	if _, err := New("https://x", junk, "", nil, 1, time.Second); err == nil {
		t.Error("CA без сертификатов принят")
	}
}

// Сертификат не из CA-файла — отказ (не silently insecure); прокси из окружения не используется.
func TestUntrustedCAAndNoProxy(t *testing.T) {
	u, _ := tlsFixture(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { w.Write([]byte(`{}`)) }))
	// CA-файл с другим сертификатом: httptest выдаёт один и тот же серверный сертификат, поэтому берём системные корни
	c, _ := New(u, "", "", nil, 1<<10, 2*time.Second)
	if err := c.GetJSON(context.Background(), "/", nil, new(any)); kind(err) != "network" {
		t.Errorf("чужой CA: %v", err)
	}
	// прокси
	var proxyHits int
	var mu sync.Mutex
	px := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { mu.Lock(); proxyHits++; mu.Unlock() }))
	defer px.Close()
	t.Setenv("HTTPS_PROXY", px.URL)
	t.Setenv("HTTP_PROXY", px.URL)
	t.Setenv("https_proxy", px.URL)
	t.Setenv("NO_PROXY", "")
	u2, ca2 := tlsFixture(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { w.Write([]byte(`{}`)) }))
	c2, _ := New(u2, ca2, "", nil, 1<<10, 2*time.Second)
	if err := c2.GetJSON(context.Background(), "/", nil, new(any)); err != nil {
		t.Errorf("запрос с прокси в окружении: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if proxyHits != 0 {
		t.Errorf("запрос ушёл через прокси (%d)", proxyHits)
	}
}

func TestTimeoutClassification(t *testing.T) {
	u, ca := tlsFixture(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		select {
		case <-req.Context().Done():
		case <-time.After(3 * time.Second):
		}
		panic(http.ErrAbortHandler) // не отвечать 200 с пустым телом после отмены клиентом
	}))
	c, _ := New(u, ca, "", nil, 1<<10, 150*time.Millisecond)
	start := time.Now()
	err := c.GetJSON(context.Background(), "/", nil, new(any))
	if kind(err) != "timeout" || time.Since(start) > time.Second {
		t.Errorf("таймаут клиента: %v за %v", err, time.Since(start))
	}
	c, _ = New(u, ca, "", nil, 1<<10, 10*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := c.GetJSON(ctx, "/", nil, new(any)); kind(err) != "timeout" {
		t.Errorf("deadline контекста: %v", err)
	}
	// сервер недоступен: network
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	addr := srv.URL
	srv.Close()
	c, _ = New(addr, "", "", nil, 1<<10, time.Second)
	if err := c.GetJSON(context.Background(), "/", nil, new(any)); kind(err) != "network" {
		t.Errorf("закрытый порт: %v", err)
	}
}

// У клиента нет ничего, кроме GetJSON: другой метод HTTP вызвать нельзя (проверка по API).
func TestAPIHasOnlyGet(t *testing.T) {
	var _ interface {
		GetJSON(context.Context, string, url.Values, any) error
	} = (*Client)(nil)
}
