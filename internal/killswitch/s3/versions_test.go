package s3_test

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/limpjungle/aegis3311/internal/killswitch/s3"
	"github.com/limpjungle/aegis3311/internal/killswitch/s3/s3test"
)

func kindOf(t *testing.T, err error) string {
	t.Helper()
	var se *s3.Error
	if !errors.As(err, &se) {
		t.Fatalf("ожидалась *s3.Error, получено %v", err)
	}
	return se.Kind
}

func TestFakePutGetRegression(t *testing.T) {
	f, c := s3test.New(t)
	ctx := context.Background()
	key := "dir with space/ü.json"
	if err := c.Put(ctx, key, []byte(`{"a":1}`), "application/json"); err != nil {
		t.Fatal(err)
	}
	b, err := c.Get(ctx, key)
	if err != nil || string(b) != `{"a":1}` {
		t.Fatalf("%q %v", b, err)
	}
	if _, err := c.Get(ctx, "nope"); kindOf(t, err) != "http_404" {
		t.Fatalf("404: %v", err)
	}
	if len(f.Versions(key)) != 1 {
		t.Fatal("ожидалась одна версия")
	}
}

func TestPutObjectSignsMD5AndLockHeaders(t *testing.T) {
	f, c := s3test.New(t)
	body := []byte("{\"x\":1}\n")
	sum := md5.Sum(body)
	h := http.Header{}
	h.Set("Content-MD5", base64.StdEncoding.EncodeToString(sum[:]))
	h.Set("x-amz-object-lock-mode", "COMPLIANCE")
	h.Set("x-amz-object-lock-retain-until-date", "2030-01-01T00:00:00Z")
	if err := c.PutObject(context.Background(), "p/k.json", body, "application/json", h); err != nil {
		t.Fatal(err)
	}
	vs := f.Versions("p/k.json")
	if len(vs) != 1 || vs[0].Lock.Get("x-amz-object-lock-mode") != "COMPLIANCE" ||
		vs[0].Lock.Get("x-amz-object-lock-retain-until-date") != "2030-01-01T00:00:00Z" {
		t.Fatalf("lock не сохранён: %+v", vs)
	}
	_, hdr, err := c.GetVersion(context.Background(), "p/k.json", vs[0].ID)
	if err != nil || hdr.Get("x-amz-object-lock-mode") != "COMPLIANCE" {
		t.Fatalf("GetVersion: %v %v", err, hdr)
	}
	// PutObject не должен менять переданную карту заголовков.
	if h.Get("Content-Type") != "" {
		t.Error("PutObject изменил hdr вызывающего")
	}
}

// tamper подменяет заголовки после подписи: фейк обязан ответить 403.
type tamper struct {
	inner s3.Doer
	mut   func(*http.Request)
}

func (d tamper) Do(r *http.Request) (*http.Response, error) {
	d.mut(r)
	return d.inner.Do(r)
}

func TestSignatureCoversLockAndMD5(t *testing.T) {
	cases := map[string]func(*http.Request){
		"md5 изменён":         func(r *http.Request) { r.Header.Set("Content-MD5", "AAAAAAAAAAAAAAAAAAAAAA==") },
		"mode изменён":        func(r *http.Request) { r.Header.Set("x-amz-object-lock-mode", "GOVERNANCE") },
		"retain-until":        func(r *http.Request) { r.Header.Set("x-amz-object-lock-retain-until-date", "2001-01-01T00:00:00Z") },
		"добавлен lock-legal": func(r *http.Request) { r.Header.Set("x-amz-object-lock-legal-hold", "OFF") },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			f, c := s3test.New(t)
			c.HTTP = tamper{c.HTTP, mut}
			body := []byte("x\n")
			sum := md5.Sum(body)
			h := http.Header{}
			h.Set("Content-MD5", base64.StdEncoding.EncodeToString(sum[:]))
			h.Set("x-amz-object-lock-mode", "COMPLIANCE")
			h.Set("x-amz-object-lock-retain-until-date", "2030-01-01T00:00:00Z")
			err := c.PutObject(context.Background(), "k", body, "application/json", h)
			if err == nil || kindOf(t, err) != "http_403" {
				t.Fatalf("ожидался http_403, получено %v", err)
			}
			if len(f.Keys()) != 0 {
				t.Fatal("объект записан несмотря на неверную подпись")
			}
		})
	}
}

func TestPutObjectMD5Mismatch(t *testing.T) {
	_, c := s3test.New(t)
	h := http.Header{}
	h.Set("Content-MD5", "AAAAAAAAAAAAAAAAAAAAAA==")
	if err := c.PutObject(context.Background(), "k", []byte("x"), "text/plain", h); kindOf(t, err) != "http_400" {
		t.Fatalf("ожидался http_400: %v", err)
	}
}

func TestListVersionsPaginationAndDeleteMarker(t *testing.T) {
	f, c := s3test.New(t)
	f.PageSize = 2
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := c.Put(ctx, "p/a.json", []byte(fmt.Sprint(i)), "application/json"); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.Put(ctx, "p/b.json", []byte("b"), "application/json"); err != nil {
		t.Fatal(err)
	}
	f.AddDeleteMarker("p/b.json")
	if err := c.Put(ctx, "other/c.json", []byte("c"), "application/json"); err != nil {
		t.Fatal(err)
	}
	vs, err := c.ListVersions(ctx, "p/")
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 5 {
		t.Fatalf("ожидалось 5 версий, получено %d: %+v", len(vs), vs)
	}
	var dm, a int
	seen := map[string]bool{}
	for _, v := range vs {
		if seen[v.VersionID] {
			t.Errorf("версия %s повторилась", v.VersionID)
		}
		seen[v.VersionID] = true
		if v.DeleteMarker {
			dm++
			if v.Key != "p/b.json" || !v.IsLatest {
				t.Errorf("delete marker: %+v", v)
			}
		}
		if v.Key == "p/a.json" {
			a++
		}
	}
	if dm != 1 || a != 3 {
		t.Fatalf("dm=%d a=%d", dm, a)
	}
	pages := 0
	for _, r := range f.Requests() {
		if strings.Contains(r.Query, "versions=") {
			pages++
		}
	}
	if pages != 3 {
		t.Errorf("ожидалось 3 страницы листинга, получено %d", pages)
	}
}

func TestListVersionsQuerySigned(t *testing.T) {
	f, c := s3test.New(t)
	if _, err := c.ListVersions(context.Background(), "a b/ü&=/"); err != nil {
		t.Fatal(err)
	}
	r := f.Requests()
	if len(r) != 1 || !strings.HasPrefix(r[0].Query, "prefix=") && !strings.Contains(r[0].Query, "versions=") {
		t.Fatalf("запрос: %+v", r)
	}
	if strings.Contains(r[0].Query, "versions&") || strings.HasSuffix(r[0].Query, "versions") {
		t.Errorf("versions без '=': %q", r[0].Query)
	}
}

func TestListVersionsBadResponses(t *testing.T) {
	cases := map[string]struct {
		body []byte
		kind string
	}{
		"мусор":                 {[]byte("<<<not xml"), "parse"},
		"пусто":                 {[]byte(" "), "parse"},
		"oversize":              {append([]byte("<ListVersionsResult>"), bytes.Repeat([]byte("a"), 2<<20)...), "oversize"},
		"truncated без маркера": {[]byte(`<ListVersionsResult><IsTruncated>true</IsTruncated></ListVersionsResult>`), "parse"},
		"зацикленный маркер":    {[]byte(`<ListVersionsResult><IsTruncated>true</IsTruncated><NextKeyMarker>k</NextKeyMarker><NextVersionIdMarker>v</NextVersionIdMarker></ListVersionsResult>`), "parse"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f, c := s3test.New(t)
			f.RawList(tc.body)
			_, err := c.ListVersions(context.Background(), "p/")
			if err == nil {
				t.Fatal("ошибка ожидалась")
			}
			if k := kindOf(t, err); k != tc.kind {
				t.Fatalf("kind %q, ожидался %q", k, tc.kind)
			}
		})
	}
}

func TestListVersionsHTTPErrorNoBody(t *testing.T) {
	f, c := s3test.New(t)
	f.FailNext(500)
	_, err := c.ListVersions(context.Background(), "p/")
	if kindOf(t, err) != "http_500" || strings.Contains(err.Error(), "секрет") {
		t.Fatalf("%v", err)
	}
}

// pagesDoer отдаёт бесконечный листинг с новыми маркерами.
type pagesDoer struct{ n atomic.Int64 }

func (d *pagesDoer) Do(r *http.Request) (*http.Response, error) {
	i := d.n.Add(1)
	body := fmt.Sprintf(`<ListVersionsResult><IsTruncated>true</IsTruncated><NextKeyMarker>k%d</NextKeyMarker><NextVersionIdMarker>v%d</NextVersionIdMarker></ListVersionsResult>`, i, i)
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
}

func TestListVersionsTooManyPages(t *testing.T) {
	_, c := s3test.New(t)
	d := &pagesDoer{}
	c.HTTP = d
	_, err := c.ListVersions(context.Background(), "p/")
	if kindOf(t, err) != "too_many_pages" {
		t.Fatalf("%v", err)
	}
	if n := d.n.Load(); n != 10000 {
		t.Errorf("страниц запрошено %d, ожидалось 10000", n)
	}
}

func TestGetVersionSpecificAndEmptyID(t *testing.T) {
	f, c := s3test.New(t)
	ctx := context.Background()
	c.Put(ctx, "k", []byte("one"), "text/plain")
	c.Put(ctx, "k", []byte("two"), "text/plain")
	vs := f.Versions("k")
	b, _, err := c.GetVersion(ctx, "k", vs[0].ID)
	if err != nil || string(b) != "one" {
		t.Fatalf("%q %v", b, err)
	}
	if _, _, err := c.GetVersion(ctx, "k", ""); err == nil {
		t.Error("пустой version id принят")
	}
	if _, _, err := c.GetVersion(ctx, "k", "nope"); kindOf(t, err) != "http_404" {
		t.Errorf("%v", err)
	}
}
