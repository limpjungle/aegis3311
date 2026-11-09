// Package s3test — фейк S3 с версионированием и Object Lock для тестов: проверяет SigV4 собственной эталонной
// реализацией, хранит версии (каждый PUT — новая), отдаёт ListObjectVersions с пагинацией. Только для тестов.
package s3test

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/limpjungle/aegis3311/internal/killswitch/s3"
)

const (
	Bucket    = "test-bucket"
	Region    = "ru-central1"
	AccessKey = "AK"
	SecretKey = "test-secret"
)

// Version — сохранённая версия объекта.
type Version struct {
	ID           string
	Body         []byte
	DeleteMarker bool
	Lock         http.Header // x-amz-object-lock-* из PUT
}

// Fake — фейк S3 (path-style, один bucket).
type Fake struct {
	// RequireMD5 — PUT без верного Content-MD5 отклоняется (как при default lock в Yandex Object Storage).
	RequireMD5 bool
	// PageSize — максимум записей на страницу листинга; 0 — 1000. max-keys в запросе может уменьшить.
	PageSize int
	// Delay — задержка перед обработкой каждого запроса.
	Delay time.Duration

	mu       sync.Mutex
	objects  map[string][]Version // версии по возрастанию; последняя — текущая
	seq      int
	fail     []int
	requests []Request
	rawList  []byte
	Srv      *httptest.Server
}

// Request — журнал запросов (без тел).
type Request struct {
	Method, Path, Query string
	Header              http.Header
}

// New поднимает TLS-сервер и возвращает фейк и клиент, настроенный на него (ключи во временных файлах).
func New(t testing.TB) (*Fake, *s3.Client) {
	t.Helper()
	f := &Fake{objects: map[string][]Version{}}
	f.Srv = httptest.NewTLSServer(f)
	t.Cleanup(f.Srv.Close)
	dir := t.TempDir()
	write := func(name, v string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(v+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	c := &s3.Client{
		Cfg:   s3.Config{Endpoint: f.Srv.URL, Region: Region, Bucket: Bucket, PathStyle: true},
		Creds: s3.CredFiles{AccessKeyIDFile: write("ak", AccessKey), SecretKeyFile: write("sk", SecretKey)},
		HTTP:  f.Srv.Client(),
	}
	return f, c
}

// FailNext заставляет следующий запрос вернуть status (тело ответа секретное, чтобы проверять, что оно не утекает).
func (f *Fake) FailNext(status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail = append(f.fail, status)
}

// RawList подменяет тело ответа листинга версий (nil — снова нормальное поведение).
func (f *Fake) RawList(b []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rawList = b
}

// Versions — копия версий ключа key (без bucket'а), по возрастанию.
func (f *Fake) Versions(key string) []Version {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Version(nil), f.objects[key]...)
}

// Keys — все ключи, отсортированные.
func (f *Fake) Keys() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var ks []string
	for k := range f.objects {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// Requests — журнал запросов.
func (f *Fake) Requests() []Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Request(nil), f.requests...)
}

// AddDeleteMarker добавляет delete marker (как DELETE без versionId).
func (f *Fake) AddDeleteMarker(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.add(key, Version{DeleteMarker: true})
}

func (f *Fake) add(key string, v Version) string {
	f.seq++
	v.ID = fmt.Sprintf("v%06d", f.seq)
	f.objects[key] = append(f.objects[key], v)
	return v.ID
}

func hm(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func enc(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// checkSig пересчитывает подпись по эталонному алгоритму SigV4.
func checkSig(r *http.Request, body []byte) bool {
	auth := r.Header.Get("Authorization")
	const pre = "AWS4-HMAC-SHA256 "
	if !strings.HasPrefix(auth, pre) {
		return false
	}
	parts := map[string]string{}
	for _, p := range strings.Split(auth[len(pre):], ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(p), "=")
		if !ok {
			return false
		}
		parts[k] = v
	}
	date := r.Header.Get("x-amz-date")
	if len(date) < 8 || r.Header.Get("x-amz-content-sha256") != hex.EncodeToString(sum(body)) {
		return false
	}
	signed := strings.Split(parts["SignedHeaders"], ";")
	has := map[string]bool{}
	var ch strings.Builder
	for _, n := range signed {
		has[n] = true
		v := r.Header.Get(n)
		if n == "host" {
			v = r.Host
		}
		ch.WriteString(n + ":" + strings.Join(strings.Fields(v), " ") + "\n")
	}
	// Обязательно подписаны host, x-amz-* и все заголовки lock/MD5, пришедшие в запросе.
	if !has["host"] || !has["x-amz-date"] || !has["x-amz-content-sha256"] {
		return false
	}
	for k := range r.Header {
		lk := strings.ToLower(k)
		if (strings.HasPrefix(lk, "x-amz-") || lk == "content-md5") && !has[lk] {
			return false
		}
	}
	var qs []string
	for k, vs := range r.URL.Query() {
		for _, v := range vs {
			qs = append(qs, enc(k)+"="+enc(v))
		}
	}
	sort.Strings(qs)
	canon := strings.Join([]string{r.Method, r.URL.EscapedPath(), strings.Join(qs, "&"), ch.String(),
		parts["SignedHeaders"], r.Header.Get("x-amz-content-sha256")}, "\n")
	scope := date[:8] + "/" + Region + "/s3/aws4_request"
	sts := "AWS4-HMAC-SHA256\n" + date + "\n" + scope + "\n" + hex.EncodeToString(sum([]byte(canon)))
	k := hm([]byte("AWS4"+SecretKey), date[:8])
	k = hm(k, Region)
	k = hm(k, "s3")
	k = hm(k, "aws4_request")
	return parts["Credential"] == AccessKey+"/"+scope && parts["Signature"] == hex.EncodeToString(hm(k, sts))
}

func sum(b []byte) []byte { s := sha256.Sum256(b); return s[:] }

func (f *Fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	if f.Delay > 0 {
		time.Sleep(f.Delay)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, Request{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Clone()})
	if !checkSig(r, body) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if len(f.fail) > 0 {
		st := f.fail[0]
		f.fail = f.fail[1:]
		w.WriteHeader(st)
		w.Write([]byte("секретное тело ответа"))
		return
	}
	root := "/" + Bucket
	if r.URL.Path != root && !strings.HasPrefix(r.URL.Path, root+"/") {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	key := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, root), "/")
	q := r.URL.Query()
	switch {
	case key == "" && r.Method == http.MethodGet && q.Has("versions"):
		f.list(w, q)
	case key != "" && r.Method == http.MethodPut:
		f.put(w, r, key, body)
	case key != "" && r.Method == http.MethodGet:
		f.get(w, key, q.Get("versionId"))
	case key != "" && r.Method == http.MethodDelete:
		f.del(w, key, q.Get("versionId"))
	default:
		w.WriteHeader(http.StatusBadRequest)
	}
}

func (f *Fake) put(w http.ResponseWriter, r *http.Request, key string, body []byte) {
	if r.Header.Get("Cache-Control") != "no-store" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if md := r.Header.Get("Content-MD5"); md != "" || f.RequireMD5 {
		s := md5.Sum(body)
		if md != base64.StdEncoding.EncodeToString(s[:]) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	}
	lock := http.Header{}
	for _, n := range []string{"x-amz-object-lock-mode", "x-amz-object-lock-retain-until-date"} {
		if v := r.Header.Get(n); v != "" {
			lock.Set(n, v)
		}
	}
	id := f.add(key, Version{Body: body, Lock: lock})
	w.Header().Set("x-amz-version-id", id)
	w.WriteHeader(http.StatusOK)
}

func (f *Fake) get(w http.ResponseWriter, key, vid string) {
	vs := f.objects[key]
	if len(vs) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	v := vs[len(vs)-1]
	if vid != "" {
		found := false
		for _, x := range vs {
			if x.ID == vid {
				v, found = x, true
			}
		}
		if !found {
			w.WriteHeader(http.StatusNotFound)
			return
		}
	}
	if v.DeleteMarker {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	for k, vv := range v.Lock {
		w.Header()[k] = vv
	}
	w.Header().Set("x-amz-version-id", v.ID)
	w.Write(v.Body)
}

func (f *Fake) del(w http.ResponseWriter, key, vid string) {
	if vid == "" {
		f.add(key, Version{DeleteMarker: true})
		w.WriteHeader(http.StatusNoContent)
		return
	}
	vs := f.objects[key]
	for i, x := range vs {
		if x.ID != vid {
			continue
		}
		if until, err := time.Parse(time.RFC3339, x.Lock.Get("x-amz-object-lock-retain-until-date")); err == nil && until.After(time.Now()) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		f.objects[key] = append(vs[:i:i], vs[i+1:]...)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.WriteHeader(http.StatusNotFound)
}

type xmlEntry struct {
	Key       string `xml:"Key"`
	VersionID string `xml:"VersionId"`
	IsLatest  bool   `xml:"IsLatest"`
}

type xmlList struct {
	XMLName             xml.Name   `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListVersionsResult"`
	Prefix              string     `xml:"Prefix"`
	IsTruncated         bool       `xml:"IsTruncated"`
	NextKeyMarker       string     `xml:"NextKeyMarker,omitempty"`
	NextVersionIDMarker string     `xml:"NextVersionIdMarker,omitempty"`
	Versions            []xmlEntry `xml:"Version"`
	DeleteMarkers       []xmlEntry `xml:"DeleteMarker"`
}

func (f *Fake) list(w http.ResponseWriter, q url.Values) {
	if f.rawList != nil {
		w.Write(f.rawList)
		return
	}
	prefix := q.Get("prefix")
	type item struct {
		key string
		v   Version
		lat bool
	}
	var items []item
	var keys []string
	for k := range f.objects {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		vs := f.objects[k]
		for i := len(vs) - 1; i >= 0; i-- { // новейшая версия первой, как в S3
			items = append(items, item{k, vs[i], i == len(vs)-1})
		}
	}
	start := 0
	if km := q.Get("key-marker"); km != "" {
		vm := q.Get("version-id-marker")
		start = len(items)
		for i, it := range items {
			if it.key == km && it.v.ID == vm {
				start = i + 1
				break
			}
		}
	}
	page := f.PageSize
	if page <= 0 {
		page = 1000
	}
	if mk, err := strconv.Atoi(q.Get("max-keys")); err == nil && mk > 0 && mk < page {
		page = mk
	}
	res := xmlList{Prefix: prefix}
	end := start + page
	if end < len(items) {
		res.IsTruncated = true
	} else {
		end = len(items)
	}
	for _, it := range items[start:end] {
		e := xmlEntry{Key: it.key, VersionID: it.v.ID, IsLatest: it.lat}
		if it.v.DeleteMarker {
			res.DeleteMarkers = append(res.DeleteMarkers, e)
		} else {
			res.Versions = append(res.Versions, e)
		}
	}
	if res.IsTruncated {
		last := items[end-1]
		res.NextKeyMarker, res.NextVersionIDMarker = last.key, last.v.ID
	}
	b, _ := xml.Marshal(res)
	w.Header().Set("Content-Type", "application/xml")
	w.Write(append([]byte(xml.Header), b...))
}
