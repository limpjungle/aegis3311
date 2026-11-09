package s3

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Doer — транспорт запросов (в тестах подменяется).
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// Config — расположение объекта. Endpoint — https://host[:port] без пути; PathStyle: https://host/bucket/key,
// иначе virtual-hosted: https://bucket.host/key. Для Yandex Object Storage — path_style.
type Config struct {
	Endpoint  string `json:"endpoint"`
	Region    string `json:"region"`
	Bucket    string `json:"bucket"`
	Key       string `json:"key"`
	CAFile    string `json:"ca_file"`
	PathStyle bool   `json:"path_style"`
}

// NewHTTPClient — http.Client для S3: TLS 1.2+, CA из файла (пусто — системные), без прокси и редиректов.
func NewHTTPClient(caFile string, timeout time.Duration) (*http.Client, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			var pe *os.PathError
			if errors.As(err, &pe) {
				err = pe.Err
			}
			return nil, fmt.Errorf("s3: ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("s3: ca_file: нет сертификатов PEM")
		}
		tc.RootCAs = pool
	}
	tr := &http.Transport{Proxy: nil, TLSClientConfig: tc, DialContext: (&net.Dialer{Timeout: timeout}).DialContext,
		TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout, MaxIdleConns: 4, IdleConnTimeout: time.Minute}
	return &http.Client{Transport: tr, Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

// Error — ошибка запроса; Kind: timeout | network | oversize | http_<код>. Тело ответа в ошибку не попадает.
type Error struct{ Kind string }

func (e *Error) Error() string   { return "s3: " + e.Kind }
func (e *Error) ErrKind() string { return e.Kind }

// Client — GET, PUT объекта и листинг версий с подписью SigV4.
type Client struct {
	Cfg      Config
	Creds    CredFiles
	HTTP     Doer
	Now      func() time.Time
	MaxBytes int64 // потолок ответа GET (листинг версий — не меньше maxListBytes)
}

const (
	maxListBytes = 1 << 20 // потолок ответа ListObjectVersions
	maxListPages = 10000   // жёсткий предел числа страниц листинга
)

// endpointHost разбирает Endpoint: https://host[:port] без пути.
func (c *Client) endpointHost() (string, error) {
	ep, err := url.Parse(c.Cfg.Endpoint)
	if err != nil || ep.Scheme != "https" || ep.Host == "" || (ep.Path != "" && ep.Path != "/") || ep.RawQuery != "" || ep.User != nil {
		return "", errors.New("s3: endpoint: ожидается https://host[:port]")
	}
	return ep.Host, nil
}

func (c *Client) url(key string) (*url.URL, error) {
	if key == "" || strings.HasPrefix(key, "/") {
		return nil, errors.New("s3: bucket и key обязательны, key без ведущего /")
	}
	return c.target(key)
}

// bucketURL — корень bucket'а (листинг).
func (c *Client) bucketURL() (*url.URL, error) { return c.target("") }

func (c *Client) target(key string) (*url.URL, error) {
	host, err := c.endpointHost()
	if err != nil {
		return nil, err
	}
	if c.Cfg.Bucket == "" {
		return nil, errors.New("s3: bucket и key обязательны, key без ведущего /")
	}
	u := &url.URL{Scheme: "https", Host: host}
	if c.Cfg.PathStyle {
		u.Path = "/" + c.Cfg.Bucket + "/" + key
	} else {
		u.Host = c.Cfg.Bucket + "." + host
		u.Path = "/" + key
	}
	u.RawPath = canonicalURI(u.Path)
	return u, nil
}

// do выполняет запрос. key == "" — корень bucket'а. Все заголовки hdr подписываются. Возвращает тело (GET) и заголовки ответа.
func (c *Client) do(ctx context.Context, method, key string, query url.Values, body []byte, hdr http.Header) ([]byte, http.Header, error) {
	var u *url.URL
	var err error
	if key == "" {
		u, err = c.bucketURL()
	} else {
		u, err = c.url(key)
	}
	if err != nil {
		return nil, nil, err
	}
	if len(query) > 0 {
		u.RawQuery = query.Encode()
	}
	creds, err := c.Creds.Load()
	if err != nil {
		return nil, nil, err
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return nil, nil, &Error{"network"}
	}
	var extra []string
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
		if !strings.EqualFold(k, "Content-Type") { // как и прежде, Content-Type не подписывается
			extra = append(extra, k)
		}
	}
	if method == http.MethodPut {
		if req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", "application/octet-stream")
		}
		req.Header.Set("Cache-Control", "no-store")
	}
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	if err := SignV4(req, sha256Hex(body), creds, c.Cfg.Region, "s3", now(), extra...); err != nil {
		return nil, nil, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		var ne net.Error
		if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
			return nil, nil, &Error{"timeout"}
		}
		return nil, nil, &Error{"network"}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && !(method == http.MethodPut && resp.StatusCode == http.StatusNoContent) {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<10))
		return nil, nil, &Error{fmt.Sprintf("http_%d", resp.StatusCode)}
	}
	if method == http.MethodPut {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<10))
		return nil, resp.Header, nil
	}
	max := c.MaxBytes
	if max <= 0 {
		max = 64 << 10
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		var ne net.Error
		if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
			return nil, nil, &Error{"timeout"}
		}
		return nil, nil, &Error{"network"}
	}
	if int64(len(b)) > max {
		return nil, nil, &Error{"oversize"}
	}
	return b, resp.Header, nil
}

// Get читает объект key.
func (c *Client) Get(ctx context.Context, key string) ([]byte, error) {
	b, _, err := c.do(ctx, http.MethodGet, key, nil, nil, nil)
	return b, err
}

// Put записывает объект key (Content-Type, Cache-Control: no-store).
func (c *Client) Put(ctx context.Context, key string, body []byte, contentType string) error {
	return c.PutObject(ctx, key, body, contentType, nil)
}

// PutObject записывает объект key с дополнительными заголовками hdr (Content-MD5, x-amz-object-lock-*); все они подписываются.
func (c *Client) PutObject(ctx context.Context, key string, body []byte, contentType string, hdr http.Header) error {
	if body == nil {
		body = []byte{}
	}
	h := hdr.Clone()
	if h == nil {
		h = http.Header{}
	}
	h.Set("Content-Type", contentType)
	_, _, err := c.do(ctx, http.MethodPut, key, nil, body, h)
	return err
}

// GetVersion читает конкретную версию объекта key; возвращает тело и заголовки ответа.
func (c *Client) GetVersion(ctx context.Context, key, versionID string) ([]byte, http.Header, error) {
	if versionID == "" {
		return nil, nil, errors.New("s3: version id обязателен")
	}
	return c.do(ctx, http.MethodGet, key, url.Values{"versionId": {versionID}}, nil, nil)
}

// ObjectVersion — версия объекта или delete marker из листинга.
type ObjectVersion struct {
	Key, VersionID string
	IsLatest       bool
	DeleteMarker   bool
}

type listEntry struct {
	Key       string `xml:"Key"`
	VersionID string `xml:"VersionId"`
	IsLatest  bool   `xml:"IsLatest"`
}

type listResult struct {
	XMLName             xml.Name    `xml:"ListVersionsResult"`
	IsTruncated         bool        `xml:"IsTruncated"`
	NextKeyMarker       string      `xml:"NextKeyMarker"`
	NextVersionIDMarker string      `xml:"NextVersionIdMarker"`
	Versions            []listEntry `xml:"Version"`
	DeleteMarkers       []listEntry `xml:"DeleteMarker"`
}

// parseListVersions разбирает страницу ListVersionsResult.
func parseListVersions(b []byte) (listResult, error) {
	var r listResult
	if err := xml.Unmarshal(b, &r); err != nil {
		return listResult{}, &Error{"parse"}
	}
	return r, nil
}

// ListVersions перечисляет все версии и delete marker'ы ключей с префиксом prefix (с пагинацией).
// Ответ страницы ограничен 1 МиБ, число страниц — 10000; превышение — ошибка.
func (c *Client) ListVersions(ctx context.Context, prefix string) ([]ObjectVersion, error) {
	cc := *c
	if cc.MaxBytes < maxListBytes {
		cc.MaxBytes = maxListBytes
	}
	var out []ObjectVersion
	var keyMarker, verMarker string
	for page := 0; page < maxListPages; page++ {
		q := url.Values{"versions": {""}, "prefix": {prefix}}
		if keyMarker != "" {
			q.Set("key-marker", keyMarker)
		}
		if verMarker != "" {
			q.Set("version-id-marker", verMarker)
		}
		b, _, err := cc.do(ctx, http.MethodGet, "", q, nil, nil)
		if err != nil {
			return nil, err
		}
		r, err := parseListVersions(b)
		if err != nil {
			return nil, err
		}
		for _, v := range r.Versions {
			out = append(out, ObjectVersion{Key: v.Key, VersionID: v.VersionID, IsLatest: v.IsLatest})
		}
		for _, v := range r.DeleteMarkers {
			out = append(out, ObjectVersion{Key: v.Key, VersionID: v.VersionID, IsLatest: v.IsLatest, DeleteMarker: true})
		}
		if !r.IsTruncated {
			return out, nil
		}
		if r.NextKeyMarker == "" || (r.NextKeyMarker == keyMarker && r.NextVersionIDMarker == verMarker) {
			return nil, &Error{"parse"}
		}
		keyMarker, verMarker = r.NextKeyMarker, r.NextVersionIDMarker
	}
	return nil, &Error{"too_many_pages"}
}
