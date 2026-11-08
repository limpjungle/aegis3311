package s3

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
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

// Client — GET и PUT объекта с подписью SigV4.
type Client struct {
	Cfg      Config
	Creds    CredFiles
	HTTP     Doer
	Now      func() time.Time
	MaxBytes int64 // потолок ответа GET
}

func (c *Client) url(key string) (*url.URL, error) {
	ep, err := url.Parse(c.Cfg.Endpoint)
	if err != nil || ep.Scheme != "https" || ep.Host == "" || (ep.Path != "" && ep.Path != "/") || ep.RawQuery != "" || ep.User != nil {
		return nil, errors.New("s3: endpoint: ожидается https://host[:port]")
	}
	if c.Cfg.Bucket == "" || key == "" || strings.HasPrefix(key, "/") {
		return nil, errors.New("s3: bucket и key обязательны, key без ведущего /")
	}
	u := &url.URL{Scheme: "https", Host: ep.Host}
	if c.Cfg.PathStyle {
		u.Path = "/" + c.Cfg.Bucket + "/" + key
	} else {
		u.Host = c.Cfg.Bucket + "." + ep.Host
		u.Path = "/" + key
	}
	u.RawPath = canonicalURI(u.Path)
	return u, nil
}

func (c *Client) do(ctx context.Context, method, key string, body []byte, contentType string) ([]byte, error) {
	u, err := c.url(key)
	if err != nil {
		return nil, err
	}
	creds, err := c.Creds.Load()
	if err != nil {
		return nil, err
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return nil, &Error{"network"}
	}
	if method == http.MethodPut {
		req.Header.Set("Content-Type", contentType)
		req.Header.Set("Cache-Control", "no-store")
	}
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	if err := SignV4(req, sha256Hex(body), creds, c.Cfg.Region, "s3", now()); err != nil {
		return nil, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		var ne net.Error
		if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
			return nil, &Error{"timeout"}
		}
		return nil, &Error{"network"}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && !(method == http.MethodPut && resp.StatusCode == http.StatusNoContent) {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<10))
		return nil, &Error{fmt.Sprintf("http_%d", resp.StatusCode)}
	}
	if method == http.MethodPut {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<10))
		return nil, nil
	}
	max := c.MaxBytes
	if max <= 0 {
		max = 64 << 10
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		var ne net.Error
		if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
			return nil, &Error{"timeout"}
		}
		return nil, &Error{"network"}
	}
	if int64(len(b)) > max {
		return nil, &Error{"oversize"}
	}
	return b, nil
}

// Get читает объект key.
func (c *Client) Get(ctx context.Context, key string) ([]byte, error) {
	return c.do(ctx, http.MethodGet, key, nil, "")
}

// Put записывает объект key (Content-Type, Cache-Control: no-store).
func (c *Client) Put(ctx context.Context, key string, body []byte, contentType string) error {
	if body == nil {
		body = []byte{}
	}
	_, err := c.do(ctx, http.MethodPut, key, body, contentType)
	return err
}
