// Package httpget — read-only HTTP-клиент источников intake: только GET, без редиректов, без прокси, TLS 1.2+ с CA из файла,
// токен читается из файла на каждый запрос, размер ответа ограничен, тело ответа в ошибки не попадает.
package httpget

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
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

// Потолки размера ответа (предложение).
const (
	MaxBytesMetrics = 4 << 20 // Prometheus, Alertmanager
	MaxBytesKube    = 8 << 20
)

// Error — ошибка запроса; Kind: timeout | network | oversize | decode | http_<код>. Класс читает intake через ErrKind.
type Error struct{ Kind string }

func (e *Error) Error() string   { return "httpget: " + e.Kind }
func (e *Error) ErrKind() string { return e.Kind }

type Client struct {
	base      *url.URL
	hc        *http.Client
	tokenFile string
	headers   map[string]string
	maxBytes  int64
}

// New создаёт клиент. caFile — PEM с корневыми сертификатами (пусто — системные); tokenFile — файл с Bearer-токеном
// (пусто — без авторизации; читаемость проверяется сразу). Токен не отправляется по http.
func New(base, caFile, tokenFile string, headers map[string]string, maxBytes int64, timeout time.Duration) (*Client, error) {
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, errors.New("httpget: некорректный URL")
	}
	if tokenFile != "" && u.Scheme != "https" {
		return nil, errors.New("httpget: токен отправляется только по https")
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("httpget: ca_file: %w", pathErr(err))
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("httpget: ca_file: нет сертификатов PEM")
		}
		tc.RootCAs = pool
	}
	if tokenFile != "" {
		if _, err := readToken(tokenFile); err != nil {
			return nil, err
		}
	}
	tr := &http.Transport{Proxy: nil, TLSClientConfig: tc, DialContext: (&net.Dialer{Timeout: timeout}).DialContext,
		TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout, MaxIdleConns: 4, IdleConnTimeout: time.Minute, DisableCompression: false}
	hc := &http.Client{Transport: tr, Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &Client{base: u, hc: hc, tokenFile: tokenFile, headers: headers, maxBytes: maxBytes}, nil
}

func pathErr(err error) error {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

func readToken(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("httpget: файл токена: %w", pathErr(err))
	}
	t := strings.TrimSpace(string(b))
	if t == "" || strings.ContainsAny(t, "\r\n") {
		return "", errors.New("httpget: файл токена пуст или некорректен")
	}
	return t, nil
}

// GetJSON выполняет GET base+path?q и разбирает ответ 200 в out. Статус не 200 — Error{http_<код>}; редирект — ошибка.
func (c *Client) GetJSON(ctx context.Context, path string, q url.Values, out any) error {
	u := *c.base
	u.Path = strings.TrimRight(c.base.Path, "/") + path
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return &Error{"network"}
	}
	req.Header.Set("Accept", "application/json")
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}
	if c.tokenFile != "" {
		t, err := readToken(c.tokenFile)
		if err != nil {
			return &Error{"network"}
		}
		req.Header.Set("Authorization", "Bearer "+t)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return classify(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<10))
		return &Error{fmt.Sprintf("http_%d", resp.StatusCode)}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBytes+1))
	if err != nil {
		return classify(err)
	}
	if int64(len(body)) > c.maxBytes {
		return &Error{"oversize"}
	}
	if err := json.Unmarshal(body, out); err != nil {
		return &Error{"decode"}
	}
	return nil
}

func classify(err error) error {
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
		return &Error{"timeout"}
	}
	return &Error{"network"}
}
