package openrouter

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// MaxResponseBytes — потолок тела ответа (предложение): больше — TransportError{"oversize"}.
const MaxResponseBytes = 8 << 20

const getPrefix = "https://openrouter.ai/api/v1/"

type Response struct {
	Status int
	Header http.Header
	Body   []byte
}

// TransportError — сбой транспорта. Kind: "timeout" | "network" | "oversize". Сообщение не содержит деталей
// ответа, заголовков и адреса.
type TransportError struct{ Kind string }

func (e *TransportError) Error() string { return "transport_" + e.Kind }

type Transport interface {
	Post(ctx context.Context, url string, h http.Header, body []byte) (Response, error)
	Get(ctx context.Context, url string, h http.Header) (Response, error)
}

type httpTransport struct{ c *http.Client }

// NewHTTPTransport — net/http. Редиректы не следуются (3xx приходит как ответ и классифицируется как case_error:
// Authorization не должен уйти на другой адрес); loopback — без прокси, иначе http.ProxyFromEnvironment
// (egress-прокси, T-17); TLS не ниже 1.2; таймаут задаётся контекстом попытки.
// POST разрешён только на APIURL или loopback, GET — только на https://openrouter.ai/api/v1/ или loopback.
func NewHTTPTransport() Transport {
	tr := &http.Transport{
		Proxy: func(r *http.Request) (*url.URL, error) {
			if hostLocal(r.URL.String()) {
				return nil, nil
			}
			return http.ProxyFromEnvironment(r)
		},
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}
	return &httpTransport{c: &http.Client{
		Transport:     tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func (t *httpTransport) Post(ctx context.Context, u string, h http.Header, body []byte) (Response, error) {
	if u != APIURL && !hostLocal(u) {
		return Response{}, &TransportError{"network"}
	}
	return t.do(ctx, http.MethodPost, u, h, bytes.NewReader(body))
}

func (t *httpTransport) Get(ctx context.Context, u string, h http.Header) (Response, error) {
	if !strings.HasPrefix(u, getPrefix) && !hostLocal(u) {
		return Response{}, &TransportError{"network"}
	}
	return t.do(ctx, http.MethodGet, u, h, nil)
}

func (t *httpTransport) do(ctx context.Context, method, u string, h http.Header, body io.Reader) (Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return Response{}, &TransportError{"network"}
	}
	for k, vs := range h {
		req.Header[k] = append([]string(nil), vs...)
	}
	resp, err := t.c.Do(req)
	if err != nil {
		return Response{}, classifyNetErr(ctx, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	if err != nil {
		return Response{}, classifyNetErr(ctx, err)
	}
	if len(b) > MaxResponseBytes {
		return Response{}, &TransportError{"oversize"}
	}
	return Response{Status: resp.StatusCode, Header: resp.Header, Body: b}, nil
}

func classifyNetErr(ctx context.Context, err error) error {
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) ||
		(errors.As(err, &ne) && ne.Timeout()) {
		return &TransportError{"timeout"}
	}
	return &TransportError{"network"}
}
