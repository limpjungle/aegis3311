package killswitch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/limpjungle/aegis3311/internal/killswitch/s3"
)

// ConfigMapPublisher записывает документ в ConfigMap канала через server-side apply (PATCH). ConfigMap должен
// существовать (создаётся при установке): права on-call и renewer — get, patch без create. Client — транспорт
// (TLS с CA кластера, без редиректов; см. s3.NewHTTPClient).
type ConfigMapPublisher struct {
	Client                                      s3.Doer
	APIURL, Namespace, ConfigMapName, TokenFile string
}

func (p ConfigMapPublisher) token() (string, error) {
	b, err := os.ReadFile(p.TokenFile)
	if err != nil {
		var pe *os.PathError
		if errors.As(err, &pe) {
			err = pe.Err
		}
		return "", fmt.Errorf("kube: файл токена: %w", err)
	}
	t := strings.TrimSpace(string(b))
	if t == "" || strings.ContainsAny(t, "\r\n") {
		return "", errors.New("kube: файл токена пуст или некорректен")
	}
	return t, nil
}

func (p ConfigMapPublisher) path() string {
	return strings.TrimRight(p.APIURL, "/") + "/api/v1/namespaces/" + url.PathEscape(p.Namespace) + "/configmaps/" + url.PathEscape(p.ConfigMapName)
}

func (p ConfigMapPublisher) do(ctx context.Context, method, u, contentType string, body []byte) (*http.Response, error) {
	tok, err := p.token()
	if err != nil {
		return nil, err
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, &s3.Error{Kind: "network"}
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := p.Client.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, &s3.Error{Kind: "timeout"}
		}
		return nil, &s3.Error{Kind: "network"}
	}
	return resp, nil
}

// Publish записывает документ в data.document.
func (p ConfigMapPublisher) Publish(ctx context.Context, doc []byte) error {
	body, err := json.Marshal(map[string]any{"apiVersion": "v1", "kind": "ConfigMap",
		"metadata": map[string]string{"name": p.ConfigMapName, "namespace": p.Namespace},
		"data":     map[string]string{ConfigMapKey: string(doc)}})
	if err != nil {
		return err
	}
	resp, err := p.do(ctx, http.MethodPatch, p.path()+"?fieldManager=aegis-killswitch&force=true", "application/apply-patch+yaml", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<10))
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return &s3.Error{Kind: fmt.Sprintf("http_%d", resp.StatusCode)}
	}
	return nil
}

// Read читает data.document (для read-back и renew).
func (p ConfigMapPublisher) Read(ctx context.Context) ([]byte, error) {
	resp, err := p.do(ctx, http.MethodGet, p.path(), "", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<10))
		return nil, &s3.Error{Kind: fmt.Sprintf("http_%d", resp.StatusCode)}
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20+1))
	if err != nil || len(b) > 8<<20 {
		return nil, &s3.Error{Kind: "network"}
	}
	var cm struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(b, &cm); err != nil {
		return nil, &s3.Error{Kind: "decode"}
	}
	v, ok := cm.Data[ConfigMapKey]
	if !ok {
		return nil, &s3.Error{Kind: "no_document"}
	}
	return []byte(v), nil
}

// Name — имя канала.
func (p ConfigMapPublisher) Name() string { return "configmap" }

// S3Publisher записывает документ в объект внешнего канала.
type S3Publisher struct{ C *s3.Client }

func (p S3Publisher) Publish(ctx context.Context, doc []byte) error {
	return p.C.Put(ctx, p.C.Cfg.Key, doc, "application/json")
}

func (p S3Publisher) Read(ctx context.Context) ([]byte, error) { return p.C.Get(ctx, p.C.Cfg.Key) }

func (p S3Publisher) Name() string { return "oob" }
