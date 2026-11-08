package kube

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/limpjungle/aegis3311/internal/intake/httpget"
)

func TestConfigMapData(t *testing.T) {
	const path = "/api/v1/namespaces/aegisops-control/configmaps/kill-switch"
	e := newEnv(t, map[string]func(url.Values) any{
		path: static(obj("data", obj("document", `{"a":1}`, "other", "x"))),
		"/api/v1/namespaces/aegisops-control/configmaps/empty": static(obj("data", obj("other", "x"))),
	}, "")
	b, err := e.c.ConfigMapData(context.Background(), "aegisops-control", "kill-switch", "document")
	if err != nil || string(b) != `{"a":1}` {
		t.Fatalf("%q %v", b, err)
	}
	var he *httpget.Error
	if _, err := e.c.ConfigMapData(context.Background(), "aegisops-control", "empty", "document"); !errors.As(err, &he) || he.Kind != "no_document" {
		t.Errorf("нет ключа: %v", err)
	}
	if _, err := e.c.ConfigMapData(context.Background(), "aegisops-control", "absent", "document"); !errors.As(err, &he) || he.Kind != "http_404" {
		t.Errorf("404: %v", err)
	}
	e.onlyGet(t)
	if len(e.queries(path)) != 1 {
		t.Error("ожидается один запрос")
	}
}
