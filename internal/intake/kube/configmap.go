package kube

import (
	"context"
	"net/url"

	"github.com/limpjungle/aegis3311/internal/intake/httpget"
)

// ConfigMapData читает значение ключа key из data ConfigMap ns/name (канал kill switch). Нет ключа — Error{no_document} (пустой канал, в отличие от decode — неразобранного ответа).
// Нужное право: get на конкретный ConfigMap (resourceNames) в Role, не ClusterRole.
func (c *Client) ConfigMapData(ctx context.Context, ns, name, key string) ([]byte, error) {
	var cm struct {
		Data map[string]string `json:"data"`
	}
	if err := c.c.GetJSON(ctx, "/api/v1/namespaces/"+url.PathEscape(ns)+"/configmaps/"+url.PathEscape(name), nil, &cm); err != nil {
		return nil, err
	}
	v, ok := cm.Data[key]
	if !ok {
		return nil, &httpget.Error{Kind: "no_document"}
	}
	return []byte(v), nil
}
