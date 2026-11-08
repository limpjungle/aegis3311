// Package alertmanager — read-only источник активных алертов: GET /api/v2/alerts.
package alertmanager

import (
	"context"
	"net/url"
	"time"

	"github.com/limpjungle/aegis3311/internal/intake"
	"github.com/limpjungle/aegis3311/internal/intake/httpget"
)

const maxAlerts = 1000

type Client struct {
	c        *httpget.Client
	matchers []string
}

// New: src — адрес, CA, заголовки и matchers из конфигурации; tokenFile — AEGIS_ALERTMANAGER_TOKEN_FILE (может быть пуст).
func New(src intake.HTTPSource, tokenFile string, timeout time.Duration) (*Client, error) {
	c, err := httpget.New(src.URL, src.CAFile, tokenFile, src.Headers, httpget.MaxBytesMetrics, timeout)
	if err != nil {
		return nil, err
	}
	return &Client{c: c, matchers: src.Matchers}, nil
}

// wire — минимальная форма ответа API v2 (нестрогий разбор внешнего API: неизвестные поля игнорируются).
type wire struct {
	Fingerprint string            `json:"fingerprint"`
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
	StartsAt    time.Time         `json:"startsAt"`
	Status      struct {
		State string `json:"state"`
	} `json:"status"`
}

// Firing возвращает активные, не заглушённые и не подавленные алерты под matchers. Алерты без alertname, namespace
// или service отбрасываются позже трекером (вне реестра).
func (c *Client) Firing(ctx context.Context) ([]intake.Alert, error) {
	q := url.Values{"active": {"true"}, "silenced": {"false"}, "inhibited": {"false"}, "unprocessed": {"false"}}
	if len(c.matchers) > 0 {
		q["filter"] = c.matchers
	}
	var ws []wire
	if err := c.c.GetJSON(ctx, "/api/v2/alerts", q, &ws); err != nil {
		return nil, err
	}
	var out []intake.Alert
	for _, w := range ws {
		if w.Status.State != "" && w.Status.State != "active" {
			continue
		}
		out = append(out, intake.Alert{Fingerprint: w.Fingerprint, Name: w.Labels["alertname"], Severity: w.Labels["severity"],
			Namespace: w.Labels["namespace"], Service: w.Labels["service"], Summary: w.Annotations["summary"],
			Description: w.Annotations["description"], StartsAt: w.StartsAt.UTC()})
		if len(out) == maxAlerts {
			break
		}
	}
	return out, nil
}
