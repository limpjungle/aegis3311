package intake

import (
	"context"
	"errors"
	"time"
)

// RawSeries — серия метрики из Prometheus, уже выровненная по сетке окна: ровно SeriesPoints значений.
type RawSeries struct {
	Labels []Label
	Values []*float64
}

// Интерфейсы источников. Реализации — только чтение (HTTP GET); в тестах подменяются фейками.

// AlertSource — активные (не заглушённые, не подавленные) алерты, подходящие под matchers конфигурации.
type AlertSource interface {
	Firing(ctx context.Context) ([]Alert, error)
}

// ErrTruncated — источник вернул корректные, но неполные данные (сработал потолок листа Kubernetes). Возвращается
// ВМЕСТЕ со значением: значение годно, источник помечается truncated. Не SourceError — класса ошибки нет.
var ErrTruncated = errors.New("источник: данные усечены по потолку")

// ClusterSource: любой метод может вернуть (значение, ErrTruncated); прочие ошибки — без значения.
type ClusterSource interface {
	Topology(ctx context.Context, svc ServiceConfig) (Topology, error)
	Events(ctx context.Context, svc ServiceConfig, pods []string, since time.Time) ([]Event, error)
	LastDeploy(ctx context.Context, svc ServiceConfig) (*Deploy, error)             // nil — деплоев не найдено
	Rollout(ctx context.Context, svc ServiceConfig, t0 time.Time) (*Rollout, error) // nil — у сервиса нет Rollout
	PDB(ctx context.Context, svc ServiceConfig) (*PDB, error)                       // nil — PDB нет
}

// MetricsSource: окно [end-30m, end] с шагом step; end кратен минуте.
type MetricsSource interface {
	QueryRange(ctx context.Context, q string, start, end time.Time, step time.Duration) ([]RawSeries, error)
}

type DBSource interface {
	Aggregates(ctx context.Context, svc ServiceConfig, t0 time.Time) (*DBAggregates, error)
}

// SourceError — ошибка источника; Kind: timeout | network | oversize | decode | http_<код>. Текст и тело ответа в неё не попадают.
type SourceError struct{ Kind string }

func (e *SourceError) Error() string   { return "источник: " + e.Kind }
func (e *SourceError) ErrKind() string { return e.Kind }
