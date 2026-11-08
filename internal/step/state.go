// Package step содержит детерминированные правила шага и вывод доступных действий.
// Формулы — зеркало eval/golden-synthetic/generate.py (step_*, allowed_actions_v2); расхождение ловит кросс-проверка на наборах
// (формат набора v3: поды цели берутся из input.service.pods).
package step

import "fmt"

// Autoscaler — состояние HPA/KEDA цели.
type Autoscaler struct {
	Kind        string `json:"kind"`
	DeclaredMin int    `json:"declared_min"`
	CurrentMin  int    `json:"current_min"`
	Max         int    `json:"max"`
	Replicas    int    `json:"replicas"`
}

// Rollout — состояние Argo Rollout. Name у Healthy-rollout может быть null; AnalysisRun — имя активного AnalysisRun, может быть пустым.
// AnalysisVerdict — вердикт этого AnalysisRun (success | degradation | inconclusive | error | running), пусто без анализа.
// Правила шага его не используют; его читает PEP: автономный откат только при вердикте, подтверждающем причину отката.
type Rollout struct {
	Name            *string `json:"name"`
	Phase           string  `json:"phase"`
	AnalysisRun     string  `json:"analysis_run"`
	AnalysisVerdict string  `json:"analysis_verdict,omitempty"`
}

type PgBouncer struct {
	Database string `json:"database"`
	PoolSize int    `json:"pool_size"`
}

type Postgres struct {
	MaxConnections    int `json:"max_connections"`
	SuperuserReserved int `json:"superuser_reserved_connections"`
	OtherPoolsTotal   int `json:"other_pools_total"`
	Headroom          int `json:"headroom"`
}

type DB struct {
	PgBouncer PgBouncer `json:"pgbouncer"`
	Postgres  Postgres  `json:"postgres"`
}

// TargetState — состояние цели, из которого правила шага выводят доступные действия и величины.
type TargetState struct {
	Service    string      `json:"service"`
	Namespace  string      `json:"namespace"`
	Database   *string     `json:"database"`
	Autoscaler *Autoscaler `json:"autoscaler"`
	Pods       []string    `json:"pods"`
	Rollout    *Rollout    `json:"rollout"`
	DB         *DB         `json:"db"`
	// InsufficientDataPolicy — политика сервиса при недостатке данных canary (hold | rollback | human) из реестра
	// сервисов; nil — не задана. Правила шага её не используют; её читает PEP для отката insufficient_data_policy.
	InsufficientDataPolicy *string `json:"insufficient_data_policy,omitempty"`
}

// Validate проверяет только то, без чего правила дают бессмысленный результат: целые >= 0 и вид autoscaler'а.
func (s TargetState) Validate() error {
	if a := s.Autoscaler; a != nil {
		if a.Kind != "HorizontalPodAutoscaler" && a.Kind != "ScaledObject" {
			return fmt.Errorf("autoscaler.kind %q не из HorizontalPodAutoscaler/ScaledObject", a.Kind)
		}
		if err := nonNegative(map[string]int{"autoscaler.declared_min": a.DeclaredMin, "autoscaler.current_min": a.CurrentMin,
			"autoscaler.max": a.Max, "autoscaler.replicas": a.Replicas}); err != nil {
			return err
		}
	}
	if d := s.DB; d != nil {
		return nonNegative(map[string]int{"db.pgbouncer.pool_size": d.PgBouncer.PoolSize,
			"db.postgres.max_connections": d.Postgres.MaxConnections, "db.postgres.superuser_reserved_connections": d.Postgres.SuperuserReserved,
			"db.postgres.other_pools_total": d.Postgres.OtherPoolsTotal, "db.postgres.headroom": d.Postgres.Headroom})
	}
	return nil
}

// maxValue — потолок для целых в состоянии: защита от переполнения в правилах (2*n, n*1.5) на заведомо нереальных значениях.
const maxValue = 1 << 31

func nonNegative(m map[string]int) error {
	// порядок обхода map недетерминирован, поэтому сообщаем о наименьшем имени
	first := ""
	for k, v := range m {
		if (v < 0 || v > maxValue) && (first == "" || k < first) {
			first = k
		}
	}
	if first != "" {
		return fmt.Errorf("%s вне диапазона [0, %d]", first, maxValue)
	}
	return nil
}
