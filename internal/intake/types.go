package intake

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/limpjungle/aegis3311/internal/audit"
	"github.com/limpjungle/aegis3311/internal/step"
)

// Alert — активный алерт Alertmanager (после sanitize; времена абсолютные).
type Alert struct {
	Fingerprint string    `json:"fingerprint"`
	Name        string    `json:"name"`
	Severity    string    `json:"severity"`
	Namespace   string    `json:"namespace"`
	Service     string    `json:"service"`
	Summary     string    `json:"summary"`
	Description string    `json:"description"`
	StartsAt    time.Time `json:"starts_at"`
}

// Topology — сервис, автоскейлер и поды. NamespaceLabels и TargetLabels нужны только PEP и в модель не уходят.
type Topology struct {
	Service                string            `json:"service"`
	Namespace              string            `json:"namespace"`
	Database               *string           `json:"database"`
	InsufficientDataPolicy *string           `json:"insufficient_data_policy"`
	Autoscaler             *step.Autoscaler  `json:"autoscaler"`
	Pods                   []string          `json:"pods"`
	NamespaceLabels        map[string]string `json:"namespace_labels"`
	TargetLabels           map[string]string `json:"target_labels"`
}

type Event struct {
	Type   string    `json:"type"`
	Reason string    `json:"reason"`
	Object string    `json:"object"` // pod/<имя>
	Count  int       `json:"count"`
	At     time.Time `json:"at"`
}

type Deploy struct {
	Revision    int       `json:"revision"`
	ImageDigest string    `json:"image_digest"`
	AuthorID    string    `json:"author_id"`
	At          time.Time `json:"at"`
}

// Num — число, помнящее вид (целое или дробное): в golden-наборе baseline/canary фазы Bake целые, а у threshold — дробные
// даже при целом значении. Живые клиенты всегда дают дробное (Int=false).
type Num struct {
	F   float64
	Int bool
}

func (n *Num) UnmarshalJSON(b []byte) error {
	if err := json.Unmarshal(b, &n.F); err != nil {
		return err
	}
	n.Int = !bytes.ContainsAny(b, ".eE")
	return nil
}

func (n Num) MarshalJSON() ([]byte, error) {
	if n.Int {
		return []byte(fmt.Sprintf("%d", int64(n.F))), nil
	}
	return json.Marshal(n.F)
}

type AnalysisMetric struct {
	Name            string `json:"name"`
	Test            string `json:"test"`
	Baseline        *Num   `json:"baseline"`
	Canary          *Num   `json:"canary"`
	PValue          *Num   `json:"p_value"`
	HolmSignificant bool   `json:"holm_significant"`
	Samples         *int   `json:"samples"`     // только у статистических тестов
	MinSamples      *int   `json:"min_samples"` //
}

type AnalysisRun struct {
	Name    string           `json:"name"`
	Verdict string           `json:"verdict"` // success | degradation | inconclusive | running
	Metrics []AnalysisMetric `json:"metrics"`
}

// PreviousAnalysisRun — последний AnalysisRun другой ревизии Rollout. Подставляется, только если у текущей ревизии
// анализа ещё нет и фаза Progressing или Bake; к текущему canary не относится, в TargetState не попадает.
type PreviousAnalysisRun struct {
	Revision *int             `json:"revision"` // ревизия Rollout этого анализа; nil — её ReplicaSet уже удалён
	Name     string           `json:"name"`
	Verdict  string           `json:"verdict"`
	Metrics  []AnalysisMetric `json:"metrics"`
}

type Rollout struct {
	Name            *string      `json:"name"`
	Phase           string       `json:"phase"`
	CanaryRevision  *int         `json:"canary_revision"`
	StableRevision  *int         `json:"stable_revision"`
	CanaryWeightPct int          `json:"canary_weight_pct"`
	AnalysisRun     *AnalysisRun `json:"analysis_run"`

	PreviousAnalysisRun *PreviousAnalysisRun `json:"previous_analysis_run,omitempty"`
}

type Label struct{ K, V string }

// Series — серия метрики: ровно 31 точка с шагом 60 с, T0-30m…T0; nil — пропуск (в модель уходит null).
type Series struct {
	Name   string     `json:"name"`
	Unit   string     `json:"unit"`
	Labels []Label    `json:"labels"`
	Values []*float64 `json:"values"`
}

type SessionRow struct {
	State    string `json:"state"`
	Sessions int    `json:"sessions"`
	Over60s  int    `json:"over_60s"`
}

type PoolRow struct {
	Database  string  `json:"database"`
	ClActive  int     `json:"cl_active"`
	ClWaiting int     `json:"cl_waiting"`
	SvActive  int     `json:"sv_active"`
	SvIdle    int     `json:"sv_idle"`
	MaxWaitS  float64 `json:"maxwait_s"`
}

// DBAggregates — агрегаты СУБД (data-classes §3: только счётчики, без текстов запросов).
type DBAggregates struct {
	PgBouncer       step.PgBouncer `json:"pgbouncer"`
	Postgres        step.Postgres  `json:"postgres"`
	SessionsByState []SessionRow   `json:"sessions_by_state"`
	ShowPools       []PoolRow      `json:"show_pools"`
}

// PDB — PodDisruptionBudget как есть: значение целое или строка-процент.
type PDB struct {
	MinAvailable   any `json:"min_available,omitempty"`
	MaxUnavailable any `json:"max_unavailable,omitempty"`
}

// Opt: Present=false — ключа в input нет (источник не дал данных); Present=true и Value=nil — ключ со значением null
// (источник исправен, объекта нет).
type Opt[T any] struct {
	Present bool
	Value   *T
}

func Some[T any](v *T) Opt[T] { return Opt[T]{Present: true, Value: v} }

// Snapshot — всё, что собрано по инциденту на момент T0.
type Snapshot struct {
	T0       time.Time
	Alert    Alert
	Topology Topology
	Metrics  []Series
	Events   []Event
	Deploys  []Deploy
	Rollout  Opt[Rollout]
	DB       Opt[DBAggregates]
	PDB      Opt[PDB]
	Status   []audit.SourceStatus
}

// ParseSnapshot разбирает фикстуру replay: Snapshot в JSON, строго. Rollout, DB и PDB: нет ключа — Present=false,
// null — Present=true с пустым значением.
func ParseSnapshot(b []byte) (Snapshot, error) {
	var w struct {
		T0       time.Time            `json:"t0"`
		Alert    Alert                `json:"alert"`
		Topology Topology             `json:"topology"`
		Metrics  []Series             `json:"metrics"`
		Events   []Event              `json:"events"`
		Deploys  []Deploy             `json:"deploys"`
		Rollout  json.RawMessage      `json:"rollout"`
		DB       json.RawMessage      `json:"db"`
		PDB      json.RawMessage      `json:"pdb"`
		Status   []audit.SourceStatus `json:"status"`
	}
	if err := strictDecode(b, &w); err != nil {
		return Snapshot{}, fmt.Errorf("фикстура: %w", err)
	}
	s := Snapshot{T0: w.T0, Alert: w.Alert, Topology: w.Topology, Metrics: w.Metrics, Events: w.Events, Deploys: w.Deploys, Status: w.Status}
	var err error
	if s.Rollout, err = parseOpt[Rollout](w.Rollout, "rollout"); err != nil {
		return Snapshot{}, err
	}
	if s.DB, err = parseOpt[DBAggregates](w.DB, "db"); err != nil {
		return Snapshot{}, err
	}
	if s.PDB, err = parseOpt[PDB](w.PDB, "pdb"); err != nil {
		return Snapshot{}, err
	}
	return s, nil
}

func parseOpt[T any](raw json.RawMessage, name string) (Opt[T], error) {
	if len(raw) == 0 {
		return Opt[T]{}, nil
	}
	if strings.TrimSpace(string(raw)) == "null" {
		return Opt[T]{Present: true}, nil
	}
	var v T
	if err := strictDecode(raw, &v); err != nil {
		return Opt[T]{}, fmt.Errorf("фикстура: %s: %w", name, err)
	}
	return Opt[T]{Present: true, Value: &v}, nil
}

// ErrCriticalSource — без этого источника запроса к модели нет (топология; метрики целиком; rollout и db, если они
// у сервиса есть): модель, не видящая ключевой части картины, давала бы вводящие в заблуждение предложения.
type ErrCriticalSource struct {
	Source string
	Err    error
}

func (e *ErrCriticalSource) Error() string {
	return "intake: критичный источник " + e.Source + " недоступен: " + e.Err.Error()
}
func (e *ErrCriticalSource) Unwrap() error { return e.Err }
