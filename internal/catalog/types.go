// Package catalog загружает и проверяет записи каталога действий (catalog/actions/*.yaml).
// Формат записи — docs/03-autonomy/action-catalog.md §1.
package catalog

import (
	"encoding/json"
	"fmt"
	"time"
)

type Reversibility string

const (
	R1 Reversibility = "R1"
	R2 Reversibility = "R2"
	R3 Reversibility = "R3"
)

// Duration — time.Duration, который читается из строк вида "10m", "0m", "24h".
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	if err != nil {
		return fmt.Errorf("duration %q: %w", b, err)
	}
	if v < 0 {
		return fmt.Errorf("duration %q: отрицательное значение", b)
	}
	d.Duration = v
	return nil
}

func (d Duration) MarshalText() ([]byte, error) { return []byte(d.String()), nil }

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

// Entry — запись каталога.
type Entry struct {
	Name                 string           `yaml:"name" json:"name"`
	Version              string           `yaml:"version" json:"version"`
	Reversibility        Reversibility    `yaml:"reversibility" json:"reversibility"`
	Targets              Targets          `yaml:"targets" json:"targets"`
	Params               map[string]Param `yaml:"params" json:"params"`
	Step                 []StepSpec       `yaml:"step" json:"step,omitempty"`
	Preconditions        []Check          `yaml:"preconditions" json:"preconditions"`
	Postconditions       Postconditions   `yaml:"postconditions" json:"postconditions"`
	Rollback             Rollback         `yaml:"rollback" json:"rollback"`
	Execution            string           `yaml:"execution" json:"execution"`
	RateLimit            RateLimit        `yaml:"rate_limit" json:"rate_limit"`
	BlastRadius          BlastRadius      `yaml:"blast_radius" json:"blast_radius"`
	Lease                string           `yaml:"lease" json:"lease"`
	ErrorBudgetExhausted string           `yaml:"error_budget_exhausted" json:"error_budget_exhausted"`
	DegradedMode         string           `yaml:"degraded_mode" json:"degraded_mode"`
	Snapshot             []string         `yaml:"snapshot" json:"snapshot"`
}

// Targets — селектор допустимых целей. SameAs разрешает загрузчик: после Load поле SameAs пусто, Kinds и Labels заполнены.
type Targets struct {
	Kinds  []string          `yaml:"kinds" json:"kinds"`
	Labels map[string]string `yaml:"labels" json:"labels,omitempty"`
	SameAs string            `yaml:"same_as" json:"same_as,omitempty"`
}

// Param — описание параметра. ChosenBy: model (выбирает LLM) или catalog (вычисляет код).
type Param struct {
	Type               string           `yaml:"type" json:"type,omitempty"`
	ChosenBy           string           `yaml:"chosen_by" json:"chosen_by"`
	Enum               []string         `yaml:"enum" json:"enum,omitempty"`
	RequiredIf         *Cond            `yaml:"required_if" json:"required_if,omitempty"`
	EnumFrom           string           `yaml:"enum_from" json:"enum_from,omitempty"`
	Source             string           `yaml:"source" json:"source,omitempty"`
	DependsOn          string           `yaml:"depends_on" json:"depends_on,omitempty"`
	Bounds             *Bounds          `yaml:"bounds" json:"bounds,omitempty"`
	Variants           map[string]Param `yaml:"variants" json:"variants,omitempty"`
	Maximum            string           `yaml:"maximum" json:"maximum,omitempty"`
	RecommendationOnly bool             `yaml:"recommendation_only" json:"recommendation_only,omitempty"`
}

// Cond — условие обязательности: параметр Param должен равняться Equals.
type Cond struct {
	Param  string `yaml:"param" json:"param"`
	Equals string `yaml:"equals" json:"equals"`
}

// Bounds — границы параметра. Rule — идентификатор зарегистрированного Go-правила границ;
// Minimum и Maximum — текст формул для ревью (не интерпретируется), целый Minimum PEP проверяет дополнительно.
type Bounds struct {
	Rule    string `yaml:"rule" json:"rule"`
	Minimum string `yaml:"minimum" json:"minimum"`
	Maximum string `yaml:"maximum" json:"maximum"`
}

// StepSpec — ссылка на Go-правило шага; Expr хранится только для ревью.
type StepSpec struct {
	Param string            `yaml:"param" json:"param"`
	When  map[string]string `yaml:"when" json:"when,omitempty"`
	Rule  string            `yaml:"rule" json:"rule"`
	Expr  string            `yaml:"expr" json:"expr"`
}

type Check struct {
	ID          string `yaml:"id" json:"id"`
	Description string `yaml:"description" json:"description"`
}

type Postconditions struct {
	Window Duration `yaml:"window" json:"window"`
	Checks []Check  `yaml:"checks" json:"checks"`
}

type Rollback struct {
	Action string            `yaml:"action" json:"action"`
	Params map[string]string `yaml:"params" json:"params,omitempty"`
}

type RateLimit struct {
	PerTargetPerHour int      `yaml:"per_target_per_hour" json:"per_target_per_hour"`
	Cooldown         Duration `yaml:"cooldown" json:"cooldown"`
}

type BlastRadius struct {
	TargetsPerCall int    `yaml:"targets_per_call" json:"targets_per_call,omitempty"`
	MaxUnavailable string `yaml:"max_unavailable" json:"max_unavailable,omitempty"`
}
