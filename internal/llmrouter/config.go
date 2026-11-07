package llmrouter

import (
	"errors"
	"reflect"
	"sync"
	"time"

	"github.com/limpjungle/aegis3311/internal/audit"
	"github.com/limpjungle/aegis3311/internal/dataclass"
	"github.com/limpjungle/aegis3311/internal/openrouter"
)

type BudgetConfig struct {
	IncidentTokens   int64 // 200_000 (предложение)
	ServiceDayTokens int64 // 2_000_000 на сервис за сутки UTC (предложение)
}

type FailoverConfig struct {
	FailThreshold  int           // 3 (утверждено 05.11.2026)
	Hysteresis     time.Duration // 10 мин (утверждено 05.11.2026)
	HealthInterval time.Duration // 30 с (предложение)
}

func DefaultBudgets() BudgetConfig {
	return BudgetConfig{IncidentTokens: 200_000, ServiceDayTokens: 2_000_000}
}

func DefaultFailover() FailoverConfig {
	return FailoverConfig{FailThreshold: 3, Hysteresis: 10 * time.Minute, HealthInterval: 30 * time.Second}
}

const (
	MaskTimeout  = 2 * time.Second // на фрагмент (предложение)
	Backend      = "openrouter"
	Jurisdiction = "US" // OpenRouter — США (data-classes §1.1, реестр §1.2)
)

type Clock interface{ Now() time.Time }

// EventSink — запись событий роутера в аудит (*audit.Writer).
type EventSink interface {
	AppendEvent(ev *audit.RouterEvent) (audit.Entry, error)
}

type Options struct {
	Assets   *openrouter.Assets
	Client   *openrouter.Client
	Masker   dataclass.Masker
	Sources  *dataclass.Registry    // nil → MVPRegistry()
	Labels   *dataclass.LabelPolicy // nil → MVPLabelPolicy()
	Events   EventSink
	Clock    Clock
	Budgets  BudgetConfig
	Failover FailoverConfig
	RouterID string // initiator событий: system/<RouterID>
}

var ErrNoMasker = errors.New("llmrouter: без маскировщика роутер не создаётся (fail-closed)")

// Router — LLM-роутер. Безопасен для конкурентного использования.
type Router struct {
	o           Options
	maskTimeout time.Duration
	bud         *budgets

	mu         sync.Mutex // состояние failover, закрепления, halt
	eps        map[Role]*endpoint
	active     Role // "" — активного нет
	halted     bool
	haltReason string
	pins       map[string]Role
}

func isNil(v any) bool {
	if v == nil {
		return true
	}
	switch rv := reflect.ValueOf(v); rv.Kind() {
	case reflect.Ptr, reflect.Interface, reflect.Map, reflect.Func, reflect.Slice, reflect.Chan:
		return rv.IsNil()
	}
	return false
}

// New не делает сетевых вызовов. Начальное состояние: оба endpoint'а up, активен primary.
func New(o Options) (*Router, error) {
	if isNil(o.Masker) {
		return nil, ErrNoMasker
	}
	switch {
	case o.Masker.Version() == "":
		return nil, errors.New("llmrouter: маскировщик без версии")
	case o.Assets == nil || o.Assets.Primary == nil || o.Assets.Fallback == nil:
		return nil, errors.New("llmrouter: нет assets")
	case o.Client == nil:
		return nil, errors.New("llmrouter: нет клиента")
	case isNil(o.Events):
		return nil, errors.New("llmrouter: нет приёмника событий аудита")
	case isNil(o.Clock):
		return nil, errors.New("llmrouter: нет часов")
	case o.Budgets.IncidentTokens <= 0 || o.Budgets.ServiceDayTokens <= 0:
		return nil, errors.New("llmrouter: лимиты бюджета должны быть положительными")
	case o.Failover.FailThreshold <= 0 || o.Failover.Hysteresis <= 0 || o.Failover.HealthInterval <= 0:
		return nil, errors.New("llmrouter: параметры failover должны быть положительными")
	case !idRe.MatchString(o.RouterID):
		return nil, errors.New("llmrouter: некорректный router_id")
	}
	if o.Sources == nil {
		o.Sources = dataclass.MVPRegistry()
	}
	if o.Labels == nil {
		o.Labels = dataclass.MVPLabelPolicy()
	}
	r := &Router{o: o, maskTimeout: MaskTimeout, bud: newBudgets(o.Budgets), pins: map[string]Role{}, active: RolePrimary,
		eps: map[Role]*endpoint{
			RolePrimary:  {profile: o.Assets.Primary, role: RolePrimary, state: epUp},
			RoleFallback: {profile: o.Assets.Fallback, role: RoleFallback, state: epUp},
		}}
	return r, nil
}

func (r *Router) profile(role Role) *openrouter.Profile { return r.eps[role].profile }
