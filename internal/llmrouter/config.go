package llmrouter

import (
	"errors"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/limpjungle/aegis3311/internal/audit"
	"github.com/limpjungle/aegis3311/internal/dataclass"
	"github.com/limpjungle/aegis3311/internal/openrouter"
	"github.com/limpjungle/aegis3311/internal/routerstate"
)

type BudgetConfig struct {
	IncidentTokens   int64 // 200_000 (предложение)
	ServiceDayTokens int64 // 2_000_000 на сервис за сутки UTC (предложение)
}

type FailoverConfig struct {
	FailThreshold  int           // 3 HTTP-попытки подряд (утверждено 05.11.2026; счёт по попыткам — 07.11.2026)
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

// EventSink — запись событий роутера в аудит и поиск в цепочке (*audit.Writer). Поиск нужен при старте: разрешить
// оборванный переход по наличию события, обнаружить потерю хранилища состояния (пустой store при непустой цепочке)
// и восстановить по событиям
// состояние failover (RouterEvents — в порядке цепочки).
type EventSink interface {
	AppendEvent(ev *audit.RouterEvent) (audit.Entry, error)
	HasEvent(eventID string) bool
	LastRouterEvent() (audit.RouterEvent, bool)
	ChainNonEmpty() bool // в цепочке есть хоть одна запись (не только события роутера)
	RouterEvents() []audit.RouterEvent
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
	RouterID string            // initiator событий: system/<RouterID>
	State    routerstate.Store // обязателен: бюджеты и состояние failover переживают рестарт
}

// ErrStateStore — хранилище состояния недоступно: роутер остановлен (halted, state_store).
var ErrStateStore = errors.New("llmrouter: хранилище состояния недоступно (fail-closed)")

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

	stopGate atomic.Pointer[func() bool] // kill switch: true — запросы в hybrid не уходят (см. SetStopGate)
}

// SetStopGate задаёт ворота kill switch: пока gate() == true, Route в режиме hybrid ничего не отправляет и
// возвращает off/mode_off. Страховка поверх решения intake (оно ставит Mode=off до вызова Route). nil снимает ворота.
func (r *Router) SetStopGate(gate func() bool) {
	if gate == nil {
		r.stopGate.Store(nil)
		return
	}
	r.stopGate.Store(&gate)
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

// New не делает сетевых вызовов. Состояние — из Store (бюджеты, endpoint'ы, закрепления, halt); New может записать
// в аудит router_halted(state_lost | chain_lost) и сделать fsync в store при разрешении оборванного перехода.
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
	case isNil(o.State):
		return nil, errors.New("llmrouter: нет хранилища состояния")
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
	st, info, err := o.State.Load()
	if err != nil {
		return nil, fmt.Errorf("llmrouter: хранилище состояния: %w", err)
	}
	if want := (routerstate.Identity{RouterID: o.RouterID, Primary: o.Assets.Primary.Name, Fallback: o.Assets.Fallback.Name}); st.Identity != want {
		return nil, fmt.Errorf("llmrouter: хранилище состояния: %w", routerstate.ErrIdentity)
	}
	r := &Router{o: o, maskTimeout: MaskTimeout, bud: newBudgets(o.Budgets, o.State, st), pins: map[string]Role{},
		eps: map[Role]*endpoint{
			RolePrimary:  {profile: o.Assets.Primary, role: RolePrimary},
			RoleFallback: {profile: o.Assets.Fallback, role: RoleFallback},
		}}
	for inc, role := range st.Pins {
		r.pins[inc] = Role(role)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.applyFailoverLocked(st.Failover)
	if err := r.reconcileLocked(st, info); err != nil {
		return nil, err
	}
	// Крах мог оборвать переход между endpoint_* и active_changed: активный endpoint согласуется с состояниями.
	if !r.halted {
		if err := r.recompute("restart"); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// reconcileLocked сверяет store с цепочкой аудита при старте. Под r.mu.
func (r *Router) reconcileLocked(st *routerstate.State, info routerstate.LoadInfo) error {
	// 1. Оборванный переход: событие есть в цепочке — commit. Нет события: halt и якорь state_created не откатываются
	// (откат потерял бы остановку или якорь) — событие пишется с тем же event_id и затем commit; остальные — abort
	// (состояние до intent). Сбой записи события — New возвращает ошибку, intent остаётся для следующего старта.
	if p := st.Pending; p != nil {
		op := routerstate.Op{Kind: routerstate.OpCommit, At: r.stamp(), EventID: p.EventID}
		if !r.o.Events.HasEvent(p.EventID) {
			switch p.EventKind {
			case "router_halted":
				if err := r.appendEvent(&audit.RouterEvent{Kind: "router_halted", EventID: p.EventID, Reason: p.Next.HaltReason}, r.sys()); err != nil {
					return err
				}
			case "state_created":
				ev := r.anchorEvent()
				ev.EventID = p.EventID
				if err := r.appendEvent(&ev, r.sys()); err != nil {
					return err
				}
			default:
				op = routerstate.Op{Kind: routerstate.OpAbort, At: r.stamp(), EventID: p.EventID, Failover: &st.Failover}
			}
		}
		if err := r.o.State.Append(op); err != nil {
			return fmt.Errorf("llmrouter: хранилище состояния: %w", err)
		}
		if op.Kind == routerstate.OpCommit {
			r.applyFailoverLocked(p.Next)
		}
	}
	nonEmpty := r.o.Events.ChainNonEmpty()
	last, ok := r.o.Events.LastRouterEvent()
	switch {
	case info.Fresh && nonEmpty:
		// 2. Пустое хранилище при непустой цепочке (любая запись: decision record или событие роутера): состояние
		// failover восстанавливается из событий цепочки (источник истины), бюджеты потеряны — роутер остановлен до
		// ручного Resume. Восстановленное состояние попадает в store вместе с router_halted (intent/commit).
		// Закрепления инцидентов не восстанавливаются.
		r.applyFailoverLocked(replayFailover(r, r.o.Events.RouterEvents()))
		if err := r.halt("state_lost"); err != nil {
			return err
		}
	case !nonEmpty:
		// 3. Якорь: цепочка пуста — пишется state_created (intent/commit), после чего цепочка непуста всегда и удаление
		// store ведёт к state_lost. Сбой записи — роутер не создаётся (fail-closed); повторится при следующем старте.
		// Store не пуст (есть операции), а цепочки нет: удалена цепочка аудита — halt chain_lost рядом с якорем (в
		// Next intent якоря, чтобы крах между intent и событием не потерял остановку), затем router_halted в цепочку.
		if r.halted && r.haltReason == "audit_failed" {
			// Остановка audit_failed из прежнего процесса (store старой версии): цепочки нет, писать якорь можно.
			// Store при этом не начальный — ниже ставится chain_lost, выход по-прежнему через Resume.
			r.halted, r.haltReason = false, ""
		}
		before := r.failoverLocked()
		next := before
		// «Store не пуст»: в нём есть учёт (счета, резервы, закрепления) или failover отличается от начального. Одни
		// операции не в счёт: сбойный старт с якорем оставляет в журнале intent/abort при начальном состоянии.
		used := !info.Fresh && !storePristine(st)
		if used {
			next.Halted, next.HaltReason = true, "chain_lost"
		}
		// Сбой записи якоря: abort фиксирует в store состояние до якоря, а не остановку audit_failed — иначе новый
		// старт не смог бы записать якорь (отдельная запись восстановления могла бы и не пройти). Роутер не создаётся.
		restore := func() { r.applyFailoverLocked(before) }
		if err := r.commitEvent(r.anchorEvent(), next, r.sys(), restore); err != nil {
			return err
		}
		if used {
			// Остановка уже в store; сбой записи события оставляет в store chain_lost (не audit_failed).
			keep := func() { r.haltReason = "chain_lost" }
			if err := r.commitEvent(audit.RouterEvent{Kind: "router_halted", Reason: "chain_lost"}, r.failoverLocked(), r.sys(), keep); err != nil {
				return err
			}
		}
	case ok && last.Kind == "router_halted" && !r.halted:
		// 4. Остановка записана в цепочку, но не дошла до store (он отказал): store приводится к цепочке.
		next := r.failoverLocked()
		next.Halted, next.HaltReason = true, last.Reason
		if err := r.o.State.Append(routerstate.Op{Kind: routerstate.OpFailoverSet, At: r.stamp(), Failover: &next}); err != nil {
			return fmt.Errorf("llmrouter: хранилище состояния: %w", err)
		}
		r.applyFailoverLocked(next)
	case r.halted && r.haltReason != "audit_failed" && !chainShowsHalt(r.o.Events.RouterEvents(), r.haltReason):
		// 5. Остановка есть в store, но её события нет в цепочке: запись router_halted не удалась (например,
		// chain_lost после якоря), abort сохранил причину. Событие дописывается (intent/commit), чтобы оператор видел
		// причину. audit_failed в цепочку не пишется по определению.
		reason := r.haltReason
		keep := func() { r.haltReason = reason }
		if err := r.commitEvent(audit.RouterEvent{Kind: "router_halted", Reason: reason}, r.failoverLocked(), r.sys(), keep); err != nil {
			return err
		}
	}
	return nil
}

// chainShowsHalt — последнее из событий router_halted/router_resumed в цепочке — остановка с этой причиной.
func chainShowsHalt(evs []audit.RouterEvent, reason string) bool {
	for i := len(evs) - 1; i >= 0; i-- {
		switch evs[i].Kind {
		case "router_halted":
			return evs[i].Reason == reason
		case "router_resumed":
			return false
		}
	}
	return false
}

// storePristine — в состоянии нет ничего, что стоило бы потерять: ни счетов, ни резервов, ни закреплений, failover начальный.
func storePristine(st *routerstate.State) bool {
	return len(st.Incidents) == 0 && len(st.Days) == 0 && len(st.Holds) == 0 && st.NextHold <= 1 && len(st.Pins) == 0 &&
		st.Failover == routerstate.NewState(st.Identity).Failover
}

// anchorEvent — событие-якорь state_created: идентичность профилей (From — primary, To — fallback).
func (r *Router) anchorEvent() audit.RouterEvent {
	return audit.RouterEvent{Kind: "state_created", From: r.o.Assets.Primary.Name, To: r.o.Assets.Fallback.Name, Reason: "store_created"}
}

// replayFailover строит состояние failover по событиям роутера в порядке цепочки (state_created игнорируется): начальное (оба up, активен
// primary) плюс переходы endpoint'ов, active_changed и снятие quarantine при router_resumed. Счётчики неудач и
// halt не восстанавливаются (halt накладывает вызывающий). События неизвестных профилей пропускаются.
func replayFailover(r *Router, evs []audit.RouterEvent) routerstate.Failover {
	f := routerstate.NewState(routerstate.Identity{}).Failover
	roleOf := func(name string) (Role, bool) {
		for role, ep := range r.eps {
			if ep.profile.Name == name {
				return role, true
			}
		}
		return "", false
	}
	for _, ev := range evs {
		switch ev.Kind {
		case "endpoint_down", "endpoint_up", "endpoint_quarantined":
			if role, ok := roleOf(ev.Endpoint); ok {
				to := map[string]epState{"endpoint_down": epDown, "endpoint_up": epUp, "endpoint_quarantined": epQuarantined}[ev.Kind]
				*epRef(&f, role) = routerstate.EndpointState{State: string(to)}
			}
		case "active_changed":
			if ev.To == "none" {
				f.Active = ""
			} else if role, ok := roleOf(ev.To); ok {
				f.Active = string(role)
			}
		case "router_resumed":
			for _, role := range []Role{RolePrimary, RoleFallback} {
				if es := epRef(&f, role); es.State == string(epQuarantined) {
					*es = routerstate.EndpointState{State: string(epDown)}
				}
			}
		}
	}
	return f
}

func (r *Router) profile(role Role) *openrouter.Profile { return r.eps[role].profile }
