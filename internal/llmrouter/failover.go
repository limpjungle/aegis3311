package llmrouter

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/limpjungle/aegis3311/internal/audit"
	"github.com/limpjungle/aegis3311/internal/openrouter"
	"github.com/limpjungle/aegis3311/internal/routerstate"
)

// ErrAuditFailed — событие роутера не записано в аудит: роутер остановлен до ручного Resume.
var ErrAuditFailed = errors.New("llmrouter: событие роутера не записано в аудит (fail-closed)")

type epState string

const (
	epUp          epState = "up"
	epDown        epState = "down"
	epQuarantined epState = "quarantined"
)

type endpoint struct {
	profile           *openrouter.Profile
	role              Role
	state             epState
	reqFails, hcFails int
	okSince           time.Time // начало серии успешных health-check'ов у down; zero — серии нет
}

// State — снимок состояния роутера.
type State struct {
	Active     string // профиль или "none"
	Halted     bool
	HaltReason string
	Endpoints  map[string]string // профиль → up | down | quarantined
}

func (r *Router) State() State {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := State{Active: r.activeName(), Halted: r.halted, HaltReason: r.haltReason, Endpoints: map[string]string{}}
	for _, ep := range r.eps {
		s.Endpoints[ep.profile.Name] = string(ep.state)
	}
	return s
}

// activeName — под r.mu.
// Активный, чей endpoint не up (сбой записи active_changed), публикуется как none.
func (r *Router) activeName() string {
	if r.active == "" || r.eps[r.active].state != epUp {
		return "none"
	}
	return r.eps[r.active].profile.Name
}

// chainActive — активный endpoint, как его видит цепочка аудита (последний записанный active_changed). Под r.mu.
func (r *Router) chainActive() string {
	if r.active == "" {
		return "none"
	}
	return r.eps[r.active].profile.Name
}

// appendEvent записывает событие в аудит (под r.mu). Сбой записи останавливает роутер (audit_failed).
func (r *Router) appendEvent(ev *audit.RouterEvent, initiator audit.Actor) error {
	ev.Schema = audit.RouterEventSchema
	if ev.EventID == "" {
		ev.EventID = audit.NewEventID()
	}
	ev.RecordedAt = audit.Timestamp(r.o.Clock.Now())
	ev.Model = r.o.Assets.Config.Model
	ev.Initiator = initiator
	if _, err := r.o.Events.AppendEvent(ev); err != nil {
		r.halted, r.haltReason = true, "audit_failed"
		return fmt.Errorf("%w: %v", ErrAuditFailed, err)
	}
	return nil
}

func (r *Router) sys() audit.Actor { return audit.Actor{Kind: "system", ID: r.o.RouterID} }

func (r *Router) stamp() string { return audit.Timestamp(r.o.Clock.Now()) }

// epRef возвращает запись endpoint'а в снимке failover.
func epRef(f *routerstate.Failover, role Role) *routerstate.EndpointState {
	if role == RolePrimary {
		return &f.Primary
	}
	return &f.Fallback
}

// failoverLocked — снимок состояния failover в памяти. Под r.mu.
func (r *Router) failoverLocked() routerstate.Failover {
	f := routerstate.Failover{Active: string(r.active), Halted: r.halted, HaltReason: r.haltReason}
	for role, ep := range r.eps {
		*epRef(&f, role) = routerstate.EndpointState{State: string(ep.state), ReqFails: ep.reqFails, HCFails: ep.hcFails}
	}
	return f
}

// applyFailoverLocked публикует состояние в памяти. okSince обнуляется, если состояние endpoint'а изменилось. Под r.mu.
func (r *Router) applyFailoverLocked(f routerstate.Failover) {
	for role, ep := range r.eps {
		es := *epRef(&f, role)
		if string(ep.state) != es.State {
			ep.okSince = time.Time{}
		}
		ep.state, ep.reqFails, ep.hcFails = epState(es.State), es.ReqFails, es.HCFails
	}
	r.active, r.halted, r.haltReason = Role(f.Active), f.Halted, f.HaltReason
}

// commitEvent — переход failover: intent в store → событие в аудит → commit в store → публикация в памяти.
// Под r.mu. Ничего не публикуется, пока событие не записано в аудит; при сбое store до записи события
// роутер останавливается (state_store). onAuditFail (если задан) вызывается при сбое аудита до записи abort:
// Resume сохраняет им прежнюю причину halt.
func (r *Router) commitEvent(ev audit.RouterEvent, next routerstate.Failover, who audit.Actor, onAuditFail func()) error {
	if r.halted && r.haltReason == "audit_failed" && ev.Kind != "router_resumed" {
		return ErrAuditFailed // писать некуда; выход из этой остановки — только Resume
	}
	ev.EventID = audit.NewEventID()
	if err := r.o.State.Append(routerstate.Op{Kind: routerstate.OpIntent, At: r.stamp(), EventID: ev.EventID, EventKind: ev.Kind, Failover: &next}); err != nil {
		return r.haltStoreLocked(err) // ничего не записано и не опубликовано
	}
	if err := r.appendEvent(&ev, who); err != nil {
		if onAuditFail != nil {
			onAuditFail()
		}
		cur := r.failoverLocked() // уже с остановкой
		// Если store тоже отказал, при рестарте intent разрешится по цепочке как abort.
		_ = r.o.State.Append(routerstate.Op{Kind: routerstate.OpAbort, At: r.stamp(), EventID: ev.EventID, Failover: &cur})
		return err
	}
	if err := r.o.State.Append(routerstate.Op{Kind: routerstate.OpCommit, At: r.stamp(), EventID: ev.EventID}); err != nil {
		r.applyFailoverLocked(next) // событие уже в цепочке: память должна ему соответствовать
		return r.haltStoreLocked(err)
	}
	r.applyFailoverLocked(next)
	return nil
}

// haltStoreLocked останавливает роутер после сбоя store (state_store): событие пишется в аудит напрямую, без intent
// (store недоступен); ErrInvalidOp (store исправен) не останавливает, кроме отказа settle (память уже расходится со store). Уже остановленный роутер причину не меняет и события не пишет. Под r.mu.
func (r *Router) haltStoreLocked(err error) error {
	var se settleError
	invalid := errors.Is(err, routerstate.ErrInvalidOp)
	if invalid && !errors.As(err, &se) {
		// Store исправен и остаётся рабочим: это логическая ошибка роутера, а не сбой хранилища. Операция не
		// выполнена (запрос не считается учтённым), halt state_store не выставляется.
		return fmt.Errorf("llmrouter: хранилище состояния отклонило операцию: %w", err)
	}
	if !r.halted {
		r.halted, r.haltReason = true, "state_store"
		if aerr := r.appendEvent(&audit.RouterEvent{Kind: "router_halted", Reason: "state_store"}, r.sys()); aerr != nil {
			return aerr // appendEvent остановил роутер с причиной audit_failed
		}
	}
	if invalid { // отказ settle при исправном store: роутер остановлен, вызывающий получает исходную ошибку
		return fmt.Errorf("llmrouter: хранилище состояния отклонило расход: %w", err)
	}
	return fmt.Errorf("%w: %v", ErrStateStore, err)
}

// setCounters сохраняет счётчики endpoint'а в store и только затем меняет память. Под r.mu.
func (r *Router) setCounters(ep *endpoint, req, hc int) error {
	next := r.failoverLocked()
	es := epRef(&next, ep.role)
	es.ReqFails, es.HCFails = req, hc
	if err := r.o.State.Append(routerstate.Op{Kind: routerstate.OpFailoverSet, At: r.stamp(), Failover: &next}); err != nil {
		return r.haltStoreLocked(err)
	}
	ep.reqFails, ep.hcFails = req, hc
	return nil
}

// recompute пересчитывает активный endpoint: primary up → primary; иначе fallback up → fallback; иначе none.
// Смена активного — событие active_changed (reason — причина перехода, вызвавшего смену).
func (r *Router) recompute(reason string) error {
	var want Role
	switch {
	case r.eps[RolePrimary].state == epUp:
		want = RolePrimary
	case r.eps[RoleFallback].state == epUp:
		want = RoleFallback
	}
	if want == r.active {
		return nil
	}
	from, to := r.chainActive(), "none"
	if want != "" {
		to = r.eps[want].profile.Name
	}
	next := r.failoverLocked()
	next.Active = string(want)
	// состояние не публикуется без записи события
	return r.commitEvent(audit.RouterEvent{Kind: "active_changed", From: from, To: to, Reason: reason}, next, r.sys(), nil)
}

// transition переводит endpoint в новое состояние: событие endpoint_* пишется до смены состояния, затем
// пересчитывается активный endpoint. Под r.mu.
func (r *Router) transition(ep *endpoint, to epState, reason string, failures int, stable time.Duration) error {
	kind := map[epState]string{epDown: "endpoint_down", epUp: "endpoint_up", epQuarantined: "endpoint_quarantined"}[to]
	next := r.failoverLocked()
	*epRef(&next, ep.role) = routerstate.EndpointState{State: string(to)}
	err := r.commitEvent(audit.RouterEvent{Kind: kind, Endpoint: ep.profile.Name, Role: string(ep.role), Reason: reason,
		ConsecutiveFailures: failures, StableForS: int64(stable / time.Second)}, next, r.sys(), nil)
	if err != nil {
		return err // состояние не публикуется без записи события
	}
	return r.recompute(reason)
}

// halt останавливает роутер: аккаунт общий (auth) или оценка токенов разошлась с фактом (estimator).
func (r *Router) halt(reason string) error {
	if r.halted {
		return nil
	}
	next := r.failoverLocked()
	next.Halted, next.HaltReason = true, reason
	return r.commitEvent(audit.RouterEvent{Kind: "router_halted", Reason: reason}, next, r.sys(), nil) // сбой аудита: роутер уже остановлен (audit_failed)
}

// onAttempt учитывает результат попытки запроса. true — остановить ретраи (endpoint перестал быть up, роутер
// остановлен или хранилище состояния отказало).
func (r *Router) onAttempt(ep *endpoint, bres *pairReserver, a openrouter.Attempt) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if serr := bres.storeFailed(); serr != nil { // резерв или расход не записан: дальше не идём
		return true, r.haltStoreLocked(serr)
	}
	if r.halted {
		return true, nil
	}
	switch a.Kind {
	case openrouter.KindOK:
		if ep.reqFails > 0 {
			if err := r.setCounters(ep, 0, ep.hcFails); err != nil {
				return true, err
			}
		}
	case openrouter.KindRetry:
		if ep.state == epUp {
			if n := ep.reqFails + 1; n >= r.o.Failover.FailThreshold {
				if err := r.transition(ep, epDown, "consecutive_failures", n, 0); err != nil {
					return true, err
				}
			} else if err := r.setCounters(ep, n, ep.hcFails); err != nil {
				return true, err
			}
		}
	} // case_error — ошибка запроса, а не endpoint'а: не считается
	return ep.state != epUp, nil
}

// onAbort: 404 → endpoint down сразу; 401/402/403 → остановка роутера (аккаунт общий).
func (r *Router) onAbort(ep *endpoint, ae *openrouter.AbortError) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ae.Reason == "no_endpoint" {
		if ep.state == epUp {
			return r.transition(ep, epDown, "no_endpoint", 0, 0)
		}
		return nil
	}
	return r.halt("auth")
}

func (r *Router) quarantine(ep *endpoint) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ep.state == epQuarantined {
		return nil
	}
	return r.transition(ep, epQuarantined, "provider_mismatch", 0, 0)
}

func (r *Router) haltEstimator() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.halt("estimator")
}

// CheckHealth — один проход по обоим endpoint'ам; вызывает планировщик. Quarantined не проверяются.
func (r *Router) CheckHealth(ctx context.Context) error {
	var firstErr error
	for _, role := range []Role{RolePrimary, RoleFallback} {
		ep := r.eps[role]
		r.mu.Lock()
		skip := ep.state == epQuarantined
		r.mu.Unlock()
		if skip {
			continue
		}
		h := r.o.Client.EndpointsHealth(ctx, &r.o.Assets.Config, ep.profile)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := r.applyHealth(ep, h.OK); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (r *Router) applyHealth(ep *endpoint, ok bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.o.Clock.Now()
	switch {
	case ep.state == epUp && ok:
		if ep.hcFails > 0 {
			return r.setCounters(ep, ep.reqFails, 0)
		}
	case ep.state == epUp:
		n := ep.hcFails + 1
		if n < r.o.Failover.FailThreshold {
			return r.setCounters(ep, ep.reqFails, n)
		}
		return r.transition(ep, epDown, "health_check_failures", n, 0)
	case ep.state == epDown && !ok:
		ep.okSince = time.Time{}
	case ep.state == epDown:
		if ep.okSince.IsZero() {
			ep.okSince = now
		}
		if d := now.Sub(ep.okSince); d >= r.o.Failover.Hysteresis {
			return r.transition(ep, epUp, "health_stable", 0, d)
		}
	}
	return nil
}

// RunHealthLoop — time.Ticker(HealthInterval) + CheckHealth до отмены ctx или сбоя аудита.
func (r *Router) RunHealthLoop(ctx context.Context) error {
	t := time.NewTicker(r.o.Failover.HealthInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			if err := r.CheckHealth(ctx); err != nil && !errors.Is(err, context.Canceled) {
				return err
			}
		}
	}
}

// Resume снимает halt и quarantine (→ down); пишет router_resumed. Если запись не удалась, halt остаётся.
func (r *Router) Resume(ctx context.Context, operator string) error {
	if !idRe.MatchString(operator) {
		return fmt.Errorf("llmrouter: некорректный operator %q", operator)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	was, wasReason := r.halted, r.haltReason
	next := r.failoverLocked()
	next.Halted, next.HaltReason = false, ""
	for _, role := range []Role{RolePrimary, RoleFallback} {
		if es := epRef(&next, role); es.State == string(epQuarantined) {
			*es = routerstate.EndpointState{State: string(epDown)}
		}
	}
	keepReason := func() { // сбой записи: прежняя причина halt сохраняется (audit_failed — если была только она)
		if was && wasReason != "audit_failed" {
			r.haltReason = wasReason
		}
	}
	if err := r.commitEvent(audit.RouterEvent{Kind: "router_resumed", Reason: "operator_resume"}, next, audit.Actor{Kind: "human", ID: operator}, keepReason); err != nil {
		return err
	}
	// активный endpoint согласуется с состояниями до снятия halt; сбой записи (appendEvent уже остановил роутер) оставляет его
	return r.recompute("operator_resume")
}

// CloseIncident снимает закрепление и счёт бюджета инцидента. Сбой хранилища состояния останавливает роутер.
func (r *Router) CloseIncident(id string) error {
	r.mu.Lock()
	if _, pinned := r.pins[id]; pinned {
		if err := r.o.State.Append(routerstate.Op{Kind: routerstate.OpPin, At: r.stamp(), Incident: id}); err != nil {
			defer r.mu.Unlock()
			return r.haltStoreLocked(err)
		}
		delete(r.pins, id)
	}
	r.mu.Unlock()
	if err := r.bud.closeIncident(id, r.o.Clock.Now()); err != nil {
		r.mu.Lock()
		defer r.mu.Unlock()
		return r.haltStoreLocked(err)
	}
	return nil
}
