package llmrouter

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/limpjungle/aegis3311/internal/audit"
	"github.com/limpjungle/aegis3311/internal/openrouter"
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

// emit записывает событие в аудит (под r.mu). Сбой записи останавливает роутер (audit_failed).
func (r *Router) emit(ev audit.RouterEvent, initiator audit.Actor) error {
	if r.halted && r.haltReason == "audit_failed" {
		return ErrAuditFailed // писать некуда
	}
	ev.Schema, ev.EventID = audit.RouterEventSchema, audit.NewEventID()
	ev.RecordedAt = audit.Timestamp(r.o.Clock.Now())
	ev.Model = r.o.Assets.Config.Model
	ev.Initiator = initiator
	if _, err := r.o.Events.AppendEvent(&ev); err != nil {
		r.halted, r.haltReason = true, "audit_failed"
		return fmt.Errorf("%w: %v", ErrAuditFailed, err)
	}
	return nil
}

func (r *Router) sys() audit.Actor { return audit.Actor{Kind: "system", ID: r.o.RouterID} }

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
	if err := r.emit(audit.RouterEvent{Kind: "active_changed", From: from, To: to, Reason: reason}, r.sys()); err != nil {
		return err // состояние не публикуется без записи события
	}
	r.active = want
	return nil
}

// transition переводит endpoint в новое состояние: событие endpoint_* пишется до смены состояния, затем
// пересчитывается активный endpoint. Под r.mu.
func (r *Router) transition(ep *endpoint, to epState, reason string, failures int, stable time.Duration) error {
	kind := map[epState]string{epDown: "endpoint_down", epUp: "endpoint_up", epQuarantined: "endpoint_quarantined"}[to]
	err := r.emit(audit.RouterEvent{Kind: kind, Endpoint: ep.profile.Name, Role: string(ep.role), Reason: reason,
		ConsecutiveFailures: failures, StableForS: int64(stable / time.Second)}, r.sys())
	if err != nil {
		return err // состояние не публикуется без записи события
	}
	ep.state, ep.reqFails, ep.hcFails, ep.okSince = to, 0, 0, time.Time{}
	return r.recompute(reason)
}

// halt останавливает роутер: аккаунт общий (auth) или оценка токенов разошлась с фактом (estimator).
func (r *Router) halt(reason string) error {
	if r.halted {
		return nil
	}
	if err := r.emit(audit.RouterEvent{Kind: "router_halted", Reason: reason}, r.sys()); err != nil {
		return err // emit уже остановил роутер с причиной audit_failed
	}
	r.halted, r.haltReason = true, reason
	return nil
}

// onAttempt учитывает результат попытки запроса. true — остановить ретраи (endpoint перестал быть up).
func (r *Router) onAttempt(ep *endpoint, a openrouter.Attempt) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch a.Kind {
	case openrouter.KindOK:
		ep.reqFails = 0
	case openrouter.KindRetry:
		if ep.state == epUp {
			if ep.reqFails++; ep.reqFails >= r.o.Failover.FailThreshold {
				if err := r.transition(ep, epDown, "consecutive_failures", ep.reqFails, 0); err != nil {
					return true, err
				}
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
		ep.hcFails = 0
	case ep.state == epUp:
		if ep.hcFails++; ep.hcFails >= r.o.Failover.FailThreshold {
			return r.transition(ep, epDown, "health_check_failures", ep.hcFails, 0)
		}
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
	r.halted, r.haltReason = false, ""
	if err := r.emit(audit.RouterEvent{Kind: "router_resumed", Reason: "operator_resume"}, audit.Actor{Kind: "human", ID: operator}); err != nil {
		r.halted, r.haltReason = true, "audit_failed"
		if was && wasReason != "audit_failed" {
			r.haltReason = wasReason
		}
		return err
	}
	for _, ep := range r.eps {
		if ep.state == epQuarantined {
			ep.state, ep.reqFails, ep.hcFails, ep.okSince = epDown, 0, 0, time.Time{}
		}
	}
	// активный endpoint согласуется с состояниями до снятия halt; сбой записи (emit уже вернул halt) оставляет его
	if err := r.recompute("operator_resume"); err != nil {
		return err
	}
	return nil
}

// CloseIncident снимает закрепление и счёт бюджета инцидента.
func (r *Router) CloseIncident(id string) {
	r.mu.Lock()
	delete(r.pins, id)
	r.mu.Unlock()
	r.bud.closeIncident(id)
}
