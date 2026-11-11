package llmrouter

import (
	"context"
	"errors"
	"strings"

	"github.com/limpjungle/aegis3311/internal/openrouter"
	"github.com/limpjungle/aegis3311/internal/routerstate"
)

// Result — итог Route.
type Result struct {
	Mode    Mode
	Outcome string // "sent" | "not_sent"
	// Reason при not_sent: mode_off | required_excluded | context_ceiling | budget_incident | budget_service_day |
	// unavailable | halted | egress_canary | canceled. halted — в том числе остановка из-за хранилища состояния (state_store).
	Reason    string
	DegradeL1 bool                   // true при unavailable, halted, egress_canary, budget_*
	Role      Role                   // endpoint, на который ушёл (или готовился) запрос; "" без Prepared
	Prepared  *Prepared              // nil при mode_off, unavailable, halted до подготовки
	Call      *openrouter.CallResult // последний вызов endpoint'а, которому атрибутирована запись; nil при not_sent
	// Накоплено по всем endpoint'ам одного Route: попытки, учтённый расход, признак переключения endpoint'а.
	Attempts int
	Tokens   int64
	CostUSD  float64
	Switched bool
	Parsed   *openrouter.Parsed // nil, если не было ответа 200 ok
	// ErrorKind при sent без разбора или с отвергнутым ответом: transport_timeout | transport_network |
	// transport_oversize | http_<status> | exhausted | stopped | budget | auth | no_endpoint | context_ceiling_actual.
	ErrorKind      string
	ResponseSHA256 string // hex sha256(Call.RawBody), "" без ответа
	Assets         *openrouter.Assets
}

func (res *Result) notSent(reason string) {
	res.Outcome, res.Reason = "not_sent", reason
	switch reason {
	case "unavailable", "halted", "egress_canary", "budget_incident", "budget_service_day":
		res.DegradeL1 = true
	}
}

// selectEndpoint выбирает endpoint с закреплением инцидента. why: "" | "halted" | "unavailable".
// Ошибка — только ErrAuditFailed (событие остановки не записано); сбой store даёт why="halted".
func (r *Router) selectEndpoint(incident string) (role Role, why string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.halted {
		return "", "halted", nil
	}
	role = r.pins[incident]
	if role == "" || r.eps[role].state != epUp {
		role = r.active
	}
	if role == "" || r.eps[role].state != epUp {
		return "", "unavailable", nil
	}
	if err := r.pinLocked(incident, role); err != nil {
		if errors.Is(err, routerstate.ErrInvalidOp) { // store исправен, роутер не остановлен: ошибка без причины halted
			return "", "rejected", err
		}
		return "", "halted", softStore(err)
	}
	return role, "", nil
}

// switchTo: после остановки ретраев упавшего endpoint'а — другой up-endpoint, если есть.
// Ошибка — только ErrAuditFailed при остановке из-за store.
func (r *Router) switchTo(incident string, from Role) (Role, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	other := RoleFallback
	if from == RoleFallback {
		other = RolePrimary
	}
	if r.eps[from].state == epUp || r.eps[other].state != epUp || r.halted {
		return "", false, nil
	}
	if err := r.pinLocked(incident, other); err != nil {
		return "", false, softStore(err)
	}
	return other, true, nil
}

// pinLocked закрепляет инцидент за endpoint'ом: сначала в store, потом в памяти. Сбой store останавливает роутер.
func (r *Router) pinLocked(incident string, role Role) error {
	if r.pins[incident] == role {
		return nil
	}
	if err := r.o.State.Append(routerstate.Op{Kind: routerstate.OpPin, At: r.stamp(), Incident: incident, Role: string(role)}); err != nil {
		return r.haltStoreLocked(err)
	}
	r.pins[incident] = role
	return nil
}

// softStore: сбой хранилища состояния не ошибка вызова — роутер остановлен, следующие Route вернут halted;
// ошибка остаётся только для ErrAuditFailed.
func softStore(err error) error {
	if errors.Is(err, ErrStateStore) {
		return nil
	}
	return err
}

func errorKindOf(cr *openrouter.CallResult) string {
	if strings.HasPrefix(cr.LastError, "transport_") || strings.HasPrefix(cr.LastError, "http_") {
		return cr.LastError
	}
	return string(cr.Kind)
}

// partial: ошибка сборки/проверки тела после попыток на прежнем endpoint'е — расход не теряется, вызывающий
// получает частичный Result (атрибуция прежнего endpoint'а) вместе с ошибкой.
func (r *Router) partial(res *Result, err error) (*Result, error) {
	if res.Attempts == 0 {
		return nil, err
	}
	res.Outcome, res.ErrorKind = "sent", "stopped"
	return res, err
}

// Route выполняет конвейер и вызов модели. Ошибка ErrAuditFailed — событие роутера не записано, результат
// частичный: вызывающий код не должен формировать предложение.
func (r *Router) Route(ctx context.Context, req Request) (*Result, error) {
	if err := req.validate(); err != nil {
		return nil, err
	}
	res := &Result{Mode: req.Mode, Assets: r.o.Assets}
	if g := r.stopGate.Load(); req.Mode == ModeHybrid && g != nil && (*g)() {
		res.Mode = ModeOff
		req.Mode = ModeOff
	}
	if req.Mode == ModeOff {
		res.notSent("mode_off")
		return res, nil
	}
	if ctx.Err() != nil { // отмена до подготовки: не маскируем и не выбираем endpoint
		res.notSent("canceled")
		return res, nil
	}
	role, why, serr := r.selectEndpoint(req.IncidentID)
	if why == "rejected" { // закрепление отклонено store: как при отклонённом резерве — без результата (нет причины not_sent)
		return nil, serr
	}
	if why != "" {
		res.notSent(why)
		return res, serr
	}
	set := r.mask(ctx, req)
	cfg := &r.o.Assets.Config
	switched := false
	for {
		prep, err := r.build(set, role)
		if err != nil {
			return r.partial(res, err)
		}
		if prep.NotSent != "" && res.Attempts > 0 { // после переключения: запрос уже уходил на прежний endpoint
			res.Outcome, res.ErrorKind = "sent", "stopped"
			return res, nil
		}
		if !switched { // атрибуция резерва — только после его первой попытки (ниже)
			res.Prepared, res.Role = prep, role
		}
		if prep.NotSent != "" {
			res.notSent(prep.NotSent)
			return res, nil
		}
		if err := openrouter.AssertRequestSafe(prep.Body, cfg, prep.Profile); err != nil {
			return r.partial(res, err)
		}
		// Canary: проверяются те же байты, что уходят в Post (Client.Call передаёт prep.Body на каждой попытке без изменений).
		// Остановка, зафиксированная после selectEndpoint, ловится в Reserve перед каждой попыткой.
		// До резерва бюджета, чтобы заблокированный запрос не тратил счёт; не в Transport — там ошибка дала бы ретраи и endpoint_down.
		if _, hit := r.o.Canary.Find(prep.Body); hit {
			r.canaryBlocked.Add(1)
			herr := softStore(r.haltCanary())
			if res.Attempts > 0 { // после переключения: запрос уже уходил на прежний endpoint
				res.Outcome, res.ErrorKind = "sent", "stopped"
				return res, herr
			}
			res.notSent("egress_canary")
			return res, herr
		}
		ep := r.eps[role]
		bres := r.bud.forIncident(req.IncidentID, req.Service, r.o.Clock.Now)
		bres.gate = r.haltedNow
		est := int64(prep.EstInputTokens + prep.MaxTokens)
		reservation := openrouter.Reservation{Tokens: est, USD: openrouter.CostOf(float64(prep.EstInputTokens), float64(prep.MaxTokens), prep.Profile.Prices),
			Prices: prep.Profile.Prices}
		var auditErr error
		cr, callErr := r.o.Client.Call(ctx, prep.Body, bres, reservation, func(a openrouter.Attempt) bool {
			stop, err := r.onAttempt(ep, bres, a)
			if err != nil {
				auditErr = softStore(err) // сбой store: роутер остановлен, разбор итога продолжается
				return true
			}
			return stop
		})
		res.Attempts += cr.Attempts
		res.Tokens += cr.Tokens
		res.CostUSD += cr.CostUSD
		// Call и хеш ответа — от того же endpoint'а, что и атрибуция записи: если резерв не получил ни одной
		// попытки, остаются вызов и последний ответ прежнего endpoint'а.
		if !switched || cr.Attempts > 0 {
			res.Call = &cr
			res.ResponseSHA256 = ""
			if cr.RawBody != nil {
				res.ResponseSHA256 = openrouter.SHA256Hex(cr.RawBody)
			}
		}
		if switched && cr.Attempts > 0 { // резерв получил запрос: запись атрибутируется ему
			res.Prepared, res.Role, res.Switched = prep, role, true
		}
		if serr := bres.storeFailed(); serr != nil { // резерв или расход не записан в store: роутер останавливается
			r.mu.Lock()
			herr := r.haltStoreLocked(serr)
			r.mu.Unlock()
			if auditErr == nil {
				auditErr = softStore(herr)
			}
		}
		if auditErr != nil {
			if res.Attempts == 0 && !errors.Is(auditErr, ErrAuditFailed) { // отказ store без единой попытки
				return nil, auditErr
			}
			if res.Attempts == 0 { // запрос не уходил: «sent» и атрибуция отправки недопустимы
				res.Call, res.Prepared, res.Role, res.ResponseSHA256 = nil, nil, "", ""
				res.notSent("halted")
				return res, auditErr
			}
			// Запрос уходил, ответа нет: ретраи остановлены сбоем аудита/store, а не исчерпаны (no_response было бы ложью).
			res.Outcome, res.ErrorKind = "sent", "stopped"
			return res, auditErr
		}
		if res.Attempts == 0 && cr.Kind == openrouter.CallStopped {
			res.Call = nil
			res.notSent("canceled") // ни одной попытки на любом endpoint'е
			return res, nil
		}
		res.Outcome = "sent"
		var ae *openrouter.AbortError
		switch {
		case errors.As(callErr, &ae):
			res.ErrorKind = ae.Reason
			if err := r.onAbort(ep, ae); err != nil {
				return res, softStore(err)
			}
			return res, nil
		case callErr != nil:
			return res, callErr
		}
		switch cr.Kind {
		case openrouter.CallBudget:
			if res.Attempts == 0 {
				res.Call, res.Outcome = nil, ""
				reason := bres.lastDenied()
				switch reason {
				case "":
					reason = denyIncident
				case denyStateStore:
					reason = "halted" // резерв не записан в store; роутер остановлен (state_store)
				case denyHalted:
					reason = "halted" // параллельная остановка до первой попытки
				}
				res.notSent(reason)
				return res, nil
			}
			res.ErrorKind = "budget"
			// Резерв не записан в store или параллельная остановка (пауза между ретраями, резерв после switched): не исчерпание счёта.
			if d := bres.lastDenied(); d == denyStateStore || d == denyHalted {
				res.ErrorKind = "stopped"
			}
		case openrouter.CallStopped:
			if ctx.Err() == nil && !switched {
				next, ok, serr := r.switchTo(req.IncidentID, role)
				if serr != nil {
					res.Outcome, res.ErrorKind = "sent", "stopped"
					return res, serr
				}
				if ok {
					role, switched = next, true
					res.Outcome = ""
					continue
				}
			}
			res.ErrorKind = "stopped"
		case openrouter.CallExhausted, openrouter.CallCaseError:
			// Ошибка случая (в т.ч. 404) переключения в рамках того же Route не вызывает: на другой endpoint
			// уходит только остановка ретраев (CallStopped).
			res.ErrorKind = errorKindOf(&cr)
		case openrouter.CallOK:
			parsed := openrouter.ParseResponse(cr.Data, prep.Profile)
			res.Parsed = &parsed
			if parsed.Status == "provider_mismatch" {
				if err := r.quarantine(ep); err != nil {
					return res, softStore(err)
				}
			}
			u := parsed.Usage
			if u.PromptTokens != nil && u.CompletionTokens != nil && *u.PromptTokens+*u.CompletionTokens > int64(cfg.ContextCeiling) {
				res.ErrorKind = "context_ceiling_actual"
				res.Parsed.Answer = nil // как run.py: ответ не принимается
				if err := r.haltEstimator(); err != nil {
					return res, softStore(err)
				}
			}
		}
		return res, nil
	}
}
