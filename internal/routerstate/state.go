package routerstate

import (
	"fmt"
	"regexp"
	"time"
)

// Schema — версия формата журнала.
const Schema = "aegisops/router-state/v1"

var (
	idRe      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$`)
	eventIDRe = regexp.MustCompile(`^re-[0-9a-f]{32}$`)
)

type Identity struct {
	RouterID string `json:"router_id"`
	Primary  string `json:"primary"` // имя профиля
	Fallback string `json:"fallback"`
}

type EndpointState struct {
	State    string `json:"state"` // up | down | quarantined
	ReqFails int    `json:"req_fails"`
	HCFails  int    `json:"hc_fails"`
}

type Failover struct {
	Primary    EndpointState `json:"primary"`
	Fallback   EndpointState `json:"fallback"`
	Active     string        `json:"active"` // "" | primary | fallback (как Router.active)
	Halted     bool          `json:"halted"`
	HaltReason string        `json:"halt_reason"` // "" | auth | estimator | egress_canary | audit_failed | state_store | state_lost | chain_lost
}

type Intent struct {
	EventID   string   `json:"event_id"`   // re-<32 hex>
	EventKind string   `json:"event_kind"` // kind router-event (для диагностики)
	Next      Failover `json:"next"`
}

type Hold struct {
	ID       uint64 `json:"id"`
	Incident string `json:"incident"`
	Service  string `json:"service"`
	Tokens   int64  `json:"tokens"`
}

type Day struct {
	Day   string `json:"day"` // YYYY-MM-DD, сутки UTC
	Spent int64  `json:"spent"`
}

type State struct {
	Schema    string            `json:"schema"`
	Identity  Identity          `json:"identity"`
	Incidents map[string]int64  `json:"incidents"` // incident → spent
	Days      map[string]Day    `json:"days"`      // service → текущие сутки
	Holds     []Hold            `json:"holds"`     // незакрытые резервы, по возрастанию ID
	NextHold  uint64            `json:"next_hold"` // с 1
	Pins      map[string]string `json:"pins"`      // incident → primary | fallback
	Failover  Failover          `json:"failover"`
	Pending   *Intent           `json:"pending"` // неразрешённый intent; nil — нет
}

type OpKind string

const (
	OpSnapshot      OpKind = "snapshot" // только первая строка файла
	OpReserve       OpKind = "reserve"
	OpSettle        OpKind = "settle"
	OpCloseIncident OpKind = "close_incident"
	OpPin           OpKind = "pin"
	OpFailoverSet   OpKind = "failover_set" // изменение без события аудита: счётчики, halt без события
	OpIntent        OpKind = "failover_intent"
	OpCommit        OpKind = "failover_commit"
	OpAbort         OpKind = "failover_abort"
)

type Op struct {
	Kind      OpKind    `json:"kind"`
	At        string    `json:"at"`              // RFC3339Nano UTC
	State     *State    `json:"state,omitempty"` // snapshot
	Hold      uint64    `json:"hold,omitempty"`
	Incident  string    `json:"incident,omitempty"`
	Service   string    `json:"service,omitempty"`
	Day       string    `json:"day,omitempty"`
	Tokens    int64     `json:"tokens,omitempty"`
	Recovered bool      `json:"recovered,omitempty"` // settle осиротевшего резерва при Load
	Role      string    `json:"role,omitempty"`      // pin: primary | fallback | "" (снять)
	EventID   string    `json:"event_id,omitempty"`
	EventKind string    `json:"event_kind,omitempty"`
	Failover  *Failover `json:"failover,omitempty"`
}

// NewState — начальное состояние: оба endpoint'а up, активен primary.
func NewState(id Identity) *State {
	up := EndpointState{State: "up"}
	return &State{Schema: Schema, Identity: id, Incidents: map[string]int64{}, Days: map[string]Day{},
		Holds: []Hold{}, NextHold: 1, Pins: map[string]string{},
		Failover: Failover{Primary: up, Fallback: up, Active: "primary"}}
}

// Clone — глубокая копия.
func (s *State) Clone() *State {
	c := *s
	c.Incidents = make(map[string]int64, len(s.Incidents))
	for k, v := range s.Incidents {
		c.Incidents[k] = v
	}
	c.Days = make(map[string]Day, len(s.Days))
	for k, v := range s.Days {
		c.Days[k] = v
	}
	c.Pins = make(map[string]string, len(s.Pins))
	for k, v := range s.Pins {
		c.Pins[k] = v
	}
	c.Holds = append(make([]Hold, 0, len(s.Holds)), s.Holds...)
	if s.Pending != nil {
		p := *s.Pending
		c.Pending = &p
	}
	return &c
}

// normalize заменяет null-карты и слайс пустыми (после разбора снимка).
func (s *State) normalize() {
	if s.Incidents == nil {
		s.Incidents = map[string]int64{}
	}
	if s.Days == nil {
		s.Days = map[string]Day{}
	}
	if s.Pins == nil {
		s.Pins = map[string]string{}
	}
	if s.Holds == nil {
		s.Holds = []Hold{}
	}
}

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidOp, fmt.Sprintf(format, a...))
}

func validID(s string) bool { return idRe.MatchString(s) }

func validDay(s string) bool {
	t, err := time.Parse("2006-01-02", s)
	return err == nil && t.Format("2006-01-02") == s
}

func validEndpoint(e EndpointState) bool {
	switch e.State {
	case "up", "down", "quarantined":
		return e.ReqFails >= 0 && e.HCFails >= 0
	}
	return false
}

func validFailover(f *Failover) error {
	switch {
	case f == nil:
		return invalid("нет failover")
	case !validEndpoint(f.Primary) || !validEndpoint(f.Fallback):
		return invalid("состояние endpoint'а")
	case f.Active != "" && f.Active != "primary" && f.Active != "fallback":
		return invalid("active %q", f.Active)
	case f.Halted != (f.HaltReason != ""):
		return invalid("halted и halt_reason не согласованы")
	}
	switch f.HaltReason {
	case "", "auth", "estimator", "egress_canary", "audit_failed", "state_store", "state_lost", "chain_lost":
	default:
		return invalid("halt_reason %q", f.HaltReason)
	}
	return nil
}

func validAt(at string) error {
	if at == "" {
		return nil
	}
	if _, err := time.Parse(time.RFC3339Nano, at); err != nil {
		return invalid("at: %v", err)
	}
	return nil
}

// validate — проверка состояния, прочитанного из снимка.
func (s *State) validate() error {
	s.normalize()
	if err := validFailover(&s.Failover); err != nil {
		return err
	}
	if s.NextHold < 1 {
		return invalid("next_hold < 1")
	}
	var prev uint64
	for _, h := range s.Holds {
		if h.ID <= prev || h.ID >= s.NextHold || h.Tokens < 0 || !validID(h.Incident) || !validID(h.Service) {
			return invalid("резерв %d", h.ID)
		}
		prev = h.ID
	}
	for k, v := range s.Incidents {
		if !validID(k) || v < 0 {
			return invalid("счёт инцидента %q", k)
		}
	}
	for k, v := range s.Days {
		if !validID(k) || v.Spent < 0 || !validDay(v.Day) {
			return invalid("счёт сервиса %q", k)
		}
	}
	for k, v := range s.Pins {
		if !validID(k) || (v != "primary" && v != "fallback") {
			return invalid("закрепление %q", k)
		}
	}
	if p := s.Pending; p != nil {
		if !eventIDRe.MatchString(p.EventID) || len(p.EventKind) > 64 {
			return invalid("pending")
		}
		if err := validFailover(&p.Next); err != nil {
			return err
		}
	}
	return nil
}

// Apply проверяет и применяет операцию; при ошибке (ErrInvalidOp) s не меняется.
func (s *State) Apply(op Op) error {
	if err := validAt(op.At); err != nil {
		return err
	}
	switch op.Kind {
	case OpReserve:
		if op.Hold != s.NextHold || op.Tokens < 0 || !validID(op.Incident) || !validID(op.Service) || !validDay(op.Day) {
			return invalid("reserve")
		}
		d, ok := s.Days[op.Service]
		if !ok || op.Day > d.Day { // назад сутки не сбрасываются (часы ушли назад)
			d = Day{Day: op.Day}
		}
		s.Days[op.Service] = d
		if _, ok := s.Incidents[op.Incident]; !ok {
			s.Incidents[op.Incident] = 0
		}
		s.Holds = append(s.Holds, Hold{ID: op.Hold, Incident: op.Incident, Service: op.Service, Tokens: op.Tokens})
		s.NextHold++
	case OpSettle:
		i := -1
		for j, h := range s.Holds {
			if h.ID == op.Hold {
				i = j
				break
			}
		}
		if i < 0 || op.Tokens < 0 {
			return invalid("settle")
		}
		h := s.Holds[i]
		s.Holds = append(s.Holds[:i], s.Holds[i+1:]...)
		if _, ok := s.Incidents[h.Incident]; ok { // инцидент мог быть закрыт
			s.Incidents[h.Incident] += op.Tokens
		}
		d := s.Days[h.Service]
		d.Spent += op.Tokens
		s.Days[h.Service] = d
	case OpCloseIncident:
		if !validID(op.Incident) {
			return invalid("close_incident")
		}
		delete(s.Incidents, op.Incident)
	case OpPin:
		if !validID(op.Incident) || (op.Role != "" && op.Role != "primary" && op.Role != "fallback") {
			return invalid("pin")
		}
		if op.Role == "" {
			delete(s.Pins, op.Incident)
		} else {
			s.Pins[op.Incident] = op.Role
		}
	case OpFailoverSet:
		if s.Pending != nil {
			return invalid("failover_set при неразрешённом intent")
		}
		if err := validFailover(op.Failover); err != nil {
			return err
		}
		s.Failover = *op.Failover
	case OpIntent:
		if s.Pending != nil {
			return invalid("intent при неразрешённом intent")
		}
		if !eventIDRe.MatchString(op.EventID) || len(op.EventKind) > 64 {
			return invalid("intent: event_id")
		}
		if err := validFailover(op.Failover); err != nil {
			return err
		}
		s.Pending = &Intent{EventID: op.EventID, EventKind: op.EventKind, Next: *op.Failover}
	case OpCommit:
		if s.Pending == nil || s.Pending.EventID != op.EventID {
			return invalid("commit: нет intent %q", op.EventID)
		}
		s.Failover, s.Pending = s.Pending.Next, nil
	case OpAbort:
		if s.Pending == nil || s.Pending.EventID != op.EventID {
			return invalid("abort: нет intent %q", op.EventID)
		}
		if err := validFailover(op.Failover); err != nil {
			return err
		}
		s.Failover, s.Pending = *op.Failover, nil
	default:
		return invalid("вид %q", op.Kind)
	}
	return nil
}
