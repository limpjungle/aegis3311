package audit

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// RouterEventSchema — второй тип записи цепочки: событие LLM-роутера (переключение endpoint'а, остановка).
// Событие лежит в том же файле, что и decision record'ы, и различается полем schema внутри record.
const RouterEventSchema = "aegisops/router-event/v1"

var eventIDRe = regexp.MustCompile(`^re-[0-9a-f]{32}$`)

// RouterEvent — событие роутера. Kind:
//
//	endpoint_down | endpoint_up | endpoint_quarantined — переходы endpoint'а (Endpoint, Role);
//	active_changed — смена активного endpoint'а (From → To, профиль или "none");
//	router_halted — роутер остановлен (Reason: auth | estimator | audit_failed | state_store | state_lost | chain_lost);
//	state_created — якорь: роутер создал хранилище состояния при пустой цепочке (Reason: store_created;
//	  From/To — профили primary/fallback); после него цепочка непуста, и потеря хранилища обнаруживается;
//	router_resumed — остановка снята оператором (Initiator.Kind == human).
type RouterEvent struct {
	Schema              string `json:"schema"`
	EventID             string `json:"event_id"`    // "re-" + 32 hex
	RecordedAt          string `json:"recorded_at"` // RFC 3339, UTC
	Kind                string `json:"kind"`
	Endpoint            string `json:"endpoint"` // профиль; для endpoint_*
	Role                string `json:"role"`     // primary | fallback; для endpoint_*
	From                string `json:"from"`     // active_changed: профиль или "none"
	To                  string `json:"to"`
	Reason              string `json:"reason"`
	ConsecutiveFailures int    `json:"consecutive_failures"`
	StableForS          int64  `json:"stable_for_s"`
	Model               string `json:"model"`
	Initiator           Actor  `json:"initiator"` // system/<router id>; human при router_resumed
}

// NewEventID — случайный ID события: "re-" + 32 hex.
func NewEventID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand не отказывает на поддерживаемых платформах
	}
	return "re-" + hex.EncodeToString(b[:])
}

// Validate проверяет событие перед добавлением в цепочку.
func (e *RouterEvent) Validate() error {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if e.Schema != RouterEventSchema {
		bad("schema: %q, ожидается %q", e.Schema, RouterEventSchema)
	}
	if !eventIDRe.MatchString(e.EventID) {
		bad("event_id: некорректный %q", e.EventID)
	}
	if t, err := time.Parse(time.RFC3339Nano, e.RecordedAt); err != nil {
		bad("recorded_at: %v", err)
	} else if !strings.HasSuffix(e.RecordedAt, "Z") || t.Location() != time.UTC {
		bad("recorded_at: только UTC с суффиксом Z")
	}
	switch e.Initiator.Kind {
	case "agent", "human", "system":
	default:
		bad("initiator.kind: неизвестный %q", e.Initiator.Kind)
	}
	if !idRe.MatchString(e.Initiator.ID) {
		bad("initiator.id: некорректный %q", e.Initiator.ID)
	}
	if e.Model == "" || len(e.Model) > maxUntrustedBytes {
		bad("model: обязателен, не длиннее %d байт", maxUntrustedBytes)
	}
	if e.ConsecutiveFailures < 0 || e.StableForS < 0 {
		bad("отрицательные счётчики")
	}
	endpoint := func() {
		if e.Endpoint == "" || len(e.Endpoint) > maxUntrustedBytes {
			bad("endpoint: обязателен")
		}
		if e.Role != "primary" && e.Role != "fallback" {
			bad("role: неизвестная %q", e.Role)
		}
	}
	switch e.Kind {
	case "endpoint_down":
		endpoint()
		switch e.Reason {
		case "consecutive_failures", "health_check_failures":
			if e.ConsecutiveFailures < 1 {
				bad("consecutive_failures >= 1 обязателен для причины %q", e.Reason)
			}
		case "no_endpoint":
		default:
			bad("reason: %q недопустима для endpoint_down", e.Reason)
		}
	case "endpoint_up":
		endpoint()
		if e.Reason != "health_stable" {
			bad("reason: для endpoint_up ожидается health_stable, получено %q", e.Reason)
		}
		if e.StableForS < 1 {
			bad("stable_for_s >= 1 обязателен для endpoint_up")
		}
	case "endpoint_quarantined":
		endpoint()
		if e.Reason != "provider_mismatch" {
			bad("reason: для endpoint_quarantined ожидается provider_mismatch, получено %q", e.Reason)
		}
	case "active_changed":
		if e.From == "" || e.To == "" || e.From == e.To {
			bad("active_changed: from и to обязательны и различны")
		}
		if e.Endpoint != "" || e.Role != "" {
			bad("active_changed: endpoint и role пусты")
		}
		if e.Reason == "" {
			bad("active_changed: reason обязателен")
		}
	case "router_halted":
		switch e.Reason {
		case "auth", "estimator", "audit_failed", "state_store", "state_lost", "chain_lost":
		default:
			bad("reason: %q недопустима для router_halted", e.Reason)
		}
	case "state_created":
		if e.Reason != "store_created" {
			bad("reason: для state_created ожидается store_created, получено %q", e.Reason)
		}
		if e.From == "" || e.To == "" || len(e.From) > maxUntrustedBytes || len(e.To) > maxUntrustedBytes {
			bad("state_created: from и to (профили primary и fallback) обязательны")
		}
		if e.Endpoint != "" || e.Role != "" {
			bad("state_created: endpoint и role пусты")
		}
	case "router_resumed":
		if e.Initiator.Kind != "human" {
			bad("router_resumed: инициатор — человек")
		}
	default:
		bad("kind: неизвестный %q", e.Kind)
	}
	return errors.Join(errs...)
}
