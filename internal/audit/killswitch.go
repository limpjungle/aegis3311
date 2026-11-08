package audit

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// KillSwitchEventSchema — третий тип записи цепочки: смена состояния kill switch на intake (architecture.md §2.2).
// Событие пишется только при смене состояния, а не на каждый опрос каналов.
const KillSwitchEventSchema = "aegisops/killswitch-event/v1"

var (
	ksEventIDRe = regexp.MustCompile(`^ks-[0-9a-f]{32}$`)
	ksActionRe  = regexp.MustCompile(`^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$`)
)

const maxKillSwitchActions = 64

// KillSwitchState — состояние kill switch, с которым принято решение или записано событие.
type KillSwitchState struct {
	Stopped           bool     `json:"stopped"`
	Reason            string   `json:"reason"` // "" | global | cluster | no_confirmation
	Global            bool     `json:"global"`
	Cluster           bool     `json:"cluster"`
	Actions           []string `json:"actions"`
	LivenessConfirmed bool     `json:"liveness_confirmed"`
	EvaluatedAt       string   `json:"evaluated_at"` // "" до первой оценки; иначе RFC 3339 UTC Z
}

// KillSwitchInfo — kill switch в decision record'е: состояние на момент решения и признак остановки во время вызова модели.
type KillSwitchInfo struct {
	State              KillSwitchState `json:"state"`
	StoppedDuringRoute bool            `json:"stopped_during_route"`
}

// KillSwitchChannel — состояние одного канала при оценке. Error — только класс ошибки, без тела ответа.
type KillSwitchChannel struct {
	Channel      string   `json:"channel"`      // configmap | oob
	Status       string   `json:"status"`       // fresh | expired | absent
	Cached       bool     `json:"cached"`       // документ из кэша: канал сейчас недоступен
	Error        string   `json:"error"`        // класс; у разобранного документа partial_signatures | insufficient_signatures
	Effect       string   `json:"effect"`       // stop | run | ""
	Confirmation string   `json:"confirmation"` // oncall | renewer | none | ""
	Signers      []string `json:"signers"`      // issuer'ы валидных подписей, отсортированы
	IssuedAt     string   `json:"issued_at"`
	DocSHA256    string   `json:"doc_sha256"`
}

// KillSwitchEvent — событие смены состояния kill switch. Kind:
//
//	kill_switch_engaged — intake остановлен (From: none | running);
//	kill_switch_released — остановка снята или первое подтверждение после старта (From: none | stopped);
//	kill_switch_updated — состояние изменилось без смены остановки (водяные знаки, действия).
//
// Bootstrap — признак первого события цепочки (from=none), когда истории kill switch нет и stop_watermark взят
// как «сейчас» по часам intake: документы, выпущенные раньше, цель не вернут, нужен release позже этого знака.
//
// LatencyMs — метрика G0: applied_at − issued_at документа-триггера; nil, если триггера нет (no_confirmation).
type KillSwitchEvent struct {
	Schema           string              `json:"schema"`
	EventID          string              `json:"event_id"`    // "ks-" + 32 hex
	RecordedAt       string              `json:"recorded_at"` // RFC 3339, UTC
	Kind             string              `json:"kind"`
	From             string              `json:"from"` // none | running | stopped
	TargetCluster    string              `json:"target_cluster"`
	State            KillSwitchState     `json:"state"`
	Triggers         []string            `json:"triggers"` // doc_sha256 документов-триггеров
	IssuedAt         string              `json:"issued_at"`
	Signers          []string            `json:"signers"`
	AppliedAt        string              `json:"applied_at"`
	LatencyMs        *int64              `json:"latency_ms"`
	StopWatermark    string              `json:"stop_watermark"`
	ReleaseWatermark string              `json:"release_watermark"`
	Bootstrap        bool                `json:"bootstrap"` // первое событие цепочки без истории: stop_watermark выставлен по часам intake
	Channels         []KillSwitchChannel `json:"channels"`
	Initiator        Actor               `json:"initiator"` // system/<intake id>
}

// NewKillSwitchEventID — случайный ID события: "ks-" + 32 hex.
func NewKillSwitchEventID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand не отказывает на поддерживаемых платформах
	}
	return "ks-" + hex.EncodeToString(b[:])
}

func utcOrEmpty(name, s string, bad func(string, ...any)) {
	if s == "" {
		return
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err != nil {
		bad("%s: %v", name, err)
	} else if !strings.HasSuffix(s, "Z") || t.Location() != time.UTC {
		bad("%s: только UTC с суффиксом Z", name)
	}
}

func (s KillSwitchState) validate(bad func(string, ...any)) {
	if s.Stopped != (s.Global || s.Cluster || !s.LivenessConfirmed) {
		bad("kill_switch.state: stopped не согласован с global, cluster и liveness_confirmed")
	}
	want := ""
	switch {
	case s.Global:
		want = "global"
	case s.Cluster:
		want = "cluster"
	case !s.LivenessConfirmed:
		want = "no_confirmation"
	}
	if s.Reason != want {
		bad("kill_switch.state: reason %q, ожидается %q", s.Reason, want)
	}
	if s.Actions == nil {
		bad("kill_switch.state: actions — список обязателен (пустой, если действий нет)")
	}
	if len(s.Actions) > maxKillSwitchActions {
		bad("kill_switch.state: actions длиннее %d", maxKillSwitchActions)
	}
	if !sort.StringsAreSorted(s.Actions) {
		bad("kill_switch.state: actions не отсортированы")
	}
	for i, a := range s.Actions {
		if !ksActionRe.MatchString(a) {
			bad("kill_switch.state: некорректное действие %q", a)
		}
		if i > 0 && s.Actions[i-1] == a {
			bad("kill_switch.state: действие %q повторяется", a)
		}
	}
	utcOrEmpty("kill_switch.state.evaluated_at", s.EvaluatedAt, bad)
}

var (
	ksChannelNames  = map[string]bool{"configmap": true, "oob": true}
	ksChannelStatus = map[string]bool{"fresh": true, "expired": true, "absent": true}
	ksEffects       = map[string]bool{"": true, "stop": true, "run": true}
	ksConfirmations = map[string]bool{"": true, "oncall": true, "renewer": true, "none": true}
	ksErrorRe       = regexp.MustCompile(`^[a-z0-9_]{0,64}$`)
)

// Validate проверяет событие перед добавлением в цепочку.
func (e *KillSwitchEvent) Validate() error {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if e.Schema != KillSwitchEventSchema {
		bad("schema: %q, ожидается %q", e.Schema, KillSwitchEventSchema)
	}
	if !ksEventIDRe.MatchString(e.EventID) {
		bad("event_id: некорректный %q", e.EventID)
	}
	if t, err := time.Parse(time.RFC3339Nano, e.RecordedAt); err != nil {
		bad("recorded_at: %v", err)
	} else if !strings.HasSuffix(e.RecordedAt, "Z") || t.Location() != time.UTC {
		bad("recorded_at: только UTC с суффиксом Z")
	}
	if e.Initiator.Kind != "system" {
		bad("initiator.kind: ожидается system, получено %q", e.Initiator.Kind)
	}
	if !idRe.MatchString(e.Initiator.ID) {
		bad("initiator.id: некорректный %q", e.Initiator.ID)
	}
	if e.TargetCluster == "" || len(e.TargetCluster) > maxUntrustedBytes {
		bad("target_cluster: обязателен, не длиннее %d байт", maxUntrustedBytes)
	}
	e.State.validate(bad)
	switch e.From {
	case "none", "running", "stopped":
	default:
		bad("from: неизвестный %q", e.From)
	}
	switch e.Kind {
	case "kill_switch_engaged":
		if !e.State.Stopped || e.From == "stopped" {
			bad("kill_switch_engaged: нужны stopped и from != stopped")
		}
	case "kill_switch_released":
		if e.State.Stopped || e.From == "running" {
			bad("kill_switch_released: нужны !stopped и from != running")
		}
	case "kill_switch_updated":
		if (e.From == "stopped") != e.State.Stopped || e.From == "none" {
			bad("kill_switch_updated: from не соответствует stopped")
		}
	default:
		bad("kind: неизвестный %q", e.Kind)
	}
	if e.Triggers == nil || e.Signers == nil {
		bad("triggers и signers — списки обязательны (пустые, если триггера нет)")
	}
	noTrig := len(e.Triggers) == 0
	if noTrig != (e.IssuedAt == "") || noTrig != (e.LatencyMs == nil) || noTrig != (len(e.Signers) == 0) {
		bad("triggers, issued_at, signers и latency_ms задаются вместе")
	}
	if e.State.Reason == "no_confirmation" && !noTrig {
		bad("при no_confirmation триггеров нет")
	}
	if e.LatencyMs != nil && *e.LatencyMs < -int64(24*time.Hour/time.Millisecond) {
		bad("latency_ms: нереалистичное значение")
	}
	if len(e.Triggers) > 8 || len(e.Signers) > 8 {
		bad("triggers и signers: не больше 8")
	}
	for _, t := range e.Triggers {
		if !sha256Re.MatchString(t) {
			bad("triggers: некорректный doc_sha256 %q", t)
		}
	}
	for _, s := range e.Signers {
		if len(s) > maxUntrustedBytes {
			bad("signers: строка длиннее %d байт", maxUntrustedBytes)
		}
	}
	utcOrEmpty("issued_at", e.IssuedAt, bad)
	if e.AppliedAt == "" {
		bad("applied_at: обязателен")
	}
	utcOrEmpty("applied_at", e.AppliedAt, bad)
	utcOrEmpty("stop_watermark", e.StopWatermark, bad)
	utcOrEmpty("release_watermark", e.ReleaseWatermark, bad)
	if e.Bootstrap && (e.From != "none" || e.StopWatermark == "") {
		bad("bootstrap: только первое событие (from=none) с stop_watermark")
	}
	if len(e.Channels) < 1 || len(e.Channels) > 4 {
		bad("channels: от 1 до 4")
	}
	seen := map[string]bool{}
	for _, c := range e.Channels {
		if !ksChannelNames[c.Channel] {
			bad("channels: неизвестный канал %q", c.Channel)
		}
		if seen[c.Channel] {
			bad("channels: канал %q повторяется", c.Channel)
		}
		seen[c.Channel] = true
		if !ksChannelStatus[c.Status] {
			bad("channels[%s].status: неизвестный %q", c.Channel, c.Status)
		}
		if !ksEffects[c.Effect] {
			bad("channels[%s].effect: неизвестный %q", c.Channel, c.Effect)
		}
		if !ksConfirmations[c.Confirmation] {
			bad("channels[%s].confirmation: неизвестное %q", c.Channel, c.Confirmation)
		}
		if !ksErrorRe.MatchString(c.Error) {
			bad("channels[%s].error: некорректный класс", c.Channel)
		}
		if c.Signers == nil || len(c.Signers) > 4 {
			bad("channels[%s].signers: список обязателен, не больше 4", c.Channel)
		}
		for _, s := range c.Signers {
			if len(s) > maxUntrustedBytes {
				bad("channels[%s].signers: строка длиннее %d байт", c.Channel, maxUntrustedBytes)
			}
		}
		utcOrEmpty("channels.issued_at", c.IssuedAt, bad)
		if c.DocSHA256 != "" && !sha256Re.MatchString(c.DocSHA256) {
			bad("channels[%s].doc_sha256: некорректный", c.Channel)
		}
	}
	return errors.Join(errs...)
}

// validateKillSwitch — kill switch в decision record'е: остановка не совместима с запросом к модели.
func validateKillSwitch(r *DecisionRecord, bad func(string, ...any)) {
	k := r.KillSwitch
	if k == nil {
		return
	}
	k.State.validate(bad)
	if k.State.Stopped && ((r.LLM != nil && r.LLM.Mode != "off") || r.Model != nil) {
		bad("kill_switch: при остановке режим llm — off и модель не вызывалась")
	}
	if k.StoppedDuringRoute && k.State.Stopped {
		bad("kill_switch.stopped_during_route: только если на старте цель не была остановлена")
	}
}
