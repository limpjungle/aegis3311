// Package audit — decision record'ы и подписанная hash-chain аудита (architecture.md §7).
//
// Каждый агент ведёт собственную цепочку (chain_id). Запись цепочки (Entry) связывает хеш decision record'а
// с предыдущей записью и подписывается ключом агента (интерфейс Signer: файл-ключ Ed25519 для разработки,
// KMS/HSM в эксплуатации). Голова цепочки периодически фиксируется подписанным checkpoint'ом во внешнем
// WORM-хранилище (интерфейс Anchor); по checkpoint'ам ловятся усечение и переписывание цепочки.
//
// Отказ записи — fail-closed: Writer после ошибки ввода-вывода не принимает новых записей, и вызывающий
// код не должен продолжать действие, для которого не удалось записать decision record.
package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/limpjungle/aegis3311/internal/dataclass"
	"github.com/limpjungle/aegis3311/internal/pep"
)

const RecordSchema = "aegisops/decision-record/v1"

// Режимы работы, в которых принято решение.
const (
	ModeShadow = "shadow"  // MVP-A: решение только записывается и сравнивается с решением SRE
	ModeDryRun = "dry-run" // ручной или тестовый прогон PEP
	ModeLive   = "live"    // MVP-B: исполнение под lease
)

// DecisionRecord — запись о решении агента. Поля — architecture.md §7.
type DecisionRecord struct {
	Schema     string      `json:"schema"`
	RecordID   string      `json:"record_id"`
	RecordedAt string      `json:"recorded_at"` // RFC 3339, UTC
	Mode       string      `json:"mode"`
	Incident   IncidentRef `json:"incident"`
	Initiator  Actor       `json:"initiator"`
	// LLM — как роутер обошёлся с запросом к модели: класс данных, исключённые и отброшенные фрагменты, причина
	// неотправки. nil — роутер не участвовал (решение принято без модели).
	LLM *LLMInfo `json:"llm"`
	// Model — nil, если запрос в модель не уходил (режим off, запрос не отправлен, решение принято без модели).
	// Задан тогда и только тогда, когда LLM.Outcome == "sent".
	Model  *ModelInfo  `json:"model"`
	Prompt *PromptInfo `json:"prompt"`
	// RetrievedDocs — ID документов, извлечённых из базы знаний (Qdrant) для контекста; пустой список, если не было.
	RetrievedDocs []string    `json:"retrieved_docs"`
	Answer        *AnswerInfo `json:"answer"`
	// Verdict — вердикт PEP целиком (содержит версии каталога и политики, их дайджесты и input_digest).
	Verdict *pep.Verdict `json:"verdict"`
	// AutonomyLevel — уровень, на котором решение допущено; при наличии вердикта равен verdict.effective_level.
	AutonomyLevel string     `json:"autonomy_level"`
	Lease         *LeaseRef  `json:"lease"`      // только live
	PostCheck     *PostCheck `json:"post_check"` // только live, после исполнения
	TraceRef      string     `json:"trace_ref"`  // ссылка на трейс рассуждений (OTel GenAI / Langfuse); пусто, если нет
	// Intake — откуда взят инцидент и что собрано; nil у записей без intake (старые записи, ручной route).
	Intake *IntakeInfo `json:"intake,omitempty"`
}

// IntakeInfo — как intake собрал контекст инцидента (architecture.md §6.2, «Intake»). Без него в метриках baseline не
// видно, что модель работала без метрик или не вызывалась вовсе.
type IntakeInfo struct {
	Source       string         `json:"source"`         // alerts.alertmanager
	FirstAlertAt string         `json:"first_alert_at"` // RFC 3339 UTC Z: «начало инцидента» для baseline
	CollectedAt  string         `json:"collected_at"`   // T0 снимка
	Alerts       []string       `json:"alerts"`         // fingerprint'ы Alertmanager, ^[0-9a-f]{16}$, не больше 64
	Sources      []SourceStatus `json:"sources"`        // не больше 32
	Outcome      string         `json:"outcome"`        // routed | not_routed
	Reason       string         `json:"reason"`         // при not_routed: причина из intakeReasons, иначе пусто
}

// SourceStatus — состояние одного источника при сборе. Error — только класс ошибки, без тела ответа.
type SourceStatus struct {
	Source string `json:"source"` // ID реестра dataclass
	Status string `json:"status"` // ok | empty | partial | truncated | unavailable | skipped
	Items  int    `json:"items"`
	Error  string `json:"error"` // timeout | network | oversize | decode | http_<код>; не больше 64 байт
}

type IncidentRef struct {
	ID          string `json:"id"`
	Class       string `json:"class"` // RB-001…; пусто, если класс не определён
	Service     string `json:"service"`
	Environment string `json:"environment"`
}

// Actor — инициатор решения. Kind: agent | human | system.
type Actor struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

// LLMInfo — решение LLM-роутера по запросу (data-classes §3, §4; architecture §6.2).
type LLMInfo struct {
	Mode              string        `json:"mode"`    // hybrid | off
	Outcome           string        `json:"outcome"` // sent | not_sent
	Reason            string        `json:"reason"`  // при not_sent: причина неотправки
	DataClass         string        `json:"data_class"`
	Backend           string        `json:"backend"`
	Jurisdiction      string        `json:"jurisdiction"`
	Sources           []string      `json:"sources"`
	Masker            string        `json:"masker"`
	ExcludedFragments []FragmentRef `json:"excluded_fragments"`
	DroppedFragments  []FragmentRef `json:"dropped_fragments"`
	ContextTruncated  bool          `json:"context_truncated"` // роутер отбросил фрагменты из-за потолка 64k (T-15)
	LabelsDropped     int           `json:"labels_dropped"`
	EstInputTokens    int           `json:"est_input_tokens"`
	DegradeL1         bool          `json:"degrade_l1"`        // запрос невозможен: система работает на уровне не выше L1
	EndpointSwitched  bool          `json:"endpoint_switched"` // запрос переключился с одного endpoint'а на другой (расход обоих учтён)
}

// FragmentRef — фрагмент контекста, не попавший в запрос: исключён гейтом класса (Reason — причина) или отброшен
// по потолку контекста (Reason == context_ceiling).
type FragmentRef struct {
	ID       string `json:"id"`
	Source   string `json:"source"`
	Class    string `json:"class"`
	Reason   string `json:"reason"`
	Required bool   `json:"required"`
}

// ProviderFlags — флаги провайдера в отправленном теле запроса (T-11).
type ProviderFlags struct {
	ZDR            bool   `json:"zdr"`
	DataCollection string `json:"data_collection"`
	AllowFallbacks bool   `json:"allow_fallbacks"`
}

// Usage — расход токенов: значения провайдера (nil, если не вернул) и учтённое роутером.
type Usage struct {
	PromptTokens     *int64   `json:"prompt_tokens"`
	CompletionTokens *int64   `json:"completion_tokens"`
	TotalTokens      *int64   `json:"total_tokens"`
	ReasoningTokens  *int64   `json:"reasoning_tokens"`
	CostReported     *float64 `json:"cost_reported"`
	ChargedTokens    int64    `json:"charged_tokens"`
	CostUSD          float64  `json:"cost_usd"`
}

// ModelInfo — какая модель отвечала. Profile и EndpointTag — профиль и тег endpoint'а роутера (T-12);
// Reported — имя модели из ответа провайдера (может отличаться от запрошенного Slug); Provider — фактический
// провайдер из ответа. EndpointRole — primary | fallback. RequestFlags — флаги провайдера в отправленном теле.
type ModelInfo struct {
	Profile      string        `json:"profile"`
	Slug         string        `json:"slug"`
	Reported     string        `json:"reported"`
	Provider     string        `json:"provider"`
	EndpointTag  string        `json:"endpoint_tag"`
	EndpointRole string        `json:"endpoint_role"`
	Quantization string        `json:"quantization"`
	RequestFlags ProviderFlags `json:"request_flags"`
}

// PromptInfo — что ушло в модель. Сам промпт и вход не хранятся, только хеши. RequestSHA256 — хеш тела запроса:
// по нему запрос воспроизводится и сверяется с эталоном eval.
type PromptInfo struct {
	SystemSHA256       string `json:"system_sha256"`
	InputSHA256        string `json:"input_sha256"`
	RequestSHA256      string `json:"request_sha256"`
	AnswerSchema       string `json:"answer_schema"`
	AnswerSchemaSHA256 string `json:"answer_schema_sha256"`
	InputTokens        int    `json:"input_tokens"`
}

// AnswerInfo — ответ модели. Status: ok | truncated | schema_invalid | invalid_json | refusal | content_filter |
// provider_mismatch | error (запрос не дал ответа: ErrorKind — причина). Body — разобранный ответ (только ok).
type AnswerInfo struct {
	Status       string          `json:"status"`
	ErrorKind    string          `json:"error_kind"`
	SHA256       string          `json:"sha256"` // хеш сырого тела ответа; при error может быть пустым
	Body         json.RawMessage `json:"body"`
	FinishReason string          `json:"finish_reason"`
	GenerationID string          `json:"generation_id"`
	Attempts     int             `json:"attempts"`
	Usage        *Usage          `json:"usage"`
	SchemaErrors []string        `json:"schema_errors"`
}

type LeaseRef struct {
	ID           string `json:"id"`
	FencingToken uint64 `json:"fencing_token"`
}

// PostCheck — результат пост-проверки исполнения. Status: passed | failed | rolled_back.
type PostCheck struct {
	Status string `json:"status"`
	Detail string `json:"detail"`
}

var (
	sha256Re = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	idRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$`)
	// chainRe — ID цепочки входит в имена файлов, поэтому без '/', ':' и '@'.
	chainRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	levels  = map[string]bool{"L0": true, "L1": true, "L2": true, "L3": true}
)

// Validate проверяет запись перед добавлением в цепочку. Ошибка — запись не пишется.
func (r *DecisionRecord) Validate() error {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if r.Schema != RecordSchema {
		bad("schema: %q, ожидается %q", r.Schema, RecordSchema)
	}
	if !idRe.MatchString(r.RecordID) {
		bad("record_id: некорректный %q", r.RecordID)
	}
	if t, err := time.Parse(time.RFC3339Nano, r.RecordedAt); err != nil {
		bad("recorded_at: %v", err)
	} else if !strings.HasSuffix(r.RecordedAt, "Z") || t.Location() != time.UTC {
		bad("recorded_at: только UTC с суффиксом Z")
	}
	switch r.Mode {
	case ModeShadow, ModeDryRun, ModeLive:
	default:
		bad("mode: неизвестный %q", r.Mode)
	}
	if !idRe.MatchString(r.Incident.ID) {
		bad("incident.id: некорректный %q", r.Incident.ID)
	}
	if r.Incident.Service == "" || r.Incident.Environment == "" {
		bad("incident: service и environment обязательны")
	}
	switch r.Initiator.Kind {
	case "agent", "human", "system":
	default:
		bad("initiator.kind: неизвестный %q", r.Initiator.Kind)
	}
	if !idRe.MatchString(r.Initiator.ID) {
		bad("initiator.id: некорректный %q", r.Initiator.ID)
	}
	validateLLM(r, bad)
	if r.RetrievedDocs == nil {
		bad("retrieved_docs: список обязателен (пустой, если документов не было)")
	}
	for _, d := range r.RetrievedDocs {
		if !idRe.MatchString(d) {
			bad("retrieved_docs: некорректный ID %q", d)
		}
	}
	validateAnswer(r, bad)
	validateIntake(r, bad)
	if !levels[r.AutonomyLevel] {
		bad("autonomy_level: неизвестный %q", r.AutonomyLevel)
	}
	if r.Verdict != nil {
		if r.Verdict.Schema != pep.VerdictSchema {
			bad("verdict.schema: %q", r.Verdict.Schema)
		}
		if r.Verdict.EffectiveLevel != r.AutonomyLevel {
			bad("autonomy_level %q не совпадает с verdict.effective_level %q", r.AutonomyLevel, r.Verdict.EffectiveLevel)
		}
	} else if r.AutonomyLevel != "L0" {
		bad("без вердикта PEP допустим только L0")
	}
	if r.Mode != ModeLive {
		if r.Lease != nil || r.PostCheck != nil {
			bad("lease и post_check допустимы только в режиме live")
		}
	} else {
		if r.Verdict == nil {
			bad("live: вердикт PEP обязателен")
		}
		if r.AutonomyLevel != "L0" && r.AutonomyLevel != "L1" && r.Lease == nil {
			bad("live: исполнение без lease")
		}
	}
	if r.Lease != nil && (!idRe.MatchString(r.Lease.ID) || r.Lease.FencingToken == 0) {
		bad("lease: id и fencing_token > 0 обязательны")
	}
	if r.PostCheck != nil {
		switch r.PostCheck.Status {
		case "passed", "failed", "rolled_back":
		default:
			bad("post_check.status: неизвестный %q", r.PostCheck.Status)
		}
	}
	return errors.Join(errs...)
}

var (
	notSentReasons = map[string]bool{"mode_off": true, "required_excluded": true, "context_ceiling": true,
		"budget_incident": true, "budget_service_day": true, "unavailable": true, "halted": true,
		"canceled": true}
	degradeReasons    = map[string]bool{"unavailable": true, "halted": true, "budget_incident": true, "budget_service_day": true}
	excludeReasons    = map[string]bool{"source_class": true, "unknown_source": true, "masker_failure": true, "personal_data": true, "unknown_category": true, "malformed": true}
	answerStatuses    = map[string]bool{"ok": true, "truncated": true, "schema_invalid": true, "invalid_json": true, "refusal": true, "content_filter": true, "provider_mismatch": true, "error": true}
	maxUntrustedBytes = 256
	maxSchemaErrors   = 16
	maxSchemaErrChars = 200
)

func validateLLM(r *DecisionRecord, bad func(string, ...any)) {
	l := r.LLM
	sent := l != nil && l.Outcome == "sent"
	if (r.Model != nil) != sent {
		bad("model задан тогда и только тогда, когда llm.outcome == sent")
	}
	if (r.Model == nil) != (r.Prompt == nil) {
		bad("model и prompt задаются вместе")
	}
	if r.Model != nil {
		m := r.Model
		if m.Slug == "" || m.Profile == "" {
			bad("model: slug и profile обязательны")
		}
		if m.EndpointRole != "primary" && m.EndpointRole != "fallback" {
			bad("model.endpoint_role: неизвестная роль %q", m.EndpointRole)
		}
		if m.RequestFlags != (ProviderFlags{ZDR: true, DataCollection: "deny", AllowFallbacks: false}) {
			bad("model.request_flags: ожидается zdr=true, data_collection=deny, allow_fallbacks=false")
		}
		for _, f := range []string{m.Profile, m.Slug, m.Reported, m.Provider, m.EndpointTag, m.Quantization} {
			if len(f) > maxUntrustedBytes {
				bad("model: строка длиннее %d байт", maxUntrustedBytes)
				break
			}
		}
	}
	if r.Prompt != nil {
		p := r.Prompt
		if !sha256Re.MatchString(p.SystemSHA256) || !sha256Re.MatchString(p.InputSHA256) || !sha256Re.MatchString(p.RequestSHA256) {
			bad("prompt: хеши в формате sha256:<64 hex>")
		}
		if p.AnswerSchemaSHA256 != "" && !sha256Re.MatchString(p.AnswerSchemaSHA256) {
			bad("prompt.answer_schema_sha256: формат sha256:<64 hex>")
		}
		if p.InputTokens < 0 {
			bad("prompt: отрицательные счётчики")
		}
	}
	if l == nil {
		return
	}
	switch l.Mode {
	case "hybrid", "off":
	default:
		bad("llm.mode: неизвестный %q", l.Mode)
	}
	switch l.Outcome {
	case "sent":
		if l.Reason != "" {
			bad("llm.reason: при sent пусто")
		}
		c, err := dataclass.ParseClass(l.DataClass)
		switch {
		case err != nil:
			bad("llm.data_class: %v", err)
		case c == dataclass.Restricted:
			bad("llm.data_class: restricted не уходит во внешний LLM")
		case c == dataclass.Confidential && !dataclass.ConfidentialExternalAvailable:
			bad("llm.data_class: confidential не уходит во внешний LLM в MVP")
		}
		if l.Backend == "" || l.Jurisdiction == "" || l.Masker == "" {
			bad("llm: backend, jurisdiction и masker обязательны при sent")
		}
	case "not_sent":
		if !notSentReasons[l.Reason] {
			bad("llm.reason: неизвестная причина неотправки %q", l.Reason)
		}
		if l.DataClass != "" {
			if _, err := dataclass.ParseClass(l.DataClass); err != nil {
				bad("llm.data_class: %v", err)
			}
		}
	default:
		bad("llm.outcome: неизвестный %q", l.Outcome)
	}
	if (l.Mode == "off") != (l.Reason == "mode_off") {
		bad("llm: mode off и reason mode_off задаются вместе")
	}
	if l.Mode == "off" && (l.DataClass != "" || len(l.Sources) != 0 || len(l.ExcludedFragments) != 0 ||
		len(l.DroppedFragments) != 0 || l.Masker != "" || l.EstInputTokens != 0) {
		bad("llm: при mode off класс, источники, фрагменты, masker и оценка токенов пусты")
	}
	for _, s := range l.Sources {
		if s == "" {
			bad("llm.sources: пустой источник")
		}
	}
	if l.LabelsDropped < 0 || l.EstInputTokens < 0 {
		bad("llm: отрицательные счётчики")
	}
	seen := map[string]bool{}
	frag := func(f FragmentRef, dropped bool) {
		if !idRe.MatchString(f.ID) {
			bad("llm: некорректный ID фрагмента %q", f.ID)
		}
		if seen[f.ID] {
			bad("llm: фрагмент %q повторяется в excluded и dropped", f.ID)
		}
		seen[f.ID] = true
		if f.Source == "" {
			bad("llm: фрагмент %q без источника", f.ID)
		}
		if _, err := dataclass.ParseClass(f.Class); err != nil {
			bad("llm: фрагмент %q: %v", f.ID, err)
		}
		if dropped {
			if f.Reason != "context_ceiling" {
				bad("llm.dropped_fragments: причина %q, ожидается context_ceiling", f.Reason)
			}
			if f.Required {
				bad("llm.dropped_fragments: обязательный фрагмент %q не отбрасывается", f.ID)
			}
		} else if !excludeReasons[f.Reason] {
			bad("llm.excluded_fragments: неизвестная причина %q", f.Reason)
		}
	}
	requiredExcluded := false
	for _, f := range l.ExcludedFragments {
		frag(f, false)
		requiredExcluded = requiredExcluded || f.Required
	}
	for _, f := range l.DroppedFragments {
		frag(f, true)
	}
	if requiredExcluded != (l.Outcome == "not_sent" && l.Reason == "required_excluded") {
		bad("llm: исключённый обязательный фрагмент и reason required_excluded задаются вместе")
	}
	if l.ContextTruncated != (len(l.DroppedFragments) > 0) {
		bad("llm.context_truncated не соответствует dropped_fragments")
	}
	if l.Reason == "context_ceiling" && !l.ContextTruncated {
		bad("llm: reason context_ceiling без context_truncated")
	}
	if l.DegradeL1 != degradeReasons[l.Reason] {
		bad("llm.degrade_l1 не соответствует reason %q", l.Reason)
	}
	if l.EndpointSwitched && l.Outcome != "sent" {
		bad("llm.endpoint_switched: только при outcome sent")
	}
	if l.DegradeL1 && r.AutonomyLevel != "L0" && r.AutonomyLevel != "L1" {
		bad("llm.degrade_l1: уровень %q выше L1", r.AutonomyLevel)
	}
}

func validateAnswer(r *DecisionRecord, bad func(string, ...any)) {
	a := r.Answer
	if a == nil {
		return
	}
	if r.Model == nil || r.LLM == nil || r.LLM.Outcome != "sent" {
		bad("answer без model (запрос не отправлялся)")
	}
	if !answerStatuses[a.Status] {
		bad("answer.status: неизвестный %q", a.Status)
	}
	hasBody := len(a.Body) != 0 && string(a.Body) != "null"
	if a.Status == "ok" {
		if !hasBody || !json.Valid(a.Body) {
			bad("answer.body: обязателен при status ok")
		}
	} else if hasBody {
		bad("answer.body: только при status ok")
	}
	if (a.ErrorKind != "") != (a.Status == "error") {
		bad("answer.error_kind задаётся тогда и только тогда, когда status error")
	}
	if a.SHA256 != "" || a.Status != "error" {
		if !sha256Re.MatchString(a.SHA256) {
			bad("answer.sha256: формат sha256:<64 hex>")
		}
	}
	for _, f := range []string{a.ErrorKind, a.FinishReason, a.GenerationID} {
		if len(f) > maxUntrustedBytes {
			bad("answer: строка длиннее %d байт", maxUntrustedBytes)
			break
		}
	}
	if a.Attempts < 0 {
		bad("answer.attempts: отрицательное значение")
	}
	if u := a.Usage; u != nil {
		for _, p := range []*int64{u.PromptTokens, u.CompletionTokens, u.TotalTokens, u.ReasoningTokens} {
			if p != nil && *p < 0 {
				bad("answer.usage: отрицательные токены")
			}
		}
		if (u.CostReported != nil && *u.CostReported < 0) || u.ChargedTokens < 0 || u.CostUSD < 0 {
			bad("answer.usage: отрицательные значения")
		}
	}
	if len(a.SchemaErrors) > maxSchemaErrors {
		bad("answer.schema_errors: больше %d", maxSchemaErrors)
	}
	for _, e := range a.SchemaErrors {
		if utf8.RuneCountInString(e) > maxSchemaErrChars {
			bad("answer.schema_errors: строка длиннее %d символов", maxSchemaErrChars)
			break
		}
	}
}

var (
	fingerprintRe  = regexp.MustCompile(`^[0-9a-f]{16}$`)
	intakeReasons  = map[string]bool{"source_unavailable": true, "rate_limited": true, "resolved_before_collect": true, "attempts_exhausted": true, "invalid_request": true}
	sourceStatuses = map[string]bool{"ok": true, "empty": true, "partial": true, "truncated": true, "unavailable": true, "skipped": true}
	sourceErrorRe  = regexp.MustCompile(`^(|timeout|network|oversize|decode|http_[0-9]{3})$`)
)

const (
	maxIntakeAlerts  = 64
	maxIntakeSources = 32
	maxSourceError   = 64
)

func validateIntake(r *DecisionRecord, bad func(string, ...any)) {
	in := r.Intake
	if in == nil {
		return
	}
	utc := func(name, s string) {
		if t, err := time.Parse(time.RFC3339Nano, s); err != nil {
			bad("intake.%s: %v", name, err)
		} else if !strings.HasSuffix(s, "Z") || t.Location() != time.UTC {
			bad("intake.%s: только UTC с суффиксом Z", name)
		}
	}
	if in.Source == "" {
		bad("intake.source обязателен")
	}
	utc("first_alert_at", in.FirstAlertAt)
	utc("collected_at", in.CollectedAt)
	if len(in.Alerts) > maxIntakeAlerts {
		bad("intake.alerts: больше %d", maxIntakeAlerts)
	}
	for _, a := range in.Alerts {
		if !fingerprintRe.MatchString(a) {
			bad("intake.alerts: некорректный fingerprint %q", a)
		}
	}
	if len(in.Sources) > maxIntakeSources {
		bad("intake.sources: больше %d", maxIntakeSources)
	}
	for _, s := range in.Sources {
		switch {
		case s.Source == "":
			bad("intake.sources: пустой источник")
		case !sourceStatuses[s.Status]:
			bad("intake.sources: неизвестный статус %q", s.Status)
		case s.Items < 0:
			bad("intake.sources: отрицательное число элементов")
		case len(s.Error) > maxSourceError || !sourceErrorRe.MatchString(s.Error):
			bad("intake.sources: некорректный класс ошибки %q", s.Error)
		}
	}
	switch in.Outcome {
	case "routed":
		if in.Reason != "" {
			bad("intake.reason: при routed пусто")
		}
	case "not_routed":
		if !intakeReasons[in.Reason] {
			bad("intake.reason: неизвестная причина %q", in.Reason)
		}
	default:
		bad("intake.outcome: неизвестный %q", in.Outcome)
	}
	if (in.Outcome == "routed") != (r.LLM != nil) {
		bad("intake: outcome routed и llm задаются вместе")
	}
}
