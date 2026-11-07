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
	// Model — nil, если LLM для сервиса выключен (режим off) или решение принято без модели.
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

// ModelInfo — какая модель отвечала. Profile и EndpointTag — профиль и тег endpoint'а роутера (T-12);
// Reported — имя модели из ответа провайдера (может отличаться от запрошенного Slug).
type ModelInfo struct {
	Profile      string `json:"profile"`
	Slug         string `json:"slug"`
	Reported     string `json:"reported"`
	Provider     string `json:"provider"`
	EndpointTag  string `json:"endpoint_tag"`
	Quantization string `json:"quantization"`
}

// PromptInfo — что ушло в модель. Сам промпт и вход не хранятся, только хеши.
type PromptInfo struct {
	SystemSHA256 string `json:"system_sha256"`
	InputSHA256  string `json:"input_sha256"`
	AnswerSchema string `json:"answer_schema"`
	InputTokens  int    `json:"input_tokens"`
	// ContextTruncated — роутер отбросил фрагменты контекста из-за потолка 64k (T-15).
	ContextTruncated bool `json:"context_truncated"`
	DroppedFragments int  `json:"dropped_fragments"`
}

// AnswerInfo — ответ модели. Status: ok | truncated | schema_invalid | error. Body — разобранный ответ (только ok).
type AnswerInfo struct {
	Status string          `json:"status"`
	SHA256 string          `json:"sha256"` // хеш сырого тела ответа
	Body   json.RawMessage `json:"body"`
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
	if r.Model != nil && (r.Model.Slug == "" || r.Model.Profile == "") {
		bad("model: slug и profile обязательны")
	}
	if (r.Model == nil) != (r.Prompt == nil) {
		bad("model и prompt задаются вместе")
	}
	if r.Prompt != nil {
		if !sha256Re.MatchString(r.Prompt.SystemSHA256) || !sha256Re.MatchString(r.Prompt.InputSHA256) {
			bad("prompt: хеши в формате sha256:<64 hex>")
		}
		if r.Prompt.InputTokens < 0 || r.Prompt.DroppedFragments < 0 {
			bad("prompt: отрицательные счётчики")
		}
		if r.Prompt.DroppedFragments > 0 && !r.Prompt.ContextTruncated {
			bad("prompt: dropped_fragments > 0 без context_truncated")
		}
	}
	if r.RetrievedDocs == nil {
		bad("retrieved_docs: список обязателен (пустой, если документов не было)")
	}
	for _, d := range r.RetrievedDocs {
		if !idRe.MatchString(d) {
			bad("retrieved_docs: некорректный ID %q", d)
		}
	}
	if r.Answer != nil {
		if r.Model == nil {
			bad("answer без model")
		}
		switch r.Answer.Status {
		case "ok":
			if len(r.Answer.Body) == 0 || !json.Valid(r.Answer.Body) || string(r.Answer.Body) == "null" {
				bad("answer.body: обязателен при status ok")
			}
		case "truncated", "schema_invalid", "error":
			if len(r.Answer.Body) != 0 && string(r.Answer.Body) != "null" {
				bad("answer.body: только при status ok")
			}
		default:
			bad("answer.status: неизвестный %q", r.Answer.Status)
		}
		if !sha256Re.MatchString(r.Answer.SHA256) {
			bad("answer.sha256: формат sha256:<64 hex>")
		}
	}
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
