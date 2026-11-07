package openrouter

import (
	"math"
	"strings"
	"unicode/utf8"

	"github.com/limpjungle/aegis3311/internal/pyjson"
)

// RawLimit — сколько символов сырого содержимого сохраняется при неуспехе.
const RawLimit = 2000

type Usage struct {
	PromptTokens, CompletionTokens, TotalTokens, ReasoningTokens *int64
	CostReported                                                 *float64
}

// Parsed — разобранный ответ (порт parse_response).
type Parsed struct {
	Status                                                    string        // ok | provider_mismatch | refusal | content_filter | truncated | invalid_json | schema_invalid
	Answer                                                    *pyjson.Value // при ok и schema_invalid с объектом (как run.py)
	Final                                                     bool
	SchemaErrors                                              []string
	RawContent                                                string // ≤ RawLimit символов; при provider_mismatch пусто
	ProviderActual, ModelReported, GenerationID, FinishReason string
	Usage                                                     Usage
}

func normName(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// ProviderMatches: нормализованное (ToLower, только [a-z0-9]) имя провайдера из ответа входит в
// expected_provider_names ∪ only профиля.
func ProviderMatches(actual string, p *Profile) bool {
	if actual == "" {
		return false
	}
	n := normName(actual)
	for _, x := range append(append([]string(nil), p.ExpectedProviderNames...), p.Only...) {
		if normName(x) == n {
			return true
		}
	}
	return false
}

func truncRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n])
}

// truthy — истинность значения по правилам Python.
func truthy(v *pyjson.Value) bool {
	if v == nil {
		return false
	}
	switch v.Kind {
	case pyjson.Bool:
		return v.B
	case pyjson.Number:
		if v.IsFloat {
			return v.F != 0
		}
		return v.Int != "0"
	case pyjson.String:
		return v.S != ""
	case pyjson.Array:
		return len(v.Items) > 0
	case pyjson.Object:
		return len(v.Members) > 0
	}
	return false
}

func i64(v *pyjson.Value) *int64 {
	f, ok := num(v)
	if !ok || math.IsInf(f, 0) || math.Abs(f) > 1e18 {
		return nil
	}
	n := int64(f)
	return &n
}

// ParseResponse — порт parse_response. data — тело ответа 200, прошедшее Classify.
func ParseResponse(data *pyjson.Value, p *Profile) Parsed {
	var ch, msg, u, details *pyjson.Value
	if c := data.Get("choices"); c != nil && c.Kind == pyjson.Array && len(c.Items) > 0 {
		ch = c.Items[0]
	}
	if ch != nil {
		msg = ch.Get("message")
	}
	if u = data.Get("usage"); u != nil && u.Kind != pyjson.Object {
		u = nil
	}
	details = u.Get("completion_tokens_details")
	str := func(v *pyjson.Value) string { return strOf(v) }
	out := Parsed{Final: true,
		ProviderActual: str(data.Get("provider")), ModelReported: str(data.Get("model")),
		GenerationID: str(data.Get("id")), FinishReason: str(ch.Get("finish_reason")),
		Usage: Usage{PromptTokens: i64(u.Get("prompt_tokens")), CompletionTokens: i64(u.Get("completion_tokens")),
			TotalTokens: i64(u.Get("total_tokens")), ReasoningTokens: i64(details.Get("reasoning_tokens"))},
	}
	if c, ok := num(u.Get("cost")); ok {
		out.Usage.CostReported = &c
	}
	if !ProviderMatches(out.ProviderActual, p) {
		out.Status, out.Final = "provider_mismatch", false
		return out // содержимое не разбираем и не сохраняем
	}
	content := ""
	if cv := msg.Get("content"); cv != nil {
		switch cv.Kind {
		case pyjson.String:
			content = cv.S
		case pyjson.Null:
		default:
			content = string(pyjson.Marshal(cv, pyjson.PyDefault))
		}
	}
	switch {
	case truthy(msg.Get("refusal")):
		rf := msg.Get("refusal")
		raw := string(pyjson.Marshal(rf, pyjson.PyDefault))
		if rf.Kind == pyjson.String {
			raw = rf.S
		}
		out.Status, out.RawContent = "refusal", truncRunes(raw, RawLimit)
	case out.FinishReason == "content_filter":
		out.Status, out.RawContent = "content_filter", truncRunes(content, RawLimit)
	case out.FinishReason == "length":
		out.Status, out.RawContent = "truncated", truncRunes(content, RawLimit)
	default:
		ans, err := pyjson.Parse([]byte(content))
		switch {
		case err != nil || ans.Kind == pyjson.Null:
			out.Status, out.RawContent = "invalid_json", truncRunes(content, RawLimit)
		case ans.Kind != pyjson.Object:
			out.Status, out.RawContent = "schema_invalid", truncRunes(content, RawLimit)
			out.SchemaErrors = []string{"answer is not an object"}
		default:
			out.Answer = ans
			if errs := ValidateAnswerV2(ans); len(errs) > 0 {
				out.Status, out.SchemaErrors = "schema_invalid", errs
			} else {
				out.Status = "ok"
			}
		}
	}
	return out
}
