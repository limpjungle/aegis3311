package llmrouter

import (
	"unicode/utf8"

	"github.com/limpjungle/aegis3311/internal/audit"
	"github.com/limpjungle/aegis3311/internal/pyjson"
)

const (
	maxUntrusted = 256 // байт в строках из ответа провайдера
	maxSchemaErr = 16
	maxSchemaLen = 200 // символов в тексте ошибки схемы
)

// cut обрезает недоверенную строку до n байт по границе руны.
func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func cutRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

func fragRefs(in []FragmentRef) []audit.FragmentRef {
	out := make([]audit.FragmentRef, 0, len(in))
	for _, f := range in {
		out = append(out, audit.FragmentRef{ID: f.ID, Source: f.Source, Class: f.Class.String(), Reason: f.Reason, Required: f.Required})
	}
	return out
}

func prefixed(hex string) string {
	if hex == "" {
		return ""
	}
	return "sha256:" + hex
}

// Apply заполняет rec.LLM, rec.Model, rec.Prompt, rec.Answer. Остальные поля (verdict, уровень, инцидент) —
// забота вызывающего. При not_sent: rec.LLM заполнен, Model/Prompt/Answer = nil. При sent: всё заполнено,
// Answer — всегда (даже при транспортной ошибке: status "error" + error_kind).
func (res *Result) Apply(rec *audit.DecisionRecord) {
	l := &audit.LLMInfo{Mode: string(res.Mode), Outcome: res.Outcome, Reason: res.Reason, Backend: Backend, Jurisdiction: Jurisdiction,
		Sources: []string{}, ExcludedFragments: []audit.FragmentRef{}, DroppedFragments: []audit.FragmentRef{}, DegradeL1: res.DegradeL1,
		EndpointSwitched: res.Switched}
	rec.LLM, rec.Model, rec.Prompt, rec.Answer = l, nil, nil, nil
	p := res.Prepared
	if p != nil {
		l.DataClass = p.DataClass.String()
		if p.Sources != nil {
			l.Sources = p.Sources
		}
		l.Masker = p.MaskerVersion
		l.ExcludedFragments, l.DroppedFragments = fragRefs(p.Excluded), fragRefs(p.Dropped)
		l.ContextTruncated = len(p.Dropped) > 0
		l.LabelsDropped, l.EstInputTokens = p.LabelsDropped, p.EstInputTokens
	}
	if res.Outcome != "sent" || p == nil {
		return
	}
	a, cfg := res.Assets, &res.Assets.Config
	m := &audit.ModelInfo{Profile: p.Profile.Name, Slug: cfg.Model, EndpointTag: p.Profile.EndpointLabel, EndpointRole: string(p.Role)}
	if len(p.Profile.Quantizations) > 0 {
		m.Quantization = p.Profile.Quantizations[0]
	}
	if body, err := pyjson.Parse(p.Body); err == nil {
		prov := body.Get("provider")
		m.RequestFlags = audit.ProviderFlags{ZDR: isTrue(prov.Get("zdr")), DataCollection: strVal(prov.Get("data_collection")),
			AllowFallbacks: isTrue(prov.Get("allow_fallbacks"))}
	}
	if res.Parsed != nil {
		m.Reported, m.Provider = cut(res.Parsed.ModelReported, maxUntrusted), cut(res.Parsed.ProviderActual, maxUntrusted)
	}
	rec.Model = m
	rec.Prompt = &audit.PromptInfo{SystemSHA256: prefixed(a.SystemSHA256), InputSHA256: prefixed(p.InputSHA256),
		RequestSHA256: prefixed(p.RequestSHA256), AnswerSchema: a.SchemaFile, AnswerSchemaSHA256: prefixed(a.SchemaSHA256),
		InputTokens: p.EstInputTokens}

	ans := &audit.AnswerInfo{Status: "error", ErrorKind: res.ErrorKind, SHA256: prefixed(res.ResponseSHA256)}
	ans.Attempts = res.Attempts
	ans.Usage = &audit.Usage{ChargedTokens: res.Tokens, CostUSD: res.CostUSD}
	if res.Parsed != nil {
		ps := res.Parsed
		ans.FinishReason, ans.GenerationID = cut(ps.FinishReason, maxUntrusted), cut(ps.GenerationID, maxUntrusted)
		if ans.Usage != nil {
			ans.Usage.PromptTokens, ans.Usage.CompletionTokens = ps.Usage.PromptTokens, ps.Usage.CompletionTokens
			ans.Usage.TotalTokens, ans.Usage.ReasoningTokens, ans.Usage.CostReported = ps.Usage.TotalTokens, ps.Usage.ReasoningTokens, ps.Usage.CostReported
		}
		for i, e := range ps.SchemaErrors {
			if i == maxSchemaErr {
				break
			}
			ans.SchemaErrors = append(ans.SchemaErrors, cutRunes(e, maxSchemaLen))
		}
		if res.ErrorKind == "" {
			ans.Status = ps.Status
			if ps.Status == "ok" && ps.Answer != nil {
				ans.Body = pyjson.Marshal(ps.Answer, pyjson.Canonical)
			}
		}
	}
	if ans.Status == "error" && ans.ErrorKind == "" {
		ans.ErrorKind = "no_response"
	}
	rec.Answer = ans
}

func isTrue(v *pyjson.Value) bool { return v != nil && v.Kind == pyjson.Bool && v.B }

func strVal(v *pyjson.Value) string {
	if v != nil && v.Kind == pyjson.String {
		return v.S
	}
	return ""
}
