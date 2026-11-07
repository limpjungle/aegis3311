package openrouter

import (
	"bytes"
	"fmt"
	"math"
	"sort"

	"github.com/limpjungle/aegis3311/internal/pyjson"
)

var allowedBodyKeys = map[string]bool{"model": true, "messages": true, "response_format": true, "provider": true,
	"temperature": true, "seed": true, "max_tokens": true, "usage": true}

// SafetyError — запрос не прошёл проверку безопасности и не отправляется.
type SafetyError struct{ Reason string }

func (e *SafetyError) Error() string {
	return "openrouter: запрос небезопасен: " + e.Reason
}

// BuildRequest — порт build_request. input — собранный роутером объект; в тело попадают копии (Clone).
func BuildRequest(input *pyjson.Value, a *Assets, p *Profile) *pyjson.Value {
	cfg := &a.Config
	body := pyjson.NewObject(
		pyjson.M("model", pyjson.NewString(cfg.Model)),
		pyjson.M("messages", pyjson.NewArray(
			pyjson.NewObject(pyjson.M("role", pyjson.NewString("system")), pyjson.M("content", pyjson.NewString(a.SystemPrompt))),
			pyjson.NewObject(pyjson.M("role", pyjson.NewString("user")),
				pyjson.M("content", pyjson.NewString(string(pyjson.Marshal(input, pyjson.Canonical)))))),
		),
		pyjson.M("response_format", pyjson.NewObject(
			pyjson.M("type", pyjson.NewString("json_schema")),
			pyjson.M("json_schema", pyjson.NewObject(
				pyjson.M("name", pyjson.NewString(SchemaName)),
				pyjson.M("strict", pyjson.NewBool(true)),
				pyjson.M("schema", a.RequestSchema.Clone()))))),
		pyjson.M("provider", p.Provider.Clone()),
		pyjson.M("temperature", cfg.Generation.Temperature.Clone()),
		pyjson.M("max_tokens", pyjson.NewInt(int64(cfg.Generation.MaxTokens))),
		pyjson.M("usage", pyjson.NewObject(pyjson.M("include", pyjson.NewBool(true)))),
	)
	if p.SendSeed {
		body.Set("seed", cfg.Generation.Seed.Clone())
	}
	return body
}

// BodyBytes — байты тела запроса (canon_json).
func BodyBytes(body *pyjson.Value) []byte { return pyjson.Marshal(body, pyjson.Canonical) }

// AssertRequestSafe — порт assert_request_safe над байтами, которые уйдут в сеть.
func AssertRequestSafe(body []byte, cfg *Config, p *Profile) error {
	fail := func(format string, a ...any) error { return &SafetyError{fmt.Sprintf(format, a...)} }
	b, err := pyjson.Parse(body)
	if err != nil {
		return fail("тело не разбирается: %v", err)
	}
	if b.Kind != pyjson.Object {
		return fail("тело не объект")
	}
	var extra []string
	for _, m := range b.Members {
		if !allowedBodyKeys[m.Key] {
			extra = append(extra, m.Key)
		}
	}
	if len(extra) > 0 {
		sort.Strings(extra)
		return fail("request has disallowed keys: %q", extra)
	}
	prov := b.Get("provider")
	if prov == nil || prov.Kind != pyjson.Object || !isBool(prov.Get("zdr"), true) ||
		!isStr(prov.Get("data_collection"), "deny") || !isBool(prov.Get("allow_fallbacks"), false) {
		return fail("request provider flags are not zdr=true / data_collection=deny / allow_fallbacks=false")
	}
	if !bytes.Equal(pyjson.Marshal(prov, pyjson.Canonical), pyjson.Marshal(p.Provider, pyjson.Canonical)) {
		return fail("request provider differs from the profile")
	}
	if !isStr(b.Get("model"), cfg.Model) {
		return fail("request model differs from the config")
	}
	rf := b.Get("response_format")
	if rf == nil || rf.Kind != pyjson.Object || !isStr(rf.Get("type"), "json_schema") ||
		rf.Get("json_schema") == nil || rf.Get("json_schema").Kind != pyjson.Object || !isBool(rf.Get("json_schema").Get("strict"), true) {
		return fail("response_format must be json_schema with strict=true")
	}
	msgs := b.Get("messages")
	if msgs == nil || msgs.Kind != pyjson.Array || len(msgs.Items) != 2 ||
		!isStr(msgs.Items[0].Get("role"), "system") || !isStr(msgs.Items[1].Get("role"), "user") {
		return fail("messages must be exactly one system and one user message")
	}
	if t, ok := num(b.Get("temperature")); !ok || t != 0 || (b.Get("seed") != nil) != p.SendSeed {
		return fail("temperature/seed differ from the profile")
	}
	return nil
}

func isBool(v *pyjson.Value, want bool) bool { return v != nil && v.Kind == pyjson.Bool && v.B == want }
func isStr(v *pyjson.Value, want string) bool {
	return v != nil && v.Kind == pyjson.String && v.S == want
}

// EstimateInputTokens — порт estimate_input_tokens: длины в байтах UTF-8, деление в float64, схема — json.dumps по умолчанию.
func EstimateInputTokens(body *pyjson.Value, cfg *Config) int {
	msgs := body.Get("messages").Items
	sys, user := msgs[0].Get("content").S, msgs[1].Get("content").S
	sch := pyjson.Marshal(body.Get("response_format").Get("json_schema").Get("schema"), pyjson.PyDefault)
	n := len(sys) + len(user) + len(sch)
	return int(math.Ceil(float64(n)/cfg.CharsPerToken)) + OverheadTokens
}

// OverCeiling: оценка входа плюс max_tokens не помещается в потолок контекста.
func OverCeiling(est, maxTokens int, cfg *Config) bool { return est+maxTokens > cfg.ContextCeiling }

// CostOf — стоимость запроса по ценам за миллион токенов.
func CostOf(prompt, completion float64, pr Prices) float64 {
	return (prompt*pr.InputPerMTok + completion*pr.OutputPerMTok) / 1e6
}
