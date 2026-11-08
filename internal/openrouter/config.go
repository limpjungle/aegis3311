package openrouter

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"time"

	"github.com/limpjungle/aegis3311/internal/pyjson"
)

const (
	APIURL         = "https://openrouter.ai/api/v1/chat/completions"
	OverheadTokens = 64
	SchemaName     = "aegisops_answer_v1"
	MaxConcurrency = 16
)

var (
	slugRe              = regexp.MustCompile(`^[a-z0-9-]+/[a-z0-9.-]+-\d{8}$`)
	allowedProviderKeys = map[string]bool{"only": true, "quantizations": true, "allow_fallbacks": true, "zdr": true,
		"data_collection": true, "require_parameters": true}
)

// Generation — параметры генерации. Temperature и Seed хранят исходный вид числа (0, а не 0.0).
type Generation struct {
	Temperature *pyjson.Value
	Seed        *pyjson.Value // nil, если в конфиге нет
	MaxTokens   int
}

type RetryConfig struct {
	MaxAttempts                  int
	BaseDelay, MaxDelay, Timeout time.Duration
}

type Config struct {
	APIURL, Model  string
	ContextCeiling int
	CharsPerToken  float64
	Generation     Generation
	Retry          RetryConfig
	// Бюджет прогона eval и параллелизм из profiles.json: роутер их не использует, но ValidateProfile
	// проверяет их целиком, как validate_profile.
	MaxUSDPerRun, MaxTokensPerRun float64
	Concurrency                   int
}

type Prices struct{ InputPerMTok, OutputPerMTok float64 }

type Profile struct {
	Name, Role, EndpointLabel string // Role: "primary" | "fallback"
	ExpectedProviderNames     []string
	SendSeed                  bool
	Prices                    Prices
	Provider                  *pyjson.Value // объект provider из profiles.json целиком (идёт в тело через Clone)
	Only, Quantizations       []string
	// pricesOK — цены заданы и неотрицательны (для ValidateProfile с forNetwork).
	pricesOK bool
}

type Assets struct {
	Config                   Config
	Primary, Fallback        *Profile
	SystemPrompt             string // байты файла как есть (валидный UTF-8)
	SystemSHA256             string // hex, = manifest.prompt.sha256
	PromptFile               string
	RequestSchema            *pyjson.Value // схема без "$schema" и "$id", порядок ключей исходный
	SchemaFile, SchemaSHA256 string
	ConfigSHA256             string // sha256 байтов profiles.json
	AnswerFormat             string // "v2", иначе LoadAssets — ошибка
}

// SHA256Hex — hex sha256 байт.
func SHA256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// num — число pyjson (Int или Float, не Bool), как _num в run.py.
func num(v *pyjson.Value) (float64, bool) {
	if v == nil || v.Kind != pyjson.Number {
		return 0, false
	}
	if v.IsFloat {
		return v.F, true
	}
	f, err := strconv.ParseFloat(v.Int, 64)
	return f, err == nil
}

// isInt — целое (не bool, не float), как isinstance(v, int) в Python.
func isInt(v *pyjson.Value) bool { return v != nil && v.Kind == pyjson.Number && !v.IsFloat }

func intOf(v *pyjson.Value) int {
	if !isInt(v) {
		return 0
	}
	n, err := strconv.ParseInt(v.Int, 10, 32)
	if err != nil {
		return 0
	}
	return int(n)
}

func secs(v *pyjson.Value) time.Duration {
	f, ok := num(v)
	if !ok || f <= 0 || f > 1e6 {
		return 0
	}
	return time.Duration(f * float64(time.Second))
}

func strOf(v *pyjson.Value) string {
	if v != nil && v.Kind == pyjson.String {
		return v.S
	}
	return ""
}

func strList(v *pyjson.Value) []string {
	if v == nil || v.Kind != pyjson.Array {
		return nil
	}
	out := make([]string, 0, len(v.Items))
	for _, it := range v.Items {
		out = append(out, strOf(it))
	}
	return out
}

// LoadAssets читает конфигурацию, промпт и схему из fsys, сверяя sha256 тех же байтов, что используются дальше.
// Берутся активные manifest.prompt и manifest.answer_schema.
func LoadAssets(fsys fs.FS) (*Assets, error) {
	return loadAssets(fsys, func(man *pyjson.Value) (pf, ps, sf, ss string, err error) {
		entry := func(key string) (file, sum string, err error) {
			e := man.Get(key)
			file, sum = strOf(e.Get("file")), strOf(e.Get("sha256"))
			if file == "" || sum == "" {
				return "", "", fmt.Errorf("openrouter: manifest: нет %s.file или %s.sha256", key, key)
			}
			return file, sum, nil
		}
		if pf, ps, err = entry("prompt"); err != nil {
			return "", "", "", "", err
		}
		if sf, ss, err = entry("answer_schema"); err != nil {
			return "", "", "", "", err
		}
		return pf, ps, sf, ss, nil
	})
}

// LoadAssetsPinned — как LoadAssets, но промпт и схема заданы файлами; sha256 берётся из любой записи manifest
// (активная, staged, prompt_history, answer_schema_history). Файла нет ни в одной записи — ошибка.
// Только для тестов воспроизводимости и eval; роутер — LoadAssets.
func LoadAssetsPinned(fsys fs.FS, promptFile, schemaFile string) (*Assets, error) {
	return loadAssets(fsys, func(man *pyjson.Value) (pf, ps, sf, ss string, err error) {
		find := func(file string, keys ...string) (string, error) {
			var recs []*pyjson.Value
			for _, k := range keys {
				recs = append(recs, man.Get(k), man.Get("staged").Get(k))
				if h := man.Get(k + "_history"); h != nil && h.Kind == pyjson.Array {
					recs = append(recs, h.Items...)
				}
			}
			for _, r := range recs {
				if strOf(r.Get("file")) == file && strOf(r.Get("sha256")) != "" {
					return strOf(r.Get("sha256")), nil
				}
			}
			return "", fmt.Errorf("openrouter: manifest: файла %s нет ни в одной записи", file)
		}
		if ps, err = find(promptFile, "prompt"); err != nil {
			return "", "", "", "", err
		}
		if ss, err = find(schemaFile, "answer_schema"); err != nil {
			return "", "", "", "", err
		}
		return promptFile, ps, schemaFile, ss, nil
	})
}

func loadAssets(fsys fs.FS, pick func(man *pyjson.Value) (pf, ps, sf, ss string, err error)) (*Assets, error) {
	read := func(rel string) ([]byte, error) {
		if !fs.ValidPath(rel) || rel == "." {
			return nil, fmt.Errorf("openrouter: недопустимый путь %q", rel)
		}
		b, err := fs.ReadFile(fsys, rel)
		if err != nil {
			return nil, fmt.Errorf("openrouter: чтение %s: %w", rel, err)
		}
		return b, nil
	}
	mb, err := read("data/manifest.json")
	if err != nil {
		return nil, err
	}
	man, err := pyjson.Parse(mb)
	if err != nil || man.Kind != pyjson.Object {
		return nil, fmt.Errorf("openrouter: manifest.json: %v", err)
	}
	a := &Assets{}
	pf, ps, sf, ss, err := pick(man)
	if err != nil {
		return nil, err
	}
	if af := strOf(man.Get("answer_format")); af != "v2" {
		return nil, fmt.Errorf("openrouter: manifest.answer_format %q, поддерживается только v2", af)
	}
	a.AnswerFormat = "v2"
	pb, err := read(pf)
	if err != nil {
		return nil, err
	}
	if got := SHA256Hex(pb); got != ps {
		return nil, fmt.Errorf("openrouter: промпт %s: sha256 %.12s не совпадает с manifest %.12s", pf, got, ps)
	}
	sb, err := read(sf)
	if err != nil {
		return nil, err
	}
	if got := SHA256Hex(sb); got != ss {
		return nil, fmt.Errorf("openrouter: схема %s: sha256 %.12s не совпадает с manifest %.12s", sf, got, ss)
	}
	schema, err := pyjson.Parse(sb)
	if err != nil || schema.Kind != pyjson.Object {
		return nil, fmt.Errorf("openrouter: схема %s: %v", sf, err)
	}
	rs := pyjson.NewObject()
	for _, m := range schema.Members {
		if m.Key != "$schema" && m.Key != "$id" {
			rs.Members = append(rs.Members, pyjson.Member{Key: m.Key, Value: m.Value.Clone()})
		}
	}
	a.SystemPrompt, a.SystemSHA256, a.PromptFile = string(pb), ps, pf
	a.RequestSchema, a.SchemaFile, a.SchemaSHA256 = rs, sf, ss

	cb, err := read("profiles.json")
	if err != nil {
		return nil, err
	}
	a.ConfigSHA256 = SHA256Hex(cb)
	root, err := pyjson.Parse(cb)
	if err != nil || root.Kind != pyjson.Object {
		return nil, fmt.Errorf("openrouter: profiles.json: %v", err)
	}
	a.Config = parseConfig(root)
	profs := root.Get("profiles")
	if profs == nil || profs.Kind != pyjson.Object {
		return nil, errors.New("openrouter: profiles.json: нет profiles")
	}
	for _, m := range profs.Members {
		p := parseProfile(m.Key, m.Value)
		switch p.Role {
		case "primary":
			if a.Primary != nil {
				return nil, errors.New("openrouter: profiles.json: два профиля с ролью primary")
			}
			a.Primary = p
		case "fallback":
			if a.Fallback != nil {
				return nil, errors.New("openrouter: profiles.json: два профиля с ролью fallback")
			}
			a.Fallback = p
		case "retired":
		default:
			return nil, fmt.Errorf("openrouter: профиль %s: неизвестная роль %q", p.Name, p.Role)
		}
	}
	if a.Primary == nil || a.Fallback == nil {
		return nil, errors.New("openrouter: profiles.json: нужны профили primary и fallback")
	}
	for _, p := range []*Profile{a.Primary, a.Fallback} {
		if err := ValidateProfile(&a.Config, p, true); err != nil {
			return nil, err
		}
	}
	return a, nil
}

func parseConfig(root *pyjson.Value) Config {
	var c Config
	c.APIURL, c.Model = strOf(root.Get("api_url")), strOf(root.Get("model"))
	c.ContextCeiling = intOf(root.Get("context_ceiling_tokens"))
	c.CharsPerToken, _ = num(root.Get("chars_per_token_estimate"))
	gen := root.Get("generation")
	c.Generation.Temperature = gen.Get("temperature").Clone()
	c.Generation.Seed = gen.Get("seed").Clone()
	c.Generation.MaxTokens = intOf(gen.Get("max_tokens"))
	r := root.Get("retry")
	c.Retry.MaxAttempts = intOf(r.Get("max_attempts"))
	c.Retry.BaseDelay, c.Retry.MaxDelay, c.Retry.Timeout = secs(r.Get("base_delay_s")), secs(r.Get("max_delay_s")), secs(r.Get("timeout_s"))
	b := root.Get("budget")
	c.MaxUSDPerRun, _ = num(b.Get("max_usd_per_run"))
	c.MaxTokensPerRun, _ = num(b.Get("max_tokens_per_run"))
	c.Concurrency = intOf(root.Get("concurrency"))
	return c
}

func parseProfile(name string, v *pyjson.Value) *Profile {
	p := &Profile{Name: name, Role: strOf(v.Get("role")), EndpointLabel: strOf(v.Get("endpoint_label")),
		ExpectedProviderNames: strList(v.Get("expected_provider_names"))}
	if sd := v.Get("send_seed"); sd != nil && sd.Kind == pyjson.Bool {
		p.SendSeed = sd.B
	}
	pr := v.Get("price_usd_per_mtok")
	in, ok1 := num(pr.Get("input"))
	out, ok2 := num(pr.Get("output"))
	p.Prices = Prices{in, out}
	p.pricesOK = ok1 && ok2 && in >= 0 && out >= 0
	p.Provider = v.Get("provider").Clone()
	p.Only, p.Quantizations = strList(p.Provider.Get("only")), strList(p.Provider.Get("quantizations"))
	return p
}

// ValidateProfile — порт validate_profile. Bool проверяется по Kind, не по числу (как `is True` в Python).
func ValidateProfile(cfg *Config, p *Profile, forNetwork bool) error {
	bad := func(format string, a ...any) error { return fmt.Errorf("openrouter: "+format, a...) }
	if !slugRe.MatchString(cfg.Model) {
		return bad("model must be a dated slug without suffixes (e.g. vendor/name-20260826)")
	}
	if err := CheckAPIURL(cfg.APIURL); err != nil {
		return err
	}
	if cfg.ContextCeiling <= 0 || cfg.ContextCeiling > 64000 {
		return bad("context_ceiling_tokens must be an integer <= 64000")
	}
	if cfg.Generation.MaxTokens < 256 || cfg.Generation.MaxTokens > 16000 {
		return bad("generation.max_tokens must be an integer in [256, 16000]")
	}
	if t, ok := num(cfg.Generation.Temperature); !ok || t != 0 {
		return bad("generation.temperature must be 0")
	}
	if p.SendSeed && !isInt(cfg.Generation.Seed) {
		return bad("generation.seed must be an integer when send_seed is true")
	}
	if !(cfg.CharsPerToken > 0) || math.IsInf(cfg.CharsPerToken, 0) {
		return bad("chars_per_token_estimate must be > 0")
	}
	r := cfg.Retry
	if r.MaxAttempts < 1 || r.BaseDelay <= 0 || r.MaxDelay <= 0 || r.Timeout <= 0 {
		return bad("retry: max_attempts >= 1 and positive base_delay_s, max_delay_s, timeout_s required")
	}
	if !(cfg.MaxUSDPerRun > 0) || !(cfg.MaxTokensPerRun > 0) {
		return bad("budget.max_usd_per_run and budget.max_tokens_per_run must be positive")
	}
	if cfg.Concurrency < 1 || cfg.Concurrency > MaxConcurrency {
		return bad("concurrency must be an integer in [1, %d]", MaxConcurrency)
	}

	prov := p.Provider
	if prov == nil || prov.Kind != pyjson.Object {
		return bad("profile %s: provider is missing", p.Name)
	}
	var extra []string
	for _, m := range prov.Members {
		if !allowedProviderKeys[m.Key] {
			extra = append(extra, m.Key)
		}
	}
	if len(extra) > 0 {
		sort.Strings(extra)
		return bad("profile %s: unknown provider keys %q", p.Name, extra)
	}
	if z := prov.Get("zdr"); z == nil || z.Kind != pyjson.Bool || !z.B {
		return bad("profile %s: provider.zdr must be true", p.Name)
	}
	if d := prov.Get("data_collection"); d == nil || d.Kind != pyjson.String || d.S != "deny" {
		return bad("profile %s: provider.data_collection must be 'deny'", p.Name)
	}
	if f := prov.Get("allow_fallbacks"); f == nil || f.Kind != pyjson.Bool || f.B {
		return bad("profile %s: provider.allow_fallbacks must be false", p.Name)
	}
	for _, k := range []string{"only", "quantizations"} {
		if !nonEmptyStrings(prov.Get(k), true) {
			return bad("profile %s: provider.%s must be a list of strings", p.Name, k)
		}
	}
	if len(prov.Get("quantizations").Items) == 0 {
		return bad("profile %s: provider.quantizations must not be empty", p.Name)
	}
	if forNetwork {
		var problems []string
		if len(prov.Get("only").Items) == 0 {
			problems = append(problems, "provider.only")
		}
		if p.EndpointLabel == "" {
			problems = append(problems, "endpoint_label")
		}
		if len(p.ExpectedProviderNames) == 0 || !allNonEmpty(p.ExpectedProviderNames) {
			problems = append(problems, "expected_provider_names")
		}
		if !p.pricesOK {
			problems = append(problems, "price_usd_per_mtok")
		}
		if len(problems) > 0 {
			return bad("profile %s is incomplete (profile incomplete): fill %v", p.Name, problems)
		}
	}
	return nil
}

func allNonEmpty(ss []string) bool {
	for _, s := range ss {
		if s == "" {
			return false
		}
	}
	return true
}

// nonEmptyStrings: v — массив непустых строк (пустой массив допустим, если emptyOK).
func nonEmptyStrings(v *pyjson.Value, emptyOK bool) bool {
	if v == nil || v.Kind != pyjson.Array || (!emptyOK && len(v.Items) == 0) {
		return false
	}
	for _, it := range v.Items {
		if it.Kind != pyjson.String || it.S == "" {
			return false
		}
	}
	return true
}

// CheckAPIURL — ровно APIURL или http://{127.0.0.1|localhost|[::1]}:port/…
func CheckAPIURL(u string) error {
	if u == APIURL || hostLocal(u) {
		return nil
	}
	return fmt.Errorf("openrouter: api_url не разрешён: %q (только %s или loopback http)", u, APIURL)
}

func hostLocal(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" {
		return false
	}
	switch u.Hostname() {
	case "127.0.0.1", "localhost", "::1":
		return true
	}
	return false
}
