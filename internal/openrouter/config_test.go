package openrouter

import (
	"strings"
	"testing"
	"testing/fstest"

	goldensynthetic "github.com/limpjungle/aegis3311/eval/golden-synthetic"
	"github.com/limpjungle/aegis3311/internal/pyjson"
)

func loadReal(t testing.TB) *Assets {
	t.Helper()
	a, err := LoadAssets(goldensynthetic.FS)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestLoadAssets(t *testing.T) {
	a := loadReal(t)
	if a.Primary.Name != "inceptron-fp8" || a.Fallback.Name != "wafer-nvfp4" || a.AnswerFormat != "v2" {
		t.Fatalf("профили: %s %s", a.Primary.Name, a.Fallback.Name)
	}
	if a.Config.ContextCeiling != 64000 || a.Config.Generation.MaxTokens != 4096 || a.Config.CharsPerToken != 2.5 {
		t.Fatalf("%+v", a.Config)
	}
	if a.RequestSchema.Get("$schema") != nil || a.RequestSchema.Get("$id") != nil {
		t.Fatal("в схеме запроса остались $schema/$id")
	}
}

func mapFS(t *testing.T, mut func(m fstest.MapFS)) fstest.MapFS {
	m := fstest.MapFS{}
	for _, n := range []string{"profiles.json", "data/manifest.json", "prompt/system-v3.md", "schema/answer.schema-v2.json"} {
		b, err := goldensynthetic.FS.ReadFile(n)
		if err != nil {
			t.Fatal(err)
		}
		m[n] = &fstest.MapFile{Data: b}
	}
	mut(m)
	return m
}

func TestLoadAssetsRejects(t *testing.T) {
	prof := func(m fstest.MapFS) string { return string(m["profiles.json"].Data) }
	cases := map[string]func(m fstest.MapFS){
		"подмена промпта": func(m fstest.MapFS) { m["prompt/system-v3.md"].Data = append(m["prompt/system-v3.md"].Data, ' ') },
		"подмена схемы": func(m fstest.MapFS) {
			m["schema/answer.schema-v2.json"].Data = append(m["schema/answer.schema-v2.json"].Data, ' ')
		},
		"две primary": func(m fstest.MapFS) {
			m["profiles.json"].Data = []byte(strings.Replace(prof(m), `"fallback"`, `"primary"`, 1))
		},
		"неизвестная роль": func(m fstest.MapFS) {
			m["profiles.json"].Data = []byte(strings.Replace(prof(m), `"fallback"`, `"x"`, 1))
		},
		"answer_format v1": func(m fstest.MapFS) {
			d := string(m["data/manifest.json"].Data)
			i := strings.LastIndex(d, `"answer_format": "v2"`)
			m["data/manifest.json"].Data = []byte(d[:i] + `"answer_format": "v1"` + d[i+len(`"answer_format": "v2"`):])
		},
		"путь с ..": func(m fstest.MapFS) {
			m["data/manifest.json"].Data = []byte(strings.Replace(string(m["data/manifest.json"].Data), `"prompt/system-v3.md"`, `"../x.md"`, 1))
		},
		"zdr false": func(m fstest.MapFS) {
			m["profiles.json"].Data = []byte(strings.Replace(prof(m), `"zdr": true`, `"zdr": false`, 1))
		},
	}
	for name, mut := range cases {
		if _, err := LoadAssets(mapFS(t, mut)); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
	if _, err := LoadAssets(mapFS(t, func(fstest.MapFS) {})); err != nil {
		t.Fatalf("исходный набор: %v", err)
	}
}

func TestValidateProfile(t *testing.T) {
	base := func() (*Config, *Profile) {
		a := loadReal(t)
		cfg, p := a.Config, *a.Primary
		p.Provider = p.Provider.Clone()
		return &cfg, &p
	}
	cases := map[string]func(c *Config, p *Profile){
		"zdr false":           func(c *Config, p *Profile) { p.Provider.Set("zdr", pyjson.NewBool(false)) },
		"zdr числом":          func(c *Config, p *Profile) { p.Provider.Set("zdr", pyjson.NewInt(1)) },
		"data_collection":     func(c *Config, p *Profile) { p.Provider.Set("data_collection", pyjson.NewString("allow")) },
		"allow_fallbacks":     func(c *Config, p *Profile) { p.Provider.Set("allow_fallbacks", pyjson.NewBool(true)) },
		"лишний ключ":         func(c *Config, p *Profile) { p.Provider.Set("order", pyjson.NewArray()) },
		"пустые quantization": func(c *Config, p *Profile) { p.Provider.Set("quantizations", pyjson.NewArray()) },
		"пустой only":         func(c *Config, p *Profile) { p.Provider.Set("only", pyjson.NewArray()) },
		"slug без даты":       func(c *Config, p *Profile) { c.Model = "z-ai/glm-5.3-flash" },
		"ceiling 64001":       func(c *Config, p *Profile) { c.ContextCeiling = 64001 },
		"temperature 0.5": func(c *Config, p *Profile) {
			c.Generation.Temperature = parseF(t, "0.5")
		},
		"чужой api_url":      func(c *Config, p *Profile) { c.APIURL = "https://evil.example/api" },
		"max_tokens 100":     func(c *Config, p *Profile) { c.Generation.MaxTokens = 100 },
		"seed не целое":      func(c *Config, p *Profile) { c.Generation.Seed = parseF(t, "1.5") },
		"нет endpoint_label": func(c *Config, p *Profile) { p.EndpointLabel = "" },
		"concurrency 17":     func(c *Config, p *Profile) { c.Concurrency = 17 },
		"нет цен":            func(c *Config, p *Profile) { p.pricesOK = false },
	}
	for name, mut := range cases {
		c, p := base()
		mut(c, p)
		if err := ValidateProfile(c, p, true); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
	c, p := base()
	if err := ValidateProfile(c, p, true); err != nil {
		t.Fatal(err)
	}
}

func parseF(t *testing.T, s string) *pyjson.Value {
	v, err := pyjson.Parse([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestCheckAPIURL(t *testing.T) {
	for _, u := range []string{APIURL, "http://127.0.0.1:8080/x", "http://localhost:1/x", "http://[::1]:80/x"} {
		if err := CheckAPIURL(u); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
	for _, u := range []string{"https://evil.example/", "http://10.0.0.1/", "http://localhost.evil/", "https://127.0.0.1/", "", "https://openrouter.ai/api/v1/chat/completions/x"} {
		if err := CheckAPIURL(u); err == nil {
			t.Errorf("%s: принято", u)
		}
	}
}

func TestLoadAssetsPinned(t *testing.T) {
	const v3, v4, schema = "prompt/system-v3.md", "prompt/system-v4.md", "schema/answer.schema-v2.json"
	withV4 := func(m fstest.MapFS) {
		b, err := goldensynthetic.FS.ReadFile(v4)
		if err != nil {
			t.Fatal(err)
		}
		m[v4] = &fstest.MapFile{Data: b}
	}
	a3, err := LoadAssetsPinned(mapFS(t, withV4), v3, schema)
	if err != nil {
		t.Fatal(err)
	}
	a4, err := LoadAssetsPinned(mapFS(t, withV4), v4, schema)
	if err != nil {
		t.Fatal(err)
	}
	if a3.PromptFile != v3 || a4.PromptFile != v4 || a3.SystemSHA256 == a4.SystemSHA256 || a3.SchemaSHA256 != a4.SchemaSHA256 {
		t.Fatalf("pinned: %s %.12s / %s %.12s", a3.PromptFile, a3.SystemSHA256, a4.PromptFile, a4.SystemSHA256)
	}
	if a3.ConfigSHA256 != a4.ConfigSHA256 || a4.Primary == nil || a4.Fallback == nil {
		t.Fatal("конфигурация pinned отличается от активной")
	}
	// Активные ассеты остаются v3.
	if a := loadReal(t); a.PromptFile != v3 || a.SystemSHA256 != a3.SystemSHA256 {
		t.Fatalf("LoadAssets: активный промпт %s", a.PromptFile)
	}
	// Промпты из prompt_history тоже доступны.
	if _, err := LoadAssetsPinned(mapFS(t, func(m fstest.MapFS) {
		b, _ := goldensynthetic.FS.ReadFile("prompt/system-v2.md")
		m["prompt/system-v2.md"] = &fstest.MapFile{Data: b}
	}), "prompt/system-v2.md", schema); err != nil {
		t.Errorf("prompt_history: %v", err)
	}
	rejects := map[string]struct {
		prompt, schema string
		mut            func(m fstest.MapFS)
	}{
		"файла нет в manifest":  {"prompt/system-v9.md", schema, func(m fstest.MapFS) { m["prompt/system-v9.md"] = &fstest.MapFile{Data: []byte("x")} }},
		"схемы нет в manifest":  {v3, "schema/other.json", func(m fstest.MapFS) { m["schema/other.json"] = &fstest.MapFile{Data: []byte("{}")} }},
		"sha не совпадает":      {v4, schema, func(m fstest.MapFS) { withV4(m); m[v4].Data = append(m[v4].Data, ' ') }},
		"файл есть, но не в fs": {v4, schema, func(fstest.MapFS) {}},
		"путь с ..":             {"../x.md", schema, func(fstest.MapFS) {}},
	}
	for name, c := range rejects {
		if _, err := LoadAssetsPinned(mapFS(t, c.mut), c.prompt, c.schema); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
	// manifest с подменённым путём записи на "../": запись есть, путь недопустим.
	if _, err := LoadAssetsPinned(mapFS(t, func(m fstest.MapFS) {
		m["data/manifest.json"].Data = []byte(strings.Replace(string(m["data/manifest.json"].Data), `"prompt/system-v4.md"`, `"../x.md"`, 1))
	}), "../x.md", schema); err == nil {
		t.Error("путь с .. из manifest: принято")
	}
}
