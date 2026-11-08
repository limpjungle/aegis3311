package openrouter

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/limpjungle/aegis3311/internal/pyjson"
)

// rtSecret — маркер секрета, генерируемый в рантайме (в исходниках нет токеноподобных литералов).
func rtSecret() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return "m" + hex.EncodeToString(b)
}

func TestAPIKeyNeverPrinted(t *testing.T) {
	sec := rtSecret()
	k := APIKey{sec}
	out := fmt.Sprintf("%v %+v %#v %s %q", k, k, k, k, k)
	j, _ := json.Marshal(struct{ K APIKey }{k})
	if strings.Contains(out, sec) || strings.Contains(string(j), sec) {
		t.Fatal(out, string(j))
	}
}

func TestLoadAPIKey(t *testing.T) {
	abc, fromEnv := rtSecret(), rtSecret()
	dir := t.TempDir()
	write := func(s string) func(string) string {
		p := filepath.Join(dir, "k")
		os.WriteFile(p, []byte(s), 0o600)
		return func(n string) string {
			if n == "OPENROUTER_API_KEY_FILE" {
				return p
			}
			return "из-окружения"
		}
	}
	if k, err := LoadAPIKey(write(abc + "\n")); err != nil || k.value() != abc {
		t.Fatal(err)
	}
	for name, content := range map[string]string{"пустой": " \n", "пробел внутри": "sk a", "управляющий": "sk\x01a", "кириллица": "ключ", "больше 4 KiB": strings.Repeat("a", 4097)} {
		if _, err := LoadAPIKey(write(content)); err == nil {
			t.Errorf("%s: принят", name)
		}
	}
	if _, err := LoadAPIKey(func(string) string { return "" }); err == nil {
		t.Error("нет переменной")
	}
	_, err := LoadAPIKey(func(n string) string {
		if n == "OPENROUTER_API_KEY_FILE" {
			return filepath.Join(dir, "нет-такого")
		}
		return fromEnv
	})
	if err == nil || strings.Contains(err.Error(), fromEnv) {
		t.Errorf("OPENROUTER_API_KEY должна игнорироваться: %v", err)
	}
}

func TestTransport(t *testing.T) {
	var other atomic.Int64
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { other.Add(1) }))
	defer srv2.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redir":
			http.Redirect(w, r, srv2.URL, http.StatusFound)
		case "/big":
			w.Write(make([]byte, MaxResponseBytes+10))
		case "/slow":
			select {
			case <-r.Context().Done():
			case <-time.After(2 * time.Second):
			}
		default:
			w.Write([]byte("ok"))
		}
	}))
	defer srv.Close()
	tr := NewHTTPTransport()
	h := http.Header{"Authorization": {"Bearer x"}}
	ctx := context.Background()
	resp, err := tr.Post(ctx, srv.URL+"/redir", h, nil)
	if err != nil || resp.Status != 302 || other.Load() != 0 {
		t.Fatalf("редирект: %v %d %d", err, resp.Status, other.Load())
	}
	if k, _, _ := Classify(resp); k != KindCaseError {
		t.Errorf("3xx: %s", k)
	}
	if _, err := tr.Post(ctx, "https://example.com/", h, nil); err == nil || err.(*TransportError).Kind != "network" {
		t.Errorf("чужой хост: %v", err)
	}
	if _, err := tr.Get(ctx, "https://example.com/api/v1/x", h); err == nil {
		t.Error("GET на чужой хост")
	}
	if _, err := tr.Post(ctx, srv.URL+"/big", h, nil); err == nil || err.(*TransportError).Kind != "oversize" {
		t.Errorf("oversize: %v", err)
	}
	tctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	if _, err := tr.Post(tctx, srv.URL+"/slow", h, nil); err == nil || err.(*TransportError).Kind != "timeout" {
		t.Errorf("timeout: %v", err)
	}
}

func TestParseResponseAndValidate(t *testing.T) {
	a := loadReal(t)
	p := a.Primary
	good := `{"incident_class":"RB-006","root_cause":"load_growth","action":{"type":"workload.scale_out","params":{"scope":null,"pod_name":null,"reason":null,"parameter":null}},"confidence":1,"evidence":["a"],"summary":"s"}`
	reply := func(provider, content, finish, extra string) *pyjson.Value {
		s := fmt.Sprintf(`{"id":"g1","model":"m","provider":%s,"choices":[{"finish_reason":%q,"message":{"content":%s%s}}]}`, provider, finish, content, extra)
		v, err := pyjson.Parse([]byte(s))
		if err != nil {
			t.Fatal(err, s)
		}
		return v
	}
	q := func(s string) string { b, _ := json.Marshal(s); return string(b) }
	cases := []struct {
		name string
		data *pyjson.Value
		want string
	}{
		{"ok", reply(`"Inceptron "`, q(good), "stop", ""), "ok"},
		{"нет provider", reply(`null`, q(good), "stop", ""), "provider_mismatch"},
		{"чужой provider", reply(`"Wafer"`, q(good), "stop", ""), "provider_mismatch"},
		{"refusal", reply(`"inceptron"`, q(good), "stop", `,"refusal":"no"`), "refusal"},
		{"refusal true", reply(`"inceptron"`, q(good), "stop", `,"refusal":true`), "refusal"},
		{"refusal []", reply(`"inceptron"`, q(good), "stop", `,"refusal":[1]`), "refusal"},
		{"refusal пустая", reply(`"inceptron"`, q(good), "stop", `,"refusal":""`), "ok"},
		{"content_filter", reply(`"inceptron"`, q(good), "content_filter", ""), "content_filter"},
		{"length", reply(`"inceptron"`, q(good), "length", ""), "truncated"},
		{"null content", reply(`"inceptron"`, `null`, "stop", ""), "invalid_json"},
		{"не json", reply(`"inceptron"`, q("{"), "stop", ""), "invalid_json"},
		{"json null", reply(`"inceptron"`, q("null"), "stop", ""), "invalid_json"},
		{"массив", reply(`"inceptron"`, q("[]"), "stop", ""), "schema_invalid"},
		{"строка JSON", reply(`"inceptron"`, q(`"x"`), "stop", ""), "schema_invalid"},
		{"content-массив", reply(`"inceptron"`, `[1]`, "stop", ""), "schema_invalid"},
		{"content-объект", reply(`"inceptron"`, good, "stop", ""), "ok"},
		{"лишний ключ", reply(`"inceptron"`, q(strings.Replace(good, `"summary"`, `"x":1,"summary"`, 1)), "stop", ""), "schema_invalid"},
		{"confidence bool", reply(`"inceptron"`, q(strings.Replace(good, `"confidence":1`, `"confidence":true`, 1)), "stop", ""), "schema_invalid"},
		{"confidence 1.5", reply(`"inceptron"`, q(strings.Replace(good, `"confidence":1`, `"confidence":1.5`, 1)), "stop", ""), "schema_invalid"},
		{"confidence -0.0", reply(`"inceptron"`, q(strings.Replace(good, `"confidence":1`, `"confidence":-0.0`, 1)), "stop", ""), "ok"},
		{"enum scope", reply(`"inceptron"`, q(strings.Replace(good, `"scope":null`, `"scope":"node"`, 1)), "stop", ""), "schema_invalid"},
		{"params v1", reply(`"inceptron"`, q(strings.Replace(good, `"params":{"scope":null,"pod_name":null,"reason":null,"parameter":null}`, `"params":{"value":1}`, 1)), "stop", ""), "schema_invalid"},
		{"evidence", reply(`"inceptron"`, q(strings.Replace(good, `["a"]`, `[1]`, 1)), "stop", ""), "schema_invalid"},
	}
	for _, c := range cases {
		if got := ParseResponse(c.data, p); got.Status != c.want {
			t.Errorf("%s: %s (%v), ожидается %s", c.name, got.Status, got.SchemaErrors, c.want)
		}
	}
	got := ParseResponse(reply(`"inceptron"`, q(strings.Replace(good, `"summary"`, `"x":1,"summary"`, 1)), "stop", ""), p)
	if len(got.SchemaErrors) != 1 || got.SchemaErrors[0] != "keys mismatch: ['x']" {
		t.Errorf("%v", got.SchemaErrors)
	}
	if !ProviderMatches("inceptron ", p) || ProviderMatches("", p) {
		t.Error("ProviderMatches")
	}
}

func TestEndpointsHealth(t *testing.T) {
	a := loadReal(t)
	var path string
	body := `{"data":{"endpoints":[{"provider_name":"Inceptron","tag":"inceptron/fp8","quantization":"fp8","supported_parameters":["response_format","structured_outputs","seed"]}]}}`
	status := 200
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
	defer srv.Close()
	c, err := NewClient(&a.Config, APIKey{"k"}, NewHTTPTransport(), WithURL(srv.URL+"/api/v1/chat/completions"))
	if err != nil {
		t.Fatal(err)
	}
	h := c.EndpointsHealth(context.Background(), &a.Config, a.Primary)
	if !h.OK || h.Matching != 1 || path != "/api/v1/models/"+a.Config.Model+"/endpoints" {
		t.Fatalf("%+v %s", h, path)
	}
	if h := c.EndpointsHealth(context.Background(), &a.Config, a.Fallback); h.OK {
		t.Error("другой провайдер")
	}
	body = strings.Replace(body, `,"seed"`, ``, 1)
	if h := c.EndpointsHealth(context.Background(), &a.Config, a.Primary); h.OK {
		t.Error("без seed")
	}
	for _, b := range []string{`not json`, `{}`} {
		body = b
		if h := c.EndpointsHealth(context.Background(), &a.Config, a.Primary); h.OK {
			t.Error(b)
		}
	}
	status = 500
	if h := c.EndpointsHealth(context.Background(), &a.Config, a.Primary); h.OK || h.Status != 500 {
		t.Error("500")
	}
}
