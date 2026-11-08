package intake

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	goldensynthetic "github.com/limpjungle/aegis3311/eval/golden-synthetic"
	"github.com/limpjungle/aegis3311/internal/audit"
	"github.com/limpjungle/aegis3311/internal/catalog"
	"github.com/limpjungle/aegis3311/internal/llmrouter"
	"github.com/limpjungle/aegis3311/internal/openrouter"
	"github.com/limpjungle/aegis3311/internal/pyjson"
	"github.com/limpjungle/aegis3311/internal/routersvc"
)

const healthBody = `{"data":{"endpoints":[{"provider_name":"Inceptron","quantization":"fp8","tag":"t","supported_parameters":["response_format","structured_outputs","seed"]},` +
	`{"provider_name":"Wafer","quantization":"nvfp4","tag":"w","supported_parameters":["response_format","structured_outputs","seed"]}]}}`

// stubTr — транспорт OpenRouter без сети: Post отдаёт функция post (nil — сбой сети).
type stubTr struct {
	post func(body []byte) (openrouter.Response, error)
}

func (s *stubTr) Post(_ context.Context, _ string, _ http.Header, body []byte) (openrouter.Response, error) {
	return s.post(body)
}
func (s *stubTr) Get(context.Context, string, http.Header) (openrouter.Response, error) {
	return openrouter.Response{Status: 200, Body: []byte(healthBody)}, nil
}

// openTestRuntime открывает routersvc.Runtime во временном каталоге; ключи генерируются в рантайме.
// assets nil — активные ассеты (LoadAssets), иначе подставленные (pinned: проба привязана к своему промпту).
func openTestRuntime(t testing.TB, tr openrouter.Transport, assets ...*openrouter.Assets) (*routersvc.Runtime, routersvc.Config, audit.Keyring) {
	t.Helper()
	var a *openrouter.Assets
	if len(assets) > 0 {
		a = assets[0]
	}
	dir := t.TempDir()
	rnd := func(n int) string {
		b := make([]byte, n)
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(b)
	}
	apiP, maskP, privP, pubP := filepath.Join(dir, "api"), filepath.Join(dir, "mask"), filepath.Join(dir, "audit.pem"), filepath.Join(dir, "audit.pub")
	for p, v := range map[string]string{apiP: "m" + rnd(12), maskP: rnd(32)} {
		if err := os.WriteFile(p, []byte(v+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := audit.GenerateKey(privP, pubP); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"OPENROUTER_API_KEY_FILE": apiP, "AEGIS_MASKER_KEY_FILE": maskP, routersvc.AuditKeyEnv: privP}
	sec, err := routersvc.LoadSecrets(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	cfg := routersvc.Config{RouterID: "llmrouter-test", StatePath: filepath.Join(dir, "router.state"),
		Audit: routersvc.AuditConfig{Chain: filepath.Join(dir, "audit.jsonl"), ChainID: "chain-test"}, Failover: routersvc.FailoverConfig{HealthInterval: "1h"}}
	rt, err := routersvc.Open(cfg, sec, routersvc.OpenOptions{Create: true}, routersvc.Deps{Transport: tr, Assets: a})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rt.Close() })
	keys := audit.Keyring{}
	keys.Add(sec.Signer.Public())
	return rt, cfg, keys
}

// Запрос, собранный intake, воспроизводит request_sha256 и est_input_tokens эталонов пробы (настоящий маскировщик,
// роль primary): v4 — активные ассеты (переключение 08.11.2026), v3 — архив на закреплённом промпте v3.
func TestIntakeReproducesProbeRefs(t *testing.T) {
	for _, v := range []struct{ name, prompt string }{{"v3", "prompt/system-v3.md"}, {"v4", "prompt/system-v4.md"}} {
		t.Run(v.name, func(t *testing.T) { testIntakeReproducesProbeRefs(t, v.name, v.prompt) })
	}
}

func testIntakeReproducesProbeRefs(t *testing.T, ver, prompt string) {
	a, err := openrouter.LoadAssetsPinned(goldensynthetic.FS, prompt, "schema/answer.schema-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	rt, _, _ := openTestRuntime(t, &stubTr{}, a)
	cat := catalog.MustLoadEmbedded()
	refs, err := filepath.Glob(filepath.Join("..", "..", "eval", "golden-synthetic", "refs", "inceptron-fp8", "probe-"+ver+"-*.jsonl"))
	if err != nil || len(refs) != 1 {
		t.Fatalf("эталон: %v %v", refs, err)
	}
	want := map[string]*pyjson.Value{}
	b, err := os.ReadFile(refs[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, ln := range bytes.Split(b, []byte("\n")) {
		if len(bytes.TrimSpace(ln)) == 0 {
			continue
		}
		v, err := pyjson.Parse(ln)
		if err != nil {
			t.Fatal(err)
		}
		want[v.Get("id").S] = v
	}
	cases := loadCases(t, "probe-"+ver+".jsonl")
	if len(want) != len(cases) || len(cases) == 0 {
		t.Fatalf("эталон %d, кейсов %d", len(want), len(cases))
	}
	for _, c := range cases {
		id := c.Get("id").S
		s := snapshotFromGolden(t, pyjson.Marshal(c.Get("input"), pyjson.Canonical))
		req, _, err := Assemble(id, s, cat, llmrouter.ModeHybrid)
		if err != nil {
			t.Fatal(err)
		}
		p, err := rt.Router.Prepare(context.Background(), req, llmrouter.RolePrimary)
		if err != nil {
			t.Fatal(err)
		}
		if p.NotSent != "" || len(p.Excluded) != 0 || len(p.Dropped) != 0 || p.LabelsDropped != 0 {
			t.Fatalf("%s: NotSent=%q excluded=%d dropped=%d labels=%d", id, p.NotSent, len(p.Excluded), len(p.Dropped), p.LabelsDropped)
		}
		w := want[id]
		if w == nil || p.RequestSHA256 != w.Get("request_sha256").S || fmt.Sprint(p.EstInputTokens) != w.Get("est_input_tokens").Int {
			t.Fatalf("%s: request_sha256 %s (est %d) != эталон probe-%s", id, p.RequestSHA256, p.EstInputTokens, ver)
		}
	}
}
