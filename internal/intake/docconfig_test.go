package intake

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/limpjungle/aegis3311/internal/bundle"
)

// Пример конфигурации из docs/04-operations/intake-deploy.md проходит строгий разбор и проверку.
func TestDocExampleConfigValid(t *testing.T) {
	b, err := os.ReadFile("../../docs/04-operations/intake-deploy.md")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	i := strings.Index(s, "```json\n")
	j := strings.Index(s[i+8:], "\n```")
	if i < 0 || j < 0 {
		t.Fatal("блок json не найден")
	}
	cfg, err := ParseConfig([]byte(s[i+8 : i+8+j]))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Metrics) != 13 {
		t.Errorf("метрик %d, ожидается 13", len(cfg.Metrics))
	}
	if cfg.PolicyBundle == nil || !cfg.PolicyBundle.Required || len(cfg.PolicyBundle.Keys) != 2 {
		t.Fatalf("policy_bundle в примере: %+v", cfg.PolicyBundle)
	}
	kb, err := os.ReadFile("../../deploy/policy-bundle/keys.json")
	if err != nil {
		t.Fatal(err)
	}
	var want []bundle.KeySpec
	if err := json.Unmarshal(kb, &want); err != nil {
		t.Fatal(err)
	}
	issuers := map[string]bool{}
	for _, k := range want {
		issuers[k.Issuer] = true
	}
	for _, k := range cfg.PolicyBundle.Keys {
		if !issuers[k.Issuer] {
			t.Errorf("issuer %q из примера нет в deploy/policy-bundle/keys.json", k.Issuer)
		}
		delete(issuers, k.Issuer)
	}
	if len(issuers) != 0 {
		t.Errorf("в примере нет issuer'ов из keys.json: %v", issuers)
	}
}
