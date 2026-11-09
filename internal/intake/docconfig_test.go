package intake

import (
	"os"
	"strings"
	"testing"
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
	if cfg.PolicyBundle == nil || cfg.PolicyBundle.Required || len(cfg.PolicyBundle.Keys) != 1 {
		t.Errorf("policy_bundle в примере: %+v", cfg.PolicyBundle)
	}
}
