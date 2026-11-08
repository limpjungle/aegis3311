package pep_test

import (
	"regexp"
	"testing"

	"github.com/limpjungle/aegis3311/policy"
)

// default decision в decision.rego не может ссылаться на policy_revision (Rego запрещает переменные
// в default), поэтому там литерал. Тест ловит рассинхронизацию двух значений.
func TestPolicyRevisionDefaultInSync(t *testing.T) {
	src, err := policy.FS.ReadFile("aegis/pep/decision.rego")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^policy_revision\s*:=\s*"([^"]+)"`).FindSubmatch(src)
	if m == nil {
		t.Fatal("policy_revision не найден в decision.rego")
	}
	d := regexp.MustCompile(`(?s)default decision\s*:=\s*\{.*?"policy_revision":\s*"([^"]+)"`).FindSubmatch(src)
	if d == nil {
		t.Fatal("policy_revision в default decision не найден")
	}
	if string(m[1]) != string(d[1]) {
		t.Errorf("policy_revision %q != значение в default decision %q", m[1], d[1])
	}
}
