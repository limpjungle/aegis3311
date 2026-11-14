package intake

import (
	"strings"
	"testing"
)

func pb(m map[string]any) map[string]any { return m["policy_bundle"].(map[string]any) }

func okBundleSection() map[string]any {
	return map[string]any{"path": "/etc/aegis/policy-bundle.json", "required": false,
		"keys": []any{map[string]any{"path": "/etc/aegis/keys/policy-ci-1.pub", "issuer": "ci/policy-signing"}}}
}

// Вне prod-окружений секция policy_bundle необязательна; если есть — проверяется форма.
func TestConfigPolicyBundle(t *testing.T) {
	c, err := parse(t, miniConfig())
	if err != nil || c.PolicyBundle != nil {
		t.Fatalf("без секции: %v %+v", err, c.PolicyBundle)
	}
	m := miniConfig()
	m["policy_bundle"] = okBundleSection()
	if c, err = parse(t, m); err != nil || c.PolicyBundle == nil || c.PolicyBundle.Required || len(c.PolicyBundle.Keys) != 1 {
		t.Fatalf("с секцией: %v %+v", err, c.PolicyBundle)
	}
	pb(m)["required"] = true
	if c, err = parse(t, m); err != nil || !c.PolicyBundle.Required {
		t.Fatalf("required=true: %v", err)
	}
	bad := map[string]func(m map[string]any){
		"относительный path":  func(m map[string]any) { pb(m)["path"] = "bundle.json" },
		"пустой path":         func(m map[string]any) { pb(m)["path"] = "" },
		"нет ключей":          func(m map[string]any) { pb(m)["keys"] = []any{} },
		"keys null":           func(m map[string]any) { pb(m)["keys"] = nil },
		"относительный ключ":  func(m map[string]any) { pb(m)["keys"].([]any)[0].(map[string]any)["path"] = "k.pub" },
		"плохой issuer":       func(m map[string]any) { pb(m)["keys"].([]any)[0].(map[string]any)["issuer"] = "ci policy" },
		"неизвестное поле":    func(m map[string]any) { pb(m)["x"] = 1 },
		"неизвестное в ключе": func(m map[string]any) { pb(m)["keys"].([]any)[0].(map[string]any)["role"] = "oncall" },
		"ключ kill switch":    func(m map[string]any) { pb(m)["keys"].([]any)[0].(map[string]any)["path"] = "/etc/aegis/ks/a.pub.pem" },
		"ключ ks, путь с ./": func(m map[string]any) {
			pb(m)["keys"].([]any)[0].(map[string]any)["path"] = "/etc/aegis/ks/../ks/b.pub.pem"
		},
	}
	for name, mut := range bad {
		m := miniConfig()
		m["policy_bundle"] = okBundleSection()
		mut(m)
		if _, err := parse(t, m); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
}

// В prod-окружениях секция обязательна и required=true (T-24); в staging — двухшаговое включение.
func TestConfigPolicyBundleRequiredInProd(t *testing.T) {
	for _, env := range []string{"prod-cloud-hybrid", "prod-baremetal"} {
		t.Run(env, func(t *testing.T) {
			m := miniConfig()
			m["environment"] = env
			if _, err := parse(t, m); err == nil || !strings.Contains(err.Error(), "required") {
				t.Errorf("без секции: %v", err)
			}
			m["policy_bundle"] = okBundleSection()
			if _, err := parse(t, m); err == nil || !strings.Contains(err.Error(), "required") {
				t.Errorf("required=false: %v", err)
			}
			pb(m)["required"] = true
			if _, err := parse(t, m); err != nil {
				t.Errorf("required=true: %v", err)
			}
			pb(m)["keys"].([]any)[0].(map[string]any)["path"] = "/etc/aegis/ks/a.pub.pem"
			if _, err := parse(t, m); err == nil {
				t.Error("ключ kill switch принят при required=true")
			}
		})
	}
	m := miniConfig()
	m["environment"] = "staging"
	if _, err := parse(t, m); err != nil {
		t.Errorf("staging без секции: %v", err)
	}
	m["policy_bundle"] = okBundleSection()
	if _, err := parse(t, m); err != nil {
		t.Errorf("staging, required=false: %v", err)
	}
}
