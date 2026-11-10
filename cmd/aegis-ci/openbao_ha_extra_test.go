package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Дополнения к openbao_ha_test.go: оверлей стенда не ослабляет боевые values, боевая конфигурация не включает
// безтокенные эндпоинты, адрес агента в Git остаётся условным, в репозитории нет долей unseal и токенов.

func haConfigHCL(t *testing.T) string {
	t.Helper()
	var m map[string]any
	if err := yaml.Unmarshal(readVault(t, haValuesFile), &m); err != nil {
		t.Fatal(err)
	}
	c, _ := at(m, "server", "ha", "raft", "config")
	s, _ := c.(string)
	if s == "" {
		t.Fatal("нет HCL-конфигурации в боевых values")
	}
	return stripHCLComments(s)
}

// Оверлей стенда может менять только тег образа, affinity, размеры томов и ресурсы.
func TestOpenBaoHAOverlayDoesNotWeaken(t *testing.T) {
	var m map[string]any
	if err := yaml.Unmarshal(readVault(t, "dev/values-openbao-ha.yaml"), &m); err != nil {
		t.Fatal(err)
	}
	if len(m) != 1 {
		t.Errorf("оверлей меняет верхние ключи %v, допустим только server", m)
	}
	srv, _ := m["server"].(map[string]any)
	allowed := map[string]bool{"image": true, "affinity": true, "dataStorage": true, "auditStorage": true, "resources": true}
	for k := range srv {
		if !allowed[k] {
			t.Errorf("оверлей меняет server.%s: не входит в разрешённые %v", k, allowed)
		}
	}
	if img, _ := srv["image"].(map[string]any); len(img) != 1 || img["tag"] == nil {
		t.Errorf("оверлей должен менять в server.image только tag: %v", img)
	}
	for _, k := range []string{"dataStorage", "auditStorage"} {
		if s, _ := srv[k].(map[string]any); s != nil {
			if _, off := s["enabled"]; off {
				t.Errorf("оверлей меняет server.%s.enabled", k)
			}
		}
	}
}

// Безтокенные generate-root и rekey в 2.7.2 выключены по умолчанию; боевая конфигурация не должна их включать.
func TestOpenBaoHANoUnauthedEndpoints(t *testing.T) {
	cfg := haConfigHCL(t)
	re := regexp.MustCompile(`disable_unauthed_(generate_root|rekey)_endpoints\s*=\s*(false|0|"false"|"0")`)
	if re.MatchString(cfg) {
		t.Errorf("конфигурация включает безтокенные generate-root/rekey: %s", re.FindString(cfg))
	}
	if strings.Contains(cfg, "allow_unauthenticated_workflows") {
		t.Error("конфигурация включает allow_unauthenticated_workflows")
	}
	// Мутация: проверка обязана это увидеть.
	if !re.MatchString(cfg + "\ndisable_unauthed_rekey_endpoints = false\n") {
		t.Error("регулярное выражение не ловит disable_unauthed_rekey_endpoints = false")
	}
}

// Адрес сервера в конфигурации агента в Git — условный; адрес стенда (openbao-active.openbao-ha) подставляет только run-ha.sh.
func TestVaultAgentAddressStaysConditional(t *testing.T) {
	var a struct {
		Vault struct {
			Address string `json:"address"`
			CACert  string `json:"ca_cert"`
		} `json:"vault"`
	}
	raw := readVault(t, "agent/aegis-intake.json")
	if err := json.Unmarshal(raw, &a); err != nil {
		t.Fatal(err)
	}
	if a.Vault.Address != "https://vault.vault.svc:8200" {
		t.Errorf("vault.address в Git: %q, ожидается условный https://vault.vault.svc:8200 (§10 п. 9)", a.Vault.Address)
	}
	if a.Vault.CACert == "" {
		t.Error("vault.ca_cert пуст: проверка сертификата сервера обязательна")
	}
	if strings.Contains(string(raw), "openbao-ha") || strings.Contains(string(raw), "openbao-active") {
		t.Error("в конфигурации агента в Git адрес стенда")
	}
}

// Стендовые токены и политики не должны быть требованием боевых values и документов; bg-init (токен-инициатор
// break-glass) — боевой элемент, описанный в §5 и в policies/bg-init.json, но не в values, ролях и конфигурации агента.
func TestStandOnlyTokensNotInProduction(t *testing.T) {
	for _, f := range []string{"server/openbao-ha.yaml", "policies/aegis-intake.json", "roles/aegis-intake.json", "agent/aegis-intake.json"} {
		s := string(readVault(t, f))
		for _, w := range []string{"ops-dev", "bg-init"} {
			if strings.Contains(s, w) {
				t.Errorf("%s: упоминает %q", f, w)
			}
		}
	}
	docs, _ := os.ReadFile("../../docs/02-security/identity-secrets-mvp-a.md")
	if strings.Contains(string(docs), "ops-dev") {
		t.Error("identity-secrets-mvp-a.md: ops-dev — только для стенда")
	}
}

const bgInitPolicy = "bg-init"

// checkBGInit: токен-инициатор break-glass имеет ровно эти права и не больше — без delete (отмена чужой процедуры),
// sudo, list и прочих путей.
func checkBGInit(raw []byte) error {
	var p struct {
		Path map[string]struct {
			Capabilities []string `json:"capabilities"`
		} `json:"path"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return err
	}
	want := map[string]string{
		"sys/generate-root-token/attempt": "create,read,update",
		"sys/generate-root-token/update":  "update",
		"sys/rotate/root/init":            "create,read,update",
		"sys/rotate/root/update":          "update",
		"auth/token/lookup-self":          "read",
		"auth/token/renew-self":           "update",
	}
	for path, r := range p.Path {
		w, ok := want[path]
		if !ok {
			return fmt.Errorf("bg-init: лишний путь %q", path)
		}
		caps := append([]string(nil), r.Capabilities...)
		sort.Strings(caps)
		if got := strings.Join(caps, ","); got != w {
			return fmt.Errorf("bg-init: %s capabilities %q, ожидается %q (delete отменял бы чужой break-glass)", path, got, w)
		}
	}
	for path := range want {
		if _, ok := p.Path[path]; !ok {
			return fmt.Errorf("bg-init: нет пути %q", path)
		}
	}
	return nil
}

func TestBreakGlassInitiatorPolicy(t *testing.T) {
	raw := readVault(t, "policies/bg-init.json")
	if err := checkBGInit(raw); err != nil {
		t.Fatal(err)
	}
	mut := func(f func(path map[string]any)) []byte {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		f(m["path"].(map[string]any))
		out, _ := json.Marshal(m)
		return out
	}
	for name, c := range map[string]struct {
		want string
		raw  []byte
	}{
		"delete на attempt": {"delete", mut(func(p map[string]any) {
			p["sys/generate-root-token/attempt"] = map[string]any{"capabilities": []any{"create", "read", "update", "delete"}}
		})},
		"sudo на update": {"capabilities", mut(func(p map[string]any) {
			p["sys/generate-root-token/update"] = map[string]any{"capabilities": []any{"update", "sudo"}}
		})},
		"лишний путь":    {"лишний путь", mut(func(p map[string]any) { p["sys/policy/*"] = map[string]any{"capabilities": []any{"read"}} })},
		"нет renew-self": {"нет пути", mut(func(p map[string]any) { delete(p, "auth/token/renew-self") })},
	} {
		if err := checkBGInit(c.raw); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: ошибка %v, ожидалось %q", name, err, c.want)
		}
	}
}

// В репозитории нет долей unseal (66 hex подряд) и root/service-токенов OpenBao.
func TestNoUnsealSharesOrTokensInRepo(t *testing.T) {
	reShare := regexp.MustCompile(`\b[0-9a-f]{66}\b`)
	reTok := regexp.MustCompile(`\b(hvs|hvb|bao-s)\.[A-Za-z0-9_-]{20,}|\bs\.[A-Za-z0-9]{24}\b`)
	for _, root := range []string{"../../deploy/vault", "../../docs"} {
		err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return err
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			if reShare.Match(b) {
				t.Errorf("%s: похоже на долю unseal (66 hex)", p)
			}
			if reTok.Match(b) {
				t.Errorf("%s: похоже на токен OpenBao", p)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

// Скрипт стенда не кладёт доли и токены в argv: ввод только через stdin (key=-, токен первой строкой stdin).
func TestRunHAScriptNoSecretsInArgv(t *testing.T) {
	b, err := os.ReadFile("../../deploy/vault/dev/run-ha.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if re := regexp.MustCompile(`(^|\s)key=["$]`); re.MatchString(s) {
		t.Errorf("run-ha.sh: доля передаётся как key=<значение> (argv): %s", re.FindString(s))
	}
	for _, bad := range []string{"set -x", "xtrace", "BAO_TOKEN=$tok", "BAO_TOKEN=$bgi", "BAO_TOKEN=$root"} {
		if strings.Contains(s, bad) {
			t.Errorf("run-ha.sh содержит %q: токен мог попасть в argv или трассировку", bad)
		}
	}
	if !strings.Contains(s, "key=-") {
		t.Error("run-ha.sh: unseal без key=- (stdin)")
	}
	if !strings.Contains(s, "umask 077") || !strings.Contains(s, "mkdir -p -m 700") {
		t.Error("run-ha.sh: каталог состояния без 0700/umask 077")
	}
}
