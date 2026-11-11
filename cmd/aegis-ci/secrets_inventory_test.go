package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/limpjungle/aegis3311/internal/strictjson"
)

const (
	inventoryDoc  = "../../docs/02-security/identity-secrets-mvp-a.md"
	vaultDir      = "../../deploy/vault"
	vaultKVPrefix = "aegis-kv/data/mvp-a/"
	carrierVault  = "Vault KV"
	carrierSA     = "projected SA token"
	carrierOut    = "вне Vault"
)

type invRow struct{ Env, Consumer, Carrier, VaultPath string }

// loadInventory разбирает таблицу раздела «Инвентаризация секретов»: столбцы 0 (переменная), 1 (потребитель),
// 6 (носитель), 7 (путь Vault); обратные кавычки снимаются. Носитель нормализуется по префиксу до первой запятой
// («Vault KV, до выбора KMS» → «Vault KV»).
func loadInventory(t *testing.T) []invRow {
	t.Helper()
	raw, err := os.ReadFile(inventoryDoc)
	if err != nil {
		t.Fatal(err)
	}
	var rows []invRow
	in, header := false, false
	for _, line := range strings.Split(string(raw), "\n") {
		if !in {
			in = strings.HasPrefix(line, "#") && strings.Contains(line, "Инвентаризация секретов")
			continue
		}
		if !strings.HasPrefix(line, "|") {
			if header {
				break
			}
			continue
		}
		if !header {
			header = true // заголовок таблицы; следующая строка — разделитель
			continue
		}
		if strings.HasPrefix(line, "|---") {
			continue
		}
		cells := strings.Split(strings.Trim(strings.TrimSpace(line), "|"), "|")
		if len(cells) != 8 {
			t.Fatalf("строка инвентаризации %q: %d столбцов, ожидается 8", line, len(cells))
		}
		for i := range cells {
			cells[i] = strings.TrimSpace(strings.ReplaceAll(cells[i], "`", ""))
		}
		carrier := strings.TrimSpace(strings.SplitN(cells[6], ",", 2)[0])
		path := cells[7]
		if path == "—" {
			path = ""
		}
		rows = append(rows, invRow{Env: cells[0], Consumer: cells[1], Carrier: carrier, VaultPath: path})
	}
	if len(rows) == 0 {
		t.Fatal("таблица инвентаризации секретов не найдена или пуста")
	}
	return rows
}

// goFiles — не тестовые *.go в cmd/ и internal/.
func goFiles(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, root := range []string{"../../cmd", "../../internal"} {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go") {
				out = append(out, p)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}

var secretEnvRe = regexp.MustCompile(`"((?:AEGIS|OPENROUTER)_[A-Z0-9_]+_FILE)"`)

// codeSecretEnvs — имена *_FILE из литералов не тестового кода → файлы, где они встречаются.
func codeSecretEnvs(t *testing.T) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	for _, p := range goFiles(t) {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range secretEnvRe.FindAllStringSubmatch(string(b), -1) {
			if fl := out[m[1]]; len(fl) == 0 || fl[len(fl)-1] != p {
				out[m[1]] = append(fl, p)
			}
		}
	}
	return out
}

func TestSecretInventoryMatchesCode(t *testing.T) {
	rows := loadInventory(t)
	code := codeSecretEnvs(t)
	doc := map[string]bool{}
	for _, r := range rows {
		switch r.Carrier {
		case carrierVault, carrierSA, carrierOut:
		default:
			t.Errorf("%s (%s): носитель %q вне {%s, %s, %s}", r.Env, r.Consumer, r.Carrier, carrierVault, carrierSA, carrierOut)
		}
		if (r.Carrier == carrierVault) != (r.VaultPath != "") {
			t.Errorf("%s (%s): путь Vault %q должен быть непуст тогда и только тогда, когда носитель %q", r.Env, r.Consumer, r.VaultPath, carrierVault)
		}
		if r.VaultPath != "" && !strings.HasPrefix(r.VaultPath, vaultKVPrefix) {
			t.Errorf("%s: путь %q не начинается с %s", r.Env, r.VaultPath, vaultKVPrefix)
		}
		if strings.HasSuffix(r.Env, "_FILE") {
			doc[r.Env] = true
		}
	}
	for env, files := range code {
		if !doc[env] {
			t.Errorf("%s есть в коде (%s), но нет в инвентаризации", env, strings.Join(files, ", "))
		}
	}
	for env := range doc {
		if _, ok := code[env]; !ok {
			t.Errorf("%s есть в инвентаризации, но не читается кодом", env)
		}
	}
}

var secretValueEnvRe = regexp.MustCompile(`"(OPENROUTER_API_KEY|AEGIS_[A-Z0-9_]*(?:KEY|TOKEN|SECRET)[A-Z0-9_]*)"`)

// Секреты не читаются значением из окружения: только путь к файлу (*_FILE). Allowlist пуст.
func TestNoSecretValueEnv(t *testing.T) {
	for _, p := range goFiles(t) {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range secretValueEnvRe.FindAllStringSubmatch(string(b), -1) {
			if !strings.HasSuffix(m[1], "_FILE") {
				t.Errorf("%s: литерал %q — секрет должен читаться из файла (*_FILE)", p, m[1])
			}
		}
	}
}

func TestKillSwitchSecretsOutsideVault(t *testing.T) {
	n := 0
	for _, r := range loadInventory(t) {
		if strings.HasPrefix(r.Consumer, "aegis-killswitch") || r.Env == "-key" {
			n++
			if r.Carrier != carrierOut {
				t.Errorf("%s (%s): секреты kill switch — только %q, а не %q", r.Env, r.Consumer, carrierOut, r.Carrier)
			}
		}
	}
	if n == 0 {
		t.Fatal("в инвентаризации нет строк kill switch")
	}
}

type vaultPolicy struct {
	Path map[string]struct {
		Capabilities []string `json:"capabilities"`
	} `json:"path"`
}

type vaultRole struct {
	SANames      []string `json:"bound_service_account_names"`
	SANamespaces []string `json:"bound_service_account_namespaces"`
	Audience     string   `json:"audience"`
	TokenPolicy  []string `json:"token_policies"`
	TokenTTL     string   `json:"token_ttl"`
	TokenMaxTTL  string   `json:"token_max_ttl"`
}

type vaultAgent struct {
	Vault struct {
		Address string `json:"address"`
		CACert  string `json:"ca_cert"`
		Retry   struct {
			NumRetries int `json:"num_retries"`
		} `json:"retry"`
	} `json:"vault"`
	AutoAuth struct {
		// В JSON-форме HCL блок method — список; объект агент отвергает («one and only one "method" block is required»),
		// проверено на dev-стенде deploy/vault/dev.
		Method []struct {
			Type      string `json:"type"`
			MountPath string `json:"mount_path"`
			Config    struct {
				Role      string `json:"role"`
				TokenPath string `json:"token_path"`
			} `json:"config"`
		} `json:"method"`
	} `json:"auto_auth"`
	ExitAfterAuth  bool `json:"exit_after_auth"`
	TemplateConfig struct {
		ExitOnRetryFailure bool `json:"exit_on_retry_failure"`
	} `json:"template_config"`
	Template []struct {
		Contents       string `json:"contents"`
		Destination    string `json:"destination"`
		Perms          string `json:"perms"`
		ErrorOnMissKey bool   `json:"error_on_missing_key"`
	} `json:"template"`
}

// checkPolicy: точные пути под aegis-kv/data/mvp-a/, без шаблонов и системных путей, права ровно read (или deny).
// Возвращает множество путей.
func checkPolicy(raw []byte) (map[string]bool, error) {
	var p vaultPolicy
	if err := strictjson.Decode(raw, &p); err != nil {
		return nil, err
	}
	if len(p.Path) == 0 {
		return nil, errors.New("политика без путей")
	}
	paths := map[string]bool{}
	for path, v := range p.Path {
		if strings.ContainsAny(path, "*+") {
			return nil, fmt.Errorf("путь %q содержит шаблон", path)
		}
		if !strings.HasPrefix(path, vaultKVPrefix) {
			return nil, fmt.Errorf("путь %q вне %s", path, vaultKVPrefix)
		}
		for _, bad := range []string{"sys/", "auth/", "identity/"} {
			if strings.Contains(path, bad) {
				return nil, fmt.Errorf("путь %q содержит %s", path, bad)
			}
		}
		if len(v.Capabilities) != 1 || (v.Capabilities[0] != "read" && v.Capabilities[0] != "deny") {
			return nil, fmt.Errorf("путь %q: capabilities %v, разрешено ровно [read] или [deny]", path, v.Capabilities)
		}
		paths[path] = true
	}
	return paths, nil
}

func ttlAtMost(name, v string, max time.Duration) error {
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return fmt.Errorf("%s: %q — не положительная длительность", name, v)
	}
	if d > max {
		return fmt.Errorf("%s: %s больше %s", name, v, max)
	}
	return nil
}

// checkRole: имя роли = имя файла = имя единственной политики; policyExists сообщает, есть ли файл политики.
func checkRole(raw []byte, name string, policyExists func(string) bool) error {
	var r vaultRole
	if err := strictjson.Decode(raw, &r); err != nil {
		return err
	}
	for field, v := range map[string][]string{"bound_service_account_names": r.SANames, "bound_service_account_namespaces": r.SANamespaces} {
		if len(v) != 1 || v[0] == "" || strings.Contains(v[0], "*") {
			return fmt.Errorf("%s: %v — нужно ровно одно значение без *", field, v)
		}
	}
	if r.Audience != "vault" {
		return fmt.Errorf("audience %q, ожидается vault", r.Audience)
	}
	if len(r.TokenPolicy) != 1 || r.TokenPolicy[0] != name {
		return fmt.Errorf("token_policies %v, ожидается [%s]", r.TokenPolicy, name)
	}
	if !policyExists(name) {
		return fmt.Errorf("нет файла политики %s", name)
	}
	if err := ttlAtMost("token_ttl", r.TokenTTL, 5*time.Minute); err != nil {
		return err
	}
	return ttlAtMost("token_max_ttl", r.TokenMaxTTL, 10*time.Minute)
}

var withSecretRe = regexp.MustCompile(`with secret "([^"]+)"`)

// checkAgent: init-режим без sink/listener/api_proxy/cache (их отвергает strictjson), строгие шаблоны;
// пути секретов = want (инвентаризация) и все есть в политике policy.
func checkAgent(raw []byte, roleExists func(string) bool, policy, want map[string]bool) error {
	var a vaultAgent
	if err := strictjson.Decode(raw, &a); err != nil {
		return err
	}
	if !strings.HasPrefix(a.Vault.Address, "https://") {
		return fmt.Errorf("vault.address %q не https", a.Vault.Address)
	}
	if a.Vault.CACert == "" {
		return errors.New("не задан vault.ca_cert")
	}
	// Без явного предела агент повторяет чтение отсутствующего пути ~5 минут (12 попыток); при малом пределе init-контейнер
	// падает за секунды, а повторы делает Kubernetes (CrashLoopBackOff, видно в мониторинге).
	if n := a.Vault.Retry.NumRetries; n < 1 || n > 5 {
		return fmt.Errorf("vault.retry.num_retries %d: нужно от 1 до 5", n)
	}
	if len(a.AutoAuth.Method) != 1 {
		return fmt.Errorf("auto_auth.method: %d блоков, нужен ровно один", len(a.AutoAuth.Method))
	}
	m := a.AutoAuth.Method[0]
	if m.Type != "kubernetes" || m.MountPath == "" {
		return fmt.Errorf("auto_auth.method: type %q, mount_path %q", m.Type, m.MountPath)
	}
	if !roleExists(m.Config.Role) {
		return fmt.Errorf("роль %q: нет файла в roles/", m.Config.Role)
	}
	if m.Config.TokenPath == "" || m.Config.TokenPath == "/var/run/secrets/kubernetes.io/serviceaccount/token" {
		return fmt.Errorf("token_path %q: нужен отдельный projected-токен с audience vault", m.Config.TokenPath)
	}
	if !a.ExitAfterAuth || !a.TemplateConfig.ExitOnRetryFailure {
		return errors.New("нужны exit_after_auth и template_config.exit_on_retry_failure")
	}
	got, dest := map[string]bool{}, map[string]bool{}
	for i, tp := range a.Template {
		if tp.Perms != "0400" || !tp.ErrorOnMissKey {
			return fmt.Errorf("template %d: perms %q, error_on_missing_key %v", i, tp.Perms, tp.ErrorOnMissKey)
		}
		if !strings.HasPrefix(tp.Destination, "/vault/secrets/") || strings.Contains(tp.Destination, "..") || dest[tp.Destination] {
			return fmt.Errorf("template %d: destination %q (префикс /vault/secrets/, без .., уникальный)", i, tp.Destination)
		}
		dest[tp.Destination] = true
		ms := withSecretRe.FindAllStringSubmatch(tp.Contents, -1)
		if len(ms) != 1 {
			return fmt.Errorf("template %d: ожидается ровно один with secret", i)
		}
		if !policy[ms[0][1]] {
			return fmt.Errorf("template %d: путь %q вне политики", i, ms[0][1])
		}
		got[ms[0][1]] = true
	}
	for p := range got {
		if !want[p] {
			return fmt.Errorf("путь %q не из инвентаризации intake", p)
		}
	}
	for p := range want {
		if !got[p] {
			return fmt.Errorf("путь %q из инвентаризации не доставляется агентом", p)
		}
	}
	for p := range policy {
		if !want[p] {
			return fmt.Errorf("политика содержит лишний путь %q", p)
		}
	}
	return nil
}

func readVault(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(vaultDir, rel))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func vaultFiles(t *testing.T, sub string) []string {
	t.Helper()
	fl, err := filepath.Glob(filepath.Join(vaultDir, sub, "*.json"))
	if err != nil || len(fl) == 0 {
		t.Fatalf("нет файлов %s/*.json (%v)", sub, err)
	}
	return fl
}

func stem(p string) string { return strings.TrimSuffix(filepath.Base(p), ".json") }

func existsIn(sub string) func(string) bool {
	return func(name string) bool {
		_, err := os.Stat(filepath.Join(vaultDir, sub, name+".json"))
		return err == nil
	}
}

func intakePaths(t *testing.T) map[string]bool {
	want := map[string]bool{}
	for _, r := range loadInventory(t) {
		if r.VaultPath != "" && strings.HasPrefix(r.Consumer, "intake") {
			want[r.VaultPath] = true
		}
	}
	return want
}

func TestVaultPolicyLeastPrivilege(t *testing.T) {
	for _, f := range vaultFiles(t, "policies") {
		if stem(f) == bgInitPolicy {
			continue // политика токена-инициатора break-glass — не intake; проверяется TestBreakGlassInitiatorPolicy
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := checkPolicy(raw); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
}

func TestVaultRoleBounds(t *testing.T) {
	for _, f := range vaultFiles(t, "roles") {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if err := checkRole(raw, stem(f), existsIn("policies")); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
}

func TestVaultAgentIntake(t *testing.T) {
	pol, err := checkPolicy(readVault(t, "policies/aegis-intake.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range vaultFiles(t, "agent") {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if err := checkAgent(raw, existsIn("roles"), pol, intakePaths(t)); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
}

// Мутации реальных файлов: каждая проверка обязана их отвергнуть.
func TestVaultNegativeCases(t *testing.T) {
	mutate := func(t *testing.T, raw []byte, f func(m map[string]any)) []byte {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		f(m)
		out, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	polRaw, roleRaw, agentRaw := readVault(t, "policies/aegis-intake.json"), readVault(t, "roles/aegis-intake.json"), readVault(t, "agent/aegis-intake.json")
	pol, err := checkPolicy(polRaw)
	if err != nil {
		t.Fatal(err)
	}
	want := intakePaths(t)
	firstPath := func(m map[string]any) (string, map[string]any) {
		pm := m["path"].(map[string]any)
		keys := make([]string, 0, len(pm))
		for k := range pm {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return keys[0], pm
	}
	tmpl0 := func(m map[string]any) map[string]any { return m["template"].([]any)[0].(map[string]any) }

	cases := []struct {
		name string
		want string // подстрока причины ошибки
		run  func() error
	}{
		{"* в пути политики", "содержит шаблон", func() error {
			_, err := checkPolicy(mutate(t, polRaw, func(m map[string]any) {
				k, pm := firstPath(m)
				pm[k+"/*"] = pm[k]
			}))
			return err
		}},
		{"update в capabilities", "capabilities", func() error {
			_, err := checkPolicy(mutate(t, polRaw, func(m map[string]any) {
				k, pm := firstPath(m)
				pm[k] = map[string]any{"capabilities": []any{"read", "update"}}
			}))
			return err
		}},
		{"путь sys/", "вне aegis-kv", func() error {
			_, err := checkPolicy(mutate(t, polRaw, func(m map[string]any) {
				m["path"].(map[string]any)["sys/policy/aegis-intake"] = map[string]any{"capabilities": []any{"read"}}
			}))
			return err
		}},
		{"token_ttl 1h", "token_ttl", func() error {
			return checkRole(mutate(t, roleRaw, func(m map[string]any) { m["token_ttl"] = "1h" }), "aegis-intake", existsIn("policies"))
		}},
		{"два namespace", "bound_service_account_namespaces", func() error {
			return checkRole(mutate(t, roleRaw, func(m map[string]any) { m["bound_service_account_namespaces"] = []any{"aegis-system", "kube-system"} }), "aegis-intake", existsIn("policies"))
		}},
		{"audience не vault", "audience", func() error {
			return checkRole(mutate(t, roleRaw, func(m map[string]any) { m["audience"] = "https://kubernetes.default.svc" }), "aegis-intake", existsIn("policies"))
		}},
		{"sink в агенте", "UNK:sink", func() error {
			return checkAgent(mutate(t, agentRaw, func(m map[string]any) {
				m["sink"] = []any{map[string]any{"type": "file"}}
			}), existsIn("roles"), pol, want)
		}},
		{"listener в агенте", "UNK:listener", func() error {
			return checkAgent(mutate(t, agentRaw, func(m map[string]any) { m["listener"] = []any{} }), existsIn("roles"), pol, want)
		}},
		{"perms 0644", "perms", func() error {
			return checkAgent(mutate(t, agentRaw, func(m map[string]any) { tmpl0(m)["perms"] = "0644" }), existsIn("roles"), pol, want)
		}},
		{"template на путь вне политики", "вне политики", func() error {
			return checkAgent(mutate(t, agentRaw, func(m map[string]any) {
				tmpl0(m)["contents"] = `{{ with secret "aegis-kv/data/mvp-a/other" }}{{ .Data.data.v }}{{ end }}`
			}), existsIn("roles"), pol, want)
		}},
		{"method объектом", "method", func() error {
			return checkAgent(mutate(t, agentRaw, func(m map[string]any) {
				aa := m["auto_auth"].(map[string]any)
				aa["method"] = aa["method"].([]any)[0]
			}), existsIn("roles"), pol, want)
		}},
		{"два method", "нужен ровно один", func() error {
			return checkAgent(mutate(t, agentRaw, func(m map[string]any) {
				aa := m["auto_auth"].(map[string]any)
				aa["method"] = append(aa["method"].([]any), aa["method"].([]any)[0])
			}), existsIn("roles"), pol, want)
		}},
		{"без предела повторов", "num_retries", func() error {
			return checkAgent(mutate(t, agentRaw, func(m map[string]any) { delete(m["vault"].(map[string]any), "retry") }), existsIn("roles"), pol, want)
		}},
		{"exit_after_auth false", "exit_after_auth", func() error {
			return checkAgent(mutate(t, agentRaw, func(m map[string]any) { m["exit_after_auth"] = false }), existsIn("roles"), pol, want)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.run()
			if err == nil {
				t.Fatal("мутация принята, ожидалась ошибка")
			}
			if f, ok := strings.CutPrefix(c.want, "UNK:"); ok {
				var uf *strictjson.UnknownFieldError
				if !errors.As(err, &uf) || uf.Field != f {
					t.Errorf("ожидался UnknownFieldError(%s), получено: %v", f, err)
				}
				return
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("ошибка %q не содержит %q (отклонено по другой причине)", err, c.want)
			}
		})
	}
}
