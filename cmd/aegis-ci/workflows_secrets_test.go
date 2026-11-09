package main

import (
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

var xtraceRe = regexp.MustCompile(`(?m)\bset\s+-[a-zA-Z]*x|xtrace|\bprintenv\b|^\s*env\s*(\||$)|^\s*export\s+-p|ACTIONS_STEP_DEBUG|ACTIONS_RUNNER_DEBUG`)

// Секрет не попадает в логи и артефакты: нет трассировки shell и дампа окружения, ключ пишется в файл через printf
// с umask 077 и удаляется шагом if: always(); в артефакты уходят только неподписанный манифест и dist/.
func TestWorkflowSigningKeyHygiene(t *testing.T) {
	var sawSign bool
	for _, w := range loadWorkflows(t) {
		for id, job := range w.jobs() {
			for _, s := range steps(job) {
				if r := key(s, "run"); r != nil && xtraceRe.MatchString(r.Value) {
					t.Errorf("%s/%s: трассировка shell или дамп окружения в run: %q", w.name, id, r.Value)
				}
			}
		}
		if w.name != "policy-bundle.yml" {
			continue
		}
		sign := w.jobs()["sign"]
		if sign == nil {
			t.Fatal("policy-bundle.yml: нет job sign")
		}
		sawSign = true
		if env := key(sign, "environment"); env == nil || env.Value != "policy-signing" {
			t.Error("sign должен идти в environment policy-signing")
		}
		var writer, wiper *yaml.Node
		for _, s := range steps(sign) {
			env := key(s, "env")
			if k := key(env, "KEY"); k != nil {
				if k.Value != "${{ secrets.POLICY_BUNDLE_SIGNING_KEY }}" {
					t.Errorf("KEY должен быть секретом POLICY_BUNDLE_SIGNING_KEY, а не %q", k.Value)
				}
				writer = s
			}
			if r := key(s, "run"); r != nil && strings.Contains(r.Value, "rm -f") && strings.Contains(r.Value, "k.pem") {
				wiper = s
			}
		}
		if writer == nil || wiper == nil {
			t.Fatal("sign: нет шага записи ключа или шага удаления ключа")
		}
		run := key(writer, "run").Value
		if !strings.Contains(run, "umask 077") || !strings.Contains(run, `printf '%s\n' "$KEY" >`) || strings.Contains(run, "echo") {
			t.Errorf("ключ должен писаться через umask 077 и printf в файл, без echo:\n%s", run)
		}
		if c := key(wiper, "if"); c == nil || strings.ReplaceAll(c.Value, " ", "") != "always()" {
			t.Error("шаг удаления ключа должен быть с if: always()")
		}
		// Секрет читают только шаги записи ключа: ни одно другое значение в sign его не содержит.
		for _, s := range steps(sign) {
			if s == writer {
				continue
			}
			scalars(s, func(n *yaml.Node) {
				if strings.Contains(n.Value, "POLICY_BUNDLE_SIGNING_KEY") {
					t.Errorf("sign: секрет упомянут вне шага записи ключа: %q", n.Value)
				}
			})
		}
		// Шаг удаления стоит после записи и до публикации/аттестации.
		var iw, ir, ia int = -1, -1, -1
		for i, s := range steps(sign) {
			switch {
			case s == writer:
				iw = i
			case s == wiper:
				ir = i
			case key(s, "uses") != nil && strings.HasPrefix(key(s, "uses").Value, "actions/attest-build-provenance@"):
				ia = i
			}
		}
		if !(iw < ir && ir < ia) {
			t.Errorf("порядок шагов sign: запись %d, удаление %d, аттестация %d", iw, ir, ia)
		}
		// sign получает работу только от plan и только когда есть что подписывать.
		if n := key(sign, "needs"); n == nil || n.Value != "plan" {
			t.Error("sign должен зависеть только от plan")
		}
		if c := key(sign, "if"); c == nil || !strings.Contains(c.Value, "changed == 'true'") {
			t.Error("sign должен запускаться только при changed == 'true'")
		}
	}
	if !sawSign {
		t.Fatal("policy-bundle.yml не найден")
	}
}

// Кэш setup-go включён только в ci.yml (там нет секретов и записи): отравление кэша не должно доходить до подписи и релиза.
func TestWorkflowCacheOnlyInCI(t *testing.T) {
	for _, w := range loadWorkflows(t) {
		for id, job := range w.jobs() {
			for _, s := range steps(job) {
				u := key(s, "uses")
				if u == nil || !strings.HasPrefix(u.Value, "actions/cache") && !strings.HasPrefix(u.Value, "actions/setup-") {
					continue
				}
				if strings.HasPrefix(u.Value, "actions/cache") && w.name != "ci.yml" {
					t.Errorf("%s/%s: actions/cache вне ci.yml", w.name, id)
				}
				if w.name == "four-eyes.yml" && strings.HasPrefix(u.Value, "actions/setup-go@") {
					// four-eyes.yml исполняет код PR: кэш допустим только без записи, но здесь его быть не должно (по умолчанию).
					if n := key(key(s, "with"), "cache"); n != nil && n.Value != "false" {
						t.Errorf("%s/%s: cache включён", w.name, id)
					}
				}
			}
		}
	}
}

// Только push в main и ручной запуск запускают подпись; события PR и review — никогда (там код из PR).
func TestWorkflowSigningTriggers(t *testing.T) {
	for _, w := range loadWorkflows(t) {
		if w.name != "policy-bundle.yml" {
			continue
		}
		for _, tr := range w.triggers() {
			if tr != "push" && tr != "workflow_dispatch" {
				t.Errorf("policy-bundle.yml: недопустимый триггер %q", tr)
			}
		}
		on := key(w.root, "on")
		br := key(key(on, "push"), "branches")
		if br == nil || len(br.Content) != 1 || br.Content[0].Value != "main" {
			t.Error("policy-bundle.yml: push только в main")
		}
		for id, job := range w.jobs() {
			if c := key(job, "if"); id == "plan" && (c == nil || !strings.Contains(c.Value, "refs/heads/main")) {
				t.Error("plan должен проверять github.ref == refs/heads/main (workflow_dispatch из другой ветки)")
			}
		}
	}
}

// Проверяющий в policy-bundle.yml собирается из worktree B0 (или из S только для genesis) и не запускается через go run из
// проверяемого коммита; sign сверяет содержимое с деревом S (-tree), а не со встроенным в бинарь B0.
func TestWorkflowVerifierIsolation(t *testing.T) {
	for _, w := range loadWorkflows(t) {
		if w.name != "policy-bundle.yml" {
			continue
		}
		for id, job := range w.jobs() {
			for _, s := range steps(job) {
				r := key(s, "run")
				if r == nil {
					continue
				}
				if strings.Contains(r.Value, "go run") {
					t.Errorf("policy-bundle.yml/%s: go run исполняет код проверяемого коммита", id)
				}
				if strings.Contains(r.Value, "bundle sign") && !strings.Contains(r.Value, "-tree .") {
					t.Errorf("policy-bundle.yml/%s: bundle sign без -tree", id)
				}
				if strings.Contains(r.Value, "go build") && strings.Contains(r.Value, "worktree add") &&
					!strings.Contains(r.Value, `cd "$RUNNER_TEMP/b0"`) {
					t.Errorf("policy-bundle.yml/%s: сборка B0 не из worktree", id)
				}
			}
		}
	}
}
