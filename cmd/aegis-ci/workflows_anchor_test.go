package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// stepRun возвращает run шага job'а plan, имя которого содержит part, и его индекс.
func stepRun(t *testing.T, job, part string) (string, int) {
	t.Helper()
	for _, w := range loadWorkflows(t) {
		if w.name != "policy-bundle.yml" {
			continue
		}
		for i, s := range steps(w.jobs()[job]) {
			if n := key(s, "name"); n != nil && strings.Contains(n.Value, part) {
				return key(s, "run").Value, i
			}
		}
	}
	t.Fatalf("шаг %q в %s не найден", part, job)
	return "", 0
}

// B0 привязывается к main и тегу до сборки из него; ключи предыдущего bundle читаются из B0.
func TestPolicyBundleB0Anchor(t *testing.T) {
	anchor, ia := stepRun(t, "plan", "Привязка B0")
	keysRun, ik := stepRun(t, "plan", "Ключи предыдущего bundle из B0")
	build, ib := stepRun(t, "plan", "Проверяющий aegis-ci")
	_, ip := stepRun(t, "plan", "Предыдущий подписанный bundle")
	if !(ip < ia && ia < ik && ik < ib) {
		t.Errorf("порядок шагов plan: prev %d, привязка %d, ключи %d, сборка %d", ip, ia, ik, ib)
	}
	for _, need := range []string{`merge-base --is-ancestor "$B0" "$GITHUB_SHA^"`, `merge-base --is-ancestor "$B0" origin/main`, `refs/tags/policy-bundle-$NUM^{commit}`} {
		if !strings.Contains(anchor, need) {
			t.Errorf("в привязке нет %q", need)
		}
	}
	if !strings.Contains(keysRun, `git show "$B0:deploy/policy-bundle/keys.json"`) {
		t.Error("ключи prev должны читаться git show из B0")
	}
	if !strings.Contains(build, "git worktree add") {
		t.Error("сборка из B0 не найдена")
	}
	plan, _ := stepRun(t, "plan", "План подписи")
	if !strings.Contains(plan, `-prev-keys "$RUNNER_TEMP/b0keys/keys.json"`) || !strings.Contains(plan, "-keys deploy/policy-bundle/keys.json") {
		t.Error("plan: ключи prev — из B0 (-prev-keys), ключи нового bundle — из S (-keys)")
	}
	// В шагах привязки и ключей нет кода из B0 или S: только git, jq и shell.
	for _, r := range []string{anchor, keysRun} {
		if strings.Contains(r, "go ") || strings.Contains(r, "aegis-ci") {
			t.Error("шаги привязки и ключей не должны исполнять Go-код")
		}
	}
}

func gitT(t *testing.T, dir string, env []string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// Шаг привязки исполняется на временном репозитории: B0 не предок, тег на другом коммите, B0 вне main — отказ.
func TestB0AnchorScript(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git не найден")
	}
	script, _ := stepRun(t, "plan", "Привязка B0")
	dir := t.TempDir()
	for _, a := range [][]string{{"init", "-q", "-b", "main"}, {"config", "user.email", "t@example.com"}, {"config", "user.name", "t"}, {"config", "commit.gpgsign", "false"}} {
		gitT(t, dir, nil, a...)
	}
	commit := func(msg string) string {
		os.WriteFile(filepath.Join(dir, "f"), []byte(msg), 0o644)
		gitT(t, dir, nil, "add", "-A")
		gitT(t, dir, nil, "commit", "-q", "-m", msg)
		return gitT(t, dir, nil, "rev-parse", "HEAD")
	}
	c1 := commit("c1")
	b0 := commit("b0")
	s0 := commit("s-parent")
	s := commit("s")
	gitT(t, dir, nil, "checkout", "-q", "-b", "side", c1)
	evil := commit("evil")
	gitT(t, dir, nil, "checkout", "-q", "main")
	gitT(t, dir, nil, "update-ref", "refs/remotes/origin/main", s)
	gitT(t, dir, nil, "tag", "policy-bundle-1", b0)
	gitT(t, dir, nil, "tag", "-a", "-m", "annotated", "policy-bundle-2", b0)
	gitT(t, dir, nil, "tag", "policy-bundle-3", evil)
	gitT(t, dir, nil, "tag", "policy-bundle-4", s0)

	run := func(b, sha, num string) error {
		cmd := exec.Command("bash", "-c", script)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "B0="+b, "NUM="+num, "GITHUB_SHA="+sha)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Logf("отказ: %s", strings.TrimSpace(string(out)))
		}
		return err
	}
	if err := run(b0, s, "1"); err != nil {
		t.Errorf("B0 — предок S^ и main, тег на B0: %v", err)
	}
	if err := run(b0, s, "2"); err != nil {
		t.Errorf("аннотированный тег на B0: %v", err)
	}
	if err := run(s0, s, "4"); err != nil {
		t.Errorf("B0 == S^: %v", err)
	}
	if run(evil, s, "3") == nil {
		t.Error("B0 из боковой ветки (не предок S^) должен быть отказом")
	}
	if run(b0, s, "3") == nil {
		t.Error("тег на другом коммите должен быть отказом")
	}
	if run(b0, s, "99") == nil {
		t.Error("несуществующий тег должен быть отказом")
	}
	if run(s, s, "1") == nil {
		t.Error("B0 == S (не предок родителя) должен быть отказом")
	}
	// B0 — предок S^, но не входит в origin/main: отказ.
	gitT(t, dir, nil, "update-ref", "refs/remotes/origin/main", c1)
	if run(b0, s, "1") == nil {
		t.Error("B0 вне истории origin/main должен быть отказом")
	}
}
