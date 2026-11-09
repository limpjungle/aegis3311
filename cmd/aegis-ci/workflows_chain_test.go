package main

import (
	"strings"
	"testing"
)

func runsOf(t *testing.T, name string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, w := range loadWorkflows(t) {
		if w.name != name {
			continue
		}
		for id, job := range w.jobs() {
			var b strings.Builder
			for _, s := range steps(job) {
				if r := key(s, "run"); r != nil {
					b.WriteString(r.Value + "\n")
				}
			}
			out[id] = b.String()
		}
	}
	if len(out) == 0 {
		t.Fatalf("%s не найден", name)
	}
	return out
}

// Проверяющий для подписи собирается из коммита предыдущего bundle (B0), а не запускается из проверяемого коммита.
func TestPolicyBundleVerifierFromB0(t *testing.T) {
	runs := runsOf(t, "policy-bundle.yml")
	for id, r := range runs {
		if strings.Contains(r, "go run") {
			t.Errorf("policy-bundle.yml/%s: go run исполняет код проверяемого коммита; проверяющий собирается из B0", id)
		}
	}
	for _, id := range []string{"plan", "sign"} {
		r := runs[id]
		if !strings.Contains(r, `git worktree add --detach "$RUNNER_TEMP/b0" "$B0"`) || !strings.Contains(r, `go build -o "$RUNNER_TEMP/aegis-ci" ./cmd/aegis-ci`) {
			t.Errorf("policy-bundle.yml/%s: нет сборки aegis-ci из worktree B0", id)
		}
		if !strings.Contains(r, `"$RUNNER_TEMP/aegis-ci" bundle`) {
			t.Errorf("policy-bundle.yml/%s: bundle не запускается собранным бинарём", id)
		}
	}
	if !strings.Contains(runs["sign"], "-tree .") {
		t.Error("sign должен сверять содержимое с деревом проверяемого коммита (-tree .)")
	}
	if !strings.Contains(runs["plan"], "git diff --stat") || !strings.Contains(runs["plan"], "GITHUB_STEP_SUMMARY") {
		t.Error("plan должен печатать diff защитного кода для ревьюера в сводку")
	}
	for _, w := range loadWorkflows(t) {
		if w.name != "policy-bundle.yml" {
			continue
		}
		for _, job := range w.jobs() {
			for _, s := range steps(job) {
				if u := key(s, "uses"); u != nil && strings.HasPrefix(u.Value, "actions/checkout@") {
					if n := key(key(s, "with"), "fetch-depth"); n == nil || n.Value != "0" {
						t.Error("checkout в policy-bundle.yml нужен с fetch-depth: 0 (worktree B0)")
					}
				}
			}
		}
	}
}

// Genesis не выбирается автоматически: только workflow_dispatch с genesis=true и confirm=genesis, и только без тегов.
func TestGenesisNeverAutomatic(t *testing.T) {
	for _, w := range loadWorkflows(t) {
		if w.name != "policy-bundle.yml" {
			continue
		}
		in := key(key(key(w.root, "on"), "workflow_dispatch"), "inputs")
		if g := key(key(in, "genesis"), "type"); g == nil || g.Value != "boolean" {
			t.Error("workflow_dispatch: нужен boolean-вход genesis")
		}
		if key(in, "confirm") == nil {
			t.Error("workflow_dispatch: нужен вход confirm")
		}
	}
	prev := runsOf(t, "policy-bundle.yml")["plan"]
	i := strings.Index(prev, "genesis=true")
	if i < 0 {
		t.Fatal("нет ветки genesis")
	}
	// Единственное место, где выбирается genesis, окружено проверками события, входов и пустоты тегов.
	ctx := prev[:i]
	for _, need := range []string{`"$EVENT" = "workflow_dispatch"`, `"$GENESIS" = "true"`, `"$CONFIRM" = "genesis"`, `! -s "$RUNNER_TEMP/tags.txt"`} {
		if !strings.Contains(ctx, need) {
			t.Errorf("перед выбором genesis нет проверки %s", need)
		}
	}
	for _, need := range []string{"git tag -l 'policy-bundle-*'", "--paginate", "diff -u", "Нет предыдущего bundle"} {
		if !strings.Contains(prev, need) {
			t.Errorf("plan: нет %q (сверка тегов и релизов, отказ без bundle)", need)
		}
	}
}

// Списки релизов — только с пагинацией, без усечения до первых 100.
func TestNoUnpaginatedReleaseList(t *testing.T) {
	for _, name := range []string{"policy-bundle.yml", "release.yml"} {
		for id, r := range runsOf(t, name) {
			if strings.Contains(r, "gh release list") || strings.Contains(r, "--limit 100") {
				t.Errorf("%s/%s: gh release list/--limit 100 усекает список; используйте gh api --paginate", name, id)
			}
			if strings.Contains(r, "/releases") && !strings.Contains(r, "--paginate") {
				t.Errorf("%s/%s: список релизов без --paginate", name, id)
			}
		}
	}
}
