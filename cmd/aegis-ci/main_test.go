package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/limpjungle/aegis3311/internal/bundle"
	"github.com/limpjungle/aegis3311/internal/bundle/bundletest"
)

const testRules = `{"schema":"aegisops/four-eyes/v1","min_approvals":2,"min_groups":2,
 "groups":{"owners":["alice","bob"],"sec":["carol"]},"excluded":[],
 "protected":[{"path":"policy/","groups":["owners","sec"],"require":[]},
              {"path":"catalog/","groups":["owners","sec"],"require":[]},
              {"path":"eval/golden-synthetic/","groups":["owners","sec"],"require":[]},
              {"path":"deploy/","groups":["owners","sec"],"require":[]},
              {"path":".github/","groups":["owners","sec"],"require":[]}]}`

func code(err error) int {
	var ee exitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &ee):
		return ee.code
	}
	return -1
}

type harness struct {
	t      *testing.T
	repo   string
	dir    string
	keys   string // keys.json
	signer string // имя ключа
	routes map[string]string
	srv    *httptest.Server
}

func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func copyTree(t *testing.T, from, to string) {
	t.Helper()
	b, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Dir(to), 0o755)
	if err := os.WriteFile(to, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git не найден")
	}
	h := &harness{t: t, dir: t.TempDir(), routes: map[string]string{}}
	h.repo = filepath.Join(h.dir, "repo")
	os.MkdirAll(h.repo, 0o755)
	for _, a := range [][]string{{"init", "-q", "-b", "main"}, {"config", "user.email", "t@example.com"}, {"config", "user.name", "t"}, {"config", "commit.gpgsign", "false"}} {
		gitIn(t, h.repo, a...)
	}
	// Содержимое bundle — копия реального: FromDir должен совпасть со встроенным (bundle sign сверяет с Embedded).
	root := "../.."
	for _, g := range []string{"policy/aegis/*/*.rego", "catalog/actions/*.yaml", "eval/golden-synthetic/prompt/*", "eval/golden-synthetic/schema/*"} {
		m, _ := filepath.Glob(filepath.Join(root, g))
		for _, f := range m {
			rel, _ := filepath.Rel(root, f)
			copyTree(t, f, filepath.Join(h.repo, rel))
		}
	}
	copyTree(t, root+"/eval/golden-synthetic/profiles.json", h.repo+"/eval/golden-synthetic/profiles.json")
	copyTree(t, root+"/eval/golden-synthetic/data/manifest.json", h.repo+"/eval/golden-synthetic/data/manifest.json")
	h.write(".github/four-eyes.json", testRules)
	h.write("README.md", "1")
	h.write("deploy/base.txt", "1")
	h.commit("base")

	_, spec := bundletest.Key(t, h.dir, "ci")
	spec.Path = "ci.pub"
	b, _ := json.Marshal([]bundle.KeySpec{spec})
	h.keys = filepath.Join(h.dir, "keys.json")
	os.WriteFile(h.keys, b, 0o644)
	h.signer = "ci"

	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if body, ok := h.routes[r.URL.Path]; ok {
			io.WriteString(w, body)
			return
		}
		w.WriteHeader(404)
	}))
	t.Cleanup(h.srv.Close)
	return h
}

func (h *harness) write(path, content string) {
	h.t.Helper()
	full := filepath.Join(h.repo, path)
	os.MkdirAll(filepath.Dir(full), 0o755)
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) commit(msg string) string {
	h.t.Helper()
	gitIn(h.t, h.repo, "add", "-A")
	gitIn(h.t, h.repo, "commit", "-q", "-m", msg, "--allow-empty")
	return gitIn(h.t, h.repo, "rev-parse", "HEAD")
}

// squash имитирует PR: ветка pr с тем же изменением (head) и коммит на main с тем же деревом (squash-коммит).
func (h *harness) squash(files map[string]string) (merge, head string) {
	h.t.Helper()
	base := gitIn(h.t, h.repo, "rev-parse", "HEAD")
	gitIn(h.t, h.repo, "checkout", "-q", "-B", "pr", base)
	for p, c := range files {
		h.write(p, c)
	}
	head = h.commit("pr head")
	gitIn(h.t, h.repo, "checkout", "-q", "main")
	for p, c := range files {
		h.write(p, c)
	}
	merge = h.commit("squash")
	return merge, head
}

func pullJSON(n int, author, head, mergeSHA string) string {
	merged := "null"
	if mergeSHA != "" {
		merged = `"2026-01-01T00:00:00Z"`
	}
	ms := "null"
	if mergeSHA != "" {
		ms = `"` + mergeSHA + `"`
	}
	return fmt.Sprintf(`{"number":%d,"user":{"login":%q,"type":"User"},"merged_at":%s,"merge_commit_sha":%s,"head":{"sha":%q},"base":{"ref":"main"}}`,
		n, author, merged, ms, head)
}

func reviewJSON(id int, login, state, commit string) string {
	return fmt.Sprintf(`{"id":%d,"user":{"login":%q,"type":"User"},"state":%q,"commit_id":%q}`, id, login, state, commit)
}

// routePR настраивает API: PR n слит коммитом merge, head head, ревью approvers (логин → APPROVED на head).
func (h *harness) routePR(n int, merge, head string, approvers ...string) {
	var rv []string
	for i, a := range approvers {
		rv = append(rv, reviewJSON(100+i, a, "APPROVED", head))
	}
	h.routes[fmt.Sprintf("/repos/o/r/commits/%s/pulls", merge)] = "[" + pullJSON(n, "zed", head, merge) + "]"
	h.routes[fmt.Sprintf("/repos/o/r/pulls/%d/reviews", n)] = "[" + strings.Join(rv, ",") + "]"
	h.routes[fmt.Sprintf("/repos/o/r/pulls/%d/commits", n)] = `[{"author":{"login":"zed"},"committer":{"login":"zed"}}]`
	h.routes[fmt.Sprintf("/repos/o/r/pulls/%d", n)] = pullJSON(n, "zed", head, merge)
}

func (h *harness) run(args ...string) (stdout string, err error) {
	var out, errb bytes.Buffer
	e := env{getenv: func(string) string { return "" }, stdout: &out, stderr: &errb,
		now: func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) }}
	err = run(context.Background(), args, e)
	return out.String() + errb.String(), err
}

func (h *harness) plan(sha string, extra ...string) (string, string, error) {
	out := filepath.Join(h.dir, "unsigned.json")
	ghOut := filepath.Join(h.dir, "gh-output")
	os.Remove(out)
	os.Remove(ghOut)
	args := append([]string{"bundle", "plan", "-repo", "o/r", "-sha", sha, "-git-dir", h.repo, "-keys", h.keys, "-out", out,
		"-github-output", ghOut, "-api-url", h.srv.URL}, extra...)
	text, err := h.run(args...)
	o, _ := os.ReadFile(ghOut)
	return text, string(o), err
}

func (h *harness) sign(in, out string) (string, error) {
	return h.run("bundle", "sign", "-in", in, "-key-file", filepath.Join(h.dir, h.signer+".key"), "-issuer", bundletest.Issuer,
		"-keys", h.keys, "-out", out)
}

// genesis проводит genesis-bundle и возвращает путь к подписанному bundle и его коммит.
func (h *harness) genesis() (path, commit string) {
	h.t.Helper()
	merge, head := h.squash(map[string]string{"deploy/g.txt": "g"})
	h.routePR(1, merge, head, "alice", "carol")
	text, outs, err := h.plan(merge, "-genesis")
	if err != nil || !strings.Contains(outs, "changed=true") || !strings.Contains(outs, "sequence=1") {
		h.t.Fatalf("genesis plan: %v\n%s\n%s", err, text, outs)
	}
	path = filepath.Join(h.dir, "bundle1.json")
	if text, err := h.sign(filepath.Join(h.dir, "unsigned.json"), path); err != nil {
		h.t.Fatalf("sign: %v\n%s", err, text)
	}
	return path, merge
}

func TestPlanSignVerifyChain(t *testing.T) {
	h := newHarness(t)
	b1, g := h.genesis()
	out, err := h.run("bundle", "verify", "-in", b1, "-keys", h.keys, "-commit", g)
	if err != nil || !strings.Contains(out, "sequence 1") || !strings.Contains(out, "alice") {
		t.Fatalf("verify: %v %s", err, out)
	}
	// Второй bundle: цепочка от G, правила из G.
	m2, h2 := h.squash(map[string]string{"deploy/y.txt": "y"})
	h.routePR(2, m2, h2, "bob", "carol")
	text, outs, err := h.plan(m2, "-prev", b1)
	if err != nil || !strings.Contains(outs, "sequence=2") {
		t.Fatalf("plan 2: %v\n%s\n%s", err, text, outs)
	}
	var m bundle.Manifest
	raw, _ := os.ReadFile(filepath.Join(h.dir, "unsigned.json"))
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m.Sequence != 2 || m.PrevCommit == nil || *m.PrevCommit != g || m.Commit != m2 || m.Approvals.PR != 2 || len(m.Approvals.Approvers) != 2 ||
		m.IssuedAt != "2026-01-02T03:04:05Z" || len(m.Signatures) != 0 {
		t.Errorf("манифест: %+v", m)
	}
	// Нет защищённых изменений — подписывать нечего, PR не нужен.
	h.write("README.md", "2")
	readme := h.commit("readme")
	// b1 привязан к G, а m2 (защищённое изменение до readme) не подписан: цепочка разорвана.
	text, _, err = h.plan(readme, "-prev", b1)
	if code(err) != 1 {
		t.Errorf("между B0 и README есть неподписанное изменение m2: %v %s", err, text)
	}
}

func TestPlanNoProtectedChanges(t *testing.T) {
	h := newHarness(t)
	b1, _ := h.genesis()
	h.write("README.md", "2")
	readme := h.commit("readme")
	text, outs, err := h.plan(readme, "-prev", b1)
	if err != nil || !strings.Contains(outs, "changed=false") || strings.Contains(outs, "sequence") {
		t.Fatalf("changed=false ожидался: %v\n%s\n%s", err, text, outs)
	}
	if _, err := os.Stat(filepath.Join(h.dir, "unsigned.json")); err == nil {
		t.Error("при changed=false манифест писать не нужно")
	}
}

func TestPlanRefusals(t *testing.T) {
	t.Run("push без PR", func(t *testing.T) {
		h := newHarness(t)
		b1, _ := h.genesis()
		h.write("deploy/direct.txt", "x")
		sha := h.commit("direct")
		h.routes[fmt.Sprintf("/repos/o/r/commits/%s/pulls", sha)] = "[]"
		text, _, err := h.plan(sha, "-prev", b1)
		if code(err) != 1 || !strings.Contains(err.Error(), "в обход PR") {
			t.Errorf("%v %s", err, text)
		}
	})
	t.Run("разрыв цепочки", func(t *testing.T) {
		h := newHarness(t)
		b1, _ := h.genesis()
		h.squash(map[string]string{"deploy/skipped.txt": "x"}) // слит, но bundle не получил
		m3, h3 := h.squash(map[string]string{"deploy/z.txt": "z"})
		h.routePR(3, m3, h3, "alice", "carol")
		text, _, err := h.plan(m3, "-prev", b1)
		if code(err) != 1 || !strings.Contains(err.Error(), "без подписи") {
			t.Errorf("%v %s", err, text)
		}
	})
	t.Run("коммит не совпадает с head PR", func(t *testing.T) {
		h := newHarness(t)
		b1, _ := h.genesis()
		m2, h2 := h.squash(map[string]string{"deploy/y.txt": "y"})
		// «Head» PR на самом деле другой коммит с другим содержимым.
		gitIn(t, h.repo, "checkout", "-q", "-B", "other", "HEAD~1")
		h.write("deploy/y.txt", "другое")
		other := h.commit("other")
		gitIn(t, h.repo, "checkout", "-q", "main")
		_ = h2
		h.routePR(2, m2, other, "bob", "carol")
		text, _, err := h.plan(m2, "-prev", b1)
		if code(err) != 1 || !strings.Contains(err.Error(), "отличается от head") {
			t.Errorf("%v %s", err, text)
		}
	})
	t.Run("недостаточно одобрений", func(t *testing.T) {
		h := newHarness(t)
		b1, _ := h.genesis()
		m2, h2 := h.squash(map[string]string{"deploy/y.txt": "y"})
		h.routePR(2, m2, h2, "alice")
		text, _, err := h.plan(m2, "-prev", b1)
		if code(err) != 1 || !strings.Contains(err.Error(), "недостаточны") {
			t.Errorf("%v %s", err, text)
		}
	})
	t.Run("две одобрившие из одной группы", func(t *testing.T) {
		h := newHarness(t)
		b1, _ := h.genesis()
		m2, h2 := h.squash(map[string]string{"deploy/y.txt": "y"})
		h.routePR(2, m2, h2, "alice", "bob")
		if _, _, err := h.plan(m2, "-prev", b1); code(err) != 1 {
			t.Errorf("ожидался код 1: %v", err)
		}
	})
	// Правила берутся из B0, а не из PR: PR ослабляет four-eyes.json (min_groups 1) и приносит одобрения одной группы.
	t.Run("изменение four-eyes.json в том же PR не влияет", func(t *testing.T) {
		h := newHarness(t)
		b1, _ := h.genesis()
		weak := strings.Replace(testRules, `"min_groups":2`, `"min_groups":1`, 1)
		m2, h2 := h.squash(map[string]string{".github/four-eyes.json": weak, "deploy/y.txt": "y"})
		h.routePR(2, m2, h2, "alice", "bob")
		text, _, err := h.plan(m2, "-prev", b1)
		if code(err) != 1 || !strings.Contains(err.Error(), "недостаточны") {
			t.Errorf("ослабленные в PR правила не должны применяться: %v %s", err, text)
		}
	})
	t.Run("genesis: правила из коммита", func(t *testing.T) {
		h := newHarness(t)
		weak := strings.Replace(testRules, `"min_groups":2`, `"min_groups":1`, 1)
		m, hd := h.squash(map[string]string{".github/four-eyes.json": weak})
		h.routePR(1, m, hd, "alice", "bob")
		// bundle.Verify всё равно потребует две группы, но план по правилам коммита может пройти — проверяем, что одобрение
		// из одной группы даёт манифест, который Verify отвергнет (approvals).
		text, _, err := h.plan(m, "-genesis")
		if err != nil {
			t.Fatalf("план по правилам коммита: %v %s", err, text)
		}
		if _, serr := h.sign(filepath.Join(h.dir, "unsigned.json"), filepath.Join(h.dir, "b.json")); serr == nil {
			t.Error("bundle с одобрениями одной группы не должен подписываться")
		}
	})
	t.Run("рабочее дерево не на коммите", func(t *testing.T) {
		h := newHarness(t)
		b1, g := h.genesis()
		h.write("deploy/more.txt", "x")
		h.commit("more")
		if _, _, err := h.plan(g, "-prev", b1); code(err) != 1 {
			t.Errorf("ожидался код 1: %v", err)
		}
	})
	t.Run("пустые ключи", func(t *testing.T) {
		h := newHarness(t)
		os.WriteFile(h.keys, []byte("[]"), 0o644)
		merge, head := h.squash(map[string]string{"deploy/g.txt": "g"})
		h.routePR(1, merge, head, "alice", "carol")
		text, _, err := h.plan(merge, "-genesis")
		if code(err) != 2 || !strings.Contains(err.Error(), "нет ключей") {
			t.Errorf("%v %s", err, text)
		}
	})
	t.Run("genesis и prev вместе", func(t *testing.T) {
		h := newHarness(t)
		if _, _, err := h.plan(strings.Repeat("a", 40), "-genesis", "-prev", "x"); code(err) != 2 {
			t.Errorf("ожидался код 2: %v", err)
		}
	})
	t.Run("prev не проверяется", func(t *testing.T) {
		h := newHarness(t)
		b1, _ := h.genesis()
		raw, _ := os.ReadFile(b1)
		bad := filepath.Join(h.dir, "bad.json")
		os.WriteFile(bad, bytes.Replace(raw, []byte(`"sequence":1`), []byte(`"sequence":9`), 1), 0o644)
		m2, h2 := h.squash(map[string]string{"deploy/y.txt": "y"})
		h.routePR(2, m2, h2, "bob", "carol")
		if _, _, err := h.plan(m2, "-prev", bad); code(err) != 1 {
			t.Errorf("подделанный prev: %v", err)
		}
	})
}

func TestSignWrongKey(t *testing.T) {
	h := newHarness(t)
	merge, head := h.squash(map[string]string{"deploy/g.txt": "g"})
	h.routePR(1, merge, head, "alice", "carol")
	if text, _, err := h.plan(merge, "-genesis"); err != nil {
		t.Fatalf("%v %s", err, text)
	}
	// Ключ, которого нет в keys.json.
	bundletest.Key(t, h.dir, "rogue")
	out := filepath.Join(h.dir, "rogue.json")
	text, err := h.run("bundle", "sign", "-in", filepath.Join(h.dir, "unsigned.json"), "-key-file", filepath.Join(h.dir, "rogue.key"),
		"-issuer", bundletest.Issuer, "-keys", h.keys, "-out", out)
	if code(err) != 1 {
		t.Errorf("подпись чужим ключом: %v %s", err, text)
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("при отказе подписанный файл писать нельзя")
	}
	if code(func() error {
		_, e := h.sign(filepath.Join(h.dir, "unsigned.json"), filepath.Join(h.dir, "ok.json"))
		return e
	}()) != 0 {
		t.Error("подпись правильным ключом должна проходить")
	}
}

func TestVerifyForeignContent(t *testing.T) {
	h := newHarness(t)
	_, spec := bundletest.Key(t, h.dir, "x")
	_ = spec
	s := bundletest.Signer(t, h.dir, "ci")
	m := bundletest.Manifest(t)
	m.Files = append([]bundle.File(nil), m.Files...)
	m.Files[0].SHA256 = strings.Repeat("0", 64)
	signed, err := bundle.Sign(m, s, bundletest.Issuer)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(h.dir, "foreign.json")
	os.WriteFile(p, bundle.Marshal(signed), 0o644)
	text, err := h.run("bundle", "verify", "-in", p, "-keys", h.keys)
	if code(err) != 1 || !strings.Contains(err.Error(), "mismatch") {
		t.Errorf("%v %s", err, text)
	}
	// Правильное содержимое проходит, неверный -commit — отказ.
	good, _ := bundle.Sign(bundletest.Manifest(t), s, bundletest.Issuer)
	os.WriteFile(p, bundle.Marshal(good), 0o644)
	if _, err := h.run("bundle", "verify", "-in", p, "-keys", h.keys); err != nil {
		t.Errorf("валидный bundle: %v", err)
	}
	if _, err := h.run("bundle", "verify", "-in", p, "-keys", h.keys, "-commit", strings.Repeat("9", 40)); code(err) != 1 {
		t.Errorf("чужой -commit: %v", err)
	}
}

func TestFindPR(t *testing.T) {
	h := newHarness(t)
	sha := strings.Repeat("a", 40)
	h.routes["/repos/o/r/commits/"+sha+"/pulls"] = "[" + pullJSON(5, "zed", "h", sha) + "," + pullJSON(6, "zed", "g", "") + "]"
	out, err := h.run("bundle", "find-pr", "-repo", "o/r", "-sha", sha, "-api-url", h.srv.URL)
	if err != nil || strings.TrimSpace(out) != "5" {
		t.Errorf("%v %q", err, out)
	}
	h.routes["/repos/o/r/commits/"+sha+"/pulls"] = "[" + pullJSON(5, "zed", "h", sha) + "," + pullJSON(7, "zed", "h", sha) + "]"
	if _, err := h.run("bundle", "find-pr", "-repo", "o/r", "-sha", sha, "-api-url", h.srv.URL); code(err) != 1 {
		t.Errorf("два PR с одним merge-коммитом: %v", err)
	}
}

func TestFourEyesCommand(t *testing.T) {
	h := newHarness(t)
	base := gitIn(t, h.repo, "rev-parse", "HEAD")
	head := strings.Repeat("e", 40)
	rev := func(approvers ...string) string {
		var rv []string
		for i, a := range approvers {
			rv = append(rv, reviewJSON(i+1, a, "APPROVED", head))
		}
		return "[" + strings.Join(rv, ",") + "]"
	}
	h.routes["/repos/o/r/pulls/4"] = pullJSON(4, "zed", head, "")
	h.routes["/repos/o/r/pulls/4/files"] = `[{"filename":"policy/aegis/pep/decision.rego"}]`
	h.routes["/repos/o/r/pulls/4/commits"] = `[{"author":{"login":"zed"},"committer":{"login":"zed"}}]`
	h.routes["/repos/o/r/pulls/4/reviews"] = rev("alice")
	args := []string{"foureyes", "-repo", "o/r", "-pr", "4", "-rules-rev", base, "-git-dir", h.repo, "-api-url", h.srv.URL}
	out, err := h.run(args...)
	if code(err) != 1 || !strings.Contains(out, "Отказ") {
		t.Errorf("одно одобрение: %v %s", err, out)
	}
	h.routes["/repos/o/r/pulls/4/reviews"] = rev("alice", "carol")
	if out, err := h.run(args...); err != nil || !strings.Contains(out, "alice (owners)") {
		t.Errorf("два одобрения: %v %s", err, out)
	}
	h.routes["/repos/o/r/pulls/4/files"] = `[{"filename":"README.md"}]`
	h.routes["/repos/o/r/pulls/4/reviews"] = `[]`
	if out, err := h.run(args...); err != nil || !strings.Contains(out, "не затронуты") {
		t.Errorf("нет защищённых путей: %v %s", err, out)
	}
	if _, err := h.run("foureyes", "-repo", "o/r"); code(err) != 2 {
		t.Errorf("аргументы: %v", err)
	}
}

func TestUsageErrors(t *testing.T) {
	h := newHarness(t)
	for _, a := range [][]string{{}, {"nope"}, {"bundle"}, {"bundle", "nope"}, {"sbom"}, {"bundle", "sign"}, {"bundle", "verify"}, {"bundle", "keygen"}} {
		if _, err := h.run(a...); code(err) != 2 {
			t.Errorf("%v: код %d", a, code(err))
		}
	}
}

func TestKeygenAndSBOM(t *testing.T) {
	h := newHarness(t)
	priv, pub := filepath.Join(h.dir, "n.key"), filepath.Join(h.dir, "n.pub")
	if _, err := h.run("bundle", "keygen", "-priv", priv, "-pub", pub); err != nil {
		t.Fatal(err)
	}
	if _, err := h.run("bundle", "keygen", "-priv", priv, "-pub", pub); code(err) != 2 {
		t.Error("существующий ключ не перезаписывается")
	}
	// SBOM тестового бинаря (в нём есть gopkg.in/yaml.v3: он импортируется тестами workflow).
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(h.dir, "x.cdx.json")
	if _, err := h.run("sbom", "-bin", exe, "-name", "ci.test", "-out", out); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(out)
	if !strings.Contains(string(b), `"pkg:golang/gopkg.in/yaml.v3@`) || !strings.Contains(string(b), `"specVersion": "1.5"`) {
		t.Errorf("SBOM: %.300s", b)
	}
	if _, err := h.run("sbom", "-bin", priv, "-name", "x", "-out", out); code(err) != 1 {
		t.Error("не-ELF должен быть отказом")
	}
}

// Проверяющий из B0 сверяет bundle с деревом проверяемого коммита (-tree), а не со своим встроенным содержимым.
func TestSignVerifyWithTree(t *testing.T) {
	h := newHarness(t)
	merge, head := h.squash(map[string]string{"deploy/g.txt": "g"})
	h.routePR(1, merge, head, "alice", "carol")
	if text, _, err := h.plan(merge, "-genesis"); err != nil {
		t.Fatalf("%v %s", err, text)
	}
	unsigned := filepath.Join(h.dir, "unsigned.json")
	keyFile := filepath.Join(h.dir, "ci.key")
	signArgs := func(tree, out string) []string {
		return []string{"bundle", "sign", "-in", unsigned, "-key-file", keyFile, "-issuer", bundletest.Issuer, "-keys", h.keys, "-tree", tree, "-out", out}
	}
	// Дерево с изменённым файлом политики: подпись отказывает (mismatch), файл не пишется.
	other := filepath.Join(h.dir, "other-tree")
	os.MkdirAll(other, 0o755)
	for _, d := range []string{"policy", "catalog", "eval"} {
		if out, err := exec.Command("cp", "-r", filepath.Join(h.repo, d), other).CombinedOutput(); err != nil {
			t.Fatalf("%v %s", err, out)
		}
	}
	bad := filepath.Join(h.dir, "bad.json")
	files, _ := filepath.Glob(filepath.Join(other, "policy/aegis/*/*.rego"))
	os.WriteFile(files[0], []byte("package changed\n"), 0o644)
	if _, err := h.run(signArgs(other, bad)...); code(err) != 1 || !strings.Contains(err.Error(), "mismatch") {
		t.Errorf("подпись при другом дереве: %v", err)
	}
	if _, err := os.Stat(bad); err == nil {
		t.Error("при отказе файл писать нельзя")
	}
	ok := filepath.Join(h.dir, "ok.json")
	if _, err := h.run(signArgs(h.repo, ok)...); err != nil {
		t.Fatalf("подпись по дереву S: %v", err)
	}
	if _, err := h.run("bundle", "verify", "-in", ok, "-keys", h.keys, "-tree", h.repo); err != nil {
		t.Errorf("verify -tree: %v", err)
	}
	if _, err := h.run("bundle", "verify", "-in", ok, "-keys", h.keys, "-tree", other); code(err) != 1 {
		t.Errorf("verify -tree чужого дерева: %v", err)
	}
	if _, err := h.run("bundle", "verify", "-in", ok, "-keys", h.keys, "-tree", filepath.Join(h.dir, "absent")); code(err) != 1 {
		t.Errorf("verify -tree несуществующего каталога: %v", err)
	}
}

// Предыдущий bundle проверяется ключами из B0 (-prev-keys), новый — ключами из проверяемого коммита (-keys).
func TestPlanPrevKeysFromB0(t *testing.T) {
	h := newHarness(t)
	b1, _ := h.genesis()
	m2, h2 := h.squash(map[string]string{"deploy/y.txt": "y"})
	h.routePR(2, m2, h2, "bob", "carol")
	// «Ключи из S» — другой ключ (подмена keys.json в S): prev им проверить нельзя.
	_, spec := bundletest.Key(t, h.dir, "rotated")
	spec.Path = "rotated.pub"
	b, _ := json.Marshal([]bundle.KeySpec{spec})
	sKeys := filepath.Join(h.dir, "keys-s.json")
	os.WriteFile(sKeys, b, 0o644)
	oldKeys := h.keys
	h.keys = sKeys
	if _, _, err := h.plan(m2, "-prev", b1); code(err) != 1 {
		t.Errorf("без -prev-keys prev проверяется ключами из S: %v", err)
	}
	text, outs, err := h.plan(m2, "-prev", b1, "-prev-keys", oldKeys)
	if err != nil || !strings.Contains(outs, "sequence=2") {
		t.Fatalf("с -prev-keys из B0: %v\n%s\n%s", err, text, outs)
	}
	if _, _, err := h.plan(m2, "-genesis", "-prev-keys", oldKeys); code(err) != 2 {
		t.Errorf("-prev-keys с -genesis: %v", err)
	}
}
