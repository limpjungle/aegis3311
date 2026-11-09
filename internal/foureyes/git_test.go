package foureyes

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func gitRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git не найден")
	}
	dir := t.TempDir()
	for _, a := range [][]string{{"init", "-q", "-b", "main"}, {"config", "user.email", "t@example.com"}, {"config", "user.name", "t"},
		{"config", "commit.gpgsign", "false"}} {
		gitRun(t, dir, a...)
	}
	return dir
}

func gitRun(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func commitFiles(t *testing.T, dir string, files map[string]string) string {
	t.Helper()
	for p, c := range files {
		full := filepath.Join(dir, p)
		if c == "\x00delete" {
			os.Remove(full)
			continue
		}
		os.MkdirAll(filepath.Dir(full), 0o755)
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "c", "--allow-empty")
	return gitRun(t, dir, "rev-parse", "HEAD")
}

func TestChangedProtected(t *testing.T) {
	dir := gitRepo(t)
	r := mustRules(t)
	a := commitFiles(t, dir, map[string]string{"policy/a.rego": "1", "policy/sub/b.rego": "1", "README.md": "1", "data/profiles.json": "1"})
	b := commitFiles(t, dir, map[string]string{"README.md": "2"})
	c := commitFiles(t, dir, map[string]string{"policy/a.rego": "2", "policy/new.rego": "x", "policy/sub/b.rego": "\x00delete", ".github/CODEOWNERS": "x"})
	if got, err := ChangedProtected(dir, a, b, r); err != nil || len(got) != 0 {
		t.Errorf("a..b: %v %v", got, err)
	}
	got, err := ChangedProtected(dir, a, c, r)
	want := []string{".github/CODEOWNERS", "policy/a.rego", "policy/new.rego", "policy/sub/b.rego"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("a..c: %v %v", got, err)
	}
	// Симметрично и через родителя.
	if got, _ := ChangedProtected(dir, c+"^", c, r); !reflect.DeepEqual(got, want) {
		t.Errorf("c^..c: %v", got)
	}
	tree, err := ProtectedTree(dir, a, r)
	if err != nil || len(tree) != 3 || tree["README.md"] != "" {
		t.Errorf("tree: %v %v", tree, err)
	}
	if _, err := ChangedProtected(dir, a, "--output=x", r); err == nil {
		t.Error("ревизия, похожая на опцию, должна быть отказом")
	}
	if _, err := ChangedProtected(dir, a, strings.Repeat("0", 40), r); err == nil {
		t.Error("несуществующая ревизия должна быть ошибкой")
	}
	body, err := Show(dir, a, "policy/a.rego")
	if err != nil || string(body) != "1" {
		t.Errorf("show: %q %v", body, err)
	}
	if sha, err := RevParse(dir, "HEAD"); err != nil || sha != c {
		t.Errorf("rev-parse: %s %v", sha, err)
	}
}

// Смена режима файла — изменение защищённого пути.
func TestChangedProtectedMode(t *testing.T) {
	dir := gitRepo(t)
	r := mustRules(t)
	a := commitFiles(t, dir, map[string]string{"policy/a.rego": "1"})
	if err := os.Chmod(filepath.Join(dir, "policy/a.rego"), 0o755); err != nil {
		t.Fatal(err)
	}
	b := commitFiles(t, dir, nil)
	if got, _ := ChangedProtected(dir, a, b, r); len(got) != 1 {
		t.Errorf("смена режима не замечена: %v", got)
	}
}
