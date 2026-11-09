package foureyes

import (
	"os"
	"strings"
	"testing"
)

const baseRules = `{"schema":"aegisops/four-eyes/v1","min_approvals":2,"min_groups":2,
 "groups":{"owners":["alice","bob"],"sre":["carol","dave"],"sec":["erin"]},
 "excluded":["dependabot[bot]"],
 "protected":[{"path":"policy/","groups":["owners","sre","sec"],"require":[]},
              {"path":"data/profiles.json","groups":["owners","sec"],"require":["sec"]},
              {"path":".github/","groups":["owners","sre"],"require":[]}]}`

func mustRules(t *testing.T) Rules {
	t.Helper()
	r, err := Load([]byte(baseRules))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestLoadRealFile(t *testing.T) {
	b, err := os.ReadFile("../../.github/four-eyes.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Load(b); err != nil {
		t.Fatal(err)
	}
}

func TestLoadErrors(t *testing.T) {
	sub := func(old, new string) string { return strings.Replace(baseRules, old, new, 1) }
	for name, doc := range map[string]string{
		"пересечение каталога и файла": sub(`"data/profiles.json"`, `"policy/x.rego"`),
		"тот же путь":             sub(`"data/profiles.json"`, `"policy/"`),
		"вложенные каталоги":      sub(`".github/"`, `"policy/sub/"`),
		"неизвестная группа":      sub(`"groups":["owners","sec"]`, `"groups":["owners","nope"]`),
		"пустая группа":           sub(`"sec":["erin"]`, `"sec":[]`),
		"glob":                    sub(`"data/profiles.json"`, `"data/*.json"`),
		"абсолютный путь":         sub(`"data/profiles.json"`, `"/data/profiles.json"`),
		"точки":                   sub(`"data/profiles.json"`, `"data/../profiles.json"`),
		"require вне groups":      sub(`"require":["sec"]`, `"require":["sre"]`),
		"схема":                   sub(`aegisops/four-eyes/v1`, `x`),
		"min_approvals 1":         sub(`"min_approvals":2`, `"min_approvals":1`),
		"min_groups больше групп": sub(`"min_groups":2`, `"min_groups":4`),
		"лишнее поле":             sub(`"excluded"`, `"x":1,"excluded"`),
		"повтор логина в группе":  sub(`["alice","bob"]`, `["alice","ALICE"]`),
		"плохой логин":            sub(`"erin"`, `"er in"`),
		"нет правил":              `{"schema":"aegisops/four-eyes/v1","min_approvals":2,"min_groups":2,"groups":{"a":["x"],"b":["y"]},"excluded":[],"protected":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Load([]byte(doc)); err == nil {
				t.Error("ожидалась ошибка")
			}
		})
	}
}

// Один человек может входить в несколько групп (пока в группах только один логин).
func TestLoadAllowsSameLoginInGroups(t *testing.T) {
	doc := `{"schema":"aegisops/four-eyes/v1","min_approvals":2,"min_groups":2,"groups":{"a":["x"],"b":["x"]},"excluded":[],
	"protected":[{"path":"p/","groups":["a","b"],"require":[]}]}`
	if _, err := Load([]byte(doc)); err != nil {
		t.Fatal(err)
	}
}

func TestMatchAndTouched(t *testing.T) {
	r := mustRules(t)
	for path, want := range map[string]string{"policy/a/b.rego": "policy/", "data/profiles.json": "data/profiles.json",
		".github/CODEOWNERS": ".github/", "data/profiles.json.bak": "", "policyx/a": "", "README.md": ""} {
		got, ok := r.Match(path)
		if (want == "") == ok || got.Path != want {
			t.Errorf("Match(%q) = %q, %v; ожидалось %q", path, got.Path, ok, want)
		}
	}
	touched := r.Touched([]string{"policy/a", "policy/b", "README.md", ".github/x"})
	if len(touched) != 2 || touched[0].Path != "policy/" || touched[1].Path != ".github/" {
		t.Errorf("Touched = %+v", touched)
	}
	if len(r.Touched([]string{"README.md"})) != 0 {
		t.Error("незащищённый путь затронул правило")
	}
}
