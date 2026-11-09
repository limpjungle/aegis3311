package main

import (
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/limpjungle/aegis3311/internal/foureyes"
)

// CODEOWNERS совпадает с protected из .github/four-eyes.json: тот же набор путей и владельцы — объединение групп правила.
func TestCodeownersMatchesFourEyes(t *testing.T) {
	raw, err := os.ReadFile("../../.github/four-eyes.json")
	if err != nil {
		t.Fatal(err)
	}
	rules, err := foureyes.Load(raw)
	if err != nil {
		t.Fatal(err)
	}
	co, err := os.ReadFile("../../.github/CODEOWNERS")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, line := range strings.Split(string(co), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 || !strings.HasPrefix(f[0], "/") {
			t.Fatalf("строка CODEOWNERS %q: ожидается «/путь @владелец...»", line)
		}
		var owners []string
		for _, o := range f[1:] {
			if !strings.HasPrefix(o, "@") || strings.Contains(o, "/") {
				t.Fatalf("строка %q: владельцы — только логины @user (команд у личного репозитория нет)", line)
			}
			owners = append(owners, strings.ToLower(strings.TrimPrefix(o, "@")))
		}
		sort.Strings(owners)
		if _, dup := got[f[0][1:]]; dup {
			t.Errorf("путь %s повторяется в CODEOWNERS", f[0])
		}
		got[f[0][1:]] = owners
	}
	if len(got) != len(rules.Protected) {
		t.Errorf("в CODEOWNERS %d путей, в four-eyes.json %d", len(got), len(rules.Protected))
	}
	for _, p := range rules.Protected {
		var want []string
		for _, m := range rules.Members(p.Groups) {
			want = append(want, strings.ToLower(m))
		}
		sort.Strings(want)
		have, ok := got[p.Path]
		switch {
		case !ok:
			t.Errorf("путь %s из four-eyes.json отсутствует в CODEOWNERS", p.Path)
		case strings.Join(have, " ") != strings.Join(want, " "):
			t.Errorf("владельцы %s: CODEOWNERS %v, группы %v", p.Path, have, want)
		}
		if _, err := os.Stat("../../" + strings.TrimSuffix(p.Path, "/")); err != nil {
			t.Errorf("защищённый путь %s не существует", p.Path)
		}
	}
	for _, must := range []string{".github/", "cmd/aegis-ci/", "internal/bundle/", "internal/foureyes/", "deploy/policy-bundle/"} {
		if _, ok := rules.Match(must); !ok {
			t.Errorf("путь %s должен быть защищён", must)
		}
	}
}
