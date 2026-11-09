package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Инварианты workflow'ов репозитория (docs/07-governance/ci-four-eyes.md): закрепление actions по SHA, минимальные права,
// секреты только там, где им место. Тест читает реальные файлы .github/workflows.

const wfDir = "../../.github/workflows"

var (
	usesRe    = regexp.MustCompile(`^[\w.-]+/[\w./-]+@[0-9a-f]{40}$`)
	versionRe = regexp.MustCompile(`^# v\d+(\.\d+)*\S*$`)
)

type workflow struct {
	name string
	root *yaml.Node // mapping
}

func key(m *yaml.Node, k string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == k {
			return m.Content[i+1]
		}
	}
	return nil
}

func loadWorkflows(t *testing.T) []workflow {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(wfDir, "*.yml"))
	if err != nil || len(files) < 4 {
		t.Fatalf("workflow'ы не найдены: %v %v", files, err)
	}
	var out []workflow
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var doc yaml.Node
		if err := yaml.Unmarshal(b, &doc); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		out = append(out, workflow{name: filepath.Base(f), root: doc.Content[0]})
	}
	return out
}

// jobs — пары (id, mapping job'а).
func (w workflow) jobs() map[string]*yaml.Node {
	out := map[string]*yaml.Node{}
	jn := key(w.root, "jobs")
	for i := 0; jn != nil && i+1 < len(jn.Content); i += 2 {
		out[jn.Content[i].Value] = jn.Content[i+1]
	}
	return out
}

func (w workflow) triggers() []string {
	on := key(w.root, "on")
	var out []string
	if on == nil {
		return nil
	}
	if on.Kind == yaml.MappingNode {
		for i := 0; i < len(on.Content); i += 2 {
			out = append(out, on.Content[i].Value)
		}
	} else if on.Kind == yaml.SequenceNode {
		for _, c := range on.Content {
			out = append(out, c.Value)
		}
	} else {
		out = append(out, on.Value)
	}
	return out
}

func steps(job *yaml.Node) []*yaml.Node {
	if s := key(job, "steps"); s != nil {
		return s.Content
	}
	return nil
}

// scalars обходит узел и вызывает f для каждого скаляра-значения.
func scalars(n *yaml.Node, f func(*yaml.Node)) {
	if n == nil {
		return
	}
	if n.Kind == yaml.ScalarNode {
		f(n)
		return
	}
	for _, c := range n.Content {
		scalars(c, f)
	}
}

func TestWorkflowUsesPinned(t *testing.T) {
	for _, w := range loadWorkflows(t) {
		for id, job := range w.jobs() {
			if u := key(job, "uses"); u != nil {
				t.Errorf("%s/%s: вызов reusable workflow (uses на уровне job) не допускается", w.name, id)
			}
			for _, s := range steps(job) {
				u := key(s, "uses")
				if u == nil {
					continue
				}
				switch {
				case strings.HasPrefix(u.Value, "docker://") || strings.HasPrefix(u.Value, "./") || strings.HasPrefix(u.Value, "."):
					t.Errorf("%s/%s: uses %q: docker:// и локальные actions запрещены", w.name, id, u.Value)
				case !usesRe.MatchString(u.Value):
					t.Errorf("%s/%s: uses %q не закреплён по 40-hex SHA", w.name, id, u.Value)
				case !versionRe.MatchString(u.LineComment):
					t.Errorf("%s/%s: у uses %q нет комментария версии «# vX.Y.Z» (есть %q)", w.name, id, u.Value, u.LineComment)
				}
			}
		}
	}
}

func TestWorkflowTriggersAndPermissions(t *testing.T) {
	writeAllowed := map[string]bool{"policy-bundle.yml/sign": true, "release.yml/publish": true}
	for _, w := range loadWorkflows(t) {
		for _, tr := range w.triggers() {
			if tr == "pull_request_target" {
				t.Errorf("%s: pull_request_target запрещён", w.name)
			}
		}
		top := key(w.root, "permissions")
		if top == nil {
			t.Errorf("%s: нет permissions верхнего уровня", w.name)
		}
		for id, job := range w.jobs() {
			if key(job, "timeout-minutes") == nil {
				t.Errorf("%s/%s: нет timeout-minutes", w.name, id)
			}
			eff := key(job, "permissions")
			if eff == nil {
				eff = top
				if eff == nil || len(eff.Content) == 0 {
					t.Errorf("%s/%s: нет явных permissions", w.name, id)
				}
			}
			var writes []string
			if eff != nil && eff.Kind == yaml.MappingNode {
				for i := 0; i+1 < len(eff.Content); i += 2 {
					if eff.Content[i+1].Value == "write" {
						writes = append(writes, eff.Content[i].Value)
					}
				}
			} else if eff != nil && eff.Kind == yaml.ScalarNode && strings.Contains(eff.Value, "write") {
				writes = append(writes, eff.Value)
			}
			if len(writes) > 0 && !writeAllowed[w.name+"/"+id] {
				t.Errorf("%s/%s: права на запись %v не допускаются", w.name, id, writes)
			}
		}
		// Права верхнего уровня не дают записи ни в одном workflow.
		if top != nil && top.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(top.Content); i += 2 {
				if top.Content[i+1].Value == "write" {
					t.Errorf("%s: запись на верхнем уровне permissions: %s", w.name, top.Content[i].Value)
				}
			}
		}
	}
	// Записывающие job'ы существуют и ограничены environment'ом.
	for _, want := range []struct{ wf, job string }{{"policy-bundle.yml", "sign"}, {"release.yml", "publish"}} {
		found := false
		for _, w := range loadWorkflows(t) {
			if w.name == want.wf {
				j := w.jobs()[want.job]
				found = j != nil && key(j, "environment") != nil
			}
		}
		if !found {
			t.Errorf("%s/%s: нет job'а или у него нет environment", want.wf, want.job)
		}
	}
}

func TestWorkflowSecrets(t *testing.T) {
	for _, w := range loadWorkflows(t) {
		pr := false
		for _, tr := range w.triggers() {
			if strings.HasPrefix(tr, "pull_request") {
				pr = true
			}
		}
		// Секреты вне job'ов (верхнеуровневый env и т. п.) запрещены.
		for k, v := range map[string]*yaml.Node{"env": key(w.root, "env"), "concurrency": key(w.root, "concurrency")} {
			scalars(v, func(n *yaml.Node) {
				if strings.Contains(n.Value, "secrets.") {
					t.Errorf("%s: секрет на верхнем уровне (%s)", w.name, k)
				}
			})
		}
		for id, job := range w.jobs() {
			hasEnv := key(job, "environment") != nil
			scalars(job, func(n *yaml.Node) {
				if !strings.Contains(n.Value, "secrets.") {
					return
				}
				if !hasEnv || pr {
					t.Errorf("%s/%s: secrets. допустимы только в job'е с environment и в workflow без pull_request*", w.name, id)
				}
				if strings.Contains(n.Value, "secrets.POLICY_BUNDLE_SIGNING_KEY") && w.name+"/"+id != "policy-bundle.yml/sign" {
					t.Errorf("%s/%s: ключ подписи bundle только в policy-bundle.yml/sign", w.name, id)
				}
			})
		}
	}
}

func TestWorkflowStepsHygiene(t *testing.T) {
	forbidden := []string{"${{ github.event", "github.head_ref", "${{ secrets", "${{github.event", "${{secrets"}
	for _, w := range loadWorkflows(t) {
		for id, job := range w.jobs() {
			for _, s := range steps(job) {
				if r := key(s, "run"); r != nil {
					for _, f := range forbidden {
						if strings.Contains(r.Value, f) {
							t.Errorf("%s/%s: в run: найдено %q (значение передавать через env:)", w.name, id, f)
						}
					}
				}
				u := key(s, "uses")
				if u == nil {
					continue
				}
				with := key(s, "with")
				val := func(k string) string {
					if n := key(with, k); n != nil {
						return n.Value
					}
					return ""
				}
				switch {
				case strings.HasPrefix(u.Value, "actions/checkout@"):
					if val("persist-credentials") != "false" {
						t.Errorf("%s/%s: у checkout нет persist-credentials: false", w.name, id)
					}
				case strings.HasPrefix(u.Value, "actions/setup-go@"):
					if val("go-version-file") != "go.mod" {
						t.Errorf("%s/%s: setup-go без go-version-file: go.mod", w.name, id)
					}
					if (w.name == "policy-bundle.yml" || w.name == "release.yml") && val("cache") != "false" {
						t.Errorf("%s/%s: в подписи и релизе setup-go должен быть с cache: false", w.name, id)
					}
				}
			}
		}
		if w.name == "policy-bundle.yml" {
			c := key(w.root, "concurrency")
			if n := key(c, "cancel-in-progress"); n == nil || n.Value != "false" {
				t.Error("policy-bundle.yml: concurrency.cancel-in-progress должен быть false")
			}
		}
	}
}

// Имена job'ов ci.yml и four-eyes.yml покрывают контексты required_status_checks из ruleset'а main.
func TestRulesetContextsExist(t *testing.T) {
	b, err := os.ReadFile("../../docs/07-governance/rulesets/main.json")
	if err != nil {
		t.Fatal(err)
	}
	var rs struct {
		Rules []struct {
			Type       string `json:"type"`
			Parameters struct {
				Checks []struct {
					Context string `json:"context"`
				} `json:"required_status_checks"`
			} `json:"parameters"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(b, &rs); err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, w := range loadWorkflows(t) {
		if w.name != "ci.yml" && w.name != "four-eyes.yml" {
			continue
		}
		for id, job := range w.jobs() {
			if n := key(job, "name"); n != nil {
				have[n.Value] = true
			} else {
				have[id] = true
			}
		}
	}
	var n int
	for _, r := range rs.Rules {
		if r.Type != "required_status_checks" {
			continue
		}
		for _, c := range r.Parameters.Checks {
			n++
			if !have[c.Context] {
				t.Errorf("контекст %q из ruleset'а не соответствует ни одному job'у ci.yml и four-eyes.yml", c.Context)
			}
		}
	}
	if n != 4 {
		t.Errorf("в ruleset'е %d обязательных проверок, ожидалось 4 (go, race, eval, four-eyes)", n)
	}
}
