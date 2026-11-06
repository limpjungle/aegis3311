package policyengine_test

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/tester"

	"github.com/limpjungle/aegis3311/internal/catalog"
	"github.com/limpjungle/aegis3311/internal/policyengine"
	"github.com/limpjungle/aegis3311/policy"
)

func TestRegoPolicies(t *testing.T) {
	rs, err := tester.Run(context.Background(), "../../policy")
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) == 0 {
		t.Fatal("Rego-тесты не найдены")
	}
	for _, r := range rs {
		if !r.Pass() {
			t.Errorf("%s.%s: fail=%v skip=%v err=%v", r.Package, r.Name, r.Fail, r.Skip, r.Error)
		}
	}
	t.Logf("Rego-тестов: %d", len(rs))
}

func TestStrictCompile(t *testing.T) {
	ctx := context.Background()
	if _, err := policyengine.Load(ctx, policy.FS); err != nil {
		t.Fatalf("встроенные политики: %v", err)
	}
	bad := fstest.MapFS{"bad.rego": {Data: []byte("package aegis.pep\n\ndecision := 1 if {\n\tunused := 2\n\ttrue\n}\n")}}
	if _, err := policyengine.Load(ctx, bad); err == nil {
		t.Fatal("strict-компиляция пропустила неиспользуемую переменную")
	}
	if _, err := policyengine.Load(ctx, fstest.MapFS{}); err == nil {
		t.Fatal("пустой набор политик должен быть ошибкой")
	}
}

func TestEvalAlwaysDefined(t *testing.T) {
	e, err := policyengine.Load(context.Background(), policy.FS)
	if err != nil {
		t.Fatal(err)
	}
	for name, in := range map[string]any{
		"пустой вход":         map[string]any{},
		"неизвестный уровень": map[string]any{"level": map[string]any{"granted": "L9"}},
		"неизвестная среда":   map[string]any{"target": map[string]any{"environment": "dev"}},
	} {
		d, err := e.Eval(context.Background(), in)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if len(d.Deny) == 0 || d.EffectiveLevel != "L0" {
			t.Errorf("%s: %+v", name, d)
		}
	}
}

// Вход не-объект — ошибка (strict builtin errors), а не решение: PEP превратит её в deny/policy_error.
func TestEvalNonObjectInputIsError(t *testing.T) {
	e, err := policyengine.Load(context.Background(), policy.FS)
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range []any{nil, "x", 1} {
		if d, err := e.Eval(context.Background(), in); err == nil {
			t.Errorf("вход %v: ожидалась ошибка, получено %+v", in, d)
		}
	}
}

func TestDigestExcludesTests(t *testing.T) {
	src := func(extra string) fstest.MapFS {
		return fstest.MapFS{
			"a/p.rego":      {Data: []byte("package aegis.pep\n\ndecision := {\"ceiling\": \"L0\", \"effective_level\": \"L0\", \"deny\": [], \"caps\": [], \"policy_revision\": \"x\"}\n")},
			"a/p_test.rego": {Data: []byte("package aegis.pep_test\n\n" + extra)},
		}
	}
	ctx := context.Background()
	a, err := policyengine.Load(ctx, src("test_a if true\n"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := policyengine.Load(ctx, src("test_b if false\n"))
	if a.Digest() != b.Digest() || !strings.HasPrefix(a.Digest(), "sha256:") {
		t.Errorf("digest зависит от тестов: %s vs %s", a.Digest(), b.Digest())
	}
	changed := src("")
	changed["a/p.rego"] = &fstest.MapFile{Data: append(changed["a/p.rego"].Data, '\n')}
	c, _ := policyengine.Load(ctx, changed)
	if c.Digest() == a.Digest() {
		t.Error("digest не изменился от правки политики")
	}
}

// matrixRow соответствует строке таблицы §4.4 architecture.md.
type matrixRow struct{ action, row string }

func TestMatrixMatchesArchitectureDoc(t *testing.T) {
	b, err := os.ReadFile("../../docs/00-overview/architecture.md")
	if err != nil {
		t.Fatal(err)
	}
	// Соответствие строк таблицы и действий каталога задано здесь явно.
	rows := map[string]string{
		"Rollback canary по статистическому гейту": "rollout.abort_and_rollback",
		"Scale out stateless в пределах min/max":   "workload.scale_out",
		"Scale in": "workload.scale_in",
		"Рестарт пода или Deployment (stateless)":                          "workload.restart",
		"Размер пула PgBouncer (reload) в границах":                        "pgbouncer.resize_pool",
		"Параметры СУБД с рестартом (`max_connections`, `shared_buffers`)": "postgres.set_restart_param",
	}
	type cell struct{ Max, MaxByData string }
	doc := map[string][3]cell{}
	lvl := regexp.MustCompile(`^L[0-3]$`)
	byData := regexp.MustCompile(`^(L[0-3]), по данным (L[0-3])$`)
	inTable := false
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "### 4.4") {
			inTable = true
			continue
		}
		if inTable && strings.HasPrefix(line, "### ") {
			break
		}
		if !inTable || !strings.HasPrefix(line, "|") {
			continue
		}
		parts := strings.Split(strings.Trim(line, "| "), "|")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		action, ok := rows[parts[0]]
		if !ok {
			continue
		}
		var cells [3]cell
		for i, txt := range parts[2:5] {
			switch {
			case lvl.MatchString(txt):
				cells[i] = cell{Max: txt}
			case byData.MatchString(txt):
				m := byData.FindStringSubmatch(txt)
				cells[i] = cell{Max: m[1], MaxByData: m[2]}
			default:
				t.Fatalf("строка %q: не разобрана ячейка %q", parts[0], txt)
			}
		}
		doc[action] = cells
	}
	if len(doc) != len(rows) {
		t.Fatalf("в таблице §4.4 найдено %d из %d строк", len(doc), len(rows))
	}

	// Матрица из политики отдельным запросом.
	rs, err := rego.New(rego.Query("data.aegis.autonomy.matrix"), rego.Load([]string{"../../policy"}, func(abspath string, _ os.FileInfo, _ int) bool {
		return strings.HasSuffix(abspath, "_test.rego")
	})).Eval(context.Background())
	if err != nil || len(rs) != 1 {
		t.Fatalf("запрос матрицы: %v %v", err, rs)
	}
	raw, _ := json.Marshal(rs[0].Expressions[0].Value)
	var matrix map[string]map[string]map[string]string
	if err := json.Unmarshal(raw, &matrix); err != nil {
		t.Fatal(err)
	}
	if len(matrix) != len(doc) {
		t.Errorf("в политике %d действий, в документе %d", len(matrix), len(doc))
	}
	envs := [3]string{"staging", "prod-cloud-hybrid", "prod-baremetal"}
	for action, cells := range doc {
		for i, env := range envs {
			got := matrix[action][env]
			want := map[string]string{"max": cells[i].Max}
			if cells[i].MaxByData != "" {
				want["max_by_data"] = cells[i].MaxByData
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("%s/%s: политика %v, документ %v", action, env, got, want)
			}
		}
	}
}

func TestForbiddenPatternsSync(t *testing.T) {
	rs, err := rego.New(rego.Query("data.aegis.autonomy.forbidden_patterns"), rego.Load([]string{"../../policy"}, func(p string, _ os.FileInfo, _ int) bool {
		return strings.HasSuffix(p, "_test.rego")
	})).Eval(context.Background())
	if err != nil || len(rs) != 1 {
		t.Fatalf("%v %v", err, rs)
	}
	raw, _ := json.Marshal(rs[0].Expressions[0].Value)
	var got []string
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	want := append([]string(nil), catalog.ForbiddenPatterns...)
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Rego %v, Go %v", got, want)
	}
}
