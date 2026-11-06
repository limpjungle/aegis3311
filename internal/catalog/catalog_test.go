package catalog_test

import (
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"testing/fstest"

	catalogdata "github.com/limpjungle/aegis3311/catalog"
	. "github.com/limpjungle/aegis3311/internal/catalog"
	"github.com/limpjungle/aegis3311/internal/step"
)

func TestEmbeddedCatalog(t *testing.T) {
	c := MustLoadEmbedded()
	want := []struct {
		name string
		rev  Reversibility
	}{
		{"pgbouncer.resize_pool", R2}, {"postgres.set_restart_param", R3}, {"rollout.abort_and_rollback", R1},
		{"workload.restart", R2}, {"workload.scale_in", R2}, {"workload.scale_out", R1},
	}
	if got := c.Names(); len(got) != len(want) {
		t.Fatalf("записей %d, ожидалось %d: %v", len(got), len(want), got)
	}
	for _, w := range want {
		e, ok := c.Get(w.name)
		if !ok {
			t.Fatalf("нет %s", w.name)
		}
		if e.Version != "1.0.0" || e.Reversibility != w.rev {
			t.Errorf("%s: version=%s rev=%s", w.name, e.Version, e.Reversibility)
		}
	}
	if err := c.Validate(step.DefaultRegistry()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	in, _ := c.Get("workload.scale_in")
	out, _ := c.Get("workload.scale_out")
	if in.Targets.SameAs != "" || !reflect.DeepEqual(in.Targets, out.Targets) {
		t.Errorf("same_as не разрешён: %+v", in.Targets)
	}
	if out.RateLimit.Cooldown.Minutes() != 10 {
		t.Errorf("cooldown scale_out = %v", out.RateLimit.Cooldown)
	}
	if rb, _ := c.Get("rollout.abort_and_rollback"); rb.RateLimit.Cooldown.Duration != 0 {
		t.Error("cooldown 0m должен быть нулём")
	}
}

// mutate возвращает каталог из встроенных файлов с заменой в одном из них.
func mutate(t *testing.T, file, old, new string) fstest.MapFS {
	t.Helper()
	fsys := fstest.MapFS{}
	for _, f := range []string{"pgbouncer.resize_pool", "postgres.set_restart_param", "rollout.abort_and_rollback",
		"workload.restart", "workload.scale_in", "workload.scale_out"} {
		b, err := catalogdata.FS.ReadFile("actions/" + f + ".yaml")
		if err != nil {
			t.Fatal(err)
		}
		fsys[f+".yaml"] = &fstest.MapFile{Data: b}
	}
	if file == "" {
		return fsys
	}
	s := string(fsys[file+".yaml"].Data)
	if !strings.Contains(s, old) {
		t.Fatalf("%s: нет фрагмента %q", file, old)
	}
	fsys[file+".yaml"] = &fstest.MapFile{Data: []byte(strings.Replace(s, old, new, 1))}
	return fsys
}

func TestValidate_Rejects(t *testing.T) {
	so := "workload.scale_out"
	cases := []struct {
		name          string
		file, old, nw string
		wantLoad      bool // ошибка уже при Load
		want          string
	}{
		{"неизвестное поле", so, "execution: api", "execution: api\nbogus: 1", true, "bogus"},
		{"плохой semver", so, "version: 1.0.0", "version: 1.0", false, "не semver"},
		{"R4", so, "reversibility: R1", "reversibility: R4", false, "reversibility"},
		{"нет chosen_by", so, "    chosen_by: catalog\n    bounds", "    bounds", false, "chosen_by"},
		{"неизвестное правило шага", so, "rule: workload.scale_out.v1", "rule: nope.v1", false, "не зарегистрировано"},
		{"неизвестное правило границ", so, "rule: workload.scale_out.bounds.v1", "rule: nope.bounds", false, "правило границ"},
		{"величина без шага", "pgbouncer.resize_pool", "  - {param: new_pool_size, rule: pgbouncer.resize_pool.v1", "  - {param: database, rule: pgbouncer.resize_pool.v1", false, "без зарегистрированного правила шага"},
		{"lease optional", so, "lease: required", "lease: optional", false, "lease"},
		{"budget allowed у R2", "workload.scale_in", "error_budget_exhausted: frozen", "error_budget_exhausted: allowed", false, "только у R1"},
		{"degraded allowed у R2", "workload.scale_in", "degraded_mode: forbidden", "degraded_mode: allowed", false, "только у R1"},
		{"degraded policy у R1", so, "degraded_mode: allowed", "degraded_mode: policy", false, "только у R2"},
		{"R3 не forbidden", "postgres.set_restart_param", "degraded_mode: forbidden", "degraded_mode: policy", false, "R3"},
		{"R3 budget не frozen", "postgres.set_restart_param", "error_budget_exhausted: frozen", "error_budget_exhausted: allowed", false, "R3"},
		{"rollback на неизвестное", so, "action: workload.scale_in", "action: workload.nope", false, "rollback.action"},
		{"имя файла != name", so, "name: workload.scale_out", "name: workload.scale_up", true, "имя файла"},
		{"пустые targets.kinds", so, "kinds: [apps/Deployment, autoscaling/HorizontalPodAutoscaler, keda.sh/ScaledObject]", "kinds: []", false, "targets.kinds"},
		{"плохой window", so, "window: 5m", "window: 5x", true, "duration"},
		{"rate_limit 0", so, "per_target_per_hour: 4", "per_target_per_hour: 0", false, "per_target_per_hour"},
		{"execution", so, "execution: api", "execution: ssh", false, "execution"},
		{"пустой blast_radius", so, "blast_radius: {targets_per_call: 1}", "blast_radius: {}", false, "blast_radius"},
		{"same_as на неизвестное", "workload.scale_in", "same_as: workload.scale_out", "same_as: workload.nope", true, "неизвестное действие"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cat, err := Load(mutate(t, c.file, c.old, c.nw))
			if !c.wantLoad {
				if err != nil {
					t.Fatalf("Load: %v", err)
				}
				err = cat.Validate(step.DefaultRegistry())
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("ожидалась ошибка с %q, получено: %v", c.want, err)
			}
		})
	}
}

func TestValidate_ForbiddenName(t *testing.T) {
	fsys := mutate(t, "", "", "")
	b := fsys["workload.scale_out.yaml"].Data
	fsys["storage.delete_volume.yaml"] = &fstest.MapFile{Data: []byte(strings.Replace(string(b), "name: workload.scale_out", "name: storage.delete_volume", 1))}
	cat, err := Load(fsys)
	if err != nil {
		t.Fatal(err)
	}
	if err := cat.Validate(step.DefaultRegistry()); err == nil || !strings.Contains(err.Error(), "запрещённым шаблоном") {
		t.Fatalf("got %v", err)
	}
}

func TestLoad_DuplicateName(t *testing.T) {
	fsys := mutate(t, "", "", "")
	fsys["copy.yaml"] = fsys["workload.scale_out.yaml"]
	if _, err := Load(fsys); err == nil || !strings.Contains(err.Error(), "уже занято") {
		t.Fatalf("got %v", err)
	}
}

func TestLoad_SameAsCycle(t *testing.T) {
	fsys := mutate(t, "workload.scale_out", "targets:\n  kinds: [apps/Deployment, autoscaling/HorizontalPodAutoscaler, keda.sh/ScaledObject]\n  labels: {aegisops.io/stateless: \"true\"}",
		"targets: {same_as: workload.scale_in}")
	if _, err := Load(fsys); err == nil || !strings.Contains(err.Error(), "цикл") {
		t.Fatalf("got %v", err)
	}
}

func TestDigest(t *testing.T) {
	a, err := Load(mutate(t, "", "", ""))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Load(mutate(t, "", "", ""))
	if a.Digest() != b.Digest() || !strings.HasPrefix(a.Digest(), "sha256:") || len(a.Digest()) != len("sha256:")+64 {
		t.Errorf("digest нестабилен или неверного формата: %s %s", a.Digest(), b.Digest())
	}
	c, err := Load(mutate(t, "workload.scale_out", "version: 1.0.0", "version: 1.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Digest() == a.Digest() {
		t.Error("digest не изменился от правки файла")
	}
}

func TestForbiddenPatterns(t *testing.T) {
	for _, n := range []string{"storage.delete_volume", "backup.delete", "audit.update", "policy.set", "autonomy.set_level"} {
		if !MatchesForbidden(n) {
			t.Errorf("%s должен быть запрещён", n)
		}
	}
	for _, n := range []string{"workload.scale_out", "pgbouncer.resize_pool", "rollout.abort_and_rollback"} {
		if MatchesForbidden(n) {
			t.Errorf("%s не должен быть запрещён", n)
		}
	}
}

func TestAnswerSchemaMatchesCatalog(t *testing.T) {
	b, err := os.ReadFile("../../eval/golden-synthetic/schema/answer.schema-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Properties struct {
			Action struct {
				Properties struct {
					Type struct {
						Enum []string `json:"enum"`
					} `json:"type"`
					Params struct {
						Properties map[string]struct {
							Enum []*string `json:"enum"`
						} `json:"properties"`
					} `json:"params"`
				} `json:"properties"`
			} `json:"action"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(b, &schema); err != nil {
		t.Fatal(err)
	}
	c := MustLoadEmbedded()
	wantTypes := append(c.Names(), "recommend", "none")
	sort.Strings(wantTypes)
	gotTypes := append([]string(nil), schema.Properties.Action.Properties.Type.Enum...)
	sort.Strings(gotTypes)
	if !reflect.DeepEqual(gotTypes, wantTypes) {
		t.Errorf("action.type: схема %v, каталог %v", gotTypes, wantTypes)
	}
	// Параметры модели: объединение по каталогу; перечисления совпадают (если у схемы есть enum).
	model := map[string][]string{}
	for _, n := range c.Names() {
		e, _ := c.Get(n)
		for pn, p := range e.Params {
			if p.ChosenBy == "model" {
				model[pn] = append(model[pn], p.Enum...)
			}
		}
	}
	got := schema.Properties.Action.Properties.Params.Properties
	if len(got) != len(model) {
		t.Errorf("параметры модели: схема %d, каталог %d", len(got), len(model))
	}
	for pn, enum := range model {
		sp, ok := got[pn]
		if !ok {
			t.Errorf("в схеме нет параметра %s", pn)
			continue
		}
		var schemaEnum []string
		for _, v := range sp.Enum {
			if v != nil {
				schemaEnum = append(schemaEnum, *v)
			}
		}
		sort.Strings(schemaEnum)
		uniq := map[string]bool{}
		for _, v := range enum {
			uniq[v] = true
		}
		var cat []string
		for v := range uniq {
			cat = append(cat, v)
		}
		sort.Strings(cat)
		if len(schemaEnum) == 0 && len(cat) == 0 {
			continue
		}
		// pod_name в схеме без enum, в каталоге его значения берутся из цели
		if len(schemaEnum) != 0 && !reflect.DeepEqual(schemaEnum, cat) {
			t.Errorf("%s: enum схемы %v, каталога %v", pn, schemaEnum, cat)
		}
	}
}

func TestValidate_NoPreconditions(t *testing.T) {
	fsys := mutate(t, "", "", "")
	s := string(fsys["workload.scale_in.yaml"].Data)
	i, j := strings.Index(s, "preconditions:\n"), strings.Index(s, "postconditions:")
	if i < 0 || j < i {
		t.Fatal("не найден блок preconditions")
	}
	fsys["workload.scale_in.yaml"] = &fstest.MapFile{Data: []byte(s[:i] + "preconditions: []\n" + s[j:])}
	cat, err := Load(fsys)
	if err != nil {
		t.Fatal(err)
	}
	if err := cat.Validate(step.DefaultRegistry()); err == nil || !strings.Contains(err.Error(), "preconditions") {
		t.Fatalf("got %v", err)
	}
}
