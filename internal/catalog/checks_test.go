package catalog_test

import (
	"strings"
	"testing"
	"testing/fstest"

	. "github.com/limpjungle/aegis3311/internal/catalog"
	"github.com/limpjungle/aegis3311/internal/step"
)

// Уникальность и непустота id пред- и постусловий (план: «пред/постусловия ≥1 с уникальными id»).
func TestValidate_CheckIDs(t *testing.T) {
	base := mutate(t, "", "", "")
	src := string(base["workload.scale_in.yaml"].Data)
	if !strings.Contains(src, "  - {id: load.below_threshold") {
		t.Fatal("в workload.scale_in.yaml нет ожидаемого предусловия")
	}
	cases := map[string]struct{ old, new, want string }{
		"дубль id предусловия": {
			old:  "  - {id: load.below_threshold, description: \"загрузка за последние 30 минут ниже порога, заданного политикой сервиса\"}\n",
			new:  "  - {id: load.below_threshold, description: \"a\"}\n  - {id: load.below_threshold, description: \"b\"}\n",
			want: "дубль id",
		},
		"пустой id предусловия": {
			old:  "  - {id: load.below_threshold,",
			new:  "  - {id: \"\",",
			want: "пустой id",
		},
		"дубль id постусловия": {
			old:  "    - {id: slo.burn_rate_stable,",
			new:  "    - {id: saturation.below_threshold, description: \"dup\"}\n    - {id: slo.burn_rate_stable,",
			want: "дубль id",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			fsys := fstest.MapFS{}
			for k, v := range base {
				fsys[k] = v
			}
			if !strings.Contains(src, c.old) {
				t.Fatalf("нет фрагмента %q в записи", c.old)
			}
			fsys["workload.scale_in.yaml"] = &fstest.MapFile{Data: []byte(strings.Replace(src, c.old, c.new, 1))}
			cat, err := Load(fsys)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			err = cat.Validate(step.DefaultRegistry())
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Validate: %v; ожидалась ошибка с %q", err, c.want)
			}
		})
	}
}
