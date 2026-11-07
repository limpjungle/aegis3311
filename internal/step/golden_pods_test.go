package step

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/limpjungle/aegis3311/internal/catalog"
)

func mustCatalogForPods(t *testing.T) *catalog.Catalog {
	t.Helper()
	return catalog.MustLoadEmbedded()
}

// Набор старше v3 или битый вход: pods обязан быть списком; null и отсутствие — ошибка (fail-closed).
func TestStateFromGoldenInputPodsEdgeCases(t *testing.T) {
	for name, raw := range map[string]string{
		"pods: null":          `{"service":{"name":"a","namespace":"n","pods":null}}`,
		"pods: строка":        `{"service":{"name":"a","namespace":"n","pods":"a"}}`,
		"pods: число":         `{"service":{"name":"a","namespace":"n","pods":1}}`,
		"service отсутствует": `{}`,
	} {
		if _, err := StateFromGoldenInput(json.RawMessage(raw)); err == nil {
			t.Errorf("%s: ожидалась ошибка", name)
		}
	}
	// пустой список — допустим на уровне разбора; restart тогда недоступен (len(Pods) == 0)
	s, err := StateFromGoldenInput(json.RawMessage(`{"service":{"name":"a","namespace":"n","pods":[]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Pods) != 0 {
		t.Errorf("Pods = %v, ожидался пустой", s.Pods)
	}
	for _, a := range Available(mustCatalogForPods(t), s) {
		if a.Type == "workload.restart" {
			t.Error("restart доступен при пустых pods")
		}
	}
	// порядок подов сохраняется (enum в allowed_actions строится в том же порядке)
	s, err = StateFromGoldenInput(json.RawMessage(`{"service":{"name":"a","namespace":"n","pods":["z","a","m"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(s.Pods, []string{"z", "a", "m"}) {
		t.Errorf("порядок подов: %v", s.Pods)
	}
}
