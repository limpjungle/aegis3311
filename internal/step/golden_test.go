package step

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/limpjungle/aegis3311/internal/catalog"
)

const goldenDir = "../../eval/golden-synthetic"

// GoldenCase — нужные поля кейса golden-набора.
type GoldenCase struct {
	ID    string `json:"id"`
	Input struct {
		AllowedActions json.RawMessage `json:"allowed_actions"`
		Service        struct {
			Pods       []string `json:"pods"`
			Autoscaler struct {
				Replicas int `json:"replicas"`
			} `json:"autoscaler"`
		} `json:"service"`
		K8sEvents []struct {
			Object string `json:"object"`
		} `json:"k8s_events"`
		Metrics []struct {
			Labels map[string]string `json:"labels"`
		} `json:"metrics"`
	} `json:"input"`
	RawInput json.RawMessage `json:"-"`
}

// readGolden проверяет sha256 набора по manifest.json и возвращает кейсы (файлы открываются только на чтение).
func readGolden(t *testing.T, set string, wantCases int) []GoldenCase {
	t.Helper()
	mb, err := os.ReadFile(filepath.Join(goldenDir, "data/manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Sets map[string]struct {
			File   string `json:"file"`
			Sha256 string `json:"sha256"`
			Cases  int    `json:"cases"`
		} `json:"sets"`
	}
	if err := json.Unmarshal(mb, &m); err != nil {
		t.Fatal(err)
	}
	ms, ok := m.Sets[set]
	if !ok {
		t.Fatalf("в manifest нет набора %s", set)
	}
	path := filepath.Join(goldenDir, ms.File)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != ms.Sha256 {
		t.Fatalf("%s: sha256 %s не совпадает с manifest %s (данные изменены или это не закреплённый набор)", path, got, ms.Sha256)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var cases []GoldenCase
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<26)
	for sc.Scan() {
		var line struct {
			ID    string          `json:"id"`
			Input json.RawMessage `json:"input"`
		}
		if err := json.Unmarshal(sc.Bytes(), &line); err != nil {
			t.Fatal(err)
		}
		var c GoldenCase
		c.ID, c.RawInput = line.ID, line.Input
		if err := json.Unmarshal(line.Input, &c.Input); err != nil {
			t.Fatal(err)
		}
		cases = append(cases, c)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if len(cases) != wantCases || ms.Cases != wantCases {
		t.Fatalf("%s: кейсов %d (manifest %d), ожидалось %d", set, len(cases), ms.Cases, wantCases)
	}
	return cases
}

func TestStateFromGoldenInputPods(t *testing.T) {
	// поды берутся из service.pods, а не из enum allowed_actions
	raw := json.RawMessage(`{"service":{"name":"a","namespace":"n","pods":["b"]},
		"allowed_actions":[{"type":"workload.restart","params":{"pod_name":{"enum":["a"]}}}]}`)
	s, err := StateFromGoldenInput(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(s.Pods, []string{"b"}) {
		t.Errorf("Pods = %v, ожидалось [b]", s.Pods)
	}
	// набор старше v3: поля нет — ошибка, отката на enum нет
	raw = json.RawMessage(`{"service":{"name":"a","namespace":"n"},
		"allowed_actions":[{"type":"workload.restart","params":{"pod_name":{"enum":["a"]}}}]}`)
	if _, err := StateFromGoldenInput(raw); err == nil {
		t.Error("ожидалась ошибка при отсутствии service.pods")
	}
}

// TestGoldenPodsConsistent: список подов цели согласован с событиями, метками метрик и числом реплик.
func TestGoldenPodsConsistent(t *testing.T) {
	for _, set := range []struct {
		name  string
		cases int
	}{{"probe", 480}, {"dev", 113}} {
		t.Run(set.name, func(t *testing.T) {
			for _, c := range readGolden(t, set.name, set.cases) {
				in := c.Input
				pods := map[string]bool{}
				for _, p := range in.Service.Pods {
					if pods[p] {
						t.Errorf("%s: дубликат пода %s", c.ID, p)
					}
					pods[p] = true
				}
				if len(in.Service.Pods) != in.Service.Autoscaler.Replicas {
					t.Errorf("%s: подов %d, реплик %d", c.ID, len(in.Service.Pods), in.Service.Autoscaler.Replicas)
				}
				for _, e := range in.K8sEvents {
					if name, ok := strings.CutPrefix(e.Object, "pod/"); ok && !pods[name] {
						t.Errorf("%s: событие про под %s вне service.pods", c.ID, name)
					}
				}
				for _, m := range in.Metrics {
					if p, ok := m.Labels["pod"]; ok && !pods[p] {
						t.Errorf("%s: метрика с меткой pod=%s вне service.pods", c.ID, p)
					}
				}
			}
		})
	}
}

func TestGoldenSetCrossCheck(t *testing.T) {
	cat := catalog.MustLoadEmbedded()
	for _, set := range []struct {
		name  string
		cases int
	}{{"probe", 480}, {"dev", 113}} {
		t.Run(set.name, func(t *testing.T) {
			bad := 0
			for _, c := range readGolden(t, set.name, set.cases) {
				s, err := StateFromGoldenInput(c.RawInput)
				if err != nil {
					t.Fatalf("%s: %v", c.ID, err)
				}
				if err := s.Validate(); err != nil {
					t.Errorf("%s: Validate: %v", c.ID, err)
					continue
				}
				gotB, _ := json.Marshal(Available(cat, s))
				var got, want any
				if err := json.Unmarshal(gotB, &got); err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(c.Input.AllowedActions, &want); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(got, want) {
					if bad++; bad <= 20 {
						t.Errorf("%s: allowed_actions расходится\n got  %s\n want %s", c.ID, gotB, c.Input.AllowedActions)
					}
				}
			}
			if bad > 0 {
				t.Errorf("%s: всего расхождений %d", set.name, bad)
			}
		})
	}
}
