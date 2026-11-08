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
			Pods                   []string `json:"pods"`
			InsufficientDataPolicy *string  `json:"insufficient_data_policy"`
			Autoscaler             struct {
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
// Имя вида "probe-v4" — архивный набор этой версии из manifest.sets_history, "probe-staged" — кандидат из
// manifest.staged, иначе — активный набор (v5 с 08.11.2026).
func readGolden(t *testing.T, set string, wantCases int) []GoldenCase {
	t.Helper()
	mb, err := os.ReadFile(filepath.Join(goldenDir, "data/manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	type entry struct {
		File   string `json:"file"`
		Sha256 string `json:"sha256"`
		Cases  int    `json:"cases"`
	}
	var m struct {
		Sets   map[string]entry `json:"sets"`
		Staged struct {
			Sets map[string]entry `json:"sets"`
		} `json:"staged"`
		History []struct {
			SetFormat string           `json:"set_format"`
			Sets      map[string]entry `json:"sets"`
		} `json:"sets_history"`
	}
	if err := json.Unmarshal(mb, &m); err != nil {
		t.Fatal(err)
	}
	sets, name := m.Sets, set
	if n, ok := strings.CutSuffix(set, "-staged"); ok {
		sets, name = m.Staged.Sets, n
	}
	if i := strings.LastIndex(set, "-v"); i > 0 {
		sets, name = nil, set[:i]
		for _, h := range m.History {
			if h.SetFormat == set[i+1:] {
				sets = h.Sets
			}
		}
	}
	ms, ok := sets[name]
	if !ok {
		t.Fatalf("в manifest нет набора %s", set)
	}
	if ms.Cases != wantCases {
		t.Fatalf("%s: кейсов в manifest %d, ожидалось %d", set, ms.Cases, wantCases)
	}
	return readGoldenEntry(t, ms.File, ms.Sha256, wantCases)
}

// readGoldenEntry читает набор по файлу, сверяя sha256 с manifest.
func readGoldenEntry(t *testing.T, file, wantSHA string, wantCases int) []GoldenCase {
	t.Helper()
	path := filepath.Join(goldenDir, file)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != wantSHA {
		t.Fatalf("%s: sha256 %s не совпадает с manifest %s (данные изменены или это не закреплённый набор)", path, got, wantSHA)
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
	if len(cases) != wantCases {
		t.Fatalf("%s: кейсов %d, ожидалось %d", file, len(cases), wantCases)
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
	}{{"probe", 635}, {"dev", 147}, {"probe-v3", 480}, {"dev-v3", 113}, {"probe-v4", 595}, {"dev-v4", 138}} {
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
	}{{"probe", 635}, {"dev", 147}, {"probe-v3", 480}, {"dev-v3", 113}, {"probe-v4", 595}, {"dev-v4", 138}} {
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

// TestGoldenAnalysisVerdict: вердикт анализа текущей ревизии переносится в TargetState ровно тогда, когда есть анализ.
func TestGoldenAnalysisVerdict(t *testing.T) {
	known := map[string]bool{"success": true, "degradation": true, "inconclusive": true, "error": true, "running": true}
	for _, set := range []struct {
		name  string
		cases int
	}{{"probe-v4", 595}, {"probe", 635}} {
		t.Run(set.name, func(t *testing.T) {
			seen := map[string]int{}
			for _, c := range readGolden(t, set.name, set.cases) {
				s, err := StateFromGoldenInput(c.RawInput)
				if err != nil {
					t.Fatalf("%s: %v", c.ID, err)
				}
				if s.Rollout == nil {
					continue
				}
				if (s.Rollout.AnalysisRun == "") != (s.Rollout.AnalysisVerdict == "") {
					t.Errorf("%s: analysis_run %q, verdict %q", c.ID, s.Rollout.AnalysisRun, s.Rollout.AnalysisVerdict)
				}
				if v := s.Rollout.AnalysisVerdict; v != "" {
					if !known[v] {
						t.Errorf("%s: неизвестный вердикт %q", c.ID, v)
					}
					seen[v]++
				}
			}
			if seen["degradation"] == 0 || seen["inconclusive"] == 0 || seen["running"] == 0 || (set.name == "probe" && seen["error"] == 0) {
				t.Errorf("покрытие вердиктов: %v", seen)
			}
			t.Logf("%s: %v", set.name, seen)
		})
	}
}

// TestGoldenInsufficientDataPolicy: политика сервиса при недостатке данных переносится в TargetState как есть
// (nil — поля нет во входе), значения только из {hold, rollback, human}.
func TestGoldenInsufficientDataPolicy(t *testing.T) {
	for _, set := range []struct {
		name                          string
		cases                         int
		rollback, hold, human, absent int
	}{{"probe", 635, 55, 198, 59, 323}, {"dev", 147, 14, 48, 12, 73}, {"probe-v4", 595, 44, 181, 47, 323}, {"dev-v4", 138, 12, 43, 10, 73}} {
		t.Run(set.name, func(t *testing.T) {
			seen := map[string]int{}
			for _, c := range readGolden(t, set.name, set.cases) {
				s, err := StateFromGoldenInput(c.RawInput)
				if err != nil {
					t.Fatalf("%s: %v", c.ID, err)
				}
				want := c.Input.Service.InsufficientDataPolicy
				if (s.InsufficientDataPolicy == nil) != (want == nil) || (want != nil && *s.InsufficientDataPolicy != *want) {
					t.Errorf("%s: политика в TargetState %v, во входе %v", c.ID, s.InsufficientDataPolicy, want)
				}
				if want == nil {
					seen["absent"]++
					continue
				}
				if v := *want; v != "hold" && v != "rollback" && v != "human" {
					t.Errorf("%s: неизвестная политика %q", c.ID, v)
				}
				seen[*want]++
			}
			got := [4]int{seen["rollback"], seen["hold"], seen["human"], seen["absent"]}
			if want := [4]int{set.rollback, set.hold, set.human, set.absent}; got != want {
				t.Errorf("политики rollback/hold/human/нет поля = %v, ожидалось %v", got, want)
			}
		})
	}
}
