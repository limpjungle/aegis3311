package intake

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/limpjungle/aegis3311/internal/catalog"
	"github.com/limpjungle/aegis3311/internal/llmrouter"
	"github.com/limpjungle/aegis3311/internal/pyjson"
	"github.com/limpjungle/aegis3311/internal/step"
	"github.com/limpjungle/aegis3311/internal/strictjson"
)

const goldenDir = "../../eval/golden-synthetic/data"

// probeKeys — литерал из llmrouter/golden_test.go: intake обязан повторять отображение секций один в один.
var probeKeys = map[string]struct {
	source    string
	kind      llmrouter.FragmentKind
	required  bool
	relevance int
	list      bool
}{
	"alert":           {"alerts.alertmanager", llmrouter.KindGeneric, true, 100, false},
	"allowed_actions": {"platform.action_catalog", llmrouter.KindGeneric, true, 100, false},
	"service":         {"platform.topology", llmrouter.KindGeneric, true, 100, false},
	"rollout":         {"k8s.rollout_status", llmrouter.KindGeneric, false, 60, false},
	"db":              {"db.aggregates", llmrouter.KindGeneric, false, 60, false},
	"pdb":             {"manifests.k8s", llmrouter.KindGeneric, false, 20, false},
	"metrics":         {"metrics.prometheus", llmrouter.KindMetricSeries, false, 50, true},
	"k8s_events":      {"k8s.events", llmrouter.KindGeneric, false, 40, true},
	"deploys":         {"k8s.deploys", llmrouter.KindGeneric, false, 40, true},
}

// golden-форма input (v3), строго: новый ключ ломает тест.
type goldenInput struct {
	Alert struct {
		Name     string `json:"name"`
		Severity string `json:"severity"`
		Labels   struct {
			Namespace string `json:"namespace"`
			Service   string `json:"service"`
		} `json:"labels"`
		Annotations struct {
			Summary     string `json:"summary"`
			Description string `json:"description"`
		} `json:"annotations"`
		StartsAt int `json:"starts_at_offset_min"`
	} `json:"alert"`
	AllowedActions json.RawMessage `json:"allowed_actions"`
	Service        struct {
		Name                   string           `json:"name"`
		Namespace              string           `json:"namespace"`
		Database               *string          `json:"database"`
		InsufficientDataPolicy *string          `json:"insufficient_data_policy"`
		Autoscaler             *step.Autoscaler `json:"autoscaler"`
		Pods                   []string         `json:"pods"`
	} `json:"service"`
	Rollout json.RawMessage `json:"rollout"`
	DB      json.RawMessage `json:"db"`
	PDB     json.RawMessage `json:"pdb"`
	Metrics []struct {
		Labels      map[string]string `json:"labels"`
		Name        string            `json:"name"`
		StartOffset int               `json:"start_offset_min"`
		StepS       int               `json:"step_s"`
		Unit        string            `json:"unit"`
		Values      []*float64        `json:"values"`
	} `json:"metrics"`
	Events []struct {
		Count  int    `json:"count"`
		Object string `json:"object"`
		Offset int    `json:"offset_min"`
		Reason string `json:"reason"`
		Type   string `json:"type"`
	} `json:"k8s_events"`
	Deploys []struct {
		Author   string `json:"author_id"`
		Digest   string `json:"image_digest"`
		Offset   int    `json:"offset_min"`
		Revision int    `json:"revision"`
	} `json:"deploys"`
}

var goldenT0 = time.Date(2026, 1, 2, 10, 0, 0, 0, time.UTC)

func snapshotFromGolden(t testing.TB, raw []byte) Snapshot {
	t.Helper()
	var g goldenInput
	if err := strictjson.Decode(raw, &g); err != nil {
		t.Fatalf("golden input: %v", err)
	}
	at := func(off int) time.Time { return goldenT0.Add(time.Duration(off) * time.Minute) }
	s := Snapshot{T0: goldenT0}
	s.Alert = Alert{Name: g.Alert.Name, Severity: g.Alert.Severity, Namespace: g.Alert.Labels.Namespace, Service: g.Alert.Labels.Service,
		Summary: g.Alert.Annotations.Summary, Description: g.Alert.Annotations.Description, StartsAt: at(g.Alert.StartsAt), Fingerprint: "0123456789abcdef"}
	s.Topology = Topology{Service: g.Service.Name, Namespace: g.Service.Namespace, Database: g.Service.Database,
		InsufficientDataPolicy: g.Service.InsufficientDataPolicy, Autoscaler: g.Service.Autoscaler, Pods: g.Service.Pods}
	var err error
	if s.Rollout, err = parseOpt[Rollout](g.Rollout, "rollout"); err != nil {
		t.Fatal(err)
	}
	if s.DB, err = parseOpt[DBAggregates](g.DB, "db"); err != nil {
		t.Fatal(err)
	}
	if s.PDB, err = parseOpt[PDB](g.PDB, "pdb"); err != nil {
		t.Fatal(err)
	}
	for _, m := range g.Metrics {
		if m.StartOffset != SeriesStartMn || m.StepS != SeriesStepS || len(m.Values) != SeriesPoints {
			t.Fatalf("серия %s: окно %d/%d/%d", m.Name, m.StartOffset, m.StepS, len(m.Values))
		}
		se := Series{Name: m.Name, Unit: m.Unit, Values: m.Values}
		for k, v := range m.Labels {
			se.Labels = append(se.Labels, Label{k, v})
		}
		s.Metrics = append(s.Metrics, se)
	}
	for _, e := range g.Events {
		s.Events = append(s.Events, Event{Type: e.Type, Reason: e.Reason, Object: e.Object, Count: e.Count, At: at(e.Offset)})
	}
	for _, d := range g.Deploys {
		s.Deploys = append(s.Deploys, Deploy{Revision: d.Revision, ImageDigest: d.Digest, AuthorID: d.Author, At: at(d.Offset)})
	}
	return s
}

func loadCases(t testing.TB, name string) []*pyjson.Value {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(goldenDir, name))
	if err != nil {
		t.Fatal(err)
	}
	var out []*pyjson.Value
	for _, ln := range bytes.Split(b, []byte("\n")) {
		if len(bytes.TrimSpace(ln)) == 0 {
			continue
		}
		v, err := pyjson.Parse(ln)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, v)
	}
	return out
}

// requestInput собирает input так же, как роутер: секции по порядку, список — массив, не список — значение.
func requestInput(req llmrouter.Request) *pyjson.Value {
	in := pyjson.NewObject()
	for _, sec := range req.Sections {
		if sec.List {
			arr := pyjson.NewArray()
			for _, f := range sec.Fragments {
				arr.Items = append(arr.Items, f.Value)
			}
			in.Members = append(in.Members, pyjson.M(sec.Key, arr))
		} else {
			in.Members = append(in.Members, pyjson.M(sec.Key, sec.Fragments[0].Value))
		}
	}
	return in
}

func TestAssembleMatchesGolden(t *testing.T) {
	cat := catalog.MustLoadEmbedded()
	for _, f := range []struct {
		file string
		n    int
	}{{"probe-v3.jsonl", 480}, {"dev-v3.jsonl", 113}, {"probe-v4.jsonl", 595}, {"dev-v4.jsonl", 138}, {"probe-v5.jsonl", 635}, {"dev-v5.jsonl", 147}} {
		cases := loadCases(t, f.file)
		if len(cases) != f.n {
			t.Fatalf("%s: кейсов %d, ожидается %d", f.file, len(cases), f.n)
		}
		var cov v4Coverage
		var cov5 v5Coverage
		withPolicy := 0
		for _, c := range cases {
			id := c.Get("id").S
			in := c.Get("input")
			cov.add(in)
			cov5.add(in)
			rawIn := pyjson.Marshal(in, pyjson.Canonical)
			s := snapshotFromGolden(t, rawIn)
			req, st, err := Assemble(id, s, cat, llmrouter.ModeHybrid)
			if err != nil {
				t.Fatalf("%s: %v", id, err)
			}
			if got := pyjson.Marshal(requestInput(req), pyjson.Canonical); !bytes.Equal(got, rawIn) {
				t.Fatalf("%s: input расходится с golden\n got: %s\nwant: %s", id, firstDiff(got, rawIn), firstDiff(rawIn, got))
			}
			want, err := step.StateFromGoldenInput(rawIn)
			if err != nil {
				t.Fatal(err)
			}
			if a, _ := json.Marshal(st); !bytes.Equal(a, mustJSON(t, want)) {
				t.Fatalf("%s: TargetState %s != %s", id, a, mustJSON(t, want))
			}
			if st.InsufficientDataPolicy != nil {
				withPolicy++
			}
			seen := map[string]bool{}
			for _, sec := range req.Sections {
				km, ok := probeKeys[sec.Key]
				if !ok || sec.List != km.list {
					t.Fatalf("%s: секция %q", id, sec.Key)
				}
				seen[sec.Key] = true
				for i, fr := range sec.Fragments {
					wantID := id + "/" + sec.Key
					if km.list {
						wantID += fmt.Sprintf("/%d", i)
					}
					if fr.ID != wantID || fr.Source != km.source || fr.Kind != km.kind || fr.Required != km.required || fr.Relevance != km.relevance {
						t.Fatalf("%s: фрагмент %+v не соответствует таблице", id, fr)
					}
				}
			}
			for _, m := range in.Members {
				if !seen[m.Key] {
					t.Fatalf("%s: нет секции %q", id, m.Key)
				}
			}
		}
		if withPolicy == 0 {
			t.Errorf("%s: ни у одного кейса нет политики сервиса при недостатке данных", f.file)
		}
		if strings.HasSuffix(f.file, "-v4.jsonl") || strings.HasSuffix(f.file, "-v5.jsonl") {
			cov.require(t, f.file)
		}
		if strings.HasSuffix(f.file, "-v5.jsonl") {
			cov5.require(t, f.file)
		}
	}
}

// v4Coverage — сколько кейсов набора v4 покрывают формы входа, которых не было в v3 и которые живой intake отдаёт.
type v4Coverage struct {
	prevProgressing, prevBake, running, seriesNull, liveBake int
}

func (c *v4Coverage) add(in *pyjson.Value) {
	if ro := in.Get("rollout"); ro != nil && ro.Kind == pyjson.Object {
		phase, ar := ro.Get("phase").S, ro.Get("analysis_run")
		if ro.Get("previous_analysis_run") != nil {
			if phase == "Progressing" {
				c.prevProgressing++
			}
			if phase == "Bake" {
				c.prevBake++
			}
		}
		if ar != nil && ar.Kind == pyjson.Object {
			if ar.Get("verdict").S == "running" {
				c.running++
			}
			if phase == "Bake" && ro.Get("canary_revision").Kind == pyjson.Null {
				c.liveBake++
			}
		}
	}
	for _, m := range in.Get("metrics").Items {
		for _, v := range m.Get("values").Items {
			if v.Kind == pyjson.Null {
				c.seriesNull++
				break
			}
		}
	}
}

func (c *v4Coverage) require(t *testing.T, file string) {
	t.Helper()
	for name, n := range map[string]int{"previous_analysis_run в Progressing": c.prevProgressing, "previous_analysis_run в Bake": c.prevBake,
		"verdict running": c.running, "null в сериях": c.seriesNull, "живой Bake с canary_revision null": c.liveBake} {
		if n == 0 {
			t.Errorf("%s: набор не покрывает %s", file, name)
		}
	}
	t.Logf("%s: prev Progressing %d, prev Bake %d, running %d, null в сериях %d, живой Bake %d",
		file, c.prevProgressing, c.prevBake, c.running, c.seriesNull, c.liveBake)
}

// v5Coverage — покрытие формы входа набора v5: вердикт error (Argo Error) в Progressing и в живом Bake.
type v5Coverage struct {
	errorProgressing, errorBake int
}

func (c *v5Coverage) add(in *pyjson.Value) {
	ro := in.Get("rollout")
	if ro == nil || ro.Kind != pyjson.Object {
		return
	}
	ar := ro.Get("analysis_run")
	if ar == nil || ar.Kind != pyjson.Object || ar.Get("verdict").S != "error" {
		return
	}
	switch ro.Get("phase").S {
	case "Progressing":
		c.errorProgressing++
	case "Bake":
		if ro.Get("canary_revision").Kind == pyjson.Null {
			c.errorBake++
		}
	}
}

func (c *v5Coverage) require(t *testing.T, file string) {
	t.Helper()
	for name, n := range map[string]int{"verdict error в Progressing": c.errorProgressing, "verdict error в Bake с canary_revision null": c.errorBake} {
		if n == 0 {
			t.Errorf("%s: набор не покрывает %s", file, name)
		}
	}
	t.Logf("%s: error Progressing %d, error Bake %d", file, c.errorProgressing, c.errorBake)
}

// firstDiff печатает окрестность первого расхождения a с b.
func firstDiff(a, b []byte) string {
	i := 0
	for i < len(a) && i < len(b) && a[i] == b[i] {
		i++
	}
	lo, hi := max(i-60, 0), min(i+60, len(a))
	return string(a[lo:hi])
}

func TestSectionsTableMatchesProbeKeys(t *testing.T) {
	if len(Sections) != len(probeKeys) {
		t.Fatalf("секций %d, в эталоне %d", len(Sections), len(probeKeys))
	}
	for _, sp := range Sections {
		km, ok := probeKeys[sp.Key]
		if !ok || km.source != sp.Source || km.kind != sp.Kind || km.required != sp.Required || km.relevance != sp.Relevance || km.list != sp.List {
			t.Errorf("секция %q расходится с эталоном: %+v", sp.Key, sp)
		}
	}
}

func mustJSON(t testing.TB, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
