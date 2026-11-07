package pep_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/limpjungle/aegis3311/internal/pep"
	"github.com/limpjungle/aegis3311/internal/step"
)

var update = flag.Bool("update", false, "перезаписать *.verdict.json")

const goldenDir = "../../eval/golden-synthetic"

var digestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func TestVerdictGolden(t *testing.T) {
	files, err := filepath.Glob("testdata/cases/*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("нет кейсов: %v", err)
	}
	eng := newEngine(t)
	n := 0
	for _, f := range files {
		if strings.HasSuffix(f, ".verdict.json") {
			continue
		}
		n++
		t.Run(strings.TrimSuffix(filepath.Base(f), ".json"), func(t *testing.T) {
			in, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			var req struct {
				Proposal json.RawMessage `json:"proposal"`
				Context  pep.Context     `json:"context"`
			}
			dec := json.NewDecoder(bytes.NewReader(in))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&req); err != nil {
				t.Fatal(err)
			}
			v := eng.EvaluateRaw(context.Background(), req.Proposal, req.Context)
			// Формат digest-полей проверяем отдельно, в сравнение они не входят.
			for name, d := range map[string]string{"catalog_digest": v.CatalogDigest, "policy_bundle_digest": v.PolicyDigest, "input_digest": v.InputDigest} {
				if !digestRe.MatchString(d) {
					t.Errorf("%s: формат %q", name, d)
				}
			}
			v.CatalogDigest, v.PolicyDigest, v.InputDigest = "<digest>", "<digest>", "<digest>"
			var buf bytes.Buffer
			enc := json.NewEncoder(&buf)
			enc.SetEscapeHTML(false)
			enc.SetIndent("", " ")
			if err := enc.Encode(v); err != nil {
				t.Fatal(err)
			}
			got := buf.Bytes()
			want := strings.TrimSuffix(f, ".json") + ".verdict.json"
			if *update {
				if err := os.WriteFile(want, got, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			exp, err := os.ReadFile(want)
			if err != nil {
				t.Fatalf("нет эталона (запустите с -update): %v", err)
			}
			if !bytes.Equal(exp, got) {
				t.Errorf("вердикт не совпал с %s\n got:\n%s\nwant:\n%s", want, got, exp)
			}
		})
	}
	if n == 0 {
		t.Fatal("нет кейсов")
	}
}

// ---------- golden-набор ----------

type goldenCase struct {
	ID      string
	Input   json.RawMessage
	Allowed []map[string]any
	Accept  []acceptable
	state   step.TargetState
}

type acceptable struct {
	Type   string                    `json:"type"`
	Params map[string]map[string]any `json:"params"`
}

// loadGolden читает набор только на чтение, сверив sha256 с manifest.json.
func loadGolden(t *testing.T, set string, wantCases int) []goldenCase {
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
	ms := m.Sets[set]
	path := filepath.Join(goldenDir, ms.File)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != ms.Sha256 {
		t.Fatalf("%s: sha256 не совпадает с manifest (данные изменены или это не закреплённый набор)", path)
	}
	var out []goldenCase
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 1<<20), 1<<26)
	for sc.Scan() {
		var line struct {
			ID       string          `json:"id"`
			Input    json.RawMessage `json:"input"`
			Expected struct {
				Acceptable []acceptable `json:"acceptable"`
			} `json:"expected"`
		}
		if err := json.Unmarshal(sc.Bytes(), &line); err != nil {
			t.Fatal(err)
		}
		var in struct {
			Allowed []map[string]any `json:"allowed_actions"`
		}
		if err := json.Unmarshal(line.Input, &in); err != nil {
			t.Fatal(err)
		}
		s, err := step.StateFromGoldenInput(line.Input)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, goldenCase{ID: line.ID, Input: line.Input, Allowed: in.Allowed, Accept: line.Expected.Acceptable, state: s})
	}
	if len(out) != wantCases || ms.Cases != wantCases {
		t.Fatalf("%s: кейсов %d (manifest %d), ожидалось %d", set, len(out), ms.Cases, wantCases)
	}
	return out
}

func (c goldenCase) allowed(typ string) map[string]any {
	for _, a := range c.Allowed {
		if a["type"] == typ {
			return a
		}
	}
	return nil
}

// proposalFor строит предложение по ограничениям expected.acceptable: equals -> значение, null -> nil,
// отсутствие ограничения -> первое значение enum из allowed_actions (pod_name только при scope=pod).
func (c goldenCase) proposalFor(typ string, cons map[string]map[string]any) pep.Proposal {
	vals := map[string]*string{}
	for _, name := range []string{"scope", "reason", "parameter", "pod_name"} {
		if cn, ok := cons[name]; ok {
			if v, ok := cn["equals"].(string); ok {
				vals[name] = &v
			}
			continue // null или иное ограничение -> nil
		}
		a := c.allowed(typ)
		if a == nil {
			continue
		}
		params, _ := a["params"].(map[string]any)
		pc, _ := params[name].(map[string]any)
		enum, _ := pc["enum"].([]any)
		if len(enum) == 0 || (name == "pod_name" && (vals["scope"] == nil || *vals["scope"] != "pod")) {
			continue
		}
		v := enum[0].(string)
		vals[name] = &v
	}
	return pep.Proposal{Type: typ, Params: pep.ModelParams{Scope: vals["scope"], PodName: vals["pod_name"], Reason: vals["reason"], Parameter: vals["parameter"]}}
}

func TestGoldenSetPEP(t *testing.T) {
	eng := newEngine(t)
	catalogActions := []string{"pgbouncer.resize_pool", "postgres.set_restart_param", "rollout.abort_and_rollback",
		"workload.restart", "workload.scale_in", "workload.scale_out"}
	for _, set := range []struct {
		name  string
		cases int
	}{{"probe", 480}, {"dev", 113}} {
		t.Run(set.name, func(t *testing.T) {
			bad, checked, unavailable := 0, 0, 0
			fail := func(format string, a ...any) {
				if bad++; bad <= 20 {
					t.Errorf(format, a...)
				}
			}
			for _, c := range loadGolden(t, set.name, set.cases) {
				ctx := permissive(c.state)
				for _, acc := range c.Accept {
					p := c.proposalFor(acc.Type, acc.Params)
					v := eng.Evaluate(context.Background(), p, ctx)
					checked++
					if v.Decision == "deny" {
						fail("%s: допустимое %s отклонено: %+v", c.ID, acc.Type, v.Reasons)
						continue
					}
					if acc.Type == "none" || acc.Type == "recommend" {
						continue
					}
					want, _ := c.allowed(acc.Type)["computed"].(map[string]any)
					gotB, _ := json.Marshal(v.Action.Computed)
					var got map[string]any
					_ = json.Unmarshal(gotB, &got)
					if want == nil {
						want = map[string]any{}
					}
					if !reflect.DeepEqual(got, want) {
						fail("%s: computed %s, в наборе %v", c.ID, gotB, want)
					}
				}
				for _, name := range catalogActions {
					if c.allowed(name) != nil {
						continue
					}
					unavailable++
					v := eng.Evaluate(context.Background(), c.proposalFor(name, nil), ctx)
					found := false
					for _, r := range v.Reasons {
						found = found || r.Code == "action_unavailable"
					}
					if v.Decision != "deny" || !found {
						fail("%s: %s вне allowed_actions, вердикт %s %+v", c.ID, name, v.Decision, v.Reasons)
					}
				}
			}
			if checked == 0 || unavailable == 0 {
				t.Errorf("проверок мало: acceptable=%d unavailable=%d", checked, unavailable)
			}
			t.Logf("%s: acceptable=%d, недоступных проверено=%d, ошибок=%d", set.name, checked, unavailable, bad)
		})
	}
}

// Ответы эталонных моделей: паники нет, действие вне allowed_actions -> deny.
func TestRefAnswersNoPanic(t *testing.T) {
	eng := newEngine(t)
	cases := map[string]goldenCase{}
	for _, c := range loadGolden(t, "probe", 480) {
		cases[c.ID] = c
	}
	// эталоны v2 (архив) и v3 прогоняются на состояниях активного набора по id
	var files []string
	for _, ver := range []string{"v2", "v3"} {
		fs, _ := filepath.Glob(filepath.Join(goldenDir, "refs/*/probe-"+ver+"-*.jsonl"))
		t.Logf("эталонов %s: %d", ver, len(fs))
		files = append(files, fs...)
	}
	if len(files) == 0 {
		t.Skip("нет refs")
	}
	total := 0
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(bytes.NewReader(data))
		sc.Buffer(make([]byte, 1<<20), 1<<26)
		for sc.Scan() {
			var line struct {
				ID     string `json:"id"`
				Answer *struct {
					Action json.RawMessage `json:"action"`
				} `json:"answer"`
			}
			if err := json.Unmarshal(sc.Bytes(), &line); err != nil || line.Answer == nil || line.Answer.Action == nil {
				continue
			}
			c, ok := cases[line.ID]
			if !ok {
				t.Errorf("%s: id нет в наборе", line.ID)
				continue
			}
			v := eng.EvaluateRaw(context.Background(), line.Answer.Action, permissive(c.state))
			total++
			p, err := pep.ParseProposal(line.Answer.Action)
			if err != nil {
				continue
			}
			if p.Type != "none" && p.Type != "recommend" && c.allowed(p.Type) == nil && v.Decision != "deny" {
				t.Errorf("%s: %s вне allowed_actions, вердикт %s", line.ID, p.Type, v.Decision)
			}
		}
	}
	if total == 0 {
		t.Error("не разобрано ни одного ответа")
	}
	t.Logf("ответов проверено: %d", total)
}
