package intake

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/limpjungle/aegis3311/internal/catalog"
	"github.com/limpjungle/aegis3311/internal/llmrouter"
	"github.com/limpjungle/aegis3311/internal/pyjson"
)

// Фикстура replay (JSON) даёт тот же input, что и снимок из golden: проверяет ParseSnapshot, Num и семантику Opt.
func TestParseSnapshotRoundTrip(t *testing.T) {
	cat := catalog.MustLoadEmbedded()
	for _, c := range loadCases(t, "dev-v3.jsonl")[:40] {
		s := snapshotFromGolden(t, pyjson.Marshal(c.Get("input"), pyjson.Canonical))
		m := map[string]any{"t0": s.T0, "alert": s.Alert, "topology": s.Topology, "metrics": s.Metrics, "events": s.Events, "deploys": s.Deploys}
		for k, o := range map[string]any{"rollout": optJSON(s.Rollout), "db": optJSON(s.DB), "pdb": optJSON(s.PDB)} {
			if o != absent {
				m[k] = o
			}
		}
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		s2, err := ParseSnapshot(b)
		if err != nil {
			t.Fatalf("%v\n%s", err, b)
		}
		id := c.Get("id").S
		r1, _, _ := Assemble(id, s, cat, llmrouter.ModeHybrid)
		r2, _, err := Assemble(id, s2, cat, llmrouter.ModeHybrid)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(pyjson.Marshal(requestInput(r1), pyjson.Canonical), pyjson.Marshal(requestInput(r2), pyjson.Canonical)) {
			t.Fatalf("%s: input после ParseSnapshot расходится", id)
		}
	}
}

type absentT struct{}

var absent = absentT{}

func optJSON[T any](o Opt[T]) any {
	switch {
	case !o.Present:
		return absent
	case o.Value == nil:
		return nil
	}
	return o.Value
}

func TestParseSnapshotStrict(t *testing.T) {
	if _, err := ParseSnapshot([]byte(`{"t0":"2026-01-02T10:00:00Z","unknown":1}`)); err == nil {
		t.Error("неизвестное поле должно отвергаться")
	}
}

// Replay-фикстура с previous_analysis_run: строгий разбор принимает ключ, значения доходят, лишнее поле внутри отвергается.
func TestParseSnapshotPreviousAnalysisRun(t *testing.T) {
	_, s := rolloutSnapshot(t)
	s = withRollout(s, "Progressing", nil, prevRun())
	m := map[string]any{"t0": s.T0, "alert": s.Alert, "topology": s.Topology, "metrics": s.Metrics, "events": s.Events, "deploys": s.Deploys,
		"rollout": s.Rollout.Value}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := ParseSnapshot(b)
	if err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	p := s2.Rollout.Value.PreviousAnalysisRun
	if p == nil || p.Name != "ar-prev" || p.Verdict != "success" || p.Revision == nil || *p.Revision != 7 || len(p.Metrics) != 1 || p.Metrics[0].Canary == nil {
		t.Errorf("Previous после разбора: %+v", p)
	}
	// круговое преобразование: повторная сериализация даёт тот же снимок
	b2, _ := json.Marshal(map[string]any{"t0": s2.T0, "alert": s2.Alert, "topology": s2.Topology, "metrics": s2.Metrics, "events": s2.Events,
		"deploys": s2.Deploys, "rollout": s2.Rollout.Value})
	if !bytes.Equal(b, b2) {
		t.Errorf("круговое преобразование расходится")
	}
	// неизвестное поле внутри previous_analysis_run
	bad := bytes.Replace(b, []byte(`"previous_analysis_run":{`), []byte(`"previous_analysis_run":{"extra":1,`), 1)
	if bytes.Equal(bad, b) {
		t.Fatal("подмена не сработала")
	}
	if _, err := ParseSnapshot(bad); err == nil {
		t.Error("неизвестное поле внутри previous_analysis_run должно отвергаться")
	}
}
