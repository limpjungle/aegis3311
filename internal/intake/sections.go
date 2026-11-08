package intake

import (
	"encoding/json"
	"fmt"

	"github.com/limpjungle/aegis3311/internal/catalog"
	"github.com/limpjungle/aegis3311/internal/llmrouter"
	"github.com/limpjungle/aegis3311/internal/pyjson"
	"github.com/limpjungle/aegis3311/internal/step"
)

// SectionSpec — отображение секции input на источник, вид, обязательность и релевантность фрагмента.
// Таблица Sections — точная копия probeKeys из llmrouter/golden_test.go: тест сверяет их литерально.
type SectionSpec struct {
	Key       string
	Source    string
	Kind      llmrouter.FragmentKind
	Required  bool
	Relevance int
	List      bool
}

var Sections = []SectionSpec{
	{"alert", "alerts.alertmanager", llmrouter.KindGeneric, true, 100, false},
	{"allowed_actions", "platform.action_catalog", llmrouter.KindGeneric, true, 100, false},
	{"service", "platform.topology", llmrouter.KindGeneric, true, 100, false},
	{"rollout", "k8s.rollout_status", llmrouter.KindGeneric, false, 60, false},
	{"db", "db.aggregates", llmrouter.KindGeneric, false, 60, false},
	{"pdb", "manifests.k8s", llmrouter.KindGeneric, false, 20, false},
	{"metrics", "metrics.prometheus", llmrouter.KindMetricSeries, false, 50, true},
	{"k8s_events", "k8s.events", llmrouter.KindGeneric, false, 40, true},
	{"deploys", "k8s.deploys", llmrouter.KindGeneric, false, 40, true},
}

// TargetStateOf строит TargetState так же, как step.StateFromGoldenInput: из топологии, rollout и агрегатов СУБД.
func TargetStateOf(s Snapshot) step.TargetState {
	t := s.Topology
	st := step.TargetState{Service: t.Service, Namespace: t.Namespace, Database: t.Database, Autoscaler: t.Autoscaler,
		Pods: append([]string{}, t.Pods...), InsufficientDataPolicy: t.InsufficientDataPolicy}
	if r := s.Rollout.Value; r != nil {
		st.Rollout = &step.Rollout{Name: r.Name, Phase: r.Phase}
		// PreviousAnalysisRun сознательно игнорируется: computed.analysis_run — только анализ текущей ревизии.
		if r.AnalysisRun != nil {
			st.Rollout.AnalysisRun, st.Rollout.AnalysisVerdict = r.AnalysisRun.Name, r.AnalysisRun.Verdict
		}
	}
	if d := s.DB.Value; d != nil {
		st.DB = &step.DB{PgBouncer: d.PgBouncer, Postgres: d.Postgres}
	}
	return st
}

// Assemble — чистая функция «снимок → запрос роутера + состояние цели». Снимок предварительно проходит Sanitize
// (идемпотентно). Ошибка — снимок не годится для запроса (состояние цели не прошло проверку).
func Assemble(incidentID string, s Snapshot, cat *catalog.Catalog, mode llmrouter.Mode) (llmrouter.Request, step.TargetState, error) {
	s, _ = Sanitize(s)
	st := TargetStateOf(s)
	if err := st.Validate(); err != nil {
		return llmrouter.Request{}, step.TargetState{}, fmt.Errorf("intake: состояние цели: %w", err)
	}
	acts, err := allowedActions(cat, st)
	if err != nil {
		return llmrouter.Request{}, step.TargetState{}, err
	}
	req := llmrouter.Request{IncidentID: incidentID, Service: s.Topology.Service, Mode: mode}
	for _, sp := range Sections {
		var vals []*pyjson.Value
		switch sp.Key {
		case "alert":
			vals = one(renderAlert(s.T0, s.Alert))
		case "allowed_actions":
			vals = one(acts)
		case "service":
			vals = one(renderService(s.Topology))
		case "rollout":
			if s.Rollout.Present {
				vals = one(renderRollout(s.T0, s.Rollout.Value))
			}
		case "db":
			if s.DB.Present {
				vals = one(renderDB(s.DB.Value))
			}
		case "pdb":
			if s.PDB.Present {
				vals = one(renderPDB(s.PDB.Value))
			}
		case "metrics":
			for _, m := range s.Metrics {
				vals = append(vals, renderSeries(m))
			}
		case "k8s_events":
			for _, e := range s.Events {
				vals = append(vals, renderEvent(s.T0, e))
			}
		case "deploys":
			for _, d := range s.Deploys {
				vals = append(vals, renderDeploy(s.T0, d))
			}
		}
		if vals == nil && !sp.List { // источник не дал данных: ключа в input нет
			continue
		}
		sec := llmrouter.Section{Key: sp.Key, List: sp.List}
		for i, v := range vals {
			id := incidentID + "/" + sp.Key
			if sp.List {
				id += fmt.Sprintf("/%d", i)
			}
			sec.Fragments = append(sec.Fragments, llmrouter.Fragment{ID: id, Source: sp.Source, Kind: sp.Kind, Required: sp.Required,
				Relevance: sp.Relevance, Value: v})
		}
		req.Sections = append(req.Sections, sec)
	}
	return req, st, nil
}

func one(v *pyjson.Value) []*pyjson.Value { return []*pyjson.Value{v} }

// allowedActions: step.Available → JSON → pyjson (в нём только целые и строки, поэтому вид чисел сохраняется).
func allowedActions(cat *catalog.Catalog, st step.TargetState) (*pyjson.Value, error) {
	b, err := json.Marshal(step.Available(cat, st))
	if err != nil {
		return nil, err
	}
	return pyjson.Parse(b)
}
