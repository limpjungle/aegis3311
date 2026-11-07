package routersvc

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/limpjungle/aegis3311/internal/audit"
	"github.com/limpjungle/aegis3311/internal/llmrouter"
	"github.com/limpjungle/aegis3311/internal/pyjson"
	"github.com/limpjungle/aegis3311/internal/strictjson"
)

// MaxRequestBytes — потолок размера файла запроса (предложение).
const MaxRequestBytes = 8 << 20

// RequestFile — вход подкоманды route: запрос роутера плюс данные инцидента для decision record'а.
type RequestFile struct {
	IncidentID  string        `json:"incident_id"`
	Service     string        `json:"service"`
	Environment string        `json:"environment"`
	Mode        string        `json:"mode"`
	Sections    []SectionJSON `json:"sections"`
}

type SectionJSON struct {
	Key       string         `json:"key"`
	List      bool           `json:"list"`
	Fragments []FragmentJSON `json:"fragments"`
}

type FragmentJSON struct {
	ID        string          `json:"id"`
	Source    string          `json:"source"`
	Kind      string          `json:"kind"`
	Required  bool            `json:"required"`
	Relevance int             `json:"relevance"`
	Value     json.RawMessage `json:"value"`
}

// IncidentMeta — поля инцидента, которых нет в llmrouter.Request.
type IncidentMeta struct{ ID, Service, Environment string }

// ParseRequest разбирает файл запроса (строго: неизвестные поля и дубли ключей — ошибка). Структуру запроса
// проверяет сам роутер (Route, Prepare).
func ParseRequest(b []byte) (llmrouter.Request, IncidentMeta, error) {
	if len(b) > MaxRequestBytes {
		return llmrouter.Request{}, IncidentMeta{}, fmt.Errorf("запрос: файл больше %d байт", MaxRequestBytes)
	}
	var rf RequestFile
	if err := strictjson.Decode(b, &rf); err != nil {
		return llmrouter.Request{}, IncidentMeta{}, fmt.Errorf("запрос: %w", err)
	}
	req := llmrouter.Request{IncidentID: rf.IncidentID, Service: rf.Service, Mode: llmrouter.Mode(rf.Mode)}
	for _, s := range rf.Sections {
		sec := llmrouter.Section{Key: s.Key, List: s.List}
		for _, f := range s.Fragments {
			if len(f.Value) == 0 {
				return llmrouter.Request{}, IncidentMeta{}, fmt.Errorf("запрос: фрагмент %q без value", f.ID)
			}
			v, err := pyjson.Parse(f.Value)
			if err != nil {
				return llmrouter.Request{}, IncidentMeta{}, fmt.Errorf("запрос: фрагмент %q: %w", f.ID, err)
			}
			sec.Fragments = append(sec.Fragments, llmrouter.Fragment{ID: f.ID, Source: f.Source, Kind: llmrouter.FragmentKind(f.Kind),
				Required: f.Required, Relevance: f.Relevance, Value: v})
		}
		req.Sections = append(req.Sections, sec)
	}
	if rf.Environment == "" {
		return llmrouter.Request{}, IncidentMeta{}, errors.New("запрос: environment обязателен")
	}
	return req, IncidentMeta{ID: rf.IncidentID, Service: rf.Service, Environment: rf.Environment}, nil
}

// ShadowRecord — decision record ручного прогона: режим dry-run, L0, без вердикта PEP, инициатор — оператор.
func ShadowRecord(meta IncidentMeta, operator string, now time.Time, res *llmrouter.Result) *audit.DecisionRecord {
	rec := &audit.DecisionRecord{Schema: audit.RecordSchema, RecordID: audit.NewRecordID(), RecordedAt: audit.Timestamp(now),
		Mode: audit.ModeDryRun, Incident: audit.IncidentRef{ID: meta.ID, Service: meta.Service, Environment: meta.Environment},
		Initiator: audit.Actor{Kind: "human", ID: operator}, RetrievedDocs: []string{}, AutonomyLevel: "L0"}
	res.Apply(rec)
	return rec
}
