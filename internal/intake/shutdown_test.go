package intake

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/limpjungle/aegis3311/internal/openrouter"
	"github.com/limpjungle/aegis3311/internal/pyjson"
)

// blockTr — транспорт OpenRouter, блокирующий POST до отмены контекста.
type blockTr struct{ started chan struct{} }

func (b *blockTr) Post(ctx context.Context, _ string, _ http.Header, _ []byte) (openrouter.Response, error) {
	select {
	case b.started <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return openrouter.Response{}, ctx.Err()
}
func (b *blockTr) Get(context.Context, string, http.Header) (openrouter.Response, error) {
	return openrouter.Response{Status: 200, Body: []byte(healthBody)}, nil
}

// Остановка сервиса во время Route: запись «canceled» не должна навсегда закрывать инцидент для обработки после
// рестарта (HasIncidentRecord отсекает повтор). Ожидается: записи нет, статус open, Handle возвращает nil.
func TestPipelineShutdownDuringRoute(t *testing.T) {
	tr := &blockTr{started: make(chan struct{}, 1)}
	rt, cfg, keys := openTestRuntime(t, tr)
	c := loadCases(t, "probe-v3.jsonl")[0]
	snap := snapshotFromGolden(t, pyjson.Marshal(c.Get("input"), pyjson.Canonical))
	p, inc, st := newTestPipeline(t, rt, snap, t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	go func() { <-tr.started; time.Sleep(50 * time.Millisecond); cancel() }()
	err := p.Handle(ctx, &inc)
	recs := verifyRecords(t, cfg, keys)
	got, _ := st.Get(inc.ID)
	if len(recs) != 0 {
		r := recs[0]
		reason := ""
		if r.LLM != nil {
			reason = r.LLM.Reason
		}
		if r.Answer != nil {
			t.Logf("answer.status=%s error_kind=%s llm.outcome=%s", r.Answer.Status, r.Answer.ErrorKind, r.LLM.Outcome)
		}
		t.Errorf("при остановке во время Route записана запись (llm.reason=%q, статус состояния %s, err=%v): после рестарта инцидент не будет обработан",
			reason, got.Status, err)
	}
}
