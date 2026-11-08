package llmrouter

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/limpjungle/aegis3311/internal/audit"
	"github.com/limpjungle/aegis3311/internal/openrouter"
)

// recordValidate заполняет decision record из результата роутера и возвращает ошибку Validate.
func recordValidate(res *Result) error {
	rec := &audit.DecisionRecord{Schema: audit.RecordSchema, RecordID: audit.NewRecordID(),
		RecordedAt: audit.Timestamp(time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)), Mode: audit.ModeShadow,
		Incident:  audit.IncidentRef{ID: "inc-1", Service: "geo-svc", Environment: "staging"},
		Initiator: audit.Actor{Kind: "agent", ID: "a1"}, RetrievedDocs: []string{}, AutonomyLevel: "L0"}
	res.Apply(rec)
	return rec.Validate()
}

// Отмена до первой попытки: решение not_sent/canceled должно проходить audit.Validate (иначе Append его отвергнет).
func TestRecheckCanceledNotSentValidates(t *testing.T) {
	tr := &stubTransport{post: func([]byte) (openrouter.Response, error) { return reply("Inceptron", 1, 1), nil }}
	rg := newRig(t, &identityMasker{}, tr, "", nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := simpleReq(t, one("alert", frag(t, "a", "alerts.alertmanager", false, 100, `{"n":1}`)))
	res, err := rg.r.Route(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != "not_sent" || res.Reason != "canceled" {
		t.Fatalf("outcome=%s reason=%s, ожидается not_sent/canceled", res.Outcome, res.Reason)
	}
	if tr.calls != 0 {
		t.Fatalf("транспорт вызван %d раз", tr.calls)
	}
	if err := recordValidate(res); err != nil {
		t.Errorf("решение not_sent/canceled не проходит audit.Validate: %v", err)
	}
}

// Сбой записи active_changed после endpoint_down: публикуемое состояние не должно указывать на down-endpoint
// как на активный, и после Resume запросы не должны уходить на down-endpoint.
func TestRecheckActiveChangedEmitFailureNoStaleActive(t *testing.T) {
	ctx := context.Background()
	var mu sync.Mutex
	primaryCalls := 0
	tr := &stubTransport{post: func(b []byte) (openrouter.Response, error) {
		if providerOf(b) == "inceptron" {
			mu.Lock()
			primaryCalls++
			mu.Unlock()
			return openrouter.Response{Status: 503}, nil
		}
		return reply("Wafer", 100, 50), nil
	}}
	sink := &memSink{failOn: "active_changed"}
	rg := newRig(t, &identityMasker{}, tr, "", sink)
	_, err := rg.r.Route(ctx, routeReq(t))
	if !errors.Is(err, ErrAuditFailed) {
		t.Fatalf("ожидается ErrAuditFailed: %v", err)
	}
	consistent := func(st State) error {
		if st.Active != "none" && st.Endpoints[st.Active] != "up" {
			return fmt.Errorf("active=%s, а его endpoint в состоянии %q", st.Active, st.Endpoints[st.Active])
		}
		return nil
	}
	if err := consistent(rg.r.State()); err != nil {
		t.Errorf("после сбоя записи active_changed: %v (state=%+v)", err, rg.r.State())
	}
	sink.failOn = ""
	if err := rg.r.Resume(ctx, "sre-1"); err != nil {
		t.Fatalf("Resume: %v", err)
	}
	if err := consistent(rg.r.State()); err != nil {
		t.Errorf("после Resume: %v (state=%+v)", err, rg.r.State())
	}
	mu.Lock()
	before := primaryCalls
	mu.Unlock()
	req := routeReq(t)
	req.IncidentID = "inc-2"
	res, err := rg.r.Route(ctx, req)
	if err != nil {
		t.Fatalf("Route после Resume: %v", err)
	}
	mu.Lock()
	after := primaryCalls
	mu.Unlock()
	if after != before {
		t.Errorf("после Resume запрос ушёл на down-endpoint (%d попыток), role=%s", after-before, res.Role)
	}
}
