package llmrouter

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/limpjungle/aegis3311/internal/audit"
	"github.com/limpjungle/aegis3311/internal/masker"
	"github.com/limpjungle/aegis3311/internal/openrouter"
)

// realMasker — production-маскировщик с фиксированным ключом.
func realMasker(t testing.TB) *masker.Masker {
	t.Helper()
	m, err := masker.New(masker.Config{PseudonymKey: bytes.Repeat([]byte{0x42}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// Эталоны проб воспроизводятся побайтно и с реальным маскировщиком: на «чистых» данных он ничего не меняет.
func TestProbeV3ReproducibleRealMasker(t *testing.T) { testProbeReproducibleRealMasker(t, probeV3) }
func TestProbeV4ReproducibleRealMasker(t *testing.T) { testProbeReproducibleRealMasker(t, probeV4) }

func testProbeReproducibleRealMasker(t *testing.T, v probeVersion) {
	cases := v.load(t)
	ctx := context.Background()
	for _, pp := range probeProfiles {
		rf := loadRefs(t, v, pp.name)
		m := realMasker(t)
		rg := newRigAssets(t, v.assets(t), m, &stubTransport{}, "", nil)
		for _, c := range cases {
			req, _ := caseRequest(t, c)
			p, err := rg.r.Prepare(ctx, req, pp.role)
			if err != nil {
				t.Fatalf("%s %s: %v", pp.name, req.IncidentID, err)
			}
			ref := rf.rows[req.IncidentID]
			if ref == nil {
				t.Fatalf("%s: нет в эталоне %s", req.IncidentID, pp.name)
			}
			if p.NotSent != "" || len(p.Excluded) != 0 || len(p.Dropped) != 0 || p.LabelsDropped != 0 || p.DataClass.String() != "internal" {
				t.Fatalf("%s %s: NotSent=%q excluded=%d dropped=%d labels=%d class=%s", pp.name, req.IncidentID, p.NotSent, len(p.Excluded), len(p.Dropped), p.LabelsDropped, p.DataClass)
			}
			if p.MaskerVersion != m.Version() {
				t.Fatalf("MaskerVersion %q != %q", p.MaskerVersion, m.Version())
			}
			wantSHA, wantEst := ref.Get("request_sha256").S, ref.Get("est_input_tokens").Int
			if p.RequestSHA256 != wantSHA || fmt.Sprint(p.EstInputTokens) != wantEst {
				t.Fatalf("%s %s: request_sha256 %s != эталон %s; est_input_tokens %d != %s (реальный маскировщик изменил данные эталона)",
					pp.name, req.IncidentID, p.RequestSHA256, wantSHA, p.EstInputTokens, wantEst)
			}
		}
	}
}

// intRig — роутер с реальным маскировщиком и транспортом, запоминающим тела запросов.
type intRig struct {
	*rig
	m      *masker.Masker
	tr     *stubTransport
	mu     sync.Mutex
	bodies [][]byte
}

func newIntRig(t *testing.T) *intRig {
	t.Helper()
	ir := &intRig{m: realMasker(t)}
	ir.tr = &stubTransport{post: func(b []byte) (openrouter.Response, error) {
		ir.mu.Lock()
		ir.bodies = append(ir.bodies, append([]byte(nil), b...))
		ir.mu.Unlock()
		return reply("Inceptron", 10, 5), nil
	}}
	ir.rig = newRig(t, ir.m, ir.tr, "", nil)
	return ir
}

func (ir *intRig) lastBody(t *testing.T) []byte {
	t.Helper()
	ir.mu.Lock()
	defer ir.mu.Unlock()
	if len(ir.bodies) == 0 {
		t.Fatal("запрос не уходил")
	}
	return ir.bodies[len(ir.bodies)-1]
}

func applyRecord(t *testing.T, res *Result) *audit.DecisionRecord {
	t.Helper()
	rec := &audit.DecisionRecord{Schema: audit.RecordSchema, RecordID: audit.NewRecordID(),
		RecordedAt: audit.Timestamp(time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)), Mode: audit.ModeShadow,
		Incident:  audit.IncidentRef{ID: "inc-1", Service: "geo-svc", Environment: "staging"},
		Initiator: audit.Actor{Kind: "agent", ID: "a1"}, RetrievedDocs: []string{}, AutonomyLevel: "L0"}
	res.Apply(rec)
	if err := rec.Validate(); err != nil {
		t.Fatalf("decision record не проходит Validate: %v", err)
	}
	return rec
}

// Секрет в аннотации алерта вырезается, запрос уходит, класс остаётся internal.
func TestRealMaskerSecretCutAndSent(t *testing.T) {
	ir := newIntRig(t)
	m1, m2 := runtimeMarker(t), runtimeMarker(t)
	marker := strings.TrimPrefix(m1, "mk-")
	secret := ("ghp_" + marker + strings.TrimPrefix(m2, "mk-"))[:44] // 36 символов после префикса
	js := fmt.Sprintf(`{"annotations":{"summary":%q},"n":1}`, "leaked "+secret+" in logs")
	req := simpleReq(t, one("alert", frag(t, "a", "alerts.alertmanager", true, 100, js)))
	res, err := ir.r.Route(context.Background(), req)
	if err != nil || res.Outcome != "sent" {
		t.Fatalf("err=%v outcome=%s reason=%s", err, res.Outcome, res.Reason)
	}
	body := ir.lastBody(t)
	if bytes.Contains(body, []byte(secret)) || bytes.Contains(body, []byte(marker)) {
		t.Error("секрет ушёл в тело запроса")
	}
	if !bytes.Contains(body, []byte("<SECRET_REMOVED>")) {
		t.Error("в теле нет заглушки <SECRET_REMOVED>")
	}
	if res.Prepared.DataClass.String() != "internal" || len(res.Prepared.Excluded) != 0 {
		t.Errorf("класс %s, исключено %d", res.Prepared.DataClass, len(res.Prepared.Excluded))
	}
	rec := applyRecord(t, res)
	if rec.LLM.Masker != ir.m.Version() || rec.LLM.DataClass != "internal" {
		t.Errorf("llm: masker=%q class=%q", rec.LLM.Masker, rec.LLM.DataClass)
	}
	if strings.Contains(decisionJSON(t, res), secret) {
		t.Error("секрет попал в decision record")
	}
}

// Email в необязательном фрагменте: фрагмент исключён (personal_data), остальное отправлено.
func TestRealMaskerPersonalOptionalExcluded(t *testing.T) {
	ir := newIntRig(t)
	email := "u" + strings.ToLower(strings.ReplaceAll(runtimeMarker(t), "-", "")) + "@example.org"
	req := simpleReq(t,
		one("alert", frag(t, "a", "alerts.alertmanager", true, 100, `{"n":1}`)),
		list("k8s_events", frag(t, "e1", "k8s.events", false, 40, fmt.Sprintf(`{"message":%q}`, "notified "+email)),
			frag(t, "e2", "k8s.events", false, 40, `{"message":"pod restarted"}`)))
	res, err := ir.r.Route(context.Background(), req)
	if err != nil || res.Outcome != "sent" {
		t.Fatalf("err=%v outcome=%s reason=%s", err, res.Outcome, res.Reason)
	}
	ex := res.Prepared.Excluded
	if len(ex) != 1 || ex[0].ID != "e1" || ex[0].Reason != "personal_data" {
		t.Fatalf("Excluded = %+v, ожидается e1/personal_data", ex)
	}
	body := ir.lastBody(t)
	if bytes.Contains(body, []byte(email)) || bytes.Contains(body, []byte("<PERSON_")) {
		t.Error("ПДн или её псевдоним ушли в тело запроса")
	}
	if !bytes.Contains(body, []byte("pod restarted")) {
		t.Error("остальные фрагменты должны быть отправлены")
	}
	rec := applyRecord(t, res)
	if len(rec.LLM.ExcludedFragments) != 1 || rec.LLM.ExcludedFragments[0].Reason != "personal_data" {
		t.Errorf("ExcludedFragments: %+v", rec.LLM.ExcludedFragments)
	}
	if strings.Contains(decisionJSON(t, res), email) {
		t.Error("email попал в decision record")
	}
}

// Тот же email в обязательном фрагменте: запрос не уходит.
func TestRealMaskerPersonalRequiredNotSent(t *testing.T) {
	ir := newIntRig(t)
	email := "u" + strings.ToLower(strings.ReplaceAll(runtimeMarker(t), "-", "")) + "@example.org"
	req := simpleReq(t, one("alert", frag(t, "a", "alerts.alertmanager", true, 100, fmt.Sprintf(`{"annotations":{"summary":%q}}`, "user "+email))))
	res, err := ir.r.Route(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != "not_sent" || res.Reason != "required_excluded" || res.Prepared == nil || res.Prepared.NotSent != "required_excluded" {
		t.Fatalf("outcome=%s reason=%s", res.Outcome, res.Reason)
	}
	if ir.tr.calls != 0 {
		t.Errorf("транспорт вызван %d раз", ir.tr.calls)
	}
	if strings.Contains(decisionJSON(t, res), email) {
		t.Error("email попал в decision record")
	}
}
