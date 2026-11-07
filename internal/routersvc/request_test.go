package routersvc

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/limpjungle/aegis3311/internal/openrouter"
)

func TestParseRequest(t *testing.T) {
	req, meta, err := ParseRequest(requestJSON("hybrid"))
	if err != nil {
		t.Fatal(err)
	}
	if req.IncidentID != "inc-1" || req.Service != "geo-svc" || string(req.Mode) != "hybrid" || len(req.Sections) != 1 ||
		meta.ID != "inc-1" || meta.Environment != "staging" || meta.Service != "geo-svc" {
		t.Fatalf("%+v %+v", req, meta)
	}
	// null — допустимое значение.
	if _, _, err := ParseRequest([]byte(strings.Replace(string(requestJSON("hybrid")), `{"n":1}`, `null`, 1))); err != nil {
		t.Errorf("null: %v", err)
	}
}

func TestParseRequestInvalid(t *testing.T) {
	ok := string(requestJSON("hybrid"))
	cases := map[string]string{
		"неизвестное поле":   strings.Replace(ok, `"mode"`, `"zzz":1,"mode"`, 1),
		"неизвестное во фр.": strings.Replace(ok, `"required"`, `"zzz":1,"required"`, 1),
		"дубль ключа":        strings.Replace(ok, `"mode":"hybrid"`, `"mode":"hybrid","mode":"off"`, 1),
		"дубль внутри value": strings.Replace(ok, `{"n":1}`, `{"n":1,"n":2}`, 1),
		"пустой value":       strings.Replace(ok, `,"value":{"n":1}`, ``, 1),
		"нет environment":    strings.Replace(ok, `"environment":"staging",`, ``, 1),
		"не JSON":            `x`,
		"мусор после":        ok + ` {}`,
	}
	for name, s := range cases {
		if _, _, err := ParseRequest([]byte(s)); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
	// Неизвестный kind ловит валидация роутера (Route/Prepare), не ParseRequest.
	f := newFixture(t)
	rt := f.mustOpen(true)
	defer rt.Close()
	req, _, err := ParseRequest([]byte(strings.Replace(ok, `"generic"`, `"weird"`, 1)))
	if err != nil {
		return // строгий разбор тоже допустим
	}
	if res, err := rt.Router.Route(context.Background(), req); err == nil && (res == nil || res.Outcome == "sent") {
		t.Errorf("неизвестный kind принят: %+v", res)
	}
	big := make([]byte, MaxRequestBytes+1)
	if _, _, err := ParseRequest(big); err == nil || !strings.Contains(err.Error(), "больше") {
		t.Errorf("лимит: %v", err)
	}
}

func shadow(t *testing.T, rt *Runtime, mode string) {
	t.Helper()
	req, meta, err := ParseRequest(requestJSON(mode))
	must(t, err)
	res, rerr := rt.Router.Route(context.Background(), req)
	if res == nil {
		t.Fatalf("res nil: %v", rerr)
	}
	rec := ShadowRecord(meta, "alice", time.Now(), res)
	if err := rec.Validate(); err != nil {
		t.Fatalf("%s/%s/%s: %v", res.Outcome, res.Reason, mode, err)
	}
	if rec.Mode != "dry-run" || rec.AutonomyLevel != "L0" || rec.Initiator.Kind != "human" || rec.Initiator.ID != "alice" ||
		rec.Incident.Environment != "staging" || rec.Verdict != nil || len(rec.RetrievedDocs) != 0 {
		t.Fatalf("%+v", rec)
	}
	if _, err := rt.Writer.Append(rec); err != nil {
		t.Fatalf("Append: %v", err)
	}
}

func TestShadowRecordValid(t *testing.T) {
	f := newFixture(t)
	rt := f.mustOpen(true)
	defer rt.Close()
	shadow(t, rt, "hybrid") // sent
	if p, _ := f.tr.counts(); p != 1 {
		t.Fatalf("POST: %d", p)
	}
	shadow(t, rt, "off") // not_sent / mode_off
	if p, _ := f.tr.counts(); p != 1 {
		t.Fatalf("mode off обратился к сети: %d", p)
	}
	_, st := f.verifyChain()
	if st.Records != 2 {
		t.Fatalf("decision record'ов: %d", st.Records)
	}
}

func TestShadowRecordHalted(t *testing.T) {
	f := newFixture(t)
	f.mustOpen(true).Close()
	must(t, os.Remove(f.cfg.StatePath))
	rt := f.mustOpen(true)
	defer rt.Close()
	if !rt.Status().Halted {
		t.Fatal("не halted")
	}
	shadow(t, rt, "hybrid") // not_sent / halted
	if p, _ := f.tr.counts(); p != 0 {
		t.Fatalf("halted отправил запрос: %d", p)
	}
}

func TestRouteAuthHalts(t *testing.T) {
	f := newFixture(t)
	f.tr.post = func([]byte) (openrouter.Response, error) {
		return openrouter.Response{Status: 401, Body: []byte(`{}`)}, nil
	}
	rt := f.mustOpen(true)
	defer rt.Close()
	shadow(t, rt, "hybrid")
	if st := rt.Status(); !st.Halted || st.HaltReason != "auth" {
		t.Fatalf("%+v", st)
	}
}
