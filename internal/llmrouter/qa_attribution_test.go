package llmrouter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"

	"github.com/limpjungle/aegis3311/internal/audit"
	"github.com/limpjungle/aegis3311/internal/openrouter"
)

// Тесты перепроверки (итерация 4): атрибуция резерва (fallback) в decision record и частичный Result.

func qaSHA(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// qaPrimaryTimeouts: primary всегда отвечает таймаутом (3 подряд → down → переключение).
// fb формирует ответ fallback по номеру его попытки.
func qaPrimaryTimeouts(pn *int, fbBodies *[][]byte, fb func(n int) (openrouter.Response, error)) *stubTransport {
	fn := 0
	return &stubTransport{post: func(b []byte) (openrouter.Response, error) {
		if providerOf(b) == "inceptron" {
			*pn++
			return openrouter.Response{}, &openrouter.TransportError{Kind: "timeout"}
		}
		fn++
		*fbBodies = append(*fbBodies, append([]byte(nil), b...))
		return fb(fn)
	}}
}

// Резерв сделал >= 1 попытку и упал (503 / сеть / таймаут): запись атрибутирует fallback, его тело и хеш ответа.
func TestQAFallbackAttemptsThenFailAttribution(t *testing.T) {
	const fbBody = `{"error":{"code":503,"message":"overloaded"}}`
	cases := []struct {
		name      string
		fb        func(n int) (openrouter.Response, error)
		wantSHA   string // ожидаемый хеш ответа fallback
		wantChars int    // списано за попытки fallback, в резервах
	}{
		{name: "503", fb: func(int) (openrouter.Response, error) {
			return openrouter.Response{Status: 503, Body: []byte(fbBody)}, nil
		}, wantSHA: qaSHA([]byte(fbBody)), wantChars: 0},
		{name: "network", fb: func(int) (openrouter.Response, error) {
			return openrouter.Response{}, &openrouter.TransportError{Kind: "network"}
		}, wantSHA: "", wantChars: 0},
		{name: "timeout", fb: func(int) (openrouter.Response, error) {
			return openrouter.Response{}, &openrouter.TransportError{Kind: "timeout"}
		}, wantSHA: "", wantChars: 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pn := 0
			var fbBodies [][]byte
			tr := qaPrimaryTimeouts(&pn, &fbBodies, c.fb)
			rg := newRig(t, &identityMasker{}, tr, "", nil)
			res, err := rg.r.Route(context.Background(), routeReq(t))
			if err != nil {
				t.Fatal(err)
			}
			if len(fbBodies) == 0 {
				t.Fatal("fallback не получил ни одной попытки")
			}
			if res.Outcome != "sent" || res.ErrorKind != "stopped" {
				t.Errorf("outcome=%s error_kind=%s, ожидается sent/stopped (fallback упал по порогу)", res.Outcome, res.ErrorKind)
			}
			if !res.Switched || res.Role != RoleFallback || res.Prepared.Profile.Name != "wafer-nvfp4" {
				t.Errorf("switched=%v role=%s profile=%s, ожидается switched/fallback/wafer-nvfp4", res.Switched, res.Role, res.Prepared.Profile.Name)
			}
			if res.Attempts != tr.calls {
				t.Errorf("attempts=%d, транспорт вызван %d раз", res.Attempts, tr.calls)
			}
			reserve := int64(res.Prepared.EstInputTokens + res.Prepared.MaxTokens)
			wantTokens := 3*reserve + int64(c.wantChars)*reserve
			if c.name == "timeout" {
				wantTokens = 6 * reserve
			}
			if res.Tokens != wantTokens {
				t.Errorf("учтено %d токенов, ожидается %d", res.Tokens, wantTokens)
			}
			if res.ResponseSHA256 != c.wantSHA {
				t.Errorf("ResponseSHA256=%q, ожидается %q (хеш ответа fallback)", res.ResponseSHA256, c.wantSHA)
			}
			rec := decisionRecord(res)
			if err := rec.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
			if !rec.LLM.EndpointSwitched || rec.Model == nil || rec.Model.EndpointRole != "fallback" || rec.Model.Profile != "wafer-nvfp4" {
				t.Errorf("атрибуция: switched=%v model=%+v", rec.LLM.EndpointSwitched, rec.Model)
			}
			last := fbBodies[len(fbBodies)-1]
			if rec.Prompt == nil || rec.Prompt.RequestSHA256 != "sha256:"+qaSHA(last) {
				t.Errorf("request_sha256 записи не совпадает с телом, которое получил fallback")
			}
			if rec.Answer == nil || rec.Answer.Status != "error" || rec.Answer.Attempts != tr.calls {
				t.Errorf("answer: %+v", rec.Answer)
			}
		})
	}
}

// Переключение, fallback успешен: атрибуция fallback, хеш ответа и хеш тела — от fallback.
func TestQAFallbackSuccessAttribution(t *testing.T) {
	pn := 0
	var fbBodies [][]byte
	var okResp []byte
	tr := qaPrimaryTimeouts(&pn, &fbBodies, func(int) (openrouter.Response, error) {
		r := reply("Wafer", 100, 50)
		okResp = append([]byte(nil), r.Body...)
		return r, nil
	})
	rg := newRig(t, &identityMasker{}, tr, "", nil)
	res, err := rg.r.Route(context.Background(), routeReq(t))
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != "sent" || res.ErrorKind != "" || res.Parsed == nil || res.Parsed.Status != "ok" {
		t.Fatalf("outcome=%s error_kind=%q parsed=%+v", res.Outcome, res.ErrorKind, res.Parsed)
	}
	if res.ResponseSHA256 != qaSHA(okResp) {
		t.Errorf("ResponseSHA256 не совпадает с телом ответа fallback")
	}
	reserve := int64(res.Prepared.EstInputTokens + res.Prepared.MaxTokens)
	if res.Tokens != 3*reserve+150 || res.Attempts != 4 {
		t.Errorf("tokens=%d attempts=%d, ожидается %d и 4", res.Tokens, res.Attempts, 3*reserve+150)
	}
	rec := decisionRecord(res)
	if err := rec.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if rec.Model.Provider != "Wafer" || rec.Model.EndpointRole != "fallback" || !rec.LLM.EndpointSwitched {
		t.Errorf("model=%+v switched=%v", rec.Model, rec.LLM.EndpointSwitched)
	}
	if rec.Prompt.RequestSHA256 != "sha256:"+qaSHA(fbBodies[len(fbBodies)-1]) {
		t.Errorf("request_sha256 не совпадает с телом fallback")
	}
	if rec.Answer.Status != "ok" || rec.Answer.SHA256 != "sha256:"+qaSHA(okResp) {
		t.Errorf("answer: status=%s sha=%s", rec.Answer.Status, rec.Answer.SHA256)
	}
}

// Бюджет отказал fallback после трёх таймаутов primary: записи нужна атрибуция primary.
// Хеш ответа и Call — от последнего ответа primary (503 с телом), а не от пустого вызова резерва.
func TestQABudgetDeniedOnFallbackAfterPrimary503(t *testing.T) {
	const pBody = `{"error":{"code":503}}`
	var rg *rig
	pn := 0
	tr := &stubTransport{post: func(b []byte) (openrouter.Response, error) {
		if providerOf(b) == "inceptron" {
			pn++
			if pn == 3 {
				rg.r.bud.cfg.IncidentTokens = 1
			}
			return openrouter.Response{Status: 503, Body: []byte(pBody)}, nil
		}
		t.Errorf("fallback получил запрос при отказе бюджета")
		return reply("Wafer", 100, 50), nil
	}}
	rg = newRig(t, &identityMasker{}, tr, "", nil)
	res, err := rg.r.Route(context.Background(), routeReq(t))
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != "sent" || res.ErrorKind != "budget" || res.Attempts != 3 {
		t.Fatalf("outcome=%s error_kind=%s attempts=%d, ожидается sent/budget/3", res.Outcome, res.ErrorKind, res.Attempts)
	}
	if res.Switched || res.Role != RolePrimary {
		t.Errorf("switched=%v role=%s, ожидается false/primary", res.Switched, res.Role)
	}
	rec := decisionRecord(res)
	if err := rec.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if rec.LLM.EndpointSwitched || rec.Model == nil || rec.Model.EndpointRole != "primary" || rec.Model.Profile != "inceptron-fp8" {
		t.Errorf("атрибуция: switched=%v model=%+v", rec.LLM.EndpointSwitched, rec.Model)
	}
	if len(rec.Prompt.RequestSHA256) != len("sha256:")+64 {
		t.Errorf("request_sha256 пуст")
	}
	if rec.Answer.SHA256 != "sha256:"+qaSHA([]byte(pBody)) {
		t.Errorf("answer.sha256=%q, ожидается хеш последнего ответа primary", rec.Answer.SHA256)
	}
	if res.Call == nil || res.Call.Attempts != 3 {
		t.Errorf("Call должен быть вызовом primary с 3 попытками: %+v", res.Call)
	}
}

// Переключение и последующий Resume: fallback отвечает 401 (halt auth), после Resume запрос снова уходит на fallback.
// Атрибуция каждого Route — без ложного endpoint_switched; цепочка аудита проходит Verify.
func TestQAFallbackAuthHaltThenResumeAttribution(t *testing.T) {
	ctx := context.Background()
	fbAuth := true
	pn := 0
	tr := &stubTransport{post: func(b []byte) (openrouter.Response, error) {
		if providerOf(b) == "inceptron" {
			pn++
			return openrouter.Response{}, &openrouter.TransportError{Kind: "timeout"}
		}
		if fbAuth {
			return openrouter.Response{Status: 401}, nil
		}
		return reply("Wafer", 100, 50), nil
	}}
	wr := newWriterRig(t, &identityMasker{}, tr)

	// Route 1: переключение на fallback, 401 на fallback — но сначала нужен успех. Поэтому переключение делаем отдельно:
	// первый Route — primary таймауты, fallback отвечает 401 → halt; Resume; затем штатные Route.
	res1, err := wr.r.Route(ctx, routeReq(t))
	if err != nil {
		t.Fatal(err)
	}
	if res1.Outcome != "sent" || res1.ErrorKind != "auth" || !res1.Switched || res1.Role != RoleFallback {
		t.Fatalf("route1: outcome=%s error_kind=%s switched=%v role=%s", res1.Outcome, res1.ErrorKind, res1.Switched, res1.Role)
	}
	if rec := decisionRecord(res1); rec.Validate() != nil || !rec.LLM.EndpointSwitched || rec.Model.EndpointRole != "fallback" {
		t.Fatalf("route1 record: %v %+v", rec.Validate(), rec.Model)
	}

	res2, err := wr.r.Route(ctx, routeReq(t))
	if err != nil {
		t.Fatal(err)
	}
	if res2.Outcome != "not_sent" || res2.Reason != "halted" || res2.DegradeL1 != true {
		t.Fatalf("route2 при halt: outcome=%s reason=%s", res2.Outcome, res2.Reason)
	}
	if rec := decisionRecord(res2); rec.Validate() != nil {
		t.Fatalf("route2 record: %v", rec.Validate())
	}

	fbAuth = false
	if err := wr.r.Resume(ctx, "sre-1"); err != nil {
		t.Fatalf("Resume: %v", err)
	}
	res3, err := wr.r.Route(ctx, routeReq(t))
	if err != nil {
		t.Fatal(err)
	}
	if res3.Outcome != "sent" || res3.ErrorKind != "" || res3.Switched || res3.Role != RoleFallback {
		t.Fatalf("route3 после Resume: outcome=%s error_kind=%q switched=%v role=%s, ожидается sent/без ошибки/false/fallback",
			res3.Outcome, res3.ErrorKind, res3.Switched, res3.Role)
	}
	rec3 := decisionRecord(res3)
	if err := rec3.Validate(); err != nil {
		t.Fatalf("route3 record Validate: %v", err)
	}
	if rec3.LLM.EndpointSwitched || rec3.Model.EndpointRole != "fallback" || rec3.Model.Profile != "wafer-nvfp4" {
		t.Errorf("route3 атрибуция: switched=%v model=%+v", rec3.LLM.EndpointSwitched, rec3.Model)
	}

	// Цепочка: три решения (sent, not_sent/halted, sent) и события пишутся в один файл; Verify проходит.
	for i, res := range []*Result{res1, res2, res3} {
		if _, err := wr.w.Append(decisionRecord(res)); err != nil {
			t.Fatalf("Append решения %d: %v", i+1, err)
		}
	}
	if err := wr.w.Close(); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(wr.chain)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var st audit.VerifyStats
	if _, err := audit.Verify(f, wr.keys, audit.VerifyOptions{Stats: &st}); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if st.Records != 3 || st.RouterEvents == 0 {
		t.Errorf("stats=%+v, ожидается 3 решения и события роутера", st)
	}
}

// Частичный Result при ошибке сборки fallback после попыток primary: sent/stopped, атрибуция primary, запись проходит Validate.
func TestQABuildErrorPartialAttribution(t *testing.T) {
	var rg *rig
	tr := failoverTransport(func(n int) {
		if n == 3 {
			p := *rg.r.eps[RoleFallback].profile
			p.Provider = pj(t, `{"only":["wafer"],"zdr":false,"data_collection":"deny","allow_fallbacks":false}`)
			rg.r.eps[RoleFallback].profile = &p
		}
	})
	rg = newRig(t, &identityMasker{}, tr, "", nil)
	res, err := rg.r.Route(context.Background(), routeReq(t))
	if err == nil || res == nil {
		t.Fatalf("ожидается частичный Result и ошибка, получено res=%v err=%v", res, err)
	}
	if res.Outcome != "sent" || res.ErrorKind != "stopped" || res.Attempts != 3 || res.Switched || res.Role != RolePrimary {
		t.Errorf("outcome=%s error_kind=%s attempts=%d switched=%v role=%s, ожидается sent/stopped/3/false/primary",
			res.Outcome, res.ErrorKind, res.Attempts, res.Switched, res.Role)
	}
	rec := decisionRecord(res)
	if err := rec.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if rec.Model == nil || rec.Model.Profile != "inceptron-fp8" || rec.LLM.EndpointSwitched {
		t.Errorf("атрибуция: model=%+v switched=%v", rec.Model, rec.LLM.EndpointSwitched)
	}
}
