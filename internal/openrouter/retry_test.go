package openrouter

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeTr struct {
	mu    sync.Mutex
	resp  []any // Response или error
	calls int
}

func (f *fakeTr) Post(context.Context, string, http.Header, []byte) (Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	i := f.calls
	f.calls++
	if i >= len(f.resp) {
		i = len(f.resp) - 1
	}
	if e, ok := f.resp[i].(error); ok {
		return Response{}, e
	}
	return f.resp[i].(Response), nil
}
func (f *fakeTr) Get(context.Context, string, http.Header) (Response, error) {
	return f.resp[0].(Response), nil
}

type fakeBudget struct {
	mu          sync.Mutex
	max         int64
	held, spent int64
	reserves    int
	settled     []int64
}

func (b *fakeBudget) Reserve(tokens int64, _ float64) (Hold, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.reserves++
	if b.spent+b.held+tokens > b.max {
		return nil, false
	}
	b.held += tokens
	return tokens, true
}
func (b *fakeBudget) Settle(h Hold, tokens int64, _ float64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.held -= h.(int64)
	b.spent += tokens
	b.settled = append(b.settled, tokens)
}

func okResp(usage string) Response {
	return Response{Status: 200, Body: []byte(`{"choices":[{"message":{"content":"x"}}]` + usage + `}`)}
}

func testClient(t *testing.T, tr Transport, sleeps *[]time.Duration, opts ...ClientOption) *Client {
	a := loadReal(t)
	opts = append([]ClientOption{WithRand(func() float64 { return 0.999 }), WithSleep(func(_ context.Context, d time.Duration) error {
		if sleeps != nil {
			*sleeps = append(*sleeps, d)
		}
		return nil
	})}, opts...)
	c, err := NewClient(&a.Config, APIKey{rtSecret()}, tr, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

var res1 = Reservation{Tokens: 1000, USD: 0.5, Prices: Prices{1, 2}}

func TestCall429_503_200(t *testing.T) {
	tr := &fakeTr{resp: []any{Response{Status: 429}, Response{Status: 503}, okResp(`,"usage":{"prompt_tokens":100,"completion_tokens":50,"cost":0.9}`)}}
	b := &fakeBudget{max: 1 << 30}
	var atts []Attempt
	cr, err := testClient(t, tr, nil).Call(context.Background(), []byte("{}"), b, res1, func(a Attempt) bool { atts = append(atts, a); return false })
	if err != nil || cr.Kind != CallOK || cr.Attempts != 3 || len(atts) != 3 {
		t.Fatalf("%v %+v", err, cr)
	}
	if cr.Tokens != 150 || cr.CostUSD != 0.9 { // cost_reported (0.9) > расчётная стоимость
		t.Errorf("расчёт: %d %v", cr.Tokens, cr.CostUSD)
	}
	if fmt.Sprint(b.settled) != "[0 0 150]" || b.held != 0 {
		t.Errorf("settle %v held %d", b.settled, b.held)
	}
}

func TestBackoffAndRetryAfter(t *testing.T) {
	a := loadReal(t)
	var sleeps []time.Duration
	h := http.Header{"Retry-After": {"1000"}}
	tr := &fakeTr{resp: []any{Response{Status: 503}, Response{Status: 503}, Response{Status: 503}, Response{Status: 503}, Response{Status: 503, Header: h}, Response{Status: 503}}}
	cr, _ := testClient(t, tr, &sleeps).Call(context.Background(), nil, &fakeBudget{max: 1 << 30}, res1, nil)
	if cr.Kind != CallExhausted || cr.Attempts != a.Config.Retry.MaxAttempts {
		t.Fatalf("%+v", cr)
	}
	// base 1s, max 60s, rand 0.999: 0.9995·{1,2,4,8}, затем Retry-After → потолок 60.
	want := []float64{0.9995, 1.999, 3.998, 7.996, 60}
	for i, w := range want {
		if d := sleeps[i].Seconds(); d < w-0.01 || d > w+0.01 {
			t.Errorf("задержка %d: %v, ожидается %v", i, d, w)
		}
	}
	// Нечисловой Retry-After игнорируется.
	sleeps = nil
	tr = &fakeTr{resp: []any{Response{Status: 503, Header: http.Header{"Retry-After": {"Wed, 21 Oct 2026 07:28:00 GMT"}}}, okResp("")}}
	testClient(t, tr, &sleeps).Call(context.Background(), nil, &fakeBudget{max: 1 << 30}, res1, nil)
	if len(sleeps) != 1 || sleeps[0].Seconds() > 1 {
		t.Errorf("%v", sleeps)
	}
}

func TestTimeoutChargesReserveAndNoUsage(t *testing.T) {
	tr := &fakeTr{resp: []any{&TransportError{"timeout"}, &TransportError{"network"}, okResp("")}}
	b := &fakeBudget{max: 1 << 30}
	cr, err := testClient(t, tr, nil).Call(context.Background(), nil, b, res1, nil)
	if err != nil || cr.Kind != CallOK {
		t.Fatal(err, cr)
	}
	if fmt.Sprint(b.settled) != "[1000 0 1000]" || cr.Tokens != 2000 { // timeout и ответ без usage — весь резерв
		t.Errorf("%v %d", b.settled, cr.Tokens)
	}
}

func TestClassifyAndAborts(t *testing.T) {
	retry := []string{`{"error":{"code":429},"choices":[]}`, `{"error":{"code":"503"}}`, `{"error":{"code":429.0}}`, `{"choices":[]}`,
		`{"choices":[{"message":3}]}`, `{"choices":[3]}`, `not json`, `[]`}
	for _, b := range retry {
		if k, _, _ := Classify(Response{Status: 200, Body: []byte(b)}); k != KindRetry {
			t.Errorf("%s: %s", b, k)
		}
	}
	if k, _, _ := Classify(Response{Status: 200, Body: []byte(`{"error":{"code":true},"choices":[{"message":{}}]}`)}); k != KindOK {
		t.Error("bool code")
	}
	if k, d, _ := Classify(Response{Status: 400, Body: []byte("secret body")}); k != KindCaseError || strings.Contains(d, "secret") {
		t.Errorf("%s %q", k, d)
	}
	bodySecret := rtSecret()
	for st, reason := range map[int]string{401: "auth", 402: "auth", 403: "auth", 404: "no_endpoint"} {
		tr := &fakeTr{resp: []any{Response{Status: st, Body: []byte(bodySecret)}}}
		cr, err := testClient(t, tr, nil).Call(context.Background(), nil, &fakeBudget{max: 1 << 30}, res1, nil)
		var ae *AbortError
		if !errors.As(err, &ae) || ae.Reason != reason || strings.Contains(err.Error(), bodySecret) || cr.Attempts != 1 {
			t.Errorf("%d: %v", st, err)
		}
	}
	tr := &fakeTr{resp: []any{Response{Status: 400}}}
	if cr, err := testClient(t, tr, nil).Call(context.Background(), nil, &fakeBudget{max: 1 << 30}, res1, nil); err != nil || cr.Kind != CallCaseError || tr.calls != 1 {
		t.Errorf("case_error: %v %+v", err, cr)
	}
}

func TestCallStopAndBudget(t *testing.T) {
	tr := &fakeTr{resp: []any{Response{Status: 503}}}
	cr, _ := testClient(t, tr, nil).Call(context.Background(), nil, &fakeBudget{max: 1 << 30}, res1, func(a Attempt) bool { return a.N == 2 })
	if cr.Kind != CallStopped || cr.Attempts != 2 {
		t.Errorf("onAttempt: %+v", cr)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if cr, _ := testClient(t, tr, nil).Call(ctx, nil, &fakeBudget{max: 1 << 30}, res1, nil); cr.Kind != CallStopped || cr.Attempts != 0 {
		t.Errorf("ctx: %+v", cr)
	}
	tr2 := &fakeTr{resp: []any{okResp("")}}
	if cr, _ := testClient(t, tr2, nil).Call(context.Background(), nil, &fakeBudget{max: 10}, res1, nil); cr.Kind != CallBudget || tr2.calls != 0 {
		t.Errorf("budget: %+v", cr)
	}
}

func TestConcurrentReservationsNeverExceedCap(t *testing.T) {
	b := &fakeBudget{max: 5000}
	tr := &fakeTr{resp: []any{okResp(`,"usage":{"prompt_tokens":400,"completion_tokens":100}`)}}
	c := testClient(t, tr, nil)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); c.Call(context.Background(), nil, b, res1, nil) }()
	}
	wg.Wait()
	if b.spent > b.max || b.held != 0 {
		t.Errorf("spent %d held %d", b.spent, b.held)
	}
}
