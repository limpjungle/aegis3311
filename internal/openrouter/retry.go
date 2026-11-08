package openrouter

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/limpjungle/aegis3311/internal/pyjson"
)

var RetryStatus = map[int]bool{408: true, 429: true, 500: true, 502: true, 503: true, 504: true,
	520: true, 521: true, 522: true, 523: true, 524: true}
var AbortStatus = map[int]bool{401: true, 402: true, 403: true}

// Kind — результат одной попытки.
type Kind string

const (
	KindOK        Kind = "ok"
	KindRetry     Kind = "retry"
	KindAbort     Kind = "abort"
	KindCaseError Kind = "case_error"
)

// Classify — порт _classify. data — разобранное тело при KindOK. detail — без текста тела ответа:
// для abort это причина ("auth" | "no_endpoint").
func Classify(r Response) (k Kind, detail string, data *pyjson.Value) {
	s := r.Status
	if s == 200 {
		d, err := pyjson.Parse(r.Body)
		if err != nil {
			return KindRetry, "200 with non-JSON body", nil
		}
		if d.Kind != pyjson.Object {
			return KindRetry, "200 with non-object body", nil
		}
		if e := d.Get("error"); e != nil && e.Kind == pyjson.Object {
			if code, ok := pyInt(e.Get("code")); ok && RetryStatus[code] {
				return KindRetry, fmt.Sprintf("200 with error code %d", code), nil
			}
		}
		ch := d.Get("choices")
		if ch == nil || ch.Kind != pyjson.Array || len(ch.Items) == 0 {
			return KindRetry, "200 without choices", nil
		}
		c0 := ch.Items[0]
		if c0.Kind != pyjson.Object || c0.Get("message") == nil || c0.Get("message").Kind != pyjson.Object {
			return KindRetry, "200 with malformed choices", nil
		}
		return KindOK, "", d
	}
	switch {
	case RetryStatus[s]:
		return KindRetry, fmt.Sprintf("http_%d", s), nil
	case AbortStatus[s]:
		return KindAbort, "auth", nil
	case s == 404:
		return KindAbort, "no_endpoint", nil
	}
	return KindCaseError, fmt.Sprintf("http_%d", s), nil
}

// pyInt — int(v) из Python для значения JSON: целое, float (усечение к нулю), bool (0/1), строка с целым.
func pyInt(v *pyjson.Value) (int, bool) {
	if v == nil {
		return 0, false
	}
	switch v.Kind {
	case pyjson.Bool:
		if v.B {
			return 1, true
		}
		return 0, true
	case pyjson.Number:
		if v.IsFloat {
			if math.IsNaN(v.F) || math.Abs(v.F) > 1e9 {
				return 0, false
			}
			return int(v.F), true
		}
		n, err := strconv.Atoi(v.Int)
		return n, err == nil
	case pyjson.String:
		n, err := strconv.Atoi(strings.TrimSpace(v.S))
		return n, err == nil
	}
	return 0, false
}

type Hold interface{}

// Reserver — бюджет: резерв берётся на каждую попытку, расчёт — по факту (порт Budget.reserve/settle).
type Reserver interface {
	Reserve(tokens int64, usd float64) (Hold, bool)
	Settle(h Hold, tokens int64, usd float64)
}

type Reservation struct {
	Tokens int64
	USD    float64
	Prices Prices
}

type Attempt struct {
	N         int
	Kind      Kind
	Transport string // "", "timeout", "network", "oversize"
	Status    int
}

type CallKind string // "ok" | "budget" | "exhausted" | "case_error" | "stopped"

const (
	CallOK        CallKind = "ok"
	CallBudget    CallKind = "budget"
	CallExhausted CallKind = "exhausted"
	CallCaseError CallKind = "case_error"
	CallStopped   CallKind = "stopped"
)

type CallResult struct {
	Kind           CallKind
	Data           *pyjson.Value
	RawBody        []byte // тело последнего ответа (для хеша в decision record); nil, если ответа не было
	Attempts       int
	LastError      string // "transport_timeout" | "transport_network" | "transport_oversize" | "http_<status>" | детали retry без тела
	LastStatus     int
	LatencyMS      int64
	LatencyTotalMS int64
	CostUSD        float64
	Tokens         int64
}

// AbortError — 401/402/403/404: общая для всех запросов проблема, ретраи бессмысленны.
type AbortError struct {
	Reason string // "auth" | "no_endpoint"
	Status int
}

func (e *AbortError) Error() string {
	return fmt.Sprintf("openrouter: прерывание: %s (http %d)", e.Reason, e.Status)
}

type Client struct {
	url   string
	key   *APIKey // указатель: fmt не печатает содержимое неэкспортируемых вложенных указателей
	tr    Transport
	retry RetryConfig
	sleep func(ctx context.Context, d time.Duration) error
	rand  func() float64
	clock func() time.Time
}

type ClientOption func(*Client)

// WithURL заменяет URL запросов (только через CheckAPIURL: тесты на httptest с loopback).
func WithURL(u string) ClientOption { return func(c *Client) { c.url = u } }
func WithSleep(f func(ctx context.Context, d time.Duration) error) ClientOption {
	return func(c *Client) { c.sleep = f }
}

// WithRand задаёт источник [0,1) для джиттера.
func WithRand(f func() float64) ClientOption { return func(c *Client) { c.rand = f } }

// WithClock задаёт часы для задержек.
func WithClock(f func() time.Time) ClientOption { return func(c *Client) { c.clock = f } }

func ctxSleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func NewClient(cfg *Config, key APIKey, tr Transport, opts ...ClientOption) (*Client, error) {
	if tr == nil {
		return nil, errors.New("openrouter: транспорт не задан")
	}
	if key.value() == "" {
		return nil, errors.New("openrouter: ключ API не задан")
	}
	c := &Client{url: cfg.APIURL, key: &key, tr: tr, retry: cfg.Retry, sleep: ctxSleep, rand: rand.Float64, clock: time.Now}
	for _, o := range opts {
		o(c)
	}
	if err := CheckAPIURL(c.url); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Client) headers() http.Header {
	return http.Header{
		"Authorization": {"Bearer " + c.key.value()},
		"Content-Type":  {"application/json"},
		"User-Agent":    {"aegisops-llm-router/1"},
	}
}

func (c *Client) delay(attempt int, h http.Header) time.Duration {
	d := math.Min(c.retry.MaxDelay.Seconds(), c.retry.BaseDelay.Seconds()*math.Pow(2, float64(attempt-1))) * (0.5 + 0.5*c.rand())
	if h != nil {
		if ra, err := strconv.ParseFloat(strings.TrimSpace(h.Get("Retry-After")), 64); err == nil && ra >= 0 {
			d = math.Min(math.Max(d, ra), c.retry.MaxDelay.Seconds())
		}
	}
	return time.Duration(d * float64(time.Second))
}

// Call — порт call_with_retries. onAttempt вызывается после каждой попытки; true — прекратить
// (роутер так останавливает ретраи на упавшем endpoint'е) → CallStopped. Отмена ctx → CallStopped.
// 401/402/403/404 → (CallResult, *AbortError).
func (c *Client) Call(ctx context.Context, body []byte, b Reserver, res Reservation, onAttempt func(Attempt) bool) (CallResult, error) {
	var (
		cr    CallResult
		start = c.clock()
	)
	finish := func(k CallKind) CallResult {
		cr.Kind = k
		cr.LatencyTotalMS = c.clock().Sub(start).Milliseconds()
		return cr
	}
	notify := func(a Attempt) bool { return onAttempt != nil && onAttempt(a) }
	for n := 1; n <= c.retry.MaxAttempts; n++ {
		if ctx.Err() != nil {
			return finish(CallStopped), nil
		}
		hold, ok := b.Reserve(res.Tokens, res.USD)
		if !ok {
			return finish(CallBudget), nil
		}
		cr.Attempts = n
		actx, cancel := context.WithTimeout(ctx, c.retry.Timeout)
		t1 := c.clock()
		resp, err := c.tr.Post(actx, c.url, c.headers(), body)
		cancel()
		cr.LatencyMS = c.clock().Sub(t1).Milliseconds()
		var retryHdr http.Header
		var att Attempt
		if err != nil {
			var te *TransportError
			kind := "network"
			if errors.As(err, &te) {
				kind = te.Kind
			}
			// timeout и oversize: запрос мог быть обработан и оплачен — списывается весь резерв.
			// Отмена вызывающим (ctx) при полёте запроса трактуется так же: платёж неизвестен.
			if kind == "timeout" || kind == "oversize" || ctx.Err() != nil {
				b.Settle(hold, res.Tokens, res.USD)
				cr.CostUSD, cr.Tokens = cr.CostUSD+res.USD, cr.Tokens+res.Tokens
				if ctx.Err() != nil { // остановка вызывающим — не сбой endpoint'а
					cr.LastError = "transport_" + kind
					return finish(CallStopped), nil
				}
			} else {
				b.Settle(hold, 0, 0)
			}
			cr.LastError, cr.LastStatus, cr.RawBody = "transport_"+kind, 0, nil
			att = Attempt{N: n, Kind: KindRetry, Transport: kind}
		} else {
			cr.RawBody, cr.LastStatus = resp.Body, resp.Status
			kind, detail, data := Classify(resp)
			att = Attempt{N: n, Kind: kind, Status: resp.Status}
			switch kind {
			case KindOK:
				tok, usd := res.Tokens, res.USD // без usage — весь резерв
				if p, cmp, okU := usageNumbers(data); okU {
					tok = int64(p + cmp)
					usd = CostOf(p, cmp, res.Prices)
					if rep, okC := num(data.Get("usage").Get("cost")); okC {
						usd = math.Max(usd, rep)
					}
				}
				b.Settle(hold, tok, usd)
				cr.CostUSD, cr.Tokens = cr.CostUSD+usd, cr.Tokens+tok
				cr.Data, cr.LastError = data, ""
				notify(att)
				return finish(CallOK), nil
			case KindAbort:
				b.Settle(hold, 0, 0)
				cr.LastError = detail
				notify(att)
				return finish(CallStopped), &AbortError{Reason: detail, Status: resp.Status}
			case KindCaseError:
				b.Settle(hold, 0, 0)
				cr.LastError = detail
				notify(att)
				return finish(CallCaseError), nil
			}
			b.Settle(hold, 0, 0)
			cr.LastError, retryHdr = detail, resp.Header
		}
		if notify(att) {
			return finish(CallStopped), nil
		}
		if n >= c.retry.MaxAttempts {
			break
		}
		if err := c.sleep(ctx, c.delay(n, retryHdr)); err != nil {
			return finish(CallStopped), nil
		}
	}
	return finish(CallExhausted), nil
}

// usageNumbers — usage с числовыми prompt_tokens и completion_tokens (как _usage_numbers).
func usageNumbers(data *pyjson.Value) (p, c float64, ok bool) {
	u := data.Get("usage")
	if u == nil || u.Kind != pyjson.Object {
		return 0, 0, false
	}
	p, ok1 := num(u.Get("prompt_tokens"))
	c, ok2 := num(u.Get("completion_tokens"))
	// Отрицательные, нецелые и непредставимые значения — не usage: списывается весь резерв.
	return p, c, ok1 && ok2 && tokenCount(p) && tokenCount(c)
}

// tokenCount — число токенов: целое от 0 до 2^53 (NaN и Inf отсекаются сравнениями).
func tokenCount(f float64) bool { return f >= 0 && f <= 1<<53 && f == math.Trunc(f) }
