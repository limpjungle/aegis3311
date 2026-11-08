package openrouter

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// runtimeMarker — маркер для проверки утечек ключа. Генерируется в рантайме, литералов, похожих на ключи, нет.
func runtimeMarker(t testing.TB) string {
	t.Helper()
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return "mk-" + hex.EncodeToString(b[:])
}

// rawTr — транспорт с заранее заданными ответами.
type rawTr struct {
	post, get       Response
	postErr, getErr error
}

func (f *rawTr) Post(context.Context, string, http.Header, []byte) (Response, error) {
	return f.post, f.postErr
}

func (f *rawTr) Get(context.Context, string, http.Header) (Response, error) {
	return f.get, f.getErr
}

func noSleep(context.Context, time.Duration) error { return nil }

// Клиент не печатает ключ ни через %v, ни через %+v, ни через %#v (ключ — в неэкспортируемом поле).
func TestClientFormattingNeverShowsKey(t *testing.T) {
	a := loadReal(t)
	key := runtimeMarker(t)
	cl, err := NewClient(&a.Config, APIKey{key}, &rawTr{})
	if err != nil {
		t.Fatal(err)
	}
	for name, s := range map[string]string{
		"%v":        fmt.Sprintf("%v", cl),
		"%+v":       fmt.Sprintf("%+v", cl),
		"%#v":       fmt.Sprintf("%#v", cl),
		"%+v копии": fmt.Sprintf("%+v", *cl),
	} {
		if strings.Contains(s, key) {
			t.Errorf("ключ попал в вывод fmt (%s)", name)
		}
	}
}

// Ошибки и результаты вызова не содержат ключа, даже если сервер или транспорт его повторяют.
func TestErrorsNeverCarryKey(t *testing.T) {
	a := loadReal(t)
	ctx := context.Background()
	key := runtimeMarker(t)

	// 401 с эхом ключа в теле.
	tr := &rawTr{post: Response{Status: 401, Body: []byte("bad key " + key)}}
	cl, err := NewClient(&a.Config, APIKey{key}, tr, WithSleep(noSleep))
	if err != nil {
		t.Fatal(err)
	}
	cr, err := cl.Call(ctx, []byte(`{}`), &fakeBudget{max: 1 << 40}, res1, nil)
	var ae *AbortError
	if !errors.As(err, &ae) || ae.Reason != "auth" {
		t.Fatalf("ожидается AbortError auth: %v", err)
	}
	if strings.Contains(err.Error(), key) || strings.Contains(cr.LastError, key) {
		t.Error("401: ключ в ошибке или LastError")
	}

	// 429 с эхом ключа: повтор, без текста тела.
	tr = &rawTr{post: Response{Status: 429, Body: []byte("rate limited for " + key)}}
	cl, _ = NewClient(&a.Config, APIKey{key}, tr, WithSleep(noSleep))
	cr, _ = cl.Call(ctx, []byte(`{}`), &fakeBudget{max: 1 << 40}, res1, nil)
	if strings.Contains(cr.LastError, key) {
		t.Error("429: ключ в LastError")
	}

	// Сетевая ошибка, в тексте которой есть ключ: в LastError попадает только вид ошибки.
	tr = &rawTr{postErr: errors.New("dial " + key)}
	cl, _ = NewClient(&a.Config, APIKey{key}, tr, WithSleep(noSleep))
	cr, err = cl.Call(ctx, []byte(`{}`), &fakeBudget{max: 1 << 40}, res1, nil)
	if err != nil || strings.Contains(cr.LastError, key) {
		t.Errorf("сетевая ошибка: %v %q", err, cr.LastError)
	}

	// EndpointsHealth: 401 с эхом ключа — только статус.
	tr = &rawTr{get: Response{Status: 401, Body: []byte("bad key " + key)}}
	cl, _ = NewClient(&a.Config, APIKey{key}, tr)
	h := cl.EndpointsHealth(ctx, &a.Config, a.Primary)
	if strings.Contains(h.Err, key) || h.Status != 401 {
		t.Errorf("health 401: %+v", h)
	}
}

// Транспорт, вернувший ошибку с текстом ключа (не TransportError), не должен протаскивать текст в Health.Err.
// Защита в глубину: штатный транспорт возвращает только TransportError.
func TestHealthErrorTextNeverCarriesKey(t *testing.T) {
	a := loadReal(t)
	key := runtimeMarker(t)
	tr := &rawTr{getErr: errors.New("connect with " + key)}
	cl, err := NewClient(&a.Config, APIKey{key}, tr)
	if err != nil {
		t.Fatal(err)
	}
	h := cl.EndpointsHealth(context.Background(), &a.Config, a.Primary)
	if strings.Contains(h.Err, key) {
		t.Error("текст ошибки транспорта с ключом попал в Health.Err")
	}
}

// Health: провайдер совпадает, но квантование или набор параметров — нет.
func TestHealthRequiresQuantizationAndParameters(t *testing.T) {
	a := loadReal(t)
	ctx := context.Background()
	key := runtimeMarker(t)
	cases := map[string]struct {
		body string
		ok   bool
	}{
		"совпадает":                {`{"data":{"endpoints":[{"provider_name":"INCEPTRON","quantization":"fp8","supported_parameters":["response_format","structured_outputs","seed"]}]}}`, true},
		"чужое квантование":        {`{"data":{"endpoints":[{"provider_name":"Inceptron","quantization":"bf16","supported_parameters":["response_format","structured_outputs","seed"]}]}}`, false},
		"нет structured":           {`{"data":{"endpoints":[{"provider_name":"Inceptron","quantization":"fp8","supported_parameters":["response_format","seed"]}]}}`, false},
		"нет response_format":      {`{"data":{"endpoints":[{"provider_name":"Inceptron","quantization":"fp8","supported_parameters":["structured_outputs","seed"]}]}}`, false},
		"провайдер не из профиля":  {`{"data":{"endpoints":[{"provider_name":"Other","quantization":"fp8","supported_parameters":["response_format","structured_outputs","seed"]}]}}`, false},
		"нет supported_parameters": {`{"data":{"endpoints":[{"provider_name":"Inceptron","quantization":"fp8"}]}}`, false},
	}
	for name, c := range cases {
		cl, err := NewClient(&a.Config, APIKey{key}, &rawTr{get: Response{Status: 200, Body: []byte(c.body)}})
		if err != nil {
			t.Fatal(err)
		}
		if h := cl.EndpointsHealth(ctx, &a.Config, a.Primary); h.OK != c.ok {
			t.Errorf("%s: OK=%v, ожидается %v (%s)", name, h.OK, c.ok, h.Err)
		}
	}
}

// Оверсайз и таймаут списывают весь резерв за каждую попытку, сетевой сбой — ничего.
func TestOversizeChargesFullReserve(t *testing.T) {
	a := loadReal(t)
	key := runtimeMarker(t)
	for _, c := range []struct {
		kind string
		want int64
	}{{"oversize", 6 * res1.Tokens}, {"network", 0}} {
		b := &fakeBudget{max: 1 << 40}
		cl, _ := NewClient(&a.Config, APIKey{key}, &rawTr{postErr: &TransportError{Kind: c.kind}}, WithSleep(noSleep))
		if _, err := cl.Call(context.Background(), []byte(`{}`), b, res1, nil); err != nil {
			t.Fatal(err)
		}
		var sum int64
		for _, s := range b.settled {
			sum += s
		}
		if sum != c.want {
			t.Errorf("%s: списано %d, ожидается %d", c.kind, sum, c.want)
		}
	}
}

// cancelTr отменяет ctx во время полёта запроса и возвращает сетевую ошибку.
type cancelTr struct{ cancel context.CancelFunc }

func (c *cancelTr) Post(context.Context, string, http.Header, []byte) (Response, error) {
	c.cancel()
	return Response{}, &TransportError{Kind: "network"}
}

func (c *cancelTr) Get(context.Context, string, http.Header) (Response, error) {
	return Response{}, nil
}

// Отмена вызывающим во время полёта: остановка (не сбой endpoint'а), onAttempt не вызывается,
// резерв списан целиком (платёж неизвестен) и совпадает с учтённым в CallResult.
func TestCancelInFlightChargesReserveWithoutAttempt(t *testing.T) {
	a := loadReal(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cl, err := NewClient(&a.Config, APIKey{runtimeMarker(t)}, &cancelTr{cancel}, WithSleep(noSleep))
	if err != nil {
		t.Fatal(err)
	}
	b := &fakeBudget{max: 1 << 40}
	notified := 0
	cr, err := cl.Call(ctx, []byte(`{}`), b, res1, func(Attempt) bool { notified++; return false })
	if err != nil || cr.Kind != CallStopped || cr.Attempts != 1 {
		t.Fatalf("%v kind=%s attempts=%d", err, cr.Kind, cr.Attempts)
	}
	if notified != 0 {
		t.Errorf("onAttempt вызван %d раз при отмене вызывающим", notified)
	}
	var sum int64
	for _, s := range b.settled {
		sum += s
	}
	if sum != res1.Tokens || cr.Tokens != res1.Tokens {
		t.Errorf("списано %d, в CallResult %d, ожидается резерв %d", sum, cr.Tokens, res1.Tokens)
	}
}
