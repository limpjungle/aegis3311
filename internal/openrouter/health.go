package openrouter

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/limpjungle/aegis3311/internal/pyjson"
)

// Health — результат проверки endpoint'ов модели (порт preflight).
type Health struct {
	OK       bool
	Matching int
	Tags     []string
	Status   int
	Err      string // без текста ответа
}

// EndpointsHealth: один GET {api_url без /chat/completions}/models/{slug}/endpoints с теми же заголовками
// (как preflight), таймаут — retry.timeout_s, без ретраев и без бюджета (вызов бесплатный).
// OK = HTTP 200, разобран data.endpoints, и хотя бы один endpoint совпал: имя провайдера, квантование и
// supported_parameters (response_format, structured_outputs и seed при send_seed).
func (c *Client) EndpointsHealth(ctx context.Context, cfg *Config, p *Profile) Health {
	u := strings.TrimSuffix(c.url, "/chat/completions") + "/models/" + cfg.Model + "/endpoints"
	actx, cancel := context.WithTimeout(ctx, c.retry.Timeout)
	defer cancel()
	resp, err := c.tr.Get(actx, u, c.headers())
	if err != nil {
		kind := "network"
		var te *TransportError
		if errors.As(err, &te) {
			kind = te.Kind
		}
		return Health{Err: "transport_" + kind}
	}
	h := Health{Status: resp.Status}
	if resp.Status != 200 {
		h.Err = "http " + strconv.Itoa(resp.Status)
		return h
	}
	root, err := pyjson.Parse(resp.Body)
	eps := root.Get("data").Get("endpoints")
	if err != nil || eps == nil || eps.Kind != pyjson.Array {
		h.Err = "unexpected response"
		return h
	}
	allowed := map[string]bool{}
	for _, x := range append(append([]string(nil), p.ExpectedProviderNames...), p.Only...) {
		allowed[normName(x)] = true
	}
	need := []string{"response_format", "structured_outputs"}
	if p.SendSeed {
		need = append(need, "seed")
	}
	for _, e := range eps.Items {
		if e.Kind != pyjson.Object || !allowed[normName(strOf(e.Get("provider_name")))] {
			continue
		}
		quant := false
		for _, q := range p.Quantizations {
			quant = quant || q == strOf(e.Get("quantization"))
		}
		sp := map[string]bool{}
		if l := e.Get("supported_parameters"); l != nil && l.Kind == pyjson.Array {
			for _, it := range l.Items {
				sp[strOf(it)] = true
			}
		}
		ok := quant
		for _, k := range need {
			ok = ok && sp[k]
		}
		if ok {
			h.Matching++
			h.Tags = append(h.Tags, strOf(e.Get("tag")))
		}
	}
	h.OK = h.Matching > 0
	if !h.OK {
		h.Err = "no endpoint matches the profile"
	}
	return h
}
