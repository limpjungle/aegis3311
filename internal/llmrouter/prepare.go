package llmrouter

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/limpjungle/aegis3311/internal/dataclass"
	"github.com/limpjungle/aegis3311/internal/openrouter"
	"github.com/limpjungle/aegis3311/internal/pyjson"
)

// Причины исключения фрагмента: "source_class" (класс по источнику не допускает внешний LLM, маскировщик не
// вызывается), "unknown_source" (то же, но источник не в реестре), "masker_failure", "personal_data",
// "unknown_category", "malformed" (ошибка фильтра меток). Причина отбрасывания по потолку: "context_ceiling".
const reasonCeiling = "context_ceiling"

// FragmentRef — фрагмент, не попавший в запрос.
type FragmentRef struct {
	ID, Source string
	Class      dataclass.Class
	Reason     string
	Required   bool
}

// Prepared — запрос, готовый к отправке (или причина, по которой его нет).
type Prepared struct {
	Profile        *openrouter.Profile
	Role           Role
	Body           []byte // ровно эти байты уходят в POST
	RequestSHA256  string // hex sha256(Body)
	InputSHA256    string // hex sha256 содержимого user-сообщения
	EstInputTokens int
	MaxTokens      int
	DataClass      dataclass.Class // Max по включённым фрагментам; при пустом наборе — Public
	Sources        []string        // отсортированные уникальные источники включённых фрагментов
	Excluded       []FragmentRef   // в порядке фрагментов запроса
	Dropped        []FragmentRef   // в порядке отбрасывания
	LabelsDropped  int
	MaskerVersion  string
	NotSent        string     // "" | "required_excluded" | "context_ceiling"
	masked         *maskedSet // для пересборки под другой профиль при failover без повторного маскирования
}

type secInfo struct {
	key  string
	list bool
}

type maskedFrag struct {
	sec      int
	frag     Fragment // исходный фрагмент (без Value)
	included bool
	value    *pyjson.Value
	class    dataclass.Class
}

type maskedSet struct {
	secs          []secInfo
	frags         []maskedFrag // в порядке секций и элементов
	excluded      []FragmentRef
	labelsDropped int
	maskerVersion string
	notSent       string
}

// Prepare: маскирование, гейт, сборка и потолок для профиля роли role. Сети нет, бюджет не трогается.
// При req.Mode == ModeOff — ошибка (вызывать не нужно: Route обрабатывает off раньше).
func (r *Router) Prepare(ctx context.Context, req Request, role Role) (*Prepared, error) {
	if err := req.validate(); err != nil {
		return nil, err
	}
	if req.Mode == ModeOff {
		return nil, errors.New("llmrouter: Prepare при mode off не вызывается")
	}
	if role != RolePrimary && role != RoleFallback {
		return nil, fmt.Errorf("llmrouter: неизвестная роль %q", role)
	}
	return r.build(r.mask(ctx, req), role)
}

// mask — гейт по источнику, фильтр меток, маскировщик и повышение класса для каждого фрагмента.
func (r *Router) mask(ctx context.Context, req Request) *maskedSet {
	set := &maskedSet{maskerVersion: r.o.Masker.Version()}
	for si, sec := range req.Sections {
		set.secs = append(set.secs, secInfo{sec.Key, sec.List})
		for _, f := range sec.Fragments {
			mf := maskedFrag{sec: si, frag: f}
			mf.frag.Value = nil
			src, known := r.o.Sources.Lookup(f.Source)
			cls := src.Class
			exclude := func(c dataclass.Class, reason string) {
				mf.class = c
				set.excluded = append(set.excluded, FragmentRef{ID: f.ID, Source: f.Source, Class: c, Reason: reason, Required: f.Required})
				if f.Required {
					set.notSent = "required_excluded"
				}
				set.frags = append(set.frags, mf)
			}
			if !dataclass.ExternalAllowed(src, cls) { // маскировщик не вызывается: запрещённые данные никому не передаются
				reason := "source_class"
				if !known {
					reason = "unknown_source"
				}
				exclude(cls, reason)
				continue
			}
			val := f.Value
			if f.Kind == KindMetricSeries {
				v, dropped, err := r.o.Labels.FilterSeries(val)
				if err != nil {
					exclude(dataclass.Restricted, "malformed")
					continue
				}
				val, set.labelsDropped = v, set.labelsDropped+dropped
			}
			masked, rep, err := r.callMasker(ctx, dataclass.FragmentMeta{IncidentID: req.IncidentID, FragmentID: f.ID, Source: f.Source, Class: cls}, val)
			if err != nil {
				exclude(dataclass.Restricted, "masker_failure")
				continue
			}
			cls2, why := dataclass.Escalate(cls, rep)
			if !dataclass.ExternalAllowed(src, cls2) {
				exclude(cls2, why)
				continue
			}
			mf.included, mf.value, mf.class = true, masked, cls2
			set.frags = append(set.frags, mf)
		}
	}
	return set
}

// callMasker вызывает маскировщик на копии значения с таймаутом; ошибка, паника, nil и истёкший ctx — сбой.
// Failed в отчёте обрабатывает Escalate.
func (r *Router) callMasker(ctx context.Context, meta dataclass.FragmentMeta, v *pyjson.Value) (*pyjson.Value, dataclass.MaskReport, error) {
	if ctx.Err() != nil { // отменённый ctx — детерминированный сбой, без гонки с горутиной
		return nil, dataclass.MaskReport{}, errors.New("контекст отменён")
	}
	mctx, cancel := context.WithTimeout(ctx, r.maskTimeout)
	defer cancel()
	type result struct {
		v   *pyjson.Value
		rep dataclass.MaskReport
		err error
	}
	ch := make(chan result, 1)
	in := v.Clone()
	go func() {
		defer func() {
			if p := recover(); p != nil {
				ch <- result{err: errors.New("паника маскировщика")}
			}
		}()
		mv, rep, err := r.o.Masker.Mask(mctx, meta, in)
		ch <- result{mv, rep, err}
	}()
	select {
	case o := <-ch:
		if o.err == nil && (o.v == nil || mctx.Err() != nil) {
			o.err = errors.New("маскировщик не вернул значение")
		}
		return o.v, o.rep, o.err
	case <-mctx.Done():
		return nil, dataclass.MaskReport{}, errors.New("таймаут маскировщика")
	}
}

// buildInput собирает input: объект по секциям в исходном порядке.
func buildInput(set *maskedSet, dropped map[string]bool) *pyjson.Value {
	in := pyjson.NewObject()
	i := 0
	for si, sec := range set.secs {
		var items []*pyjson.Value
		for ; i < len(set.frags) && set.frags[i].sec == si; i++ {
			f := set.frags[i]
			if f.included && !dropped[f.frag.ID] {
				items = append(items, f.value)
			}
		}
		switch {
		case sec.list:
			if items == nil {
				items = []*pyjson.Value{}
			}
			in.Members = append(in.Members, pyjson.M(sec.key, &pyjson.Value{Kind: pyjson.Array, Items: items}))
		case len(items) == 1:
			in.Members = append(in.Members, pyjson.M(sec.key, items[0]))
		}
	}
	return in
}

// build — сборка тела под профиль роли и потолок контекста.
func (r *Router) build(set *maskedSet, role Role) (*Prepared, error) {
	prof := r.profile(role)
	cfg := &r.o.Assets.Config
	p := &Prepared{Profile: prof, Role: role, MaxTokens: cfg.Generation.MaxTokens, MaskerVersion: set.maskerVersion,
		LabelsDropped: set.labelsDropped, Excluded: append([]FragmentRef(nil), set.excluded...), masked: set}
	dropped := map[string]bool{}
	finish := func() {
		p.DataClass = dataclass.Public
		seen := map[string]bool{}
		for _, f := range set.frags {
			if f.included && !dropped[f.frag.ID] {
				p.DataClass = dataclass.Max(p.DataClass, f.class)
				if !seen[f.frag.Source] {
					seen[f.frag.Source] = true
					p.Sources = append(p.Sources, f.frag.Source)
				}
			}
		}
		sort.Strings(p.Sources)
	}
	if set.notSent != "" {
		p.NotSent = set.notSent
		finish()
		return p, nil
	}
	for {
		body := openrouter.BuildRequest(buildInput(set, dropped), r.o.Assets, prof)
		est := openrouter.EstimateInputTokens(body, cfg)
		if openrouter.OverCeiling(est, p.MaxTokens, cfg) {
			// Кандидаты: включённые необязательные; меньшая релевантность раньше, при равенстве — поздний в запросе.
			pick := -1
			for i, f := range set.frags {
				if !f.included || dropped[f.frag.ID] || f.frag.Required {
					continue
				}
				if pick < 0 || f.frag.Relevance <= set.frags[pick].frag.Relevance {
					pick = i
				}
			}
			if pick < 0 {
				p.NotSent = reasonCeiling
				finish()
				return p, nil
			}
			f := set.frags[pick]
			dropped[f.frag.ID] = true
			p.Dropped = append(p.Dropped, FragmentRef{ID: f.frag.ID, Source: f.frag.Source, Class: f.class, Reason: reasonCeiling})
			continue
		}
		p.Body = openrouter.BodyBytes(body)
		p.EstInputTokens = est
		p.RequestSHA256 = openrouter.SHA256Hex(p.Body)
		p.InputSHA256 = openrouter.SHA256Hex([]byte(body.Get("messages").Items[1].Get("content").S))
		if err := openrouter.AssertRequestSafe(p.Body, cfg, prof); err != nil {
			return nil, err
		}
		finish()
		return p, nil
	}
}
