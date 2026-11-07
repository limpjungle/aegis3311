package dataclass

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/limpjungle/aegis3311/internal/pyjson"
)

// LabelPolicy — allowlist меток метрик и шаблоны их значений (data-classes §6 «Метки метрик», T-04).
type LabelPolicy struct{ allowed map[string]*regexp.Regexp }

// NewLabelPolicy: шаблон значения компилируется с якорями ^…$.
func NewLabelPolicy(allowed map[string]string) (*LabelPolicy, error) {
	p := &LabelPolicy{allowed: make(map[string]*regexp.Regexp, len(allowed))}
	for name, pat := range allowed {
		re, err := regexp.Compile("^(?:" + pat + ")$")
		if err != nil {
			return nil, fmt.Errorf("dataclass: шаблон метки %q: %w", name, err)
		}
		p.allowed[name] = re
	}
	return p, nil
}

// MVPLabelPolicy — allowlist MVP: имена в стиле DNS для идентификаторов, цифры для limit_mb, короткий идентификатор для source.
func MVPLabelPolicy() *LabelPolicy {
	const dns = `[a-z0-9][a-z0-9._-]{0,252}`
	m := map[string]string{"limit_mb": `[0-9]{1,7}`, "source": `[a-z][a-z_]{0,31}`}
	for _, k := range []string{"service", "namespace", "pod", "container", "deployment", "database", "cluster", "topic"} {
		m[k] = dns
	}
	p, err := NewLabelPolicy(m)
	if err != nil {
		panic(err)
	}
	return p
}

// FilterSeries принимает серию метрики (объект с необязательным ключом "labels") и возвращает копию,
// из которой удалены метки вне allowlist, метки с нестроковыми значениями и метки со значением не по шаблону.
// Порядок оставшихся меток сохраняется. labels не объект или серия не объект → ошибка (фрагмент исключается).
func (p *LabelPolicy) FilterSeries(v *pyjson.Value) (out *pyjson.Value, dropped int, err error) {
	if v == nil || v.Kind != pyjson.Object {
		return nil, 0, errors.New("серия метрики не объект")
	}
	out = v.Clone()
	lbl := out.Get("labels")
	if lbl == nil {
		return out, 0, nil
	}
	if lbl.Kind != pyjson.Object {
		return nil, 0, errors.New("labels не объект")
	}
	kept := make([]pyjson.Member, 0, len(lbl.Members))
	for _, m := range lbl.Members {
		re, ok := p.allowed[m.Key]
		if ok && m.Value.Kind == pyjson.String && re.MatchString(m.Value.S) {
			kept = append(kept, m)
		} else {
			dropped++
		}
	}
	lbl.Members = kept
	return out, dropped, nil
}
