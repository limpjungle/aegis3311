package llmrouter

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"

	"github.com/limpjungle/aegis3311/internal/dataclass"
	"github.com/limpjungle/aegis3311/internal/pyjson"
)

// Тестовые маскировщики: детекторов и примеров секретов здесь нет, только поведение интерфейса.

// identityMasker возвращает вход, пустой отчёт, считает вызовы.
type identityMasker struct{ calls atomic.Int64 }

func (m *identityMasker) Version() string { return "identity/1" }
func (m *identityMasker) Mask(_ context.Context, _ dataclass.FragmentMeta, v *pyjson.Value) (*pyjson.Value, dataclass.MaskReport, error) {
	m.calls.Add(1)
	return v, dataclass.MaskReport{}, nil
}

// pdMasker отмечает указанные фрагменты как содержащие ПДн.
type pdMasker struct {
	identityMasker
	hit map[string]bool
}

func (m *pdMasker) Mask(ctx context.Context, meta dataclass.FragmentMeta, v *pyjson.Value) (*pyjson.Value, dataclass.MaskReport, error) {
	out, rep, err := m.identityMasker.Mask(ctx, meta, v)
	if m.hit[meta.FragmentID] {
		rep.Findings = []dataclass.Finding{{Category: dataclass.CategoryPersonal, Count: 1}}
	}
	return out, rep, err
}

// failMasker падает указанным способом.
type failMasker struct {
	identityMasker
	mode string // failed | error | panic | nil | hang
}

func (m *failMasker) Mask(ctx context.Context, meta dataclass.FragmentMeta, v *pyjson.Value) (*pyjson.Value, dataclass.MaskReport, error) {
	m.calls.Add(1)
	switch m.mode {
	case "failed":
		return v, dataclass.MaskReport{Failed: true}, nil
	case "error":
		return nil, dataclass.MaskReport{}, errors.New("сбой")
	case "panic":
		panic("сбой")
	case "nil":
		return nil, dataclass.MaskReport{}, nil
	}
	<-ctx.Done() // hang
	return v, dataclass.MaskReport{}, nil
}

// secretMasker «вырезает секрет»: заменяет значение заглушкой.
type secretMasker struct{ identityMasker }

func (m *secretMasker) Mask(context.Context, dataclass.FragmentMeta, *pyjson.Value) (*pyjson.Value, dataclass.MaskReport, error) {
	m.calls.Add(1)
	return pyjson.NewString("<removed>"), dataclass.MaskReport{Findings: []dataclass.Finding{{Category: dataclass.CategorySecret, Count: 1}}, Removed: 1}, nil
}

// mutatingMasker портит переданную копию.
type mutatingMasker struct {
	identityMasker
	mu sync.Mutex
}

func (m *mutatingMasker) Mask(_ context.Context, _ dataclass.FragmentMeta, v *pyjson.Value) (*pyjson.Value, dataclass.MaskReport, error) {
	m.calls.Add(1)
	v.Kind, v.S, v.Members, v.Items = pyjson.String, "mutated", nil, nil
	return v, dataclass.MaskReport{}, nil
}
