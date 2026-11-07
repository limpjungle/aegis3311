package llmrouter

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/limpjungle/aegis3311/internal/pyjson"
)

type Mode string

const (
	ModeHybrid Mode = "hybrid"
	ModeOff    Mode = "off"
)

type Role string

const (
	RolePrimary  Role = "primary"
	RoleFallback Role = "fallback"
)

type FragmentKind string

const (
	KindGeneric      FragmentKind = "generic"
	KindMetricSeries FragmentKind = "metric_series"
)

// MaxFragments — потолок числа фрагментов в запросе (предложение).
const MaxFragments = 2048

var idRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$`)

type Fragment struct {
	ID        string // уникален в запросе, формат как audit idRe
	Source    string // ID источника из dataclass.Registry
	Kind      FragmentKind
	Required  bool          // исключён или не помещается обязательный → запроса нет
	Relevance int           // больше — релевантнее; при потолке отбрасываются с наименьшей
	Value     *pyjson.Value // не nil (JSON null — pyjson.NewNull())
}

// Section — ключ верхнего уровня input. List=false — ровно один фрагмент (значение ключа; исключён необязательный → ключа нет).
// List=true — массив из включённых фрагментов в исходном порядке; секция выводится всегда, пустая — как [].
type Section struct {
	Key       string
	List      bool
	Fragments []Fragment
}

type Request struct {
	IncidentID, Service string
	Mode                Mode
	Sections            []Section
}

// InvalidRequestError — запрос не прошёл проверку структуры: ошибка вызывающего кода, а не отказ системы.
// Текст совпадает с текстом причины.
type InvalidRequestError struct{ Err error }

func (e *InvalidRequestError) Error() string { return e.Err.Error() }
func (e *InvalidRequestError) Unwrap() error { return e.Err }

// validate — ошибка вызывающего кода, а не данных: запроса нет. Ошибка — *InvalidRequestError.
func (q *Request) validate() error {
	if err := q.check(); err != nil {
		return &InvalidRequestError{err}
	}
	return nil
}

func (q *Request) check() error {
	if !idRe.MatchString(q.IncidentID) {
		return fmt.Errorf("llmrouter: некорректный incident_id %q", q.IncidentID)
	}
	if !idRe.MatchString(q.Service) {
		return fmt.Errorf("llmrouter: некорректный service %q", q.Service)
	}
	if q.Mode != ModeHybrid && q.Mode != ModeOff {
		return fmt.Errorf("llmrouter: неизвестный режим %q", q.Mode)
	}
	keys, ids, n := map[string]bool{}, map[string]bool{}, 0
	for _, s := range q.Sections {
		if s.Key == "" || keys[s.Key] {
			return fmt.Errorf("llmrouter: пустой или повторный ключ секции %q", s.Key)
		}
		keys[s.Key] = true
		if !s.List && len(s.Fragments) != 1 {
			return fmt.Errorf("llmrouter: секция %q не список: ожидается ровно один фрагмент", s.Key)
		}
		for _, f := range s.Fragments {
			if !idRe.MatchString(f.ID) || ids[f.ID] {
				return fmt.Errorf("llmrouter: некорректный или повторный ID фрагмента %q", f.ID)
			}
			ids[f.ID] = true
			if f.Value == nil {
				return fmt.Errorf("llmrouter: фрагмент %q без значения", f.ID)
			}
			if f.Kind != KindGeneric && f.Kind != KindMetricSeries {
				return fmt.Errorf("llmrouter: фрагмент %q: неизвестный вид %q", f.ID, f.Kind)
			}
			if n++; n > MaxFragments {
				return errors.New("llmrouter: слишком много фрагментов")
			}
		}
	}
	return nil
}
