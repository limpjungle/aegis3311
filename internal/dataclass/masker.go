package dataclass

import (
	"context"

	"github.com/limpjungle/aegis3311/internal/pyjson"
)

// Category — категория находки маскировщика.
type Category string

const (
	CategorySecret   Category = "secret"        // секрет вырезан (замена-заглушка), класс не меняется
	CategoryPersonal Category = "personal_data" // найдены ПДн (замаскированы или нет)
)

// Finding — находки одной категории.
type Finding struct {
	Category Category
	Count    int
}

// MaskReport — отчёт маскировщика по фрагменту.
type MaskReport struct {
	Findings []Finding
	Removed  int  // число удалений и замен
	Failed   bool // сбой, таймаут или низкая уверенность (§3 п. 4)
}

// FragmentMeta — контекст вызова маскировщика.
type FragmentMeta struct {
	IncidentID string // для соли псевдонимов на инцидент (§5.1)
	FragmentID string
	Source     string
	Class      Class // класс до маскирования
}

// Masker — маскировщик (реализация — отдельная часть). Mask не должен менять v: роутер передаёт копию.
// Возвращённое значение заменяет фрагмент целиком. Ошибка, паника и nil-значение роутер считает сбоем.
type Masker interface {
	Version() string
	Mask(ctx context.Context, meta FragmentMeta, v *pyjson.Value) (*pyjson.Value, MaskReport, error)
}

// Escalate — класс фрагмента после маскирования и причина повышения ("" — без повышения):
//
//	Failed, Removed < 0, Count < 0 → Restricted, "masker_failure"
//	CategoryPersonal (Count > 0)   → Restricted, "personal_data"
//	  (гражданство в MVP не определить, поэтому любые найденные ПДн считаются возможными ПДн граждан РФ, §4.2)
//	неизвестная категория          → Restricted, "unknown_category"
//	CategorySecret                 → base (секрет уже вырезан маскировщиком)
//
// Результат всегда Raise(base, ...): ниже base не бывает.
func Escalate(base Class, r MaskReport) (Class, string) {
	if r.Failed || r.Removed < 0 {
		return Raise(base, Restricted), "masker_failure"
	}
	personal, unknown := false, false
	for _, f := range r.Findings {
		if f.Count < 0 {
			return Raise(base, Restricted), "masker_failure"
		}
		switch f.Category {
		case CategoryPersonal:
			personal = personal || f.Count > 0
		case CategorySecret:
		default:
			unknown = true
		}
	}
	if personal {
		return Raise(base, Restricted), "personal_data"
	}
	if unknown {
		return Raise(base, Restricted), "unknown_category"
	}
	return base, ""
}
