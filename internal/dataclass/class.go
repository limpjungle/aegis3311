package dataclass

import "fmt"

// Class — класс данных. Порядок важен: сравнение классов = сравнение строгости.
type Class int

const (
	Public Class = iota + 1
	Internal
	Confidential
	Restricted
)

// ConfidentialExternalAvailable — можно ли вообще включить отправку confidential во внешний LLM.
// В MVP нельзя: нет NER для ФИО (data-classes §1.3, §5.1). Менять — только отдельным решением security.
const ConfidentialExternalAvailable = false

var classNames = [...]string{Public: "public", Internal: "internal", Confidential: "confidential", Restricted: "restricted"}

func (c Class) String() string {
	if c < Public || c > Restricted {
		return "invalid"
	}
	return classNames[c]
}

// ParseClass разбирает имя класса (строго, в нижнем регистре).
func ParseClass(s string) (Class, error) {
	for c := Public; c <= Restricted; c++ {
		if classNames[c] == s {
			return c, nil
		}
	}
	return 0, fmt.Errorf("dataclass: неизвестный класс %q", s)
}

func (c Class) MarshalText() ([]byte, error) {
	if c < Public || c > Restricted {
		return nil, fmt.Errorf("dataclass: невалидный класс %d", int(c))
	}
	return []byte(classNames[c]), nil
}

func (c *Class) UnmarshalText(b []byte) error {
	v, err := ParseClass(string(b))
	if err != nil {
		return err
	}
	*c = v
	return nil
}

// Max — более строгий из двух классов.
func Max(a, b Class) Class {
	if a > b {
		return a
	}
	return b
}

// Raise — единственный способ изменить класс: результат не ниже cur. Понижения в API нет (§3 п. 5).
func Raise(cur, to Class) Class { return Max(cur, to) }
