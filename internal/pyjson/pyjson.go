// Package pyjson — JSON-значения с сохранением порядка ключей и вида чисел и кодирование байт-в-байт
// как Python json.dumps. Нужен, чтобы роутер отправлял в модель ровно те байты, на которых прошёл eval
// (eval/golden-synthetic/run.py: canon_json = json.dumps(ensure_ascii=False, sort_keys=True, separators=(",", ":"))).
//
// Числа: целые (без '.', 'e', 'E') печатаются как есть, дробные — как Python repr(float).
// Нечисловые значения (NaN, Infinity) и дубли ключей отвергаются.
package pyjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Kind — тип значения.
type Kind int

const (
	Null Kind = iota
	Bool
	Number
	String
	Array
	Object
)

// Member — пара ключ-значение объекта.
type Member struct {
	Key   string
	Value *Value
}

// Value — JSON-значение. Для Number хранится нормализованный текст: Int — целое, иначе float64 в F.
type Value struct {
	Kind    Kind
	B       bool
	Int     string // для целого: десятичная запись без ведущих нулей
	IsFloat bool
	F       float64
	S       string
	Items   []*Value
	Members []Member
}

func NewString(s string) *Value { return &Value{Kind: String, S: s} }
func NewBool(b bool) *Value     { return &Value{Kind: Bool, B: b} }

// NewFloat — дробное число (1 печатается как 1.0). NaN и ±Inf в JSON невыразимы — вместо них null.
func NewFloat(f float64) *Value {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return NewNull()
	}
	return &Value{Kind: Number, IsFloat: true, F: f}
}
func NewNull() *Value                 { return &Value{Kind: Null} }
func NewInt(i int64) *Value           { return &Value{Kind: Number, Int: strconv.FormatInt(i, 10)} }
func NewArray(items ...*Value) *Value { return &Value{Kind: Array, Items: items} }
func NewObject(ms ...Member) *Value   { return &Value{Kind: Object, Members: ms} }
func M(key string, v *Value) Member   { return Member{Key: key, Value: v} }
func (v *Value) Get(key string) *Value {
	if v == nil || v.Kind != Object {
		return nil
	}
	for _, m := range v.Members {
		if m.Key == key {
			return m.Value
		}
	}
	return nil
}

// Set заменяет значение ключа или добавляет его в конец.
func (v *Value) Set(key string, val *Value) {
	for i := range v.Members {
		if v.Members[i].Key == key {
			v.Members[i].Value = val
			return
		}
	}
	v.Members = append(v.Members, Member{key, val})
}

// Delete удаляет ключ (если есть).
func (v *Value) Delete(key string) {
	out := v.Members[:0]
	for _, m := range v.Members {
		if m.Key != key {
			out = append(out, m)
		}
	}
	v.Members = out
}

// Clone — глубокая копия.
func (v *Value) Clone() *Value {
	if v == nil {
		return nil
	}
	c := *v
	if v.Items != nil {
		c.Items = make([]*Value, len(v.Items))
		for i, it := range v.Items {
			c.Items[i] = it.Clone()
		}
	}
	if v.Members != nil {
		c.Members = make([]Member, len(v.Members))
		for i, m := range v.Members {
			c.Members[i] = Member{m.Key, m.Value.Clone()}
		}
	}
	return &c
}

// MaxDepth — предел вложенности при разборе.
const MaxDepth = 256

// Parse разбирает ровно одно JSON-значение. Невалидный UTF-8, дубли ключей, NaN/Infinity, данные после значения — ошибка.
func Parse(b []byte) (*Value, error) {
	if !utf8.Valid(b) {
		return nil, errors.New("pyjson: невалидный UTF-8")
	}
	if !json.Valid(b) {
		return nil, errors.New("pyjson: некорректный JSON")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	v, err := parse(dec, 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("pyjson: данные после значения")
	}
	return v, nil
}

func parse(dec *json.Decoder, depth int) (*Value, error) {
	if depth > MaxDepth {
		return nil, errors.New("pyjson: слишком глубокая вложенность")
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case nil:
		return NewNull(), nil
	case bool:
		return NewBool(t), nil
	case string:
		return NewString(t), nil
	case json.Number:
		return parseNumber(string(t))
	case json.Delim:
		switch t {
		case '[':
			a := &Value{Kind: Array, Items: []*Value{}}
			for dec.More() {
				it, err := parse(dec, depth+1)
				if err != nil {
					return nil, err
				}
				a.Items = append(a.Items, it)
			}
			_, err := dec.Token()
			return a, err
		case '{':
			o := &Value{Kind: Object, Members: []Member{}}
			seen := map[string]bool{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				k := kt.(string)
				if seen[k] {
					return nil, fmt.Errorf("pyjson: дубль ключа %q", k)
				}
				seen[k] = true
				val, err := parse(dec, depth+1)
				if err != nil {
					return nil, err
				}
				o.Members = append(o.Members, Member{k, val})
			}
			_, err := dec.Token()
			return o, err
		}
	}
	return nil, fmt.Errorf("pyjson: неожиданный токен %v", tok)
}

func parseNumber(s string) (*Value, error) {
	if !strings.ContainsAny(s, ".eE") {
		n, ok := new(big.Int).SetString(s, 10)
		if !ok {
			return nil, fmt.Errorf("pyjson: число %q", s)
		}
		return &Value{Kind: Number, Int: n.String()}, nil // "-0" → "0", как int в Python
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
		return nil, fmt.Errorf("pyjson: число %q вне float64", s)
	}
	return &Value{Kind: Number, IsFloat: true, F: f}, nil
}

// Options — параметры json.dumps.
type Options struct {
	SortKeys    bool
	EnsureASCII bool
	ItemSep     string // "," или ", "
	KeySep      string // ":" или ": "
}

// Canonical — canon_json из run.py.
var Canonical = Options{SortKeys: true, EnsureASCII: false, ItemSep: ",", KeySep: ":"}

// PyDefault — json.dumps без аргументов.
var PyDefault = Options{SortKeys: false, EnsureASCII: true, ItemSep: ", ", KeySep: ": "}

// Marshal кодирует значение как Python json.dumps с заданными параметрами.
func Marshal(v *Value, o Options) []byte {
	var b bytes.Buffer
	encode(&b, v, o)
	return b.Bytes()
}

func encode(b *bytes.Buffer, v *Value, o Options) {
	switch v.Kind {
	case Null:
		b.WriteString("null")
	case Bool:
		if v.B {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case Number:
		if v.IsFloat {
			b.WriteString(FloatRepr(v.F))
		} else {
			b.WriteString(v.Int)
		}
	case String:
		encodeString(b, v.S, o.EnsureASCII)
	case Array:
		b.WriteByte('[')
		for i, it := range v.Items {
			if i > 0 {
				b.WriteString(o.ItemSep)
			}
			encode(b, it, o)
		}
		b.WriteByte(']')
	case Object:
		ms := v.Members
		if o.SortKeys {
			ms = append([]Member(nil), ms...)
			// Порядок строк Go (по байтам UTF-8) совпадает с порядком кодовых точек, как sorted() в Python.
			sort.SliceStable(ms, func(i, j int) bool { return ms[i].Key < ms[j].Key })
		}
		b.WriteByte('{')
		for i, m := range ms {
			if i > 0 {
				b.WriteString(o.ItemSep)
			}
			encodeString(b, m.Key, o.EnsureASCII)
			b.WriteString(o.KeySep)
			encode(b, m.Value, o)
		}
		b.WriteByte('}')
	}
}

func encodeString(b *bytes.Buffer, s string, ascii bool) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			switch {
			case r < 0x20:
				fmt.Fprintf(b, `\u%04x`, r)
			case ascii && r > 0x7e:
				if r > 0xffff {
					r -= 0x10000
					fmt.Fprintf(b, `\u%04x\u%04x`, 0xd800+(r>>10), 0xdc00+(r&0x3ff))
				} else {
					fmt.Fprintf(b, `\u%04x`, r)
				}
			default:
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

// FloatRepr — repr(float) в Python 3: кратчайшая точная запись; фиксированная форма при 1e-4 <= |x| < 1e16
// (с ".0" для целых), иначе экспоненциальная с минимум двумя цифрами порядка.
func FloatRepr(f float64) string {
	if f == 0 {
		if math.Signbit(f) {
			return "-0.0"
		}
		return "0.0"
	}
	e := strconv.FormatFloat(f, 'e', -1, 64) // d.ddde±XX
	i := strings.IndexByte(e, 'e')
	exp, _ := strconv.Atoi(e[i+1:])
	if exp >= -4 && exp < 16 {
		s := strconv.FormatFloat(f, 'f', -1, 64)
		if !strings.Contains(s, ".") {
			s += ".0"
		}
		return s
	}
	mant := e[:i]
	sign := "+"
	if exp < 0 {
		sign, exp = "-", -exp
	}
	return fmt.Sprintf("%se%s%02d", mant, sign, exp)
}
