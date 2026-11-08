// Package strictjson — строгий разбор JSON для границ доверия: без неизвестных полей, без дублей ключей,
// с точным (регистрозависимым) совпадением имён полей и без данных после значения.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
)

// UnknownFieldError — в JSON есть поле, которого нет в типе. Отличает «запись новее сборки» от прочих нарушений формата.
type UnknownFieldError struct{ Field string }

func (e *UnknownFieldError) Error() string {
	return fmt.Sprintf("неизвестное поле %q (имена регистрозависимы)", e.Field)
}

// Decode разбирает ровно одно JSON-значение b в v (указатель).
func Decode(b []byte, v any) error {
	if !json.Valid(b) {
		return errors.New("некорректный JSON")
	}
	if err := Check(b, v); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// Check проверяет b (одно корректное JSON-значение) относительно типа v: дубли ключей, имена полей структур
// с точным регистром, отсутствие данных после значения. Значения типов interface{} и json.RawMessage проверяются только на дубли.
func Check(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	t := reflect.TypeOf(v)
	if t == nil {
		return errors.New("strictjson: nil тип")
	}
	if err := walk(dec, t); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("лишние данные после JSON")
	}
	return nil
}

var rawType = reflect.TypeOf(json.RawMessage(nil))

// fields — имена json-полей структуры (с учётом встраивания не работаем: в наших типах его нет).
func fields(t reflect.Type) map[string]reflect.Type {
	out := map[string]reflect.Type{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("json")
		if tag == "-" || !f.IsExported() {
			continue
		}
		name := strings.Split(tag, ",")[0]
		if name == "" {
			name = f.Name
		}
		out[name] = f.Type
	}
	return out
}

// walk читает одно значение; t == nil — тип неизвестен (проверяются только дубли).
func walk(dec *json.Decoder, t reflect.Type) error {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t != nil && (t.Kind() == reflect.Interface || t == rawType) {
		t = nil
	}
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch d {
	case '{':
		var known map[string]reflect.Type
		var elem reflect.Type
		if t != nil {
			switch t.Kind() {
			case reflect.Struct:
				known = fields(t)
			case reflect.Map:
				elem = t.Elem()
			}
		}
		seen := map[string]bool{}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return err
			}
			key, _ := kt.(string)
			if seen[key] {
				return fmt.Errorf("дубль ключа %q", key)
			}
			seen[key] = true
			ft := elem
			if known != nil {
				var found bool
				if ft, found = known[key]; !found {
					return &UnknownFieldError{Field: key}
				}
			}
			if err := walk(dec, ft); err != nil {
				return err
			}
		}
	case '[':
		var elem reflect.Type
		if t != nil && (t.Kind() == reflect.Slice || t.Kind() == reflect.Array) {
			elem = t.Elem()
		}
		for dec.More() {
			if err := walk(dec, elem); err != nil {
				return err
			}
		}
	}
	_, err = dec.Token() // закрывающая скобка
	return err
}
