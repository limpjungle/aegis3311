// Package pep — Policy Enforcement Point в режиме dry-run: проверяет предложение модели по каталогу,
// правилам шага и политике Rego и выдаёт детерминированный вердикт. Ничего не исполняет.
package pep

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/limpjungle/aegis3311/internal/strictjson"
)

// Proposal — объект action из ответа модели (schema/answer.schema-v2.json).
type Proposal struct {
	Type   string      `json:"type"`
	Params ModelParams `json:"params"`
}

// ModelParams — дискретные параметры, которые выбирает модель; null означает «не используется».
type ModelParams struct {
	Scope     *string `json:"scope"`
	PodName   *string `json:"pod_name"`
	Reason    *string `json:"reason"`
	Parameter *string `json:"parameter"`
}

var paramKeys = []string{"scope", "pod_name", "reason", "parameter"}

// ParseProposal разбирает объект action строго по схеме v2: ровно ключи type и params;
// в params ровно четыре ключа (значение null или строка), отсутствие ключа и лишние ключи — ошибка.
func ParseProposal(b []byte) (Proposal, error) {
	if !json.Valid(b) {
		return Proposal{}, errors.New("action: некорректный JSON")
	}
	// Дубли ключей и ключи в неверном регистре — ошибка (encoding/json принял бы их молча).
	if err := strictjson.Check(b, &Proposal{}); err != nil {
		return Proposal{}, fmt.Errorf("action: %w", err)
	}
	var top map[string]json.RawMessage
	if err := strictUnmarshal(b, &top); err != nil {
		return Proposal{}, fmt.Errorf("action: %w", err)
	}
	if err := exactKeys(top, "type", "params"); err != nil {
		return Proposal{}, fmt.Errorf("action: %w", err)
	}
	var p Proposal
	if err := json.Unmarshal(top["type"], &p.Type); err != nil || p.Type == "" {
		return Proposal{}, errors.New("action.type: ожидается непустая строка")
	}
	var params map[string]json.RawMessage
	if err := strictUnmarshal(top["params"], &params); err != nil || params == nil {
		return Proposal{}, errors.New("action.params: ожидается объект")
	}
	if err := exactKeys(params, paramKeys...); err != nil {
		return Proposal{}, fmt.Errorf("action.params: %w", err)
	}
	for k, dst := range map[string]**string{"scope": &p.Params.Scope, "pod_name": &p.Params.PodName,
		"reason": &p.Params.Reason, "parameter": &p.Params.Parameter} {
		if err := json.Unmarshal(params[k], dst); err != nil {
			return Proposal{}, fmt.Errorf("action.params.%s: ожидается строка или null", k)
		}
	}
	return p, nil
}

func strictUnmarshal(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("лишние данные после JSON")
	}
	return nil
}

func exactKeys(m map[string]json.RawMessage, want ...string) error {
	for _, k := range want {
		if _, ok := m[k]; !ok {
			return fmt.Errorf("нет ключа %q", k)
		}
	}
	if len(m) != len(want) {
		for k := range m {
			known := false
			for _, w := range want {
				known = known || w == k
			}
			if !known {
				return fmt.Errorf("неизвестный ключ %q", k)
			}
		}
	}
	return nil
}
