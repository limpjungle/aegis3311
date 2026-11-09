// Package policyengine выполняет политики Rego (policy/aegis) и возвращает типизированное решение.
// Решение «deny/allow» принимает PEP: здесь любая аномалия — ошибка.
package policyengine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/open-policy-agent/opa/v1/rego"

	"github.com/limpjungle/aegis3311/internal/digest"
)

// Reason — запрет (deny) от политики.
type Reason struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

// Cap — понижение уровня до Level.
type Cap struct {
	Code   string `json:"code"`
	Level  string `json:"level"`
	Detail string `json:"detail"`
}

// Decision — data.aegis.pep.decision.
type Decision struct {
	Ceiling        string   `json:"ceiling"`
	EffectiveLevel string   `json:"effective_level"`
	PolicyRevision string   `json:"policy_revision"`
	Deny           []Reason `json:"deny"`
	Caps           []Cap    `json:"caps"`
}

// Engine — подготовленный запрос к политике.
type Engine struct {
	q      rego.PreparedEvalQuery
	digest string
}

// Load компилирует *.rego из fsys (кроме *_test.rego) в строгом режиме.
func Load(ctx context.Context, fsys fs.FS) (*Engine, error) {
	paths, err := PolicyFiles(fsys)
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, errors.New("policyengine: не найдено ни одного .rego")
	}
	opts := []func(*rego.Rego){
		rego.Query("data.aegis.pep.decision"),
		rego.StrictBuiltinErrors(true),
		rego.Strict(true),
	}
	for _, p := range paths {
		src, err := fs.ReadFile(fsys, p)
		if err != nil {
			return nil, err
		}
		opts = append(opts, rego.Module(p, string(src)))
	}
	q, err := rego.New(opts...).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("policyengine: компиляция: %w", err)
	}
	d, err := digest.Files(fsys, paths)
	if err != nil {
		return nil, err
	}
	return &Engine{q: q, digest: d}, nil
}

// PolicyFiles — отсортированные пути *.rego без тестов.
func PolicyFiles(fsys fs.FS) ([]string, error) {
	var paths []string
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(p, ".rego") && !strings.HasSuffix(p, "_test.rego") {
			paths = append(paths, p)
		}
		return nil
	})
	sort.Strings(paths)
	return paths, err
}

// Digest — хеш non-test .rego файлов.
func (e *Engine) Digest() string { return e.digest }

// Eval вычисляет решение. Пустой результат, несколько выражений или неверный тип — ошибка.
func (e *Engine) Eval(ctx context.Context, input any) (Decision, error) {
	// Нормализуем вход через JSON: в Rego попадают только JSON-типы, независимо от Go-типов вызывающего.
	b, err := json.Marshal(input)
	if err != nil {
		return Decision{}, fmt.Errorf("policyengine: вход: %w", err)
	}
	var norm any
	if err := json.Unmarshal(b, &norm); err != nil {
		return Decision{}, fmt.Errorf("policyengine: вход: %w", err)
	}
	rs, err := e.q.Eval(ctx, rego.EvalInput(norm))
	if err != nil {
		return Decision{}, fmt.Errorf("policyengine: вычисление: %w", err)
	}
	if len(rs) != 1 || len(rs[0].Expressions) != 1 {
		return Decision{}, errors.New("policyengine: решение не определено")
	}
	raw, err := json.Marshal(rs[0].Expressions[0].Value)
	if err != nil {
		return Decision{}, err
	}
	var d Decision
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return Decision{}, fmt.Errorf("policyengine: тип решения: %w", err)
	}
	if d.Ceiling == "" || d.EffectiveLevel == "" || d.Deny == nil || d.Caps == nil {
		return Decision{}, errors.New("policyengine: неполное решение")
	}
	return d, nil
}
