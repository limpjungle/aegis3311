// Команда aegis-pep: dry-run PEP. Читает из stdin {"proposal": <action из ответа v2>, "context": {...}}
// и печатает вердикт JSON. Ничего не исполняет.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/limpjungle/aegis3311/internal/catalog"
	"github.com/limpjungle/aegis3311/internal/pep"
	"github.com/limpjungle/aegis3311/internal/policyengine"
	"github.com/limpjungle/aegis3311/internal/step"
	"github.com/limpjungle/aegis3311/internal/strictjson"
	"github.com/limpjungle/aegis3311/policy"
)

func main() {
	if len(os.Args) != 2 || os.Args[1] != "dry-run" {
		fmt.Fprintln(os.Stderr, "usage: aegis-pep dry-run < {\"proposal\":..., \"context\":...}")
		os.Exit(2)
	}
	if err := run(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "aegis-pep:", err)
		os.Exit(1)
	}
}

func run(in io.Reader, out io.Writer) error {
	raw, err := io.ReadAll(in)
	if err != nil {
		return err
	}
	var req struct {
		Proposal json.RawMessage `json:"proposal"`
		Context  pep.Context     `json:"context"`
	}
	if err := strictjson.Decode(raw, &req); err != nil {
		return fmt.Errorf("вход: %w", err)
	}
	cat := catalog.MustLoadEmbedded()
	if err := cat.Validate(step.DefaultRegistry()); err != nil {
		return fmt.Errorf("каталог: %w", err)
	}
	pol, err := policyengine.Load(context.Background(), policy.FS)
	if err != nil {
		return err
	}
	v := pep.New(cat, pol).EvaluateRaw(context.Background(), req.Proposal, req.Context)
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
