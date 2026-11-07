// Команда aegis-audit: ключи, запись и проверка цепочки decision record'ов и событий роутера.
//
//	aegis-audit keygen     -priv KEY.pem -pub KEY.pub.pem
//	aegis-audit append     -chain FILE -id CHAIN_ID -key KEY.pem [-pub PUB.pem ...] < record.json | event.json
//	aegis-audit verify     -chain FILE -pub PUB.pem [-pub ...] [-id CHAIN_ID] [-anchor DIR]
//	aegis-audit checkpoint -chain FILE -id CHAIN_ID -key KEY.pem [-pub PUB.pem ...] -anchor DIR
//
// Коды выхода: 0 — успех; 1 — цепочка повреждена или запись отклонена; 2 — ошибка аргументов или окружения.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/limpjungle/aegis3311/internal/audit"
	"github.com/limpjungle/aegis3311/internal/strictjson"
)

type multi []string

func (m *multi) String() string     { return fmt.Sprint(*m) }
func (m *multi) Set(s string) error { *m = append(*m, s); return nil }

// exitError несёт код выхода.
type exitError struct {
	code int
	err  error
}

func (e exitError) Error() string { return e.err.Error() }

func usage(err error) error    { return exitError{2, err} }
func rejected(err error) error { return exitError{1, err} }

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "aegis-audit:", err)
		var ee exitError
		if errors.As(err, &ee) {
			os.Exit(ee.code)
		}
		os.Exit(2)
	}
}

func run(args []string, in io.Reader, out io.Writer) error {
	if len(args) == 0 {
		return usage(errors.New("команда: keygen | append | verify | checkpoint"))
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var (
		chain, id, key, anchor, priv string
		pubs                         multi
	)
	fs.StringVar(&chain, "chain", "", "файл цепочки")
	fs.StringVar(&id, "id", "", "chain_id")
	fs.StringVar(&key, "key", "", "приватный ключ (PEM PKCS#8)")
	fs.StringVar(&anchor, "anchor", "", "каталог checkpoint'ов")
	fs.StringVar(&priv, "priv", "", "куда записать приватный ключ (keygen)")
	fs.Var(&pubs, "pub", "открытый ключ (PEM PKIX), можно несколько; в keygen — куда записать")
	if err := fs.Parse(args[1:]); err != nil {
		return usage(err)
	}
	if fs.NArg() != 0 {
		return usage(fmt.Errorf("лишние аргументы: %v", fs.Args()))
	}
	switch args[0] {
	case "keygen":
		if priv == "" || len(pubs) != 1 {
			return usage(errors.New("keygen: нужны -priv и один -pub"))
		}
		pub, err := audit.GenerateKey(priv, pubs[0])
		if err != nil {
			return usage(err)
		}
		fmt.Fprintln(out, "key_id:", audit.KeyID(pub))
		return nil
	case "append", "checkpoint":
		if chain == "" || id == "" || key == "" || (args[0] == "checkpoint" && anchor == "") {
			return usage(fmt.Errorf("%s: нужны -chain, -id, -key%s", args[0], map[bool]string{true: ", -anchor"}[args[0] == "checkpoint"]))
		}
		signer, err := audit.LoadPrivateKey(key)
		if err != nil {
			return usage(err)
		}
		keys, err := keyring(pubs)
		if err != nil {
			return usage(err)
		}
		keys.Add(signer.Public())
		w, err := audit.OpenWriter(chain, id, signer, keys)
		if err != nil {
			return rejected(err)
		}
		defer w.Close()
		if args[0] == "checkpoint" {
			c, err := w.Checkpoint()
			if err != nil {
				return rejected(err)
			}
			if err := (audit.DirAnchor{Dir: anchor}).Put(c); err != nil {
				return usage(err)
			}
			return printJSON(out, c)
		}
		raw, err := io.ReadAll(io.LimitReader(in, audit.MaxLineBytes+1))
		if err != nil {
			return usage(err)
		}
		var peek struct {
			Schema string `json:"schema"`
		}
		_ = json.Unmarshal(raw, &peek) // дубли и неизвестные поля ловит strictjson.Decode ниже
		var e audit.Entry
		switch peek.Schema {
		case audit.RecordSchema:
			var rec audit.DecisionRecord
			if err := strictjson.Decode(raw, &rec); err != nil {
				return rejected(fmt.Errorf("decision record: %w", err))
			}
			e, err = w.Append(&rec)
		case audit.RouterEventSchema:
			var ev audit.RouterEvent
			if err := strictjson.Decode(raw, &ev); err != nil {
				return rejected(fmt.Errorf("router event: %w", err))
			}
			e, err = w.AppendEvent(&ev)
		default:
			return rejected(fmt.Errorf("неизвестная схема записи %q", peek.Schema))
		}
		if err != nil {
			return rejected(err)
		}
		return printJSON(out, audit.Head{ChainID: e.ChainID, Seq: e.Seq, Hash: e.Hash})
	case "verify":
		if chain == "" || len(pubs) == 0 {
			return usage(errors.New("verify: нужны -chain и хотя бы один -pub"))
		}
		keys, err := keyring(pubs)
		if err != nil {
			return usage(err)
		}
		f, err := os.Open(chain)
		if err != nil {
			return usage(err)
		}
		defer f.Close()
		var stats audit.VerifyStats
		opts := audit.VerifyOptions{ChainID: id, Stats: &stats}
		if anchor != "" {
			if id == "" {
				return usage(errors.New("verify: с -anchor нужен -id"))
			}
			if opts.Checkpoints, err = (audit.DirAnchor{Dir: anchor}).LoadCheckpoints(id); err != nil {
				return rejected(err)
			}
		}
		head, err := audit.Verify(f, keys, opts)
		if err != nil {
			return rejected(err)
		}
		return printJSON(out, struct {
			audit.Head
			Checkpoints  int    `json:"checkpoints_checked"`
			Records      uint64 `json:"records"`
			RouterEvents uint64 `json:"router_events"`
		}{head, len(opts.Checkpoints), stats.Records, stats.RouterEvents})
	default:
		return usage(fmt.Errorf("неизвестная команда %q", args[0]))
	}
}

func keyring(paths []string) (audit.Keyring, error) {
	k := audit.Keyring{}
	for _, p := range paths {
		pub, err := audit.LoadPublicKey(p)
		if err != nil {
			return nil, err
		}
		k.Add(pub)
	}
	return k, nil
}

func printJSON(out io.Writer, v any) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
