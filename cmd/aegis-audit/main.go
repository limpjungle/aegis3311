// Команда aegis-audit: ключи, запись и проверка цепочки decision record'ов, событий роутера и событий kill switch.
//
//	aegis-audit keygen     -priv KEY.pem -pub KEY.pub.pem
//	aegis-audit append     -chain FILE -id CHAIN_ID -key KEY.pem [-pub PUB.pem ...] < record.json | event.json
//	aegis-audit verify     -chain FILE -pub PUB.pem [-pub ...] [-id CHAIN_ID] [-anchor DIR] [-integrity-only]
//	aegis-audit checkpoint -chain FILE -id CHAIN_ID -key KEY.pem [-pub PUB.pem ...] -anchor DIR
//	aegis-audit version
//
// version печатает chain_format (уровень формата цепочки, который понимает сборка) и известные схемы записей. Цепочка с
// записями новее сборки (неизвестная схема aegisops/* или неизвестное поле) не проходит verify и не открывается для
// записи: код 1 с ErrNewerFormat; обновите aegis-audit. verify -integrity-only — только чтение: цепь, хеши, подписи и
// checkpoint'ы проверяются полностью, непонятые записи считаются (unverified_records, unverified_schemas; предупреждение в
// stderr, код 0), их содержимое не проверено. Для приёмки аудита режим не годится. Порядок развёртывания: сначала
// верификаторы, потом писатели.
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
func (e exitError) Unwrap() error { return e.err }

func usage(err error) error    { return exitError{2, err} }
func rejected(err error) error { return exitError{1, err} }

// stderr — куда идут предупреждения (verify -integrity-only); в тестах подменяется.
var stderr io.Writer = os.Stderr

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
		return usage(errors.New("команда: keygen | append | verify | checkpoint | version"))
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var (
		chain, id, key, anchor, priv string
		pubs                         multi
		integrityOnly                bool
	)
	fs.StringVar(&chain, "chain", "", "файл цепочки")
	fs.StringVar(&id, "id", "", "chain_id")
	fs.StringVar(&key, "key", "", "приватный ключ (PEM PKCS#8)")
	fs.StringVar(&anchor, "anchor", "", "каталог checkpoint'ов")
	fs.StringVar(&priv, "priv", "", "куда записать приватный ключ (keygen)")
	fs.BoolVar(&integrityOnly, "integrity-only", false, "verify: не разбирать записи новее сборки, только цепь, хеши, подписи и checkpoint'ы")
	fs.Var(&pubs, "pub", "открытый ключ (PEM PKIX), можно несколько; в keygen — куда записать")
	if err := fs.Parse(args[1:]); err != nil {
		return usage(err)
	}
	if fs.NArg() != 0 {
		return usage(fmt.Errorf("лишние аргументы: %v", fs.Args()))
	}
	if integrityOnly && args[0] != "verify" {
		return usage(errors.New("-integrity-only только для verify"))
	}
	switch args[0] {
	case "version":
		return printJSON(out, struct {
			ChainFormat int      `json:"chain_format"`
			Schemas     []string `json:"schemas"`
		}{audit.ChainFormat, audit.KnownSchemas()})
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
				return rejected(decodeErr("decision record", err))
			}
			e, err = w.Append(&rec)
		case audit.RouterEventSchema:
			var ev audit.RouterEvent
			if err := strictjson.Decode(raw, &ev); err != nil {
				return rejected(decodeErr("router event", err))
			}
			e, err = w.AppendEvent(&ev)
		case audit.KillSwitchEventSchema:
			var ev audit.KillSwitchEvent
			if err := strictjson.Decode(raw, &ev); err != nil {
				return rejected(decodeErr("kill switch event", err))
			}
			e, err = w.AppendKillSwitchEvent(&ev)
		default:
			if audit.SchemaFromProject(peek.Schema) {
				return rejected(fmt.Errorf("%w: схема %q не поддерживается этой сборкой (формат цепочки %d): обновите aegis-audit",
					audit.ErrNewerFormat, peek.Schema, audit.ChainFormat))
			}
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
		opts := audit.VerifyOptions{ChainID: id, Stats: &stats, IntegrityOnly: integrityOnly}
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
		if stats.Unverified > 0 {
			fmt.Fprintf(stderr, "aegis-audit: предупреждение: %d записей схем %v не проверены по содержимому (новее этой сборки, формат цепочки %d); "+
				"режим -integrity-only для приёмки аудита не годится\n", stats.Unverified, stats.UnverifiedSchemas, audit.ChainFormat)
		}
		if stats.UnverifiedSchemas == nil {
			stats.UnverifiedSchemas = []string{}
		}
		return printJSON(out, struct {
			audit.Head
			Checkpoints       int      `json:"checkpoints_checked"`
			Records           uint64   `json:"records"`
			RouterEvents      uint64   `json:"router_events"`
			KillSwitch        uint64   `json:"kill_switch_events"`
			ChainFormat       int      `json:"chain_format"`
			Unverified        uint64   `json:"unverified_records"`
			UnverifiedSchemas []string `json:"unverified_schemas"`
		}{head, len(opts.Checkpoints), stats.Records, stats.RouterEvents, stats.KillSwitchEvents, audit.ChainFormat, stats.Unverified, stats.UnverifiedSchemas})
	default:
		return usage(fmt.Errorf("неизвестная команда %q", args[0]))
	}
}

// decodeErr: неизвестное поле известной схемы — запись новее сборки (ErrNewerFormat), прочее — нарушение формата.
func decodeErr(label string, err error) error {
	var uf *strictjson.UnknownFieldError
	if errors.As(err, &uf) {
		return fmt.Errorf("%w: %s: поле %q неизвестно этой сборке (формат цепочки %d): обновите aegis-audit", audit.ErrNewerFormat, label, uf.Field, audit.ChainFormat)
	}
	return fmt.Errorf("%s: %w", label, err)
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
