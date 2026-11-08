// Команда aegis-llmrouter: сервис LLM-роутера и операторские команды к нему.
//
//	aegis-llmrouter serve  -config FILE
//	aegis-llmrouter status -config FILE
//	aegis-llmrouter resume -config FILE -operator ID
//	aegis-llmrouter route  -config FILE -operator ID -in REQUEST.json [-prepare-only]
//
// serve держит проверки здоровья endpoint'ов и единственного писателя цепочки аудита и store состояния; при отказе
// аудита или store завершается с кодом 1 (перезапуск — за супервизором). status, resume и route — офлайн,
// при остановленном serve: файлы занимает один процесс. status выполняет полную сверку старта, как рестарт:
// может дописать событие (например, router_halted из оборванного перехода) и списать незакрытые резервы.
// route — отладочный вход до intake: реально отправляет данные в OpenRouter, тратит бюджет и пишет decision record
// (dry-run, L0, инициатор human/<operator>); -prepare-only готовит запрос без сети и бюджета, запись не пишется.
//
// Секреты — только из файлов: OPENROUTER_API_KEY_FILE, AEGIS_MASKER_KEY_FILE, AEGIS_AUDIT_KEY_FILE
// (приватный ключ Ed25519, PEM PKCS#8).
//
// Конфигурация (JSON, без секретов; budgets, failover и internal_nets необязательны):
//
//	{"router_id": "llmrouter-1", "state_path": "/var/lib/aegis/llmrouter.state",
//	 "audit": {"chain": "/var/lib/aegis/audit.jsonl", "chain_id": "aegis-prod", "public_keys": []},
//	 "budgets": {"incident_tokens": 200000, "service_day_tokens": 2000000},
//	 "failover": {"fail_threshold": 3, "hysteresis": "10m", "health_interval": "30s"},
//	 "internal_nets": ["10.0.0.0/8"]}
//
// Коды выхода: 0 — успех; 1 — fail-closed (store, цепочка или аудит отказали или повреждены);
// 2 — ошибка аргументов, конфигурации или окружения; 3 — файлы заняты работающим процессом.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/limpjungle/aegis3311/internal/audit"
	"github.com/limpjungle/aegis3311/internal/llmrouter"
	"github.com/limpjungle/aegis3311/internal/routersvc"
)

// exitError несёт код выхода.
type exitError struct {
	code int
	err  error
}

func (e exitError) Error() string { return e.err.Error() }
func (e exitError) Unwrap() error { return e.err }

func usage(err error) error { return exitError{2, err} }

// fail — код выхода по классу ошибки.
func fail(err error) error { return exitError{int(routersvc.Classify(err)), err} }

// env — окружение запуска; в тестах подменяется.
type env struct {
	getenv  func(string) string
	stdin   io.Reader
	stdout  io.Writer
	stderr  io.Writer // журнал (JSON) и итоговая строка ошибки
	deps    routersvc.Deps
	signals []os.Signal // serve и route: сигналы остановки
}

func main() {
	e := env{getenv: os.Getenv, stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr, signals: []os.Signal{syscall.SIGINT, syscall.SIGTERM}}
	err := run(context.Background(), os.Args[1:], e)
	if err == nil {
		return
	}
	if h := routersvc.Hint(err); h != "" {
		fmt.Fprintln(os.Stderr, "aegis-llmrouter:", err, "—", h)
	} else {
		fmt.Fprintln(os.Stderr, "aegis-llmrouter:", err)
	}
	var ee exitError
	if errors.As(err, &ee) {
		os.Exit(ee.code)
	}
	os.Exit(int(routersvc.Classify(err)))
}

func run(ctx context.Context, args []string, e env) error {
	const cmds = "команда: serve | status | resume | route"
	if len(args) == 0 {
		return usage(errors.New(cmds))
	}
	switch args[0] {
	case "serve", "status", "resume", "route":
	default:
		return usage(fmt.Errorf("неизвестная команда %q; %s", args[0], cmds))
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var (
		cfgPath, operator, in string
		prepareOnly           bool
	)
	fs.StringVar(&cfgPath, "config", "", "файл конфигурации (JSON)")
	fs.StringVar(&operator, "operator", "", "ID оператора (resume, route)")
	fs.StringVar(&in, "in", "", "файл запроса (route)")
	fs.BoolVar(&prepareOnly, "prepare-only", false, "route: только подготовить запрос, без сети и бюджета")
	if err := fs.Parse(args[1:]); err != nil {
		return usage(err)
	}
	if fs.NArg() != 0 {
		return usage(fmt.Errorf("лишние аргументы: %v", fs.Args()))
	}
	if cfgPath == "" {
		return usage(fmt.Errorf("%s: нужен -config", args[0]))
	}
	if prepareOnly && args[0] != "route" {
		return usage(errors.New("-prepare-only только для route"))
	}
	var (
		req  llmrouter.Request
		meta routersvc.IncidentMeta
	)
	switch args[0] {
	case "resume", "route":
		if !routersvc.ValidID(operator) {
			return usage(fmt.Errorf("%s: нужен корректный -operator", args[0]))
		}
	}
	if args[0] == "route" {
		if in == "" {
			return usage(errors.New("route: нужен -in"))
		}
		b, err := os.ReadFile(in)
		if err != nil {
			return usage(err)
		}
		if req, meta, err = routersvc.ParseRequest(b); err != nil {
			return usage(err)
		}
	}
	cfg, err := routersvc.LoadConfig(cfgPath)
	if err != nil {
		return usage(err)
	}
	sec, err := routersvc.LoadSecrets(e.getenv)
	if err != nil {
		return usage(err)
	}
	lg := slog.New(slog.NewJSONHandler(e.stderr, nil))
	d := e.deps
	d.Logger = lg
	// Обработчик сигналов ставится до Open: после строки llmrouter_opened сигнал уже обрабатывается, а не убивает процесс.
	stopSig := context.CancelFunc(func() {})
	if args[0] == "serve" && len(e.signals) > 0 {
		ctx, stopSig = signal.NotifyContext(ctx, e.signals...)
	}
	defer stopSig()
	rt, err := routersvc.Open(cfg, sec, routersvc.OpenOptions{Create: args[0] == "serve"}, d)
	if err != nil {
		return fail(err)
	}
	defer rt.Close()

	switch args[0] {
	case "serve":
		return serve(ctx, stopSig, rt, lg)
	case "status":
		if err := printJSON(e.stdout, rt.Status()); err != nil {
			return fail(err)
		}
	case "resume":
		st := rt.Status()
		lg.Info("status_before_resume", "halted", st.Halted, "halt_reason", st.HaltReason, "endpoints", st.Endpoints)
		if err := rt.Resume(ctx, operator); err != nil {
			return fail(err)
		}
		if err := printJSON(e.stdout, rt.Status()); err != nil {
			return fail(err)
		}
	case "route":
		if len(e.signals) > 0 {
			var stop context.CancelFunc
			ctx, stop = signal.NotifyContext(ctx, e.signals...)
			defer stop()
		}
		if prepareOnly {
			return prepare(ctx, rt, req, e)
		}
		return route(ctx, rt, req, meta, operator, e)
	}
	return nil
}

func serve(ctx context.Context, stop context.CancelFunc, rt *routersvc.Runtime, lg *slog.Logger) error {
	err := rt.Serve(ctx)
	stop() // повторный сигнал при остановке — завершение по умолчанию
	cerr := rt.Close()
	lg.Info("shutdown", "serve_error", fmt.Sprint(err), "close_error", fmt.Sprint(cerr))
	if err != nil {
		return fail(err)
	}
	if cerr != nil {
		return fail(cerr)
	}
	return nil
}

// prepare — подготовка запроса без сети и бюджета; тело запроса и значения фрагментов не печатаются.
func prepare(ctx context.Context, rt *routersvc.Runtime, req llmrouter.Request, e env) error {
	if req.Mode == llmrouter.ModeOff {
		return usage(errors.New("route: при mode off подготовки запроса нет"))
	}
	p, err := rt.Router.Prepare(ctx, req, llmrouter.RolePrimary)
	if err != nil {
		return fail(err)
	}
	out := struct {
		RequestSHA256  string              `json:"request_sha256"`
		InputSHA256    string              `json:"input_sha256"`
		DataClass      string              `json:"data_class"`
		Sources        []string            `json:"sources"`
		Excluded       []audit.FragmentRef `json:"excluded"`
		Dropped        []audit.FragmentRef `json:"dropped"`
		EstInputTokens int                 `json:"est_input_tokens"`
		NotSent        string              `json:"not_sent"`
	}{p.RequestSHA256, p.InputSHA256, p.DataClass.String(), nonNil(p.Sources), refs(p.Excluded), refs(p.Dropped), p.EstInputTokens, p.NotSent}
	return printJSON(e.stdout, out)
}

func refs(in []llmrouter.FragmentRef) []audit.FragmentRef {
	out := make([]audit.FragmentRef, 0, len(in))
	for _, f := range in {
		out = append(out, audit.FragmentRef{ID: f.ID, Source: f.Source, Class: f.Class.String(), Reason: f.Reason, Required: f.Required})
	}
	return out
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func route(ctx context.Context, rt *routersvc.Runtime, req llmrouter.Request, meta routersvc.IncidentMeta, operator string, e env) error {
	res, rerr := rt.Router.Route(ctx, req)
	if res == nil {
		return fail(rerr)
	}
	now := time.Now()
	if e.deps.Clock != nil {
		now = e.deps.Clock.Now()
	}
	rec := routersvc.ShadowRecord(meta, operator, now, res)
	entry, werr := rt.Writer.Append(rec)
	out := struct {
		Record *audit.DecisionRecord `json:"record"`
		Chain  *struct {
			Seq  uint64 `json:"seq"`
			Hash string `json:"hash"`
		} `json:"chain"`
	}{Record: rec}
	if werr == nil {
		out.Chain = &struct {
			Seq  uint64 `json:"seq"`
			Hash string `json:"hash"`
		}{entry.Seq, entry.Hash}
	}
	if err := printJSON(e.stdout, out); err != nil {
		return fail(err)
	}
	if err := errors.Join(rerr, werr); err != nil {
		return fail(err)
	}
	return nil
}

func printJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
