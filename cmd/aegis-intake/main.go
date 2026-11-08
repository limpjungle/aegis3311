// Команда aegis-intake: read-only intake — сбор контекста инцидента из Alertmanager, Kubernetes и Prometheus, запрос
// к LLM-роутеру, PEP dry-run и shadow decision record. Ничего не исполняется и не меняется в кластере.
//
//	aegis-intake serve   -config FILE
//	aegis-intake collect -config FILE -namespace NS -service SVC [-print-input]
//	aegis-intake replay  -config FILE -in SNAPSHOT.json [-prepare-only]
//
// serve сам открывает LLM-роутер (aegis-llmrouter serve одновременно запустить нельзя: flock, код 3) и держит
// единственного писателя цепочки аудита и store роутера. aegis-llmrouter status и resume работают офлайн при
// остановленном aegis-intake. collect — живой сбор и Prepare без отправки в модель и без записи. replay — снимок в JSON
// (intake.Snapshot) вместо живых источников: полный конвейер с записью shadow, -prepare-only — только Prepare.
//
// Секреты — только из файлов: OPENROUTER_API_KEY_FILE, AEGIS_MASKER_KEY_FILE, AEGIS_AUDIT_KEY_FILE (как у aegis-llmrouter);
// AEGIS_KUBE_TOKEN_FILE (serve, collect), AEGIS_ALERTMANAGER_TOKEN_FILE и AEGIS_PROMETHEUS_TOKEN_FILE (необязательны).
// Конфигурация — intake.Config (JSON, без секретов); пример и допущения окружения — docs/04-operations/intake-deploy.md.
//
// Коды выхода: 0 — успех; 1 — fail-closed (store, цепочка, аудит или состояние intake отказали или повреждены);
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
	"github.com/limpjungle/aegis3311/internal/catalog"
	"github.com/limpjungle/aegis3311/internal/intake"
	"github.com/limpjungle/aegis3311/internal/intake/alertmanager"
	"github.com/limpjungle/aegis3311/internal/intake/kube"
	"github.com/limpjungle/aegis3311/internal/intake/prom"
	"github.com/limpjungle/aegis3311/internal/llmrouter"
	"github.com/limpjungle/aegis3311/internal/pep"
	"github.com/limpjungle/aegis3311/internal/policyengine"
	"github.com/limpjungle/aegis3311/internal/pyjson"
	"github.com/limpjungle/aegis3311/internal/routersvc"
	"github.com/limpjungle/aegis3311/internal/step"
	"github.com/limpjungle/aegis3311/policy"
)

type exitError struct {
	code int
	err  error
}

func (e exitError) Error() string { return e.err.Error() }
func (e exitError) Unwrap() error { return e.err }

func usage(err error) error { return exitError{2, err} }

// classify: состояние intake занято — 3; всё остальное — по классам роутера (неизвестное — fail-closed 1).
func classify(err error) int {
	if errors.Is(err, intake.ErrStateLocked) {
		return int(routersvc.ClassBusy)
	}
	return int(routersvc.Classify(err))
}

func fail(err error) error { return exitError{classify(err), err} }

func hint(err error) string {
	switch {
	case errors.Is(err, intake.ErrStateLocked):
		return "файл состояния занят: запущен другой aegis-intake? остановите его и повторите"
	case errors.Is(err, intake.ErrStateCorrupt):
		return "перенесите файл состояния в сторону: старт с пустым состоянием безопасен (дубли отсекает цепочка аудита по ID инцидента)"
	}
	return routersvc.Hint(err)
}

// Live — клиенты источников; в тестах подменяются.
type Live struct {
	Alerts  intake.AlertSource
	Cluster intake.ClusterSource
	Metrics intake.MetricsSource
	DB      intake.DBSource
}

type env struct {
	getenv  func(string) string
	stdout  io.Writer
	stderr  io.Writer
	deps    routersvc.Deps
	signals []os.Signal
	live    func(cfg intake.Config, getenv func(string) string, d intake.Durations) (Live, error)
}

func main() {
	e := env{getenv: os.Getenv, stdout: os.Stdout, stderr: os.Stderr, signals: []os.Signal{syscall.SIGINT, syscall.SIGTERM}, live: newLive}
	err := run(context.Background(), os.Args[1:], e)
	if err == nil {
		return
	}
	if h := hint(err); h != "" {
		fmt.Fprintln(os.Stderr, "aegis-intake:", err, "—", h)
	} else {
		fmt.Fprintln(os.Stderr, "aegis-intake:", err)
	}
	var ee exitError
	if errors.As(err, &ee) {
		os.Exit(ee.code)
	}
	os.Exit(classify(err))
}

// newLive создаёт клиенты источников; токены читаются из файлов в *_FILE (проверяется читаемость).
func newLive(cfg intake.Config, getenv func(string) string, d intake.Durations) (Live, error) {
	am, err := alertmanager.New(cfg.Alertmanager, getenv("AEGIS_ALERTMANAGER_TOKEN_FILE"), d.Request)
	if err != nil {
		return Live{}, fmt.Errorf("alertmanager: %w", err)
	}
	pr, err := prom.New(cfg.Prometheus, getenv("AEGIS_PROMETHEUS_TOKEN_FILE"), cfg.DBQueries, d.Request)
	if err != nil {
		return Live{}, fmt.Errorf("prometheus: %w", err)
	}
	kc, err := kube.New(cfg.Kubernetes, getenv("AEGIS_KUBE_TOKEN_FILE"), d.Request)
	if err != nil {
		return Live{}, fmt.Errorf("kubernetes: %w", err)
	}
	return Live{Alerts: am, Cluster: kc, Metrics: pr, DB: pr}, nil
}

func run(ctx context.Context, args []string, e env) error {
	const cmds = "команда: serve | collect | replay"
	if len(args) == 0 {
		return usage(errors.New(cmds))
	}
	switch args[0] {
	case "serve", "collect", "replay":
	default:
		return usage(fmt.Errorf("неизвестная команда %q; %s", args[0], cmds))
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var (
		cfgPath, in, ns, svc    string
		prepareOnly, printInput bool
	)
	fs.StringVar(&cfgPath, "config", "", "файл конфигурации intake (JSON)")
	fs.StringVar(&in, "in", "", "файл снимка (replay)")
	fs.StringVar(&ns, "namespace", "", "namespace сервиса (collect)")
	fs.StringVar(&svc, "service", "", "имя сервиса (collect)")
	fs.BoolVar(&prepareOnly, "prepare-only", false, "replay: только подготовить запрос, без сети, бюджета и записи")
	fs.BoolVar(&printInput, "print-input", false, "collect: напечатать маскированный input запроса")
	if err := fs.Parse(args[1:]); err != nil {
		return usage(err)
	}
	if fs.NArg() != 0 {
		return usage(fmt.Errorf("лишние аргументы: %v", fs.Args()))
	}
	if cfgPath == "" {
		return usage(fmt.Errorf("%s: нужен -config", args[0]))
	}
	switch {
	case args[0] == "replay" && in == "":
		return usage(errors.New("replay: нужен -in"))
	case args[0] == "collect" && (ns == "" || svc == ""):
		return usage(errors.New("collect: нужны -namespace и -service"))
	case prepareOnly && args[0] != "replay":
		return usage(errors.New("-prepare-only только для replay"))
	case printInput && args[0] != "collect":
		return usage(errors.New("-print-input только для collect"))
	}
	var snap intake.Snapshot
	if args[0] == "replay" {
		b, err := os.ReadFile(in)
		if err != nil {
			return usage(err)
		}
		if snap, err = intake.ParseSnapshot(b); err != nil {
			return usage(err)
		}
	}
	icfg, err := intake.LoadConfig(cfgPath)
	if err != nil {
		return usage(err)
	}
	dur, _ := icfg.Durations()
	rcfg, err := routersvc.LoadConfig(icfg.RouterConfig)
	if err != nil {
		return usage(err)
	}
	sec, err := routersvc.LoadSecrets(e.getenv)
	if err != nil {
		return usage(err)
	}
	var live Live
	if args[0] != "replay" {
		if live, err = e.live(icfg, e.getenv, dur); err != nil {
			return usage(err)
		}
	}
	cat := catalog.MustLoadEmbedded()
	if err := cat.Validate(step.DefaultRegistry()); err != nil {
		return fmt.Errorf("каталог: %w", err)
	}
	pol, err := policyengine.Load(ctx, policy.FS)
	if err != nil {
		return err
	}
	lg := slog.New(slog.NewJSONHandler(e.stderr, nil))
	d := e.deps
	d.Logger = lg
	rt, err := routersvc.Open(rcfg, sec, routersvc.OpenOptions{Create: args[0] == "serve"}, d)
	if err != nil {
		return fail(err)
	}
	defer rt.Close()
	if len(e.signals) > 0 {
		var stop context.CancelFunc
		ctx, stop = signal.NotifyContext(ctx, e.signals...)
		defer stop()
	}

	switch args[0] {
	case "serve":
		return serve(ctx, icfg, dur, rt, live, cat, pol, lg, e)
	case "collect":
		return collect(ctx, icfg, dur, rt, live, cat, ns, svc, printInput, e)
	}
	return replay(ctx, icfg, rt, cat, pol, snap, prepareOnly, lg, e)
}

func newCollector(cfg intake.Config, d intake.Durations, l Live) *intake.Collector {
	return &intake.Collector{Cluster: l.Cluster, Metrics: l.Metrics, DB: l.DB, Specs: cfg.Metrics, RequestTimeout: d.Request, CollectTimeout: d.Collect}
}

func serve(ctx context.Context, cfg intake.Config, d intake.Durations, rt *routersvc.Runtime, live Live, cat *catalog.Catalog,
	pol *policyengine.Engine, lg *slog.Logger, e env) error {
	st, err := intake.OpenState(cfg.StatePath)
	if err != nil {
		return fail(err)
	}
	defer st.Close()
	warnUnmanaged(ctx, cfg, d, live, lg)
	lookup := func(ns, s string) (intake.ServiceConfig, bool) { return cfg.Lookup(ns, s) }
	pipe := &intake.Pipeline{IntakeID: cfg.IntakeID, Env: cfg.Environment, Settle: d.Settle, MaxPerHour: cfg.MaxRoutedPerHour, SnapshotDir: cfg.SnapshotDir,
		Cat: cat, Collector: newCollector(cfg, d, live), Router: rt.Router, Writer: rt.Writer, PEP: pep.New(cat, pol), State: st, Lookup: lookup, Log: lg}
	closePolls := int((d.CloseAfter + d.Poll - 1) / d.Poll)
	svc := &intake.Service{Cfg: cfg, D: d, Alerts: live.Alerts, State: st, Pipe: pipe, Router: rt.Router, Log: lg,
		Tracker: intake.NewTracker(cfg.Environment, func(ns, s string) bool { _, ok := cfg.Lookup(ns, s); return ok }, closePolls, cfg.MaxOpenIncidents, st, lg)}

	gctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errs := make(chan error, 2)
	go func() { errs <- rt.Serve(gctx) }()
	go func() { errs <- svc.Run(gctx) }()
	first := <-errs
	cancel()
	second := <-errs
	cerr := rt.Close()
	lg.Info("shutdown", "serve_error", fmt.Sprint(errors.Join(first, second)), "close_error", fmt.Sprint(cerr))
	if err := errors.Join(first, second, cerr); err != nil {
		return fail(err)
	}
	return nil
}

// warnUnmanaged предупреждает, если у namespace из реестра нет aegisops.io/managed=true: иначе каждый вердикт PEP —
// deny namespace_not_managed. Сбой запроса — тоже предупреждение, не отказ запуска.
func warnUnmanaged(ctx context.Context, cfg intake.Config, d intake.Durations, live Live, lg *slog.Logger) {
	seen := map[string]bool{}
	for _, s := range cfg.Services {
		if seen[s.Namespace] {
			continue
		}
		seen[s.Namespace] = true
		rc, cancel := context.WithTimeout(ctx, d.Request)
		t, err := live.Cluster.Topology(rc, s)
		cancel()
		switch {
		case err != nil && !errors.Is(err, intake.ErrTruncated): // при усечении данные годны
			lg.Warn("intake_namespace_check_failed", "namespace", s.Namespace, "service", s.Service)
		case t.NamespaceLabels["aegisops.io/managed"] != "true":
			lg.Warn("intake_namespace_not_managed", "namespace", s.Namespace,
				"hint", "без метки aegisops.io/managed=true каждый вердикт PEP по этому namespace — deny namespace_not_managed")
		}
	}
}

func collect(ctx context.Context, cfg intake.Config, d intake.Durations, rt *routersvc.Runtime, live Live, cat *catalog.Catalog,
	ns, svcName string, printInput bool, e env) error {
	sc, ok := cfg.Lookup(ns, svcName)
	if !ok {
		return usage(fmt.Errorf("collect: пары %s/%s нет в services", ns, svcName))
	}
	now := time.Now().UTC()
	t0 := now.Truncate(time.Minute)
	a := intake.SanitizeAlert(intake.Alert{Fingerprint: "0000000000000000", Name: "ManualCollect", Severity: "info", Namespace: ns, Service: svcName,
		Summary: "ручной сбор (collect)", StartsAt: now})
	inc := intake.Incident{ID: intake.IncidentID(intake.Key{Env: cfg.Environment, Namespace: ns, Service: svcName}, now), Alert: a,
		Alerts: map[string]time.Time{a.Fingerprint: now}}
	snap, cerr := newCollector(cfg, d, live).Collect(ctx, inc, sc, t0)
	out := map[string]any{"incident_id": inc.ID, "sources": nonNilStatus(snap.Status)}
	if cerr != nil {
		out["error"] = cerr.Error()
		if err := printJSON(e.stdout, out); err != nil {
			return fail(err)
		}
		return fail(cerr)
	}
	mode := llmrouter.ModeHybrid
	if sc.LLMMode == "off" {
		return usage(errors.New("collect: у сервиса llm_mode off"))
	}
	req, _, err := intake.Assemble(inc.ID, snap, cat, mode)
	if err != nil {
		return fail(err)
	}
	return prepareOut(ctx, rt, req, out, printInput, e)
}

func nonNilStatus(s []audit.SourceStatus) []audit.SourceStatus {
	if s == nil {
		return []audit.SourceStatus{}
	}
	return s
}

// prepareOut — Prepare без сети и бюджета; печатает хеши, статусы, размеры и (по запросу) маскированный input.
func prepareOut(ctx context.Context, rt *routersvc.Runtime, req llmrouter.Request, out map[string]any, printInput bool, e env) error {
	p, err := rt.Router.Prepare(ctx, req, llmrouter.RolePrimary)
	if err != nil {
		return fail(err)
	}
	refs := func(in []llmrouter.FragmentRef) []audit.FragmentRef {
		r := make([]audit.FragmentRef, 0, len(in))
		for _, f := range in {
			r = append(r, audit.FragmentRef{ID: f.ID, Source: f.Source, Class: f.Class.String(), Reason: f.Reason, Required: f.Required})
		}
		return r
	}
	out["request_sha256"], out["input_sha256"], out["data_class"] = p.RequestSHA256, p.InputSHA256, p.DataClass.String()
	out["est_input_tokens"], out["body_bytes"], out["not_sent"] = p.EstInputTokens, len(p.Body), p.NotSent
	out["excluded"], out["dropped"] = refs(p.Excluded), refs(p.Dropped)
	if printInput && p.Body != nil {
		if body, err := pyjson.Parse(p.Body); err == nil && len(body.Get("messages").Items) > 1 {
			out["input"] = json.RawMessage(body.Get("messages").Items[1].Get("content").S)
		}
	}
	return printJSON(e.stdout, out)
}

// captureWriter запоминает записанный decision record для печати.
type captureWriter struct {
	intake.RecordWriter
	last *audit.DecisionRecord
}

func (c *captureWriter) Append(r *audit.DecisionRecord) (audit.Entry, error) {
	c.last = r
	return c.RecordWriter.Append(r)
}

func replay(ctx context.Context, cfg intake.Config, rt *routersvc.Runtime, cat *catalog.Catalog, pol *policyengine.Engine, snap intake.Snapshot,
	prepareOnly bool, lg *slog.Logger, e env) error {
	inc, svc := intake.ReplayIncident(cfg.Environment, snap)
	if sc, ok := cfg.Lookup(svc.Namespace, svc.Service); ok {
		svc = sc
	}
	if prepareOnly {
		if svc.LLMMode == "off" {
			return usage(errors.New("replay: у сервиса llm_mode off, подготовки запроса нет"))
		}
		req, _, err := intake.Assemble(inc.ID, snap, cat, llmrouter.ModeHybrid)
		if err != nil {
			return fail(err)
		}
		return prepareOut(ctx, rt, req, map[string]any{"incident_id": inc.ID, "sources": nonNilStatus(snap.Status)}, false, e)
	}
	st, _ := intake.OpenState("")
	if err := st.Do(func(d *intake.Data) { d.Incidents[inc.ID] = &inc }); err != nil {
		return fail(err)
	}
	cw := &captureWriter{RecordWriter: rt.Writer}
	pipe := &intake.Pipeline{IntakeID: cfg.IntakeID, Env: cfg.Environment, MaxPerHour: cfg.MaxRoutedPerHour, SnapshotDir: cfg.SnapshotDir, Cat: cat,
		Collector: intake.FixtureCollector{Snap: snap}, Router: rt.Router, Writer: cw, PEP: pep.New(cat, pol), State: st, Log: lg,
		Lookup: func(ns, s string) (intake.ServiceConfig, bool) { return svc, ns == svc.Namespace && s == svc.Service }}
	err := pipe.Handle(ctx, &inc)
	if cw.last != nil {
		if perr := printJSON(e.stdout, map[string]any{"record": cw.last}); perr != nil {
			return fail(perr)
		}
	}
	if err != nil {
		return fail(err)
	}
	return nil
}

func printJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

var (
	_ intake.AlertSource   = (*alertmanager.Client)(nil)
	_ intake.ClusterSource = (*kube.Client)(nil)
	_ intake.MetricsSource = (*prom.Client)(nil)
	_ intake.DBSource      = (*prom.Client)(nil)
)
