package routersvc

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"reflect"
	"sync"
	"time"

	goldensynthetic "github.com/limpjungle/aegis3311/eval/golden-synthetic"
	"github.com/limpjungle/aegis3311/internal/audit"
	"github.com/limpjungle/aegis3311/internal/llmrouter"
	"github.com/limpjungle/aegis3311/internal/masker"
	"github.com/limpjungle/aegis3311/internal/openrouter"
	"github.com/limpjungle/aegis3311/internal/routerstate"
)

var (
	ErrNotInitialized  = errors.New("routersvc: хранилище состояния или цепочка не существуют (сервис ещё не запускался)")
	ErrNothingToResume = errors.New("routersvc: роутер не остановлен, карантина нет")
)

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// Deps — подменяемые зависимости; нулевые значения — рабочие.
type Deps struct {
	Transport     openrouter.Transport                      // nil → openrouter.NewHTTPTransport()
	ClientOptions []openrouter.ClientOption                 // тесты: WithSleep, WithURL
	Clock         llmrouter.Clock                           // nil → time.Now
	Logger        *slog.Logger                              // nil → без вывода
	WrapStore     func(routerstate.Store) routerstate.Store // только тесты: внедрение сбоев store
	StatePoll     time.Duration                             // 0 → 1 с; период наблюдателя за состоянием в Serve
	Assets        *openrouter.Assets                        // только тесты: nil → LoadAssets(goldensynthetic.FS)
}

type OpenOptions struct {
	// Create — создать store и цепочку, если их нет (serve). false: оба файла должны существовать, иначе
	// ErrNotInitialized и ничего не создаётся (status, resume, route).
	Create bool
}

// Runtime — открытый роутер вместе с его писателем цепочки и store. Один Runtime — единственный писатель обоих файлов.
type Runtime struct {
	Router        *llmrouter.Router
	Writer        *audit.Writer // decision record'ы агента пишутся сюда же: одна цепочка с событиями роутера
	Store         *routerstate.FileStore
	Assets        *openrouter.Assets
	Config        Config
	MaskerVersion string

	log       *slog.Logger
	poll      time.Duration
	closeOnce sync.Once
	closeErr  error
}

// Open проверяет всё, что проверяется без диска, затем открывает цепочку (источник истины), затем store и создаёт
// роутер. New роутера может дописать в цепочку router_halted(state_lost | chain_lost) и списать незакрытые резервы.
func Open(cfg Config, sec Secrets, o OpenOptions, d Deps) (*Runtime, error) {
	budgets, fo, nets, err := cfg.Effective()
	if err != nil {
		return nil, &ConfigError{err}
	}
	if err := cfg.Validate(); err != nil {
		return nil, &ConfigError{err}
	}
	if sec.Signer == nil {
		return nil, &ConfigError{errors.New("routersvc: нет ключа подписи аудита")}
	}
	log, clock, tr, poll := d.Logger, d.Clock, d.Transport, d.StatePoll
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if clock == nil {
		clock = systemClock{}
	}
	if tr == nil {
		tr = openrouter.NewHTTPTransport()
	}
	if poll <= 0 {
		poll = time.Second
	}
	a := d.Assets
	if a == nil {
		if a, err = openrouter.LoadAssets(goldensynthetic.FS); err != nil {
			return nil, err
		}
	}
	m, err := masker.New(masker.Config{PseudonymKey: sec.MaskerKey, InternalNets: nets})
	if err != nil {
		return nil, &ConfigError{err}
	}
	cl, err := openrouter.NewClient(&a.Config, sec.APIKey, tr, d.ClientOptions...)
	if err != nil {
		return nil, err
	}
	keys := audit.Keyring{}
	keys.Add(sec.Signer.Public())
	for _, p := range cfg.Audit.PublicKeys {
		pub, err := audit.LoadPublicKey(p)
		if err != nil {
			return nil, &ConfigError{fmt.Errorf("audit.public_keys: %w", err)}
		}
		keys.Add(ed25519.PublicKey(pub))
	}
	if !o.Create {
		for _, p := range []string{cfg.StatePath, cfg.Audit.Chain} {
			if _, err := os.Stat(p); err != nil {
				if errors.Is(err, os.ErrNotExist) {
					return nil, ErrNotInitialized
				}
				return nil, err
			}
		}
	}
	w, err := audit.OpenWriter(cfg.Audit.Chain, cfg.Audit.ChainID, sec.Signer, keys)
	if err != nil {
		return nil, err
	}
	id := routerstate.Identity{RouterID: cfg.RouterID, Primary: a.Primary.Name, Fallback: a.Fallback.Name}
	fs, err := routerstate.OpenFile(cfg.StatePath, id, routerstate.FileOptions{})
	if err != nil {
		w.Close()
		return nil, err
	}
	var st routerstate.Store = fs
	if d.WrapStore != nil {
		st = d.WrapStore(st)
	}
	r, err := llmrouter.New(llmrouter.Options{Assets: a, Client: cl, Masker: m, Events: w, Clock: clock,
		Budgets: budgets, Failover: fo, RouterID: cfg.RouterID, State: st})
	if err != nil {
		fs.Close()
		w.Close()
		return nil, err
	}
	rt := &Runtime{Router: r, Writer: w, Store: fs, Assets: a, Config: cfg, MaskerVersion: m.Version(), log: log, poll: poll}
	s := r.State()
	log.Info("llmrouter_opened", "router_id", cfg.RouterID, "chain_id", cfg.Audit.ChainID, "state_path", cfg.StatePath,
		"chain", cfg.Audit.Chain, "masker_version", rt.MaskerVersion, "assets_config_sha256", a.ConfigSHA256,
		"primary", a.Primary.Name, "fallback", a.Fallback.Name, "incident_tokens", budgets.IncidentTokens, "service_day_tokens", budgets.ServiceDayTokens,
		"fail_threshold", fo.FailThreshold, "hysteresis", fo.Hysteresis.String(), "health_interval", fo.HealthInterval.String(),
		"chain_seq", w.Head().Seq, "active", s.Active, "halted", s.Halted, "halt_reason", s.HaltReason)
	if s.Halted {
		log.Warn("llmrouter_halted", "halt_reason", s.HaltReason,
			"hint", "посмотрите status (last_router_halted), устраните причину и выполните resume при остановленном сервисе")
	}
	return rt, nil
}

// Close закрывает store, затем писатель цепочки. Идемпотентно.
func (rt *Runtime) Close() error {
	rt.closeOnce.Do(func() {
		rt.closeErr = errors.Join(rt.Store.Close(), rt.Writer.Close())
	})
	return rt.closeErr
}

// Serve запускает проверки здоровья и наблюдение за состоянием до отмены ctx (результат nil) или сбоя
// аудита/store (результат — эта ошибка). Runtime не закрывает.
func (rt *Runtime) Serve(ctx context.Context) error {
	done := make(chan error, 1)
	go func() { done <- rt.Router.RunHealthLoop(ctx) }()
	prev := rt.Router.State()
	t := time.NewTicker(rt.poll)
	defer t.Stop()
	var err error
loop:
	for {
		select {
		case err = <-done:
			break loop
		case <-t.C:
			if cur := rt.Router.State(); !reflect.DeepEqual(cur, prev) {
				rt.logState(cur)
				prev = cur
			}
		}
	}
	if cur := rt.Router.State(); !reflect.DeepEqual(cur, prev) {
		rt.logState(cur)
	}
	if err == nil || errors.Is(err, context.Canceled) || ctx.Err() != nil {
		return nil
	}
	rt.log.Error("health_loop_stopped", "error", err.Error(), "hint", Hint(err))
	return err
}

func (rt *Runtime) logState(s llmrouter.State) {
	rt.log.Info("router_state", "active", s.Active, "halted", s.Halted, "halt_reason", s.HaltReason, "endpoints", s.Endpoints)
}

// Status — снимок для оператора.
type Status struct {
	RouterID   string             `json:"router_id"`
	ChainID    string             `json:"chain_id"`
	ChainSeq   uint64             `json:"chain_seq"`
	Active     string             `json:"active"`
	Halted     bool               `json:"halted"`
	HaltReason string             `json:"halt_reason"`
	Endpoints  map[string]string  `json:"endpoints"`
	Masker     string             `json:"masker_version"`
	LastHalt   *audit.RouterEvent `json:"last_router_halted"`  // перед Resume оператор проверяет причину
	LastResume *audit.RouterEvent `json:"last_router_resumed"` //
}

func (rt *Runtime) Status() Status {
	s := rt.Router.State()
	st := Status{RouterID: rt.Config.RouterID, ChainID: rt.Config.Audit.ChainID, ChainSeq: rt.Writer.Head().Seq, Active: s.Active,
		Halted: s.Halted, HaltReason: s.HaltReason, Endpoints: s.Endpoints, Masker: rt.MaskerVersion}
	evs := rt.Writer.RouterEvents()
	for i := len(evs) - 1; i >= 0 && (st.LastHalt == nil || st.LastResume == nil); i-- {
		ev := evs[i]
		switch {
		case ev.Kind == "router_halted" && st.LastHalt == nil:
			st.LastHalt = &ev
		case ev.Kind == "router_resumed" && st.LastResume == nil:
			st.LastResume = &ev
		}
	}
	return st
}

// Resume снимает остановку и карантин от имени оператора. Роутер не остановлен и карантина нет —
// ErrNothingToResume (пустое router_resumed в аудит не пишется).
func (rt *Runtime) Resume(ctx context.Context, operator string) error {
	s := rt.Router.State()
	need := s.Halted
	for _, e := range s.Endpoints {
		need = need || e == "quarantined"
	}
	if !need {
		return ErrNothingToResume
	}
	return rt.Router.Resume(ctx, operator)
}
