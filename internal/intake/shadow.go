package intake

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/limpjungle/aegis3311/internal/audit"
	"github.com/limpjungle/aegis3311/internal/catalog"
	"github.com/limpjungle/aegis3311/internal/llmrouter"
	"github.com/limpjungle/aegis3311/internal/pep"
	"github.com/limpjungle/aegis3311/internal/pyjson"
	"github.com/limpjungle/aegis3311/internal/step"
)

// Router — часть llmrouter.Router, нужная intake (в тестах подменяется).
type Router interface {
	Route(context.Context, llmrouter.Request) (*llmrouter.Result, error)
	CloseIncident(string) error
}

type RecordWriter interface {
	Append(*audit.DecisionRecord) (audit.Entry, error)
	HasIncidentRecord(string) bool
}

type Verdicter interface {
	EvaluateRaw(context.Context, []byte, pep.Context) pep.Verdict
}

type Collecting interface {
	Collect(ctx context.Context, inc Incident, svc ServiceConfig, t0 time.Time) (Snapshot, error)
}

const (
	MaxAttempts  = 3                // попыток обработки инцидента (включая рестарты)
	RouteTimeout = 3 * time.Minute  // предел одного Route
	RetryPause   = 30 * time.Second // пауза между повторами сбора при сбое критичного источника
	CollectRetry = 2                // повторов сбора
	RetryWindow  = 5 * time.Minute  // повторы только в пределах settle + RetryWindow от открытия
)

// Pipeline обрабатывает один инцидент: сбор → запрос роутера → PEP dry-run → shadow decision record.
type Pipeline struct {
	IntakeID    string
	Env         string
	Settle      time.Duration
	MaxPerHour  int
	SnapshotDir string
	Cat         *catalog.Catalog
	Collector   Collecting
	Router      Router
	Writer      RecordWriter
	PEP         Verdicter
	State       *State
	Lookup      func(ns, svc string) (ServiceConfig, bool)
	Now         func() time.Time
	RetryPause  time.Duration // 0 → RetryPause
	Log         *slog.Logger

	mu   sync.Mutex
	hist map[string][]time.Time // сервис → моменты маршрутизации за последний час (в памяти)
}

func (p *Pipeline) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

func (p *Pipeline) log() *slog.Logger {
	if p.Log != nil {
		return p.Log
	}
	return slog.New(slog.DiscardHandler)
}

// allow проверяет лимит маршрутизаций сервиса за час без списания слота; take проверяет и списывает его — только
// непосредственно перед Route: инциденты, по которым модель не вызывалась, слот не тратят.
func (p *Pipeline) allow(service string, now time.Time) bool { return p.slot(service, now, false) }
func (p *Pipeline) take(service string, now time.Time) bool  { return p.slot(service, now, true) }

func (p *Pipeline) slot(service string, now time.Time, spend bool) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.hist == nil {
		p.hist = map[string][]time.Time{}
	}
	h := p.hist[service][:0:0]
	for _, t := range p.hist[service] {
		if now.Sub(t) < time.Hour {
			h = append(h, t)
		}
	}
	if len(h) >= p.MaxPerHour {
		p.hist[service] = h
		return false
	}
	if spend {
		h = append(h, now)
	}
	p.hist[service] = h
	return true
}

// Handle обрабатывает инцидент до записи. Ошибка — только фатальная (аудит, store роутера, состояние intake):
// сервис останавливается (fail-closed). Всё остальное — запись not_routed с причиной. Остановка сервиса (отмена ctx) во
// время сбора или Route записи не даёт: Handle возвращает nil, инцидент остаётся open (попытка уже посчитана) и
// обрабатывается заново после рестарта; повторный расход ограничен attempts ≤ 3 и бюджетом инцидента.
func (p *Pipeline) Handle(ctx context.Context, inc *Incident) error {
	id := inc.ID
	if p.Writer.HasIncidentRecord(id) { // крах между Append и сохранением состояния
		return p.markRecorded(id)
	}
	cur, ok := p.State.Get(id)
	if !ok {
		return nil
	}
	svc, ok := p.Lookup(cur.Key.Namespace, cur.Key.Service)
	if !ok { // реестр изменился после открытия инцидента
		return p.recordNotRouted(cur, ServiceConfig{Namespace: cur.Key.Namespace, Service: cur.Key.Service}, "invalid_request", nil, p.now())
	}
	if cur.Status == StatusClosing {
		return p.recordNotRouted(cur, svc, "resolved_before_collect", nil, p.now())
	}
	if err := p.State.Do(func(d *Data) {
		if i := d.Incidents[id]; i != nil {
			i.Attempts++
			cur.Attempts = i.Attempts
		}
	}); err != nil {
		return err
	}
	if cur.Attempts > MaxAttempts {
		return p.recordNotRouted(cur, svc, "attempts_exhausted", nil, p.now())
	}
	if !p.allow(svc.Service, p.now()) {
		return p.recordNotRouted(cur, svc, "rate_limited", nil, p.now())
	}

	mode := llmrouter.ModeHybrid
	if svc.LLMMode == "off" {
		mode = llmrouter.ModeOff
	}
	var (
		snap  Snapshot
		req   llmrouter.Request
		st    step.TargetState
		t0    time.Time
		stats []audit.SourceStatus
	)
	if mode == llmrouter.ModeOff { // модель не вызывается: источники не нужны
		t0 = p.now().UTC().Truncate(time.Minute)
		req = llmrouter.Request{IncidentID: id, Service: svc.Service, Mode: mode}
		stats = []audit.SourceStatus{{Source: "alerts.alertmanager", Status: "ok", Items: len(cur.Alerts)}}
	} else {
		var err error
		pause := p.RetryPause
		if pause == 0 {
			pause = RetryPause
		}
		for try := 0; ; try++ {
			t0 = p.now().UTC().Truncate(time.Minute)
			snap, err = p.Collector.Collect(ctx, cur, svc, t0)
			var ce *ErrCriticalSource
			if err == nil || !errors.As(err, &ce) {
				break
			}
			if try >= CollectRetry || p.now().Add(pause).After(cur.OpenedAt.Add(p.Settle+RetryWindow)) || ctx.Err() != nil {
				break
			}
			p.log().Warn("intake_collect_retry", "incident", id, "source", ce.Source, "try", try+1)
			select {
			case <-ctx.Done():
			case <-time.After(pause):
			}
			if ctx.Err() != nil {
				break
			}
		}
		stats = snap.Status
		if err != nil {
			var ce *ErrCriticalSource
			if errors.As(err, &ce) {
				p.log().Error("intake_source_unavailable", "incident", id, "source", ce.Source)
				return p.recordNotRouted(cur, svc, "source_unavailable", stats, t0)
			}
			if ctx.Err() != nil { // остановка сервиса: попытка уже посчитана, запись не пишется
				return nil
			}
			p.log().Error("intake_collect_failed", "incident", id)
			return p.recordNotRouted(cur, svc, "source_unavailable", stats, t0)
		}
		if ctx.Err() != nil {
			return nil
		}
		if req, st, err = Assemble(id, snap, p.Cat, mode); err != nil {
			p.log().Error("intake_invalid_request", "incident", id, "error", err.Error())
			return p.recordNotRouted(cur, svc, "invalid_request", stats, t0)
		}
	}

	if !p.take(svc.Service, p.now()) {
		return p.recordNotRouted(cur, svc, "rate_limited", stats, t0)
	}
	rctx, cancel := context.WithTimeout(ctx, RouteTimeout)
	defer cancel()
	res, rerr := p.Router.Route(rctx, req)
	if res == nil {
		var inv *llmrouter.InvalidRequestError
		if errors.As(rerr, &inv) {
			p.log().Error("intake_invalid_request", "incident", id, "error", rerr.Error())
			return p.recordNotRouted(cur, svc, "invalid_request", stats, t0)
		}
		return fmt.Errorf("intake: Route %s: %w", id, rerr)
	}
	if rerr != nil { // ErrAuditFailed: результат частичный, предложение формировать нельзя
		return fmt.Errorf("intake: Route %s: %w", id, rerr)
	}
	if ctx.Err() != nil { // остановка сервиса во время Route: запись-ошибку не пишем, инцидент остаётся open
		return nil
	}

	rec := p.baseRecord(cur, svc, "routed", "", stats, t0)
	res.Apply(rec)
	if ps := res.Parsed; ps != nil && ps.Status == "ok" && res.ErrorKind == "" && ps.Answer != nil {
		if act := ps.Answer.Get("action"); act != nil {
			v := p.PEP.EvaluateRaw(ctx, pyjson.Marshal(act, pyjson.Canonical), ShadowContext(p.Env, snap.Topology, st))
			rec.Verdict, rec.AutonomyLevel = &v, v.EffectiveLevel
		}
	}
	p.saveInput(res)
	return p.append(rec, id)
}

func (p *Pipeline) markRecorded(id string) error {
	return p.State.Do(func(d *Data) {
		if i := d.Incidents[id]; i != nil && i.Status == StatusOpen {
			i.Status = StatusRecorded
		}
	})
}

func (p *Pipeline) append(rec *audit.DecisionRecord, id string) error {
	if _, err := p.Writer.Append(rec); err != nil {
		return fmt.Errorf("intake: запись %s: %w", id, err)
	}
	p.log().Info("intake_recorded", "incident", id, "outcome", rec.Intake.Outcome, "reason", rec.Intake.Reason)
	return p.markRecorded(id)
}

// RecordNotRouted пишет запись об инциденте, по которому модель не вызывалась.
func (p *Pipeline) RecordNotRouted(inc Incident, svc ServiceConfig, reason string) error {
	return p.recordNotRouted(inc, svc, reason, nil, p.now())
}

func (p *Pipeline) recordNotRouted(inc Incident, svc ServiceConfig, reason string, stats []audit.SourceStatus, t0 time.Time) error {
	if p.Writer.HasIncidentRecord(inc.ID) {
		return p.markRecorded(inc.ID)
	}
	return p.append(p.baseRecord(inc, svc, "not_routed", reason, stats, t0), inc.ID)
}

func (p *Pipeline) baseRecord(inc Incident, svc ServiceConfig, outcome, reason string, stats []audit.SourceStatus, t0 time.Time) *audit.DecisionRecord {
	fps := alertFingerprints(inc)
	if len(stats) > 32 {
		stats = stats[:32]
	}
	if stats == nil {
		stats = []audit.SourceStatus{}
	}
	return &audit.DecisionRecord{Schema: audit.RecordSchema, RecordID: audit.NewRecordID(), RecordedAt: audit.Timestamp(p.now()),
		Mode: audit.ModeShadow, Incident: audit.IncidentRef{ID: inc.ID, Service: svc.Service, Environment: p.Env},
		Initiator: audit.Actor{Kind: "agent", ID: p.IntakeID}, RetrievedDocs: []string{}, AutonomyLevel: "L0",
		Intake: &audit.IntakeInfo{Source: "alerts.alertmanager", FirstAlertAt: audit.Timestamp(inc.FirstAlertAt), CollectedAt: audit.Timestamp(t0),
			Alerts: fps, Sources: stats, Outcome: outcome, Reason: reason}}
}

// saveInput сохраняет точные байты user-сообщения запроса: файл <input_sha256>.json (0600). По нему воспроизводится
// решение и строится реальный golden-набор. Сбой сохранения не мешает записи: журнал.
func (p *Pipeline) saveInput(res *llmrouter.Result) {
	pr := res.Prepared
	if pr == nil || pr.Body == nil || p.SnapshotDir == "" {
		return
	}
	body, err := pyjson.Parse(pr.Body)
	if err != nil || body.Get("messages") == nil || len(body.Get("messages").Items) < 2 {
		p.log().Error("intake_snapshot_failed", "reason", "body")
		return
	}
	content := []byte(body.Get("messages").Items[1].Get("content").S)
	if got := sha256Hex(content); got != pr.InputSHA256 {
		p.log().Error("intake_snapshot_failed", "reason", "input_sha256_mismatch")
		return
	}
	if err := writeFileAtomic(p.SnapshotDir, pr.InputSHA256+".json", content); err != nil {
		p.log().Error("intake_snapshot_failed", "reason", err.Error())
	}
}

func writeFileAtomic(dir, name string, b []byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), filepath.Join(dir, name)); err != nil {
		return err
	}
	return syncDir(dir)
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
