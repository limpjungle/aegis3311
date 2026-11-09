package intake

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/limpjungle/aegis3311/internal/audit"
	"github.com/limpjungle/aegis3311/internal/killswitch"
	"github.com/limpjungle/aegis3311/internal/llmrouter"
	"github.com/limpjungle/aegis3311/internal/promtext"
)

// KillSwitchObserver — снимок kill switch для /metrics (killswitch.Monitor).
type KillSwitchObserver interface{ Observe() killswitch.Observation }

// RouterObserver — состояние роутера (llmrouter.Router.State). Не routersvc.Status: оно копирует весь журнал событий.
type RouterObserver interface{ State() llmrouter.State }

// ChainHead — голова цепочки аудита (audit.Writer).
type ChainHead interface{ Head() audit.Head }

// AnchorObserver — состояние выгрузки checkpoint'ов в WORM (audit.Anchorer); nil — anchor не настроен.
type AnchorObserver interface{ Status() audit.AnchorStatus }

// Metrics — экспозиция Prometheus для serve: kill switch, опрос Alertmanager, записи, инциденты, роутер, цепочка.
// Наблюдаемость, а не защита. Чувствительного в ней нет: ни ID инцидентов, сервисов, namespace, issuer'ов, sha и
// intake_id, ни классов ошибок каналов; метки берутся только из фиксированных наборов (исключение — cluster из
// конфигурации). Все ряды заполняются нулями заранее, чтобы rate() и алерты видели их до первого события.
type Metrics struct {
	Cluster string
	KS      KillSwitchObserver
	Router  RouterObserver
	Chain   ChainHead
	Anchor  AnchorObserver // nil — выгрузка checkpoint'ов выключена
	State   *State
	Now     func() time.Time

	started    time.Time
	alertPolls [2]atomic.Uint64 // ok, error

	mu      sync.Mutex
	records map[recKey]uint64
}

type recKey struct {
	outcome, reason, mode string
	ksStopped             bool
}

var (
	metricReasons    = []string{"none", "source_unavailable", "rate_limited", "resolved_before_collect", "attempts_exhausted", "invalid_request", "other"}
	metricModes      = []string{"hybrid", "off", "other"}
	metricKSReasons  = []string{"none", "global", "cluster", "no_confirmation"}
	metricChannels   = []string{"configmap", "oob"}
	metricStatuses   = []string{StatusOpen, StatusRecorded, StatusClosing, "other"}
	metricHaltReason = []string{"none", "auth", "estimator", "audit_failed", "state_store", "state_lost", "chain_lost", "other"}
)

// NewMetrics создаёт набор метрик; now == nil → time.Now.
func NewMetrics(cluster string, ks KillSwitchObserver, rt RouterObserver, chain ChainHead, st *State, now func() time.Time) *Metrics {
	if now == nil {
		now = time.Now
	}
	return &Metrics{Cluster: cluster, KS: ks, Router: rt, Chain: chain, State: st, Now: now, started: now(), records: map[recKey]uint64{}}
}

// AlertPoll учитывает опрос Alertmanager. Nil-безопасно.
func (m *Metrics) AlertPoll(ok bool) {
	if m == nil {
		return
	}
	if ok {
		m.alertPolls[0].Add(1)
	} else {
		m.alertPolls[1].Add(1)
	}
}

func metricOneOf(v string, set []string) string {
	for _, s := range set {
		if v == s {
			return v
		}
	}
	return "other"
}

// Record учитывает записанный decision record. Значения нормализуются к фиксированным наборам. Nil-безопасно.
func (m *Metrics) Record(r *audit.DecisionRecord) {
	if m == nil || r == nil || r.Intake == nil {
		return
	}
	k := recKey{outcome: "not_routed"}
	if r.Intake.Outcome == "routed" {
		k.outcome = "routed"
		k.reason = "none"
		k.mode = "other"
		if r.LLM != nil {
			k.mode = metricOneOf(r.LLM.Mode, metricModes)
		}
	} else {
		k.reason = metricOneOf(r.Intake.Reason, metricReasons[1:])
	}
	k.ksStopped = r.KillSwitch != nil && r.KillSwitch.State.Stopped
	m.mu.Lock()
	m.records[k]++
	m.mu.Unlock()
}

func metricLabel(name, value string) []promtext.Label {
	return []promtext.Label{{Name: name, Value: value}}
}

func metricOneHot(name string, set []string, cur string) []promtext.Sample {
	cur = metricOneOf(cur, set)
	out := make([]promtext.Sample, 0, len(set))
	for _, v := range set {
		out = append(out, promtext.Sample{Labels: metricLabel(name, v), Value: promtext.Bool(v == cur)})
	}
	return out
}

func metricScalar(v float64) promtext.Sample { return promtext.Sample{Value: v} }

// Render собирает экспозицию на момент скрейпа.
func (m *Metrics) Render() ([]byte, error) {
	var w promtext.Writer
	var o killswitch.Observation
	if m.KS != nil {
		o = m.KS.Observe()
	}
	s := o.State
	reason := s.Reason
	if reason == "" {
		reason = "none"
	}
	w.Gauge("aegis_intake_killswitch_stopped", "1 — цель остановлена kill switch.",
		promtext.Sample{Labels: metricLabel("cluster", m.Cluster), Value: promtext.Bool(s.Stopped)})
	w.Gauge("aegis_intake_killswitch_reason", "Причина остановки (one-hot).", metricOneHot("reason", metricKSReasons, reason)...)
	w.Gauge("aegis_intake_killswitch_liveness_confirmed", "1 — есть засчитанное подтверждение работы.", metricScalar(promtext.Bool(s.LivenessConfirmed)))
	w.Gauge("aegis_intake_killswitch_actions_restricted", "Число запрещённых документом типов действий.", metricScalar(float64(len(s.Actions))))
	w.Gauge("aegis_intake_killswitch_confirmed_until_timestamp_seconds", "Конец действия подтверждения; 0 — нет.", metricScalar(promtext.Unix(s.ConfirmedUntil)))
	w.Gauge("aegis_intake_killswitch_stop_watermark_timestamp_seconds", "Водяной знак остановки W; 0 — нет.", metricScalar(promtext.Unix(s.Marks.Stop)))
	w.Gauge("aegis_intake_killswitch_release_watermark_timestamp_seconds", "Водяной знак снятия R; 0 — нет.", metricScalar(promtext.Unix(s.Marks.Release)))
	w.Gauge("aegis_intake_killswitch_bootstrap_pending", "1 — первая оценка без истории ещё не записана.", metricScalar(promtext.Bool(o.BootstrapPending)))
	w.Gauge("aegis_intake_killswitch_bootstrap_awaiting_release", "1 — W выставлен bootstrap и release после него ещё не было.", metricScalar(promtext.Bool(o.BootstrapAwaitingRelease)))
	w.Gauge("aegis_intake_killswitch_last_poll_timestamp_seconds", "Последний опрос каналов, дошедший до оценки; 0 — не было.", metricScalar(promtext.Unix(o.LastPoll)))
	var chOK, chCached, chIssued, chLast []promtext.Sample
	for _, name := range metricChannels {
		var c audit.KillSwitchChannel
		for _, x := range s.Channels {
			if x.Channel == name {
				c = x
			}
		}
		var issued time.Time
		if c.IssuedAt != "" {
			issued, _ = time.Parse(time.RFC3339Nano, c.IssuedAt)
		}
		l := metricLabel("channel", name)
		chOK = append(chOK, promtext.Sample{Labels: l, Value: promtext.Bool(c.IssuedAt != "" && c.Error == "")})
		chCached = append(chCached, promtext.Sample{Labels: l, Value: promtext.Bool(c.Cached)})
		chIssued = append(chIssued, promtext.Sample{Labels: l, Value: promtext.Unix(issued)})
		chLast = append(chLast, promtext.Sample{Labels: l, Value: promtext.Unix(o.ChannelLastOK[name])})
	}
	w.Gauge("aegis_intake_killswitch_channel_ok", "1 — в канале есть документ без ошибок.", chOK...)
	w.Gauge("aegis_intake_killswitch_channel_cached", "1 — документ канала взят из кэша (канал недоступен).", chCached...)
	w.Gauge("aegis_intake_killswitch_channel_doc_issued_timestamp_seconds", "issued_at документа в канале; 0 — нет.", chIssued...)
	w.Gauge("aegis_intake_killswitch_channel_last_success_timestamp_seconds", "Последнее успешное чтение и разбор канала; 0 — не было.", chLast...)
	if o.LastEngagedLatencyMs != nil {
		w.Gauge("aegis_intake_killswitch_last_engaged_latency_ms", "applied_at - issued_at последней остановки (метрика G0).", metricScalar(float64(*o.LastEngagedLatencyMs)))
	}
	var ev []promtext.Sample
	for _, k := range []string{"engaged", "released", "updated"} {
		ev = append(ev, promtext.Sample{Labels: metricLabel("kind", k), Value: float64(o.Events["kill_switch_"+k])})
	}
	w.Counter("aegis_intake_killswitch_events_total", "События kill switch, записанные в цепочку с момента старта.", ev...)

	w.Counter("aegis_intake_alert_polls_total", "Опросы Alertmanager.",
		promtext.Sample{Labels: metricLabel("result", "ok"), Value: float64(m.alertPolls[0].Load())},
		promtext.Sample{Labels: metricLabel("result", "error"), Value: float64(m.alertPolls[1].Load())})

	m.mu.Lock()
	byReason := map[[2]string]uint64{}
	byMode := map[string]uint64{}
	var ksStopped uint64
	for k, n := range m.records {
		byReason[[2]string{k.outcome, k.reason}] += n
		if k.outcome == "routed" {
			byMode[k.mode] += n
		}
		if k.ksStopped {
			ksStopped += n
		}
	}
	m.mu.Unlock()
	recs := []promtext.Sample{{Labels: []promtext.Label{{Name: "outcome", Value: "routed"}, {Name: "reason", Value: "none"}}, Value: float64(byReason[[2]string{"routed", "none"}])}}
	for _, r := range metricReasons[1:] {
		recs = append(recs, promtext.Sample{Labels: []promtext.Label{{Name: "outcome", Value: "not_routed"}, {Name: "reason", Value: r}}, Value: float64(byReason[[2]string{"not_routed", r}])})
	}
	w.Counter("aegis_intake_records_total", "Записанные decision records по исходу.", recs...)
	var modes []promtext.Sample
	for _, v := range metricModes {
		modes = append(modes, promtext.Sample{Labels: metricLabel("mode", v), Value: float64(byMode[v])})
	}
	w.Counter("aegis_intake_records_llm_mode_total", "Записи routed по режиму llm.", modes...)
	w.Counter("aegis_intake_records_kill_switch_stopped_total", "Записи, сделанные при остановленном kill switch.", metricScalar(float64(ksStopped)))

	counts := map[string]uint64{}
	if m.State != nil {
		m.State.View(func(d *Data) {
			for _, inc := range d.Incidents {
				counts[metricOneOf(inc.Status, metricStatuses)]++
			}
		})
	}
	var incs []promtext.Sample
	for _, v := range metricStatuses {
		incs = append(incs, promtext.Sample{Labels: metricLabel("status", v), Value: float64(counts[v])})
	}
	w.Gauge("aegis_intake_incidents", "Инциденты в состоянии intake по статусу.", incs...)

	var rs llmrouter.State
	if m.Router != nil {
		rs = m.Router.State()
	}
	halt := rs.HaltReason
	if !rs.Halted {
		halt = "none"
	} else if halt == "none" || halt == "" {
		halt = "other"
	}
	w.Gauge("aegis_intake_router_halted", "1 — роутер остановлен.", metricScalar(promtext.Bool(rs.Halted)))
	w.Gauge("aegis_intake_router_halt_reason", "Причина остановки роутера (one-hot).", metricOneHot("reason", metricHaltReason, halt)...)
	var seq uint64
	if m.Chain != nil {
		seq = m.Chain.Head().Seq
	}
	w.Gauge("aegis_intake_audit_chain_seq", "Номер последней записи цепочки аудита.", metricScalar(float64(seq)))
	var as audit.AnchorStatus
	if m.Anchor != nil {
		as = m.Anchor.Status()
	}
	w.Gauge("aegis_intake_audit_anchor_enabled", "1 — checkpoint'ы цепочки выгружаются во внешнее хранилище.", metricScalar(promtext.Bool(m.Anchor != nil)))
	w.Gauge("aegis_intake_audit_anchor_seq", "Номер записи цепочки, зафиксированной во внешнем хранилище.", metricScalar(float64(as.AnchoredSeq)))
	w.Gauge("aegis_intake_audit_anchor_lag_seconds", "Возраст самой старой незафиксированной записи; 0 — всё зафиксировано.", metricScalar(as.Lag.Seconds()))
	w.Gauge("aegis_intake_audit_anchor_last_success_timestamp_seconds", "Последняя успешная фиксация; 0 — не было.", metricScalar(promtext.Unix(as.LastSuccess)))
	w.Counter("aegis_intake_audit_anchor_errors_total", "Неудачные попытки фиксации checkpoint'а с момента старта.", metricScalar(float64(as.Errors)))
	w.Gauge("aegis_intake_start_timestamp_seconds", "Время старта процесса.", metricScalar(promtext.Unix(m.started)))
	return w.Bytes()
}

// Handler обслуживает GET/HEAD /metrics и /healthz. /healthz — только «процесс жив» и не зависит от kill switch:
// сделать из него readiness по остановке значит снять сам intake с обслуживания и ослепить наблюдение.
func (m *Metrics) Handler() http.Handler {
	mux := http.NewServeMux()
	guard := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				w.Header().Set("Allow", "GET, HEAD")
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			h(w, r)
		}
	}
	write := func(w http.ResponseWriter, r *http.Request, ct string, b []byte) {
		w.Header().Set("Content-Type", ct)
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			w.Write(b)
		}
	}
	mux.HandleFunc("/metrics", guard(func(w http.ResponseWriter, r *http.Request) {
		b, err := m.Render()
		if err != nil {
			http.Error(w, "render failed", http.StatusInternalServerError)
			return
		}
		write(w, r, promtext.ContentType, b)
	}))
	mux.HandleFunc("/healthz", guard(func(w http.ResponseWriter, r *http.Request) {
		write(w, r, "text/plain; charset=utf-8", []byte("ok\n"))
	}))
	return mux
}

// ServeMetrics обслуживает h на ln до отмены ctx и затем останавливает сервер (до 5 с). Сбой сервера после старта не
// фатален для intake: он логируется (intake_metrics_failed), возврат — nil. После возврата listener закрыт.
func ServeMetrics(ctx context.Context, ln net.Listener, h http.Handler, lg *slog.Logger) error {
	if lg == nil {
		lg = slog.New(slog.DiscardHandler)
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second,
		IdleTimeout: 60 * time.Second, MaxHeaderBytes: 8 << 10}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			lg.Error("intake_metrics_failed", "error", err.Error())
		}
	}()
	select {
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
		srv.Close()
	case <-done:
	}
	ln.Close()
	<-done
	return nil
}
