package intake

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/limpjungle/aegis3311/internal/bundle"
	"github.com/limpjungle/aegis3311/internal/killswitch"
	"github.com/limpjungle/aegis3311/internal/killswitch/s3"
	"github.com/limpjungle/aegis3311/internal/routersvc"
	"github.com/limpjungle/aegis3311/internal/strictjson"
)

const maxConfigBytes = 4 << 20

// Config — несекретная конфигурация intake (JSON, строгий разбор). Токены источников — только из файлов в *_FILE.
// Вся конкретика окружения — PromQL, db_queries, matchers, URL, реестр сервисов — живёт здесь, не в коде.
// Допущения окружения, которые нужно подтвердить до shadow, перечислены в docs/04-operations/intake-deploy.md.
//
// Пример (типовой стек: Prometheus, ingress-nginx, kube-state-metrics/cAdvisor, pgbouncer_exporter/postgres_exporter):
//
//	{"intake_id": "intake-1", "router_config": "/etc/aegis/llmrouter.json",
//	 "state_path": "/var/lib/aegis/intake.state.json", "snapshot_dir": "/var/lib/aegis/snapshots",
//	 "environment": "prod-cloud-hybrid",
//	 "alertmanager": {"url": "https://alertmanager.monitoring:9093", "ca_file": "/etc/aegis/ca.pem", "matchers": ["aegis_flow=\"true\""]},
//	 "prometheus": {"url": "https://prometheus.monitoring:9090", "ca_file": "/etc/aegis/ca.pem"},
//	 "kubernetes": {"api_url": "https://kubernetes.default.svc", "ca_file": "/etc/aegis/kube-ca.pem", "author_annotation": "ci.example.com/deployed-by"},
//	 "services": [{"namespace": "shop", "service": "geo-svc", "workload": {"kind": "Deployment", "name": "geo-svc"},
//	               "autoscaler": {"kind": "HorizontalPodAutoscaler", "name": "geo-svc"}, "declared_min": 2,
//	               "database": "geo", "pg_cluster": "pg-main", "bake": "60m", "llm_mode": "hybrid"}],
//	 "metrics": [
//	   {"name": "ingress_p99_latency_ms", "unit": "ms", "applies": "always", "max_series": 1,
//	    "query": "1000 * histogram_quantile(0.99, sum by (le) (rate(nginx_ingress_controller_request_duration_seconds_bucket{exported_namespace=\"$namespace\",exported_service=\"$service\"}[2m])))"},
//	   {"name": "ingress_5xx_ratio", "unit": "ratio", "applies": "always", "max_series": 1,
//	    "query": "sum(rate(nginx_ingress_controller_requests{exported_namespace=\"$namespace\",exported_service=\"$service\",status=~\"5..\"}[2m])) / sum(rate(nginx_ingress_controller_requests{exported_namespace=\"$namespace\",exported_service=\"$service\"}[2m]))"},
//	   {"name": "memory_working_set_mb", "unit": "MB", "applies": "always", "series_labels": ["pod"], "max_series": 12,
//	    "query": "sum by (pod) (container_memory_working_set_bytes{namespace=\"$namespace\",pod=~\"$service-.*\",container!=\"\",container!=\"POD\"}) / 1048576"},
//	   {"name": "pgbouncer_cl_waiting", "unit": "count", "applies": "database", "max_series": 1,
//	    "query": "sum(pgbouncer_pools_client_waiting_connections{database=\"$database\"})"}],
//	 "metrics_listen": ":9464",
//	 "kill_switch": {"cluster": "prod-eu-1",
//	                 "keys": [{"path": "/etc/aegis/ks/ivanov.pub.pem", "issuer": "oncall-ivanov", "role": "oncall"},
//	                          {"path": "/etc/aegis/ks/petrov.pub.pem", "issuer": "oncall-petrov", "role": "oncall"}],
//	                 "oob": {"endpoint": "https://storage.yandexcloud.net", "region": "ru-central1", "bucket": "aegis-kill-switch", "key": "kill-switch.json", "path_style": true}},
//	 "db_queries": {"pool_size": "max(pgbouncer_config_pool_size{database=\"$database\"})",
//	                "max_connections": "max(pg_settings_max_connections{cluster=\"$pg_cluster\"})"}}
//
// Остальные метрики и ключи db_queries — по тому же образцу (полный перечень ключей: DBQueryKeys).
type Config struct {
	IntakeID          string              `json:"intake_id"`                   // initiator agent/<intake_id>
	RouterConfig      string              `json:"router_config"`               // конфигурация aegis-llmrouter (routersvc.Config)
	StatePath         string              `json:"state_path"`                  // состояние intake (атомарная замена файла)
	SnapshotDir       string              `json:"snapshot_dir"`                // снимки входа модели
	Environment       string              `json:"environment"`                 // staging | prod-cloud-hybrid | prod-baremetal
	PollInterval      string              `json:"poll_interval"`               // 15s
	Settle            string              `json:"settle"`                      // 2m: ожидание перед снимком
	CloseAfter        string              `json:"close_after"`                 // 15m успешных опросов без алертов ключа
	CollectTimeout    string              `json:"collect_timeout"`             // 30s на весь сбор
	RequestTimeout    string              `json:"request_timeout"`             // 5s на запрос к источнику
	SnapshotRetention string              `json:"snapshot_retention"`          // 2160h (90 суток)
	Workers           int                 `json:"workers"`                     // 2
	MaxOpenIncidents  int                 `json:"max_open_incidents"`          // 256
	MaxRoutedPerHour  int                 `json:"max_routed_per_service_hour"` // 6
	Alertmanager      HTTPSource          `json:"alertmanager"`
	Prometheus        HTTPSource          `json:"prometheus"`
	Kubernetes        KubeSource          `json:"kubernetes"`
	Services          []ServiceConfig     `json:"services"`
	Metrics           []MetricSpec        `json:"metrics"`
	DBQueries         map[string]string   `json:"db_queries"`
	KillSwitch        *KillSwitchConfig   `json:"kill_switch"`    // обязателен: без него intake не запускается
	PolicyBundle      *PolicyBundleConfig `json:"policy_bundle"`  // проверка подписанного policy bundle (T-24); необязательна только для staging, в prod-окружениях обязательна с required=true
	MetricsListen     string              `json:"metrics_listen"` // адрес /metrics и /healthz (host:port); пусто — выключено; только serve
}

// PolicyBundleConfig — проверка подписанного policy bundle при старте (serve и replay без -prepare-only). В prod-окружениях
// (bundleRequiredEnvs) секция обязательна и required должен быть true (код 2 как ошибка конфигурации). В staging: секции нет —
// проверка выключена (предупреждение policy_bundle_missing). Секция есть и required=false — bundle проверяется полностью,
// но отказ только предупреждает (policy_bundle_unverified). required=true — отказ проверки — код 2 до приёма инцидентов.
// Ключи подписи bundle не должны совпадать с ключом аудита и ключами kill switch (код 2 независимо от required).
type PolicyBundleConfig struct {
	Path     string           `json:"path"`     // подписанный bundle (policy-bundle.json из релиза policy-bundle-N)
	Required bool             `json:"required"` // true — без валидного bundle intake не запускается
	Keys     []bundle.KeySpec `json:"keys"`     // открытые ключи подписи bundle
}

// KillSwitchConfig — kill switch (architecture.md §2.2). Секреты S3 (ключи доступа) — только из файлов в
// AEGIS_KILLSWITCH_S3_ACCESS_KEY_ID_FILE, AEGIS_KILLSWITCH_S3_SECRET_KEY_FILE и необязательный
// AEGIS_KILLSWITCH_S3_SESSION_TOKEN_FILE; токен чтения ConfigMap — общий AEGIS_KUBE_TOKEN_FILE.
type KillSwitchConfig struct {
	Cluster      string               `json:"cluster"`       // цель intake: точное совпадение с clusters[] документа
	Keys         []killswitch.KeySpec `json:"keys"`          // открытые ключи: не меньше двух oncall; renewer — ноль или не меньше двух
	PollInterval string               `json:"poll_interval"` // 10s
	MaxSkew      string               `json:"max_skew"`      // 2m: допустимое опережение issued_at
	ConfigMap    struct {
		Namespace string `json:"namespace"` // aegisops-control
		Name      string `json:"name"`      // kill-switch
	} `json:"configmap"`
	OOB s3.Config `json:"oob"` // внешний канал: объект в S3
}

// KillSwitchDurations — разобранные интервалы kill switch.
func (k KillSwitchConfig) Durations() (poll, skew time.Duration, err error) {
	if poll, err = time.ParseDuration(k.PollInterval); err != nil || poll < time.Second || poll > 5*time.Minute {
		return 0, 0, errors.New("kill_switch.poll_interval: от 1s до 5m")
	}
	if skew, err = time.ParseDuration(k.MaxSkew); err != nil || skew < 0 || skew > 10*time.Minute {
		return 0, 0, errors.New("kill_switch.max_skew: от 0 до 10m")
	}
	return poll, skew, nil
}

// HTTPSource — адрес и TLS источника. Токен (необязательный) — файл из AEGIS_ALERTMANAGER_TOKEN_FILE / AEGIS_PROMETHEUS_TOKEN_FILE.
type HTTPSource struct {
	URL      string            `json:"url"`
	CAFile   string            `json:"ca_file"`
	Matchers []string          `json:"matchers"` // только Alertmanager: label matchers фильтра алертов
	Headers  map[string]string `json:"headers"`  // например X-Scope-OrgID (Mimir/Cortex); не для секретов
}

type KubeSource struct {
	APIURL           string `json:"api_url"`
	CAFile           string `json:"ca_file"`
	AuthorAnnotation string `json:"author_annotation"` // аннотация ReplicaSet с автором деплоя (ставит CI); нет — author_id "unknown"
}

type WorkloadRef struct {
	Kind string `json:"kind"` // Deployment | Rollout
	Name string `json:"name"`
}

type AutoscalerRef struct {
	Kind string `json:"kind"` // HorizontalPodAutoscaler | ScaledObject
	Name string `json:"name"`
}

// ServiceConfig — запись реестра сервисов: целевой поток. Ревьюится в Git, алертом не управляется.
type ServiceConfig struct {
	Namespace              string         `json:"namespace"`
	Service                string         `json:"service"`
	Workload               WorkloadRef    `json:"workload"`
	Autoscaler             *AutoscalerRef `json:"autoscaler"`
	DeclaredMin            int            `json:"declared_min"`
	Database               string         `json:"database"`
	PgCluster              string         `json:"pg_cluster"`
	Kafka                  bool           `json:"kafka"` // у сервиса есть метрики Kafka (applies: kafka)
	InsufficientDataPolicy string         `json:"insufficient_data_policy"`
	Bake                   string         `json:"bake"`     // 60m; для фазы Bake rollout
	LLMMode                string         `json:"llm_mode"` // hybrid | off
}

// MetricSpec — логическая метрика input.metrics: PromQL с подстановкой $namespace, $service, $database, $pg_cluster.
type MetricSpec struct {
	Name         string            `json:"name"`
	Unit         string            `json:"unit"`
	Query        string            `json:"query"`
	SeriesLabels []string          `json:"series_labels"` // метки результата, переносимые в серию (по allowlist роутера)
	StaticLabels map[string]string `json:"static_labels"` // постоянные метки серии; значения — подстановки реестра, например {"service": "$service"}
	SelfReported bool              `json:"self_reported"` // добавляет метку source=self_reported
	Applies      string            `json:"applies"`       // always | database | kafka
	MaxSeries    int               `json:"max_series"`    // 0 → 12
}

// DBQueryKeys — ключи db_queries: instant-запросы, по одному скаляру на ключ ($database, $pg_cluster).
// headroom считается как ceil(0.1·max_connections) (action-catalog.md), запросом не задаётся.
var DBQueryKeys = []string{"pool_size", "max_connections", "superuser_reserved_connections", "other_pools_total",
	"sessions_active", "sessions_active_over_60s", "sessions_idle", "sessions_idle_over_60s",
	"sessions_idle_in_transaction", "sessions_idle_in_transaction_over_60s",
	"cl_active", "cl_waiting", "sv_active", "sv_idle", "maxwait_s"}

var (
	dnsNameRe    = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$`)
	metricRe     = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	environments = map[string]bool{"staging": true, "prod-cloud-hybrid": true, "prod-baremetal": true}
)

// Defaults подставляет значения по умолчанию вместо нулей.
func (c *Config) Defaults() {
	for _, d := range []struct {
		p *string
		v string
	}{{&c.PollInterval, "15s"}, {&c.Settle, "2m"}, {&c.CloseAfter, "15m"}, {&c.CollectTimeout, "30s"}, {&c.RequestTimeout, "5s"},
		{&c.SnapshotRetention, "2160h"}} {
		if *d.p == "" {
			*d.p = d.v
		}
	}
	if c.Workers == 0 {
		c.Workers = 2
	}
	if c.MaxOpenIncidents == 0 {
		c.MaxOpenIncidents = 256
	}
	if c.MaxRoutedPerHour == 0 {
		c.MaxRoutedPerHour = 6
	}
	if k := c.KillSwitch; k != nil {
		if k.PollInterval == "" {
			k.PollInterval = "10s"
		}
		if k.MaxSkew == "" {
			k.MaxSkew = "2m"
		}
		if k.ConfigMap.Namespace == "" {
			k.ConfigMap.Namespace = "aegisops-control"
		}
		if k.ConfigMap.Name == "" {
			k.ConfigMap.Name = "kill-switch"
		}
	}
	for i := range c.Services {
		if c.Services[i].LLMMode == "" {
			c.Services[i].LLMMode = "hybrid"
		}
	}
	for i := range c.Metrics {
		if c.Metrics[i].Applies == "" {
			c.Metrics[i].Applies = "always"
		}
		if c.Metrics[i].MaxSeries == 0 {
			c.Metrics[i].MaxSeries = 12
		}
	}
}

// Durations — разобранные интервалы.
type Durations struct{ Poll, Settle, CloseAfter, Collect, Request, SnapshotRetention time.Duration }

func (c Config) Durations() (Durations, error) {
	var d Durations
	for _, x := range []struct {
		name, s string
		dst     *time.Duration
	}{{"poll_interval", c.PollInterval, &d.Poll}, {"settle", c.Settle, &d.Settle}, {"close_after", c.CloseAfter, &d.CloseAfter},
		{"collect_timeout", c.CollectTimeout, &d.Collect}, {"request_timeout", c.RequestTimeout, &d.Request},
		{"snapshot_retention", c.SnapshotRetention, &d.SnapshotRetention}} {
		v, err := time.ParseDuration(x.s)
		if err != nil || v <= 0 {
			return d, fmt.Errorf("конфигурация: %s: ожидается положительная длительность, например \"30s\"", x.name)
		}
		*x.dst = v
	}
	return d, nil
}

// LoadConfig читает и проверяет конфигурацию: неизвестные поля и дубли ключей — ошибка.
func LoadConfig(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("конфигурация intake: %w", err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return Config{}, fmt.Errorf("конфигурация intake: %w", err)
	}
	if len(b) > maxConfigBytes {
		return Config{}, fmt.Errorf("конфигурация intake: файл больше %d байт", maxConfigBytes)
	}
	return ParseConfig(b)
}

func ParseConfig(b []byte) (Config, error) {
	var c Config
	if err := strictjson.Decode(b, &c); err != nil {
		return Config{}, fmt.Errorf("конфигурация intake: %w", err)
	}
	c.Defaults()
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// Validate проверяет конфигурацию без обращения к сети и (кроме абсолютности путей) к файловой системе.
func (c Config) Validate() error {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("конфигурация intake: "+format, a...)
	}
	if !routersvc.ValidID(c.IntakeID) {
		return bad("некорректный intake_id %q", c.IntakeID)
	}
	if !environments[c.Environment] {
		return bad("environment %q не из staging | prod-cloud-hybrid | prod-baremetal", c.Environment)
	}
	for name, p := range map[string]string{"router_config": c.RouterConfig, "state_path": c.StatePath, "snapshot_dir": c.SnapshotDir} {
		if p == "" || !filepath.IsAbs(p) {
			return bad("%s должен быть абсолютным путём", name)
		}
	}
	if _, err := c.Durations(); err != nil {
		return err
	}
	if c.Workers < 1 || c.Workers > 16 || c.MaxOpenIncidents < 1 || c.MaxOpenIncidents > 4096 || c.MaxRoutedPerHour < 1 {
		return bad("workers (1..16), max_open_incidents (1..4096) и max_routed_per_service_hour (>=1) вне диапазона")
	}
	for name, u := range map[string]string{"alertmanager.url": c.Alertmanager.URL, "prometheus.url": c.Prometheus.URL, "kubernetes.api_url": c.Kubernetes.APIURL} {
		if err := checkURL(u); err != nil {
			return bad("%s: %v", name, err)
		}
	}
	for _, m := range c.Alertmanager.Matchers {
		if strings.TrimSpace(m) == "" {
			return bad("alertmanager.matchers: пустой matcher")
		}
	}
	for _, h := range []map[string]string{c.Alertmanager.Headers, c.Prometheus.Headers} {
		for k, v := range h {
			if strings.ContainsAny(k+v, "\r\n") || k == "" || strings.EqualFold(k, "Authorization") {
				return bad("headers: недопустимый заголовок %q (токен — только через *_TOKEN_FILE)", k)
			}
		}
	}
	if err := c.validateKillSwitch(); err != nil {
		return err
	}
	if err := c.validatePolicyBundle(); err != nil {
		return err
	}
	if c.MetricsListen != "" && !validListenAddr(c.MetricsListen) {
		return bad("metrics_listen: ожидается host:port")
	}
	if len(c.Services) == 0 {
		return bad("services: реестр сервисов пуст")
	}
	seenSvc, seenPair := map[string]bool{}, map[string]bool{}
	needDB := false
	for _, s := range c.Services {
		for _, v := range []string{s.Namespace, s.Service, s.Workload.Name} {
			if !dnsNameRe.MatchString(v) {
				return bad("services: некорректное имя %q", v)
			}
		}
		if seenSvc[s.Service] { // Request.Service — ключ суточного бюджета роутера
			return bad("services: имя сервиса %q не уникально", s.Service)
		}
		seenSvc[s.Service] = true
		seenPair[s.Namespace+"/"+s.Service] = true
		if s.Workload.Kind != "Deployment" && s.Workload.Kind != "Rollout" {
			return bad("services[%s]: workload.kind %q не из Deployment | Rollout", s.Service, s.Workload.Kind)
		}
		if a := s.Autoscaler; a != nil && ((a.Kind != "HorizontalPodAutoscaler" && a.Kind != "ScaledObject") || !dnsNameRe.MatchString(a.Name)) {
			return bad("services[%s]: некорректный autoscaler", s.Service)
		}
		if s.DeclaredMin < 0 || s.DeclaredMin > 1<<20 {
			return bad("services[%s]: declared_min вне диапазона", s.Service)
		}
		if s.Database != "" {
			needDB = true
			if !dnsNameRe.MatchString(s.Database) || !dnsNameRe.MatchString(s.PgCluster) {
				return bad("services[%s]: database и pg_cluster должны быть DNS-именами", s.Service)
			}
		} else if s.PgCluster != "" && !dnsNameRe.MatchString(s.PgCluster) {
			return bad("services[%s]: некорректный pg_cluster", s.Service)
		}
		switch s.InsufficientDataPolicy {
		case "", "hold", "proceed", "abort":
		default:
			return bad("services[%s]: insufficient_data_policy %q", s.Service, s.InsufficientDataPolicy)
		}
		if s.Bake != "" {
			if d, err := time.ParseDuration(s.Bake); err != nil || d <= 0 {
				return bad("services[%s]: bake: ожидается положительная длительность", s.Service)
			}
		}
		if s.LLMMode != "hybrid" && s.LLMMode != "off" {
			return bad("services[%s]: llm_mode %q не из hybrid | off", s.Service, s.LLMMode)
		}
	}
	if len(c.Metrics) == 0 {
		return bad("metrics: список метрик пуст")
	}
	names := map[string]bool{}
	for _, m := range c.Metrics {
		if !metricRe.MatchString(m.Name) || m.Query == "" || m.Unit == "" || names[m.Name] {
			return bad("metrics: некорректная или повторная метрика %q", m.Name)
		}
		names[m.Name] = true
		switch m.Applies {
		case "always", "database", "kafka":
		default:
			return bad("metrics[%s]: applies %q", m.Name, m.Applies)
		}
		if m.MaxSeries < 1 || m.MaxSeries > 12 {
			return bad("metrics[%s]: max_series вне 1..12", m.Name)
		}
		for _, l := range m.SeriesLabels {
			if !metricRe.MatchString(l) {
				return bad("metrics[%s]: некорректная метка %q", m.Name, l)
			}
		}
		if err := checkPlaceholders(m.Query); err != nil {
			return bad("metrics[%s]: %v", m.Name, err)
		}
		for k, v := range m.StaticLabels {
			if !metricRe.MatchString(k) {
				return bad("metrics[%s]: некорректная постоянная метка %q", m.Name, k)
			}
			if err := checkPlaceholders(v); err != nil {
				return bad("metrics[%s]: static_labels[%s]: %v", m.Name, k, err)
			}
		}
	}
	known := map[string]bool{}
	for _, k := range DBQueryKeys {
		known[k] = true
	}
	for k, q := range c.DBQueries {
		if !known[k] {
			return bad("db_queries: неизвестный ключ %q", k)
		}
		if err := checkPlaceholders(q); err != nil {
			return bad("db_queries[%s]: %v", k, err)
		}
	}
	if needDB {
		for _, k := range DBQueryKeys {
			if c.DBQueries[k] == "" {
				return bad("db_queries: нет запроса %q (у сервиса задан database)", k)
			}
		}
	}
	return nil
}

var placeholderRe = regexp.MustCompile(`\$[A-Za-z_][A-Za-z0-9_]*`)

// checkPlaceholders: в запросе допустимы только подстановки из реестра.
func checkPlaceholders(q string) error {
	for _, p := range placeholderRe.FindAllString(q, -1) {
		switch p {
		case "$namespace", "$service", "$database", "$pg_cluster":
		default:
			return fmt.Errorf("неизвестная подстановка %s", p)
		}
	}
	return nil
}

func checkURL(s string) error {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("ожидается http(s)://host[:port][/путь] без учётных данных")
	}
	return nil
}

// Lookup возвращает запись реестра по паре (namespace, service).
func (c Config) Lookup(ns, svc string) (ServiceConfig, bool) {
	for _, s := range c.Services {
		if s.Namespace == ns && s.Service == svc {
			return s, true
		}
	}
	return ServiceConfig{}, false
}

// Expand подставляет значения реестра в PromQL. Значения — только из реестра (DNS-имена), никогда из алерта.
func (s ServiceConfig) Expand(q string) string {
	return strings.NewReplacer("$namespace", s.Namespace, "$service", s.Service, "$database", s.Database, "$pg_cluster", s.PgCluster).Replace(q)
}

// validListenAddr: host:port, порт 0..65535, хост пуст, IP или DNS-имя.
func validListenAddr(a string) bool {
	host, port, err := net.SplitHostPort(a)
	if err != nil {
		return false
	}
	if n, err := strconv.ParseUint(port, 10, 16); err != nil || port != strconv.FormatUint(n, 10) {
		return false
	}
	return host == "" || net.ParseIP(host) != nil || dnsNameRe.MatchString(host)
}

func (c Config) validateKillSwitch() error {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("конфигурация intake: kill_switch: "+format, a...)
	}
	k := c.KillSwitch
	if k == nil {
		return errors.New("конфигурация intake: секция kill_switch обязательна (fail-safe): добавьте её по docs/04-operations/intake-deploy.md, " +
			"раздел \"Kill switch\"; до release двумя дежурными после старта intake работает с llm.mode=off")
	}
	for name, v := range map[string]string{"cluster": k.Cluster, "configmap.namespace": k.ConfigMap.Namespace, "configmap.name": k.ConfigMap.Name} {
		if !dnsNameRe.MatchString(v) {
			return bad("%s: ожидается DNS-имя, получено %q", name, v)
		}
	}
	if _, _, err := k.Durations(); err != nil {
		return fmt.Errorf("конфигурация intake: %w", err)
	}
	if len(k.Keys) < 2 || len(k.Keys) > 16 {
		return bad("keys: от 2 до 16 ключей")
	}
	var oncall, renewer int
	for _, s := range k.Keys {
		if !filepath.IsAbs(s.Path) {
			return bad("keys: путь %q должен быть абсолютным", s.Path)
		}
		switch s.Role {
		case killswitch.RoleOncall:
			oncall++
		case killswitch.RoleRenewer:
			renewer++
		default:
			return bad("keys: роль %q не из oncall | renewer", s.Role)
		}
		if s.Issuer == "" || len(s.Issuer) > 256 || strings.ContainsAny(s.Issuer, " \t\r\n\x00") {
			return bad("keys: некорректный issuer %q", s.Issuer)
		}
	}
	if oncall < 2 || renewer == 1 {
		return bad("keys: нужно не меньше двух oncall; renewer — ноль или не меньше двух")
	}
	o := k.OOB
	u, err := url.Parse(o.Endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return bad("oob.endpoint: ожидается https://host[:port] без пути и запроса")
	}
	for name, v := range map[string]string{"region": o.Region, "bucket": o.Bucket, "key": o.Key} {
		if v == "" || len(v) > 1024 || strings.ContainsFunc(v, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			return bad("oob.%s: обязателен, без управляющих символов", name)
		}
	}
	if strings.HasPrefix(o.Key, "/") {
		return bad("oob.key не начинается с /")
	}
	if o.CAFile != "" && !filepath.IsAbs(o.CAFile) {
		return bad("oob.ca_file должен быть абсолютным путём")
	}
	return nil
}

// bundleIssuerRe — допустимый issuer ключа подписи bundle (как у ключей kill switch).
var bundleIssuerRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$`)

// bundleRequiredEnvs — окружения, где секция policy_bundle обязательна и required=true (T-24, stage-0a-status п. 3).
// Staging сохраняет двухшаговое включение (required=false, затем true).
var bundleRequiredEnvs = map[string]bool{"prod-cloud-hybrid": true, "prod-baremetal": true}

// validatePolicyBundle: секция необязательна только вне prod-окружений; если есть — абсолютные пути, хотя бы один ключ, корректные issuer'ы и
// непересечение ключей bundle с ключами kill switch и ключом аудита (последний сверяет intake при старте: здесь файлов нет).
func (c Config) validatePolicyBundle() error {
	p := c.PolicyBundle
	if bundleRequiredEnvs[c.Environment] && (p == nil || !p.Required) {
		return fmt.Errorf("конфигурация intake: policy_bundle: в окружении %s секция обязательна и required должен быть true (T-24)", c.Environment)
	}
	if p == nil {
		return nil
	}
	bad := func(format string, a ...any) error {
		return fmt.Errorf("конфигурация intake: policy_bundle: "+format, a...)
	}
	if !filepath.IsAbs(p.Path) {
		return bad("path должен быть абсолютным путём")
	}
	if len(p.Keys) == 0 || len(p.Keys) > 8 {
		return bad("keys: от 1 до 8 ключей")
	}
	paths := map[string]bool{}
	for _, k := range c.KillSwitch.Keys {
		paths[filepath.Clean(k.Path)] = true
	}
	for _, s := range p.Keys {
		if !filepath.IsAbs(s.Path) {
			return bad("keys: путь %q должен быть абсолютным", s.Path)
		}
		if !bundleIssuerRe.MatchString(s.Issuer) {
			return bad("keys: некорректный issuer %q", s.Issuer)
		}
		if paths[filepath.Clean(s.Path)] {
			return bad("keys: файл ключа %s входит и в ключи kill switch", s.Path)
		}
	}
	return nil
}
