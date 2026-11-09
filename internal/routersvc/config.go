// Package routersvc собирает LLM-роутер в работающий компонент: конфигурация, секреты из *_FILE, порядок открытия
// цепочки аудита и хранилища состояния, наблюдение за состоянием, снятие остановки оператором.
// Операторские действия выполняются офлайн, при остановленном сервисе: писатель цепочки и store — единственный.
package routersvc

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/limpjungle/aegis3311/internal/audit"
	"github.com/limpjungle/aegis3311/internal/audit/worm"
	"github.com/limpjungle/aegis3311/internal/killswitch/s3"
	"github.com/limpjungle/aegis3311/internal/llmrouter"
	"github.com/limpjungle/aegis3311/internal/masker"
	"github.com/limpjungle/aegis3311/internal/strictjson"
)

const maxConfigBytes = 1 << 20

var (
	routerIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$`) // как idRe llmrouter
	chainIDRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)    // как chainRe audit
)

// Config — несекретная конфигурация. Секреты — только из файлов, указанных в переменных *_FILE.
type Config struct {
	RouterID     string         `json:"router_id"`     // initiator system/<router_id>, Identity хранилища состояния
	StatePath    string         `json:"state_path"`    // абсолютный; каталог должен существовать
	Audit        AuditConfig    `json:"audit"`         // цепочка аудита
	Budgets      BudgetsConfig  `json:"budgets"`       // нули → llmrouter.DefaultBudgets()
	Failover     FailoverConfig `json:"failover"`      // нули и "" → llmrouter.DefaultFailover()
	InternalNets []string       `json:"internal_nets"` // CIDR; нет → masker.DefaultInternalNets()
}

type AuditConfig struct {
	Chain      string   `json:"chain"`       // абсолютный путь файла цепочки
	ChainID    string   `json:"chain_id"`    //
	PublicKeys []string `json:"public_keys"` // PEM PKIX прежних ключей (ротация); ключ подписи добавляется сам
	// Anchor — внешнее хранилище checkpoint'ов (WORM). nil — checkpoint'ы не выгружаются и не сверяются (предупреждение в логе).
	Anchor *AnchorConfig `json:"anchor"`
}

// AnchorConfig — куда выгружать checkpoint'ы цепочки и как часто.
type AnchorConfig struct {
	Kind     string      `json:"kind"`     // "s3" | "dir"
	Dir      string      `json:"dir"`      // для dir: абсолютный путь (только разработка и тесты)
	S3       worm.Config `json:"s3"`       // для s3
	Interval string      `json:"interval"` // период фиксации, по умолчанию "5m"
	MaxLag   string      `json:"max_lag"`  // отставание, после которого метрика/лог аварийные, по умолчанию "1h"
}

// Policy — период и допустимое отставание (нули заменены значениями по умолчанию).
func (a AnchorConfig) Policy() (audit.AnchorPolicy, error) {
	p := audit.AnchorPolicy{Interval: 5 * time.Minute, MaxLag: time.Hour}
	for _, d := range []struct {
		name, s string
		dst     *time.Duration
	}{{"interval", a.Interval, &p.Interval}, {"max_lag", a.MaxLag, &p.MaxLag}} {
		if d.s == "" {
			continue
		}
		v, err := time.ParseDuration(d.s)
		if err != nil || v <= 0 {
			return p, fmt.Errorf("конфигурация: audit.anchor.%s: ожидается положительная длительность, например \"5m\"", d.name)
		}
		*d.dst = v
	}
	return p, nil
}

// Validate проверяет конфигурацию без обращения к сети и файловой системе.
func (a AnchorConfig) Validate() error {
	if _, err := a.Policy(); err != nil {
		return err
	}
	switch a.Kind {
	case "s3":
		if a.Dir != "" {
			return errors.New("конфигурация: audit.anchor.dir не используется с kind \"s3\"")
		}
		if err := a.S3.Validate(); err != nil {
			return fmt.Errorf("конфигурация: audit.anchor.s3: %w", err)
		}
	case "dir":
		if a.Dir == "" || !filepath.IsAbs(a.Dir) {
			return errors.New("конфигурация: audit.anchor.dir должен быть абсолютным путём")
		}
		if a.S3 != (worm.Config{}) {
			return errors.New("конфигурация: audit.anchor.s3 не используется с kind \"dir\"")
		}
	default:
		return fmt.Errorf("конфигурация: audit.anchor.kind %q: ожидается \"s3\" или \"dir\"", a.Kind)
	}
	return nil
}

// Store строит хранилище checkpoint'ов. creds — ключи доступа к S3 (kind "s3"); now == nil → time.Now.
func (a AnchorConfig) Store(creds s3.CredFiles, now func() time.Time) (audit.CheckpointStore, error) {
	if err := a.Validate(); err != nil {
		return nil, &ConfigError{err}
	}
	if a.Kind == "dir" {
		return audit.DirAnchor{Dir: a.Dir}, nil
	}
	if creds.AccessKeyIDFile == "" || creds.SecretKeyFile == "" {
		return nil, &ConfigError{fmt.Errorf("audit.anchor: не заданы %s и %s", AnchorAccessKeyEnv, AnchorSecretKeyEnv)}
	}
	st, err := worm.New(a.S3, creds, now)
	if err != nil {
		return nil, &ConfigError{err}
	}
	return st, nil
}

type BudgetsConfig struct {
	IncidentTokens   int64 `json:"incident_tokens"`
	ServiceDayTokens int64 `json:"service_day_tokens"`
}

type FailoverConfig struct {
	FailThreshold  int    `json:"fail_threshold"`
	Hysteresis     string `json:"hysteresis"`      // time.ParseDuration, например "10m"
	HealthInterval string `json:"health_interval"` // например "30s"
}

// ValidID — допустимый идентификатор (router_id, оператор): тот же формат, что проверяет роутер.
func ValidID(s string) bool { return routerIDRe.MatchString(s) }

// LoadConfig читает и проверяет конфигурацию: неизвестные поля и дубли ключей — ошибка.
func LoadConfig(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("конфигурация: %w", err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return Config{}, fmt.Errorf("конфигурация: %w", err)
	}
	if len(b) > maxConfigBytes {
		return Config{}, fmt.Errorf("конфигурация: файл больше %d байт", maxConfigBytes)
	}
	var c Config
	if err := strictjson.Decode(b, &c); err != nil {
		return Config{}, fmt.Errorf("конфигурация: %w", err)
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// Validate проверяет конфигурацию без обращения к файловой системе.
func (c Config) Validate() error {
	_, _, _, err := c.Effective()
	if err != nil {
		return err
	}
	switch {
	case !routerIDRe.MatchString(c.RouterID):
		return fmt.Errorf("конфигурация: некорректный router_id %q", c.RouterID)
	case !chainIDRe.MatchString(c.Audit.ChainID):
		return fmt.Errorf("конфигурация: некорректный audit.chain_id %q", c.Audit.ChainID)
	case c.StatePath == "" || !filepath.IsAbs(c.StatePath):
		return errors.New("конфигурация: state_path должен быть абсолютным путём")
	case c.Audit.Chain == "" || !filepath.IsAbs(c.Audit.Chain):
		return errors.New("конфигурация: audit.chain должен быть абсолютным путём")
	case filepath.Clean(c.StatePath) == filepath.Clean(c.Audit.Chain):
		return errors.New("конфигурация: state_path и audit.chain должны различаться")
	}
	for _, p := range c.Audit.PublicKeys {
		if p == "" {
			return errors.New("конфигурация: пустой путь в audit.public_keys")
		}
	}
	if c.Audit.Anchor != nil {
		return c.Audit.Anchor.Validate()
	}
	return nil
}

// Effective — значения, с которыми создаётся роутер: нули заменены значениями по умолчанию.
func (c Config) Effective() (llmrouter.BudgetConfig, llmrouter.FailoverConfig, []netip.Prefix, error) {
	b, f := llmrouter.DefaultBudgets(), llmrouter.DefaultFailover()
	if c.Budgets.IncidentTokens < 0 || c.Budgets.ServiceDayTokens < 0 {
		return b, f, nil, errors.New("конфигурация: budgets не могут быть отрицательными")
	}
	if c.Budgets.IncidentTokens > 0 {
		b.IncidentTokens = c.Budgets.IncidentTokens
	}
	if c.Budgets.ServiceDayTokens > 0 {
		b.ServiceDayTokens = c.Budgets.ServiceDayTokens
	}
	if c.Failover.FailThreshold < 0 {
		return b, f, nil, errors.New("конфигурация: failover.fail_threshold не может быть отрицательным")
	}
	if c.Failover.FailThreshold > 0 {
		f.FailThreshold = c.Failover.FailThreshold
	}
	for _, d := range []struct {
		name, s string
		dst     *time.Duration
	}{{"hysteresis", c.Failover.Hysteresis, &f.Hysteresis}, {"health_interval", c.Failover.HealthInterval, &f.HealthInterval}} {
		if d.s == "" {
			continue
		}
		v, err := time.ParseDuration(d.s)
		if err != nil || v <= 0 {
			return b, f, nil, fmt.Errorf("конфигурация: failover.%s: ожидается положительная длительность, например \"30s\"", d.name)
		}
		*d.dst = v
	}
	nets := masker.DefaultInternalNets()
	if len(c.InternalNets) > 0 {
		nets = nil
		for _, s := range c.InternalNets {
			p, err := netip.ParsePrefix(s)
			if err != nil {
				return b, f, nil, fmt.Errorf("конфигурация: internal_nets: некорректный CIDR %q", s)
			}
			nets = append(nets, p)
		}
	}
	return b, f, nets, nil
}
