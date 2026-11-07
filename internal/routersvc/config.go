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
