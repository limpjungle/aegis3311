package pep

import (
	"fmt"

	"github.com/limpjungle/aegis3311/internal/step"
)

// Context — всё, что PEP знает о цели и окружении. Поля обязательны и объявлены указателями:
// отсутствующее поле даёт deny/context_invalid, а не небезопасное нулевое значение.
type Context struct {
	Environment     *string           `json:"environment"`
	Namespace       *string           `json:"namespace"`
	NamespaceLabels map[string]string `json:"namespace_labels"`
	TargetLabels    map[string]string `json:"target_labels"` // метки ресурса/сервиса (aegisops.io/stateless и т.п.)
	State           *step.TargetState `json:"state"`
	Level           *LevelGrant       `json:"level"`
	Flags           *Flags            `json:"flags"`
	History         *History          `json:"history"`
}

// LevelGrant — уровень, выданный для пары «действие × сервис», и признак повышения по данным (§4.5).
type LevelGrant struct {
	Level  *string `json:"level"`
	ByData *bool   `json:"by_data"`
}

type KillSwitch struct {
	Global  *bool    `json:"global"`
	Cluster *bool    `json:"cluster"`
	Actions []string `json:"actions"`
}

type Flags struct {
	KillSwitch             *KillSwitch `json:"kill_switch"`
	LivenessConfirmed      *bool       `json:"liveness_confirmed"`
	ErrorBudgetExhausted   *bool       `json:"error_budget_exhausted"`
	DegradedMode           *bool       `json:"degraded_mode"`
	RunbookPreapproved     *bool       `json:"runbook_preapproved"`
	DegradedPolicyAllowsR2 *bool       `json:"degraded_policy_allows_r2"`
	PolicyCacheExpired     *bool       `json:"policy_cache_expired"`
	LeaseHeld              *bool       `json:"lease_held"`
	HumanEngaged           *bool       `json:"human_engaged"`
	CircuitBreakerOpen     *bool       `json:"circuit_breaker_open"`
}

// History — история действий по цели; SecondsSinceLast == nil означает «действий не было».
type History struct {
	ActionsLastHour  *int `json:"actions_last_hour"`
	SecondsSinceLast *int `json:"seconds_since_last"`
}

var levelRank = map[string]int{"L0": 0, "L1": 1, "L2": 2, "L3": 3}

func minLevel(a, b string) string {
	if levelRank[b] < levelRank[a] {
		return b
	}
	return a
}

// Validate возвращает по одной причине context_invalid на каждую найденную проблему.
func (c Context) Validate() []Reason {
	var rs []Reason
	bad := func(format string, a ...any) {
		rs = append(rs, Reason{Code: "context_invalid", Source: "context", Effect: "deny", Detail: fmt.Sprintf(format, a...)})
	}
	if c.Environment == nil || *c.Environment == "" {
		bad("нет environment")
	}
	if c.Namespace == nil || *c.Namespace == "" {
		bad("нет namespace")
	}
	if c.NamespaceLabels == nil {
		bad("нет namespace_labels")
	}
	if c.TargetLabels == nil {
		bad("нет target_labels")
	}
	if c.State == nil {
		bad("нет state")
	} else {
		if err := c.State.Validate(); err != nil {
			bad("state: %v", err)
		}
		if c.State.DB != nil {
			if c.State.Database == nil {
				bad("state.db задан, а state.database нет")
			} else if *c.State.Database != c.State.DB.PgBouncer.Database {
				bad("state.database не совпадает с db.pgbouncer.database")
			}
		}
	}
	if c.Level == nil || c.Level.Level == nil || c.Level.ByData == nil {
		bad("нет level.level или level.by_data")
	} else if _, ok := levelRank[*c.Level.Level]; !ok {
		bad("неизвестный уровень %q", *c.Level.Level)
	}
	if f := c.Flags; f == nil {
		bad("нет flags")
	} else {
		if f.KillSwitch == nil || f.KillSwitch.Global == nil || f.KillSwitch.Cluster == nil || f.KillSwitch.Actions == nil {
			bad("flags.kill_switch неполон")
		}
		for name, p := range map[string]*bool{"liveness_confirmed": f.LivenessConfirmed, "error_budget_exhausted": f.ErrorBudgetExhausted,
			"degraded_mode": f.DegradedMode, "runbook_preapproved": f.RunbookPreapproved, "degraded_policy_allows_r2": f.DegradedPolicyAllowsR2,
			"policy_cache_expired": f.PolicyCacheExpired, "lease_held": f.LeaseHeld, "human_engaged": f.HumanEngaged,
			"circuit_breaker_open": f.CircuitBreakerOpen} {
			if p == nil {
				bad("нет flags.%s", name)
			}
		}
	}
	if c.History == nil || c.History.ActionsLastHour == nil {
		bad("нет history.actions_last_hour")
	} else if *c.History.ActionsLastHour < 0 {
		bad("history.actions_last_hour < 0")
	}
	if c.History != nil && c.History.SecondsSinceLast != nil && *c.History.SecondsSinceLast < 0 {
		bad("history.seconds_since_last < 0")
	}
	sortReasons(rs)
	return rs
}
