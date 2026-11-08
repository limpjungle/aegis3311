package openrouter

import (
	"fmt"
	"sort"
	"strings"

	"github.com/limpjungle/aegis3311/internal/pyjson"
)

func set(ss ...string) map[string]bool {
	m := make(map[string]bool, len(ss))
	for _, s := range ss {
		m[s] = true
	}
	return m
}

// Множества допустимых значений — копии из eval/golden-synthetic/score.py.
var (
	Classes    = set("RB-001", "RB-002", "RB-003", "RB-004", "RB-005", "RB-006", "RB-007", "other")
	RootCauses = set("pool_undersized", "client_tx_leak", "db_slow_queries", "db_connections_exhausted",
		"release_regression", "canary_insufficient_data", "downstream_db_degradation", "no_user_impact",
		"load_growth", "queue_backlog", "max_replicas_reached", "transient_spike",
		"crashloop_after_release", "crashloop_not_release", "memory_leak", "overcapacity", "unknown")
	Actions = set("rollout.abort_and_rollback", "workload.scale_out", "workload.scale_in", "workload.restart",
		"pgbouncer.resize_pool", "postgres.set_restart_param", "recommend", "none")

	paramKeysV2 = []string{"scope", "pod_name", "reason", "parameter"}
	paramEnums  = map[string]map[string]bool{
		"scope":     set("pod", "deployment"),
		"reason":    set("canary_degradation", "bake_degradation", "insufficient_data_policy"),
		"parameter": set("max_connections", "shared_buffers"),
	}
)

func keysEqual(v *pyjson.Value, want ...string) bool {
	if v.Kind != pyjson.Object || len(v.Members) != len(want) {
		return false
	}
	w := set(want...)
	for _, m := range v.Members {
		if !w[m.Key] {
			return false
		}
	}
	return true
}

func inSet(v *pyjson.Value, s map[string]bool) bool {
	return v != nil && v.Kind == pyjson.String && s[v.S]
}

// pyRepr — repr строки Python для списка ключей (достаточно для ASCII-ключей).
func pyRepr(s string) string {
	q := "'"
	if strings.Contains(s, "'") && !strings.Contains(s, `"`) {
		q = `"`
	}
	r := strings.NewReplacer(`\`, `\\`, "\n", `\n`, "\r", `\r`, "\t", `\t`)
	s = r.Replace(s)
	if q == "'" {
		s = strings.ReplaceAll(s, "'", `\'`)
	}
	return q + s + q
}

// ValidateAnswerV2 — порт score.validate для формата v2; тексты ошибок как в score.py.
func ValidateAnswerV2(ans *pyjson.Value) []string {
	if ans == nil || ans.Kind != pyjson.Object {
		return []string{"answer is not an object"}
	}
	var errs []string
	req := []string{"incident_class", "root_cause", "action", "confidence", "evidence", "summary"}
	if !keysEqual(ans, req...) {
		reqSet := set(req...)
		have := map[string]bool{}
		var diff []string
		for _, m := range ans.Members {
			have[m.Key] = true
			if !reqSet[m.Key] {
				diff = append(diff, m.Key)
			}
		}
		for _, k := range req {
			if !have[k] {
				diff = append(diff, k)
			}
		}
		sort.Strings(diff)
		for i := range diff {
			diff[i] = pyRepr(diff[i])
		}
		errs = append(errs, "keys mismatch: ["+strings.Join(diff, ", ")+"]")
	}
	if !inSet(ans.Get("incident_class"), Classes) {
		errs = append(errs, "incident_class not in enum")
	}
	if !inSet(ans.Get("root_cause"), RootCauses) {
		errs = append(errs, "root_cause not in enum")
	}
	act := ans.Get("action")
	if act == nil || !keysEqual(act, "type", "params") {
		return append(errs, "action must have exactly type and params")
	}
	if !inSet(act.Get("type"), Actions) {
		errs = append(errs, "action.type not in enum")
	}
	params := act.Get("params")
	if params == nil || !keysEqual(params, paramKeysV2...) {
		return append(errs, "action.params must contain exactly the known keys of format v2")
	}
	for _, k := range paramKeysV2 {
		v := params.Get(k)
		switch {
		case v.Kind == pyjson.Null:
		case v.Kind != pyjson.String:
			errs = append(errs, fmt.Sprintf("params.%s must be string or null", k))
		case paramEnums[k] != nil && !paramEnums[k][v.S]:
			errs = append(errs, fmt.Sprintf("params.%s not in enum", k))
		}
	}
	if c, ok := num(ans.Get("confidence")); !ok || !(c >= 0 && c <= 1) {
		errs = append(errs, "confidence must be a number in [0, 1]")
	}
	ev := ans.Get("evidence")
	evOK := ev != nil && ev.Kind == pyjson.Array
	if evOK {
		for _, e := range ev.Items {
			if e.Kind != pyjson.String {
				evOK = false
			}
		}
	}
	if !evOK {
		errs = append(errs, "evidence must be an array of strings")
	}
	if s := ans.Get("summary"); s == nil || s.Kind != pyjson.String {
		errs = append(errs, "summary must be a string")
	}
	return errs
}
