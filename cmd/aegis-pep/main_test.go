package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

const cliProposal = `{"type":"workload.scale_out","params":{"scope":null,"pod_name":null,"reason":null,"parameter":null}}`

// cliContext — разрешающий контекст: staging, L3, флаги чистые, lease есть.
const cliContext = `{
  "environment": "staging",
  "namespace": "shop",
  "namespace_labels": {"aegisops.io/managed": "true"},
  "target_labels": {"aegisops.io/stateless": "true", "aegisops.io/managed": "true"},
  "state": {
    "service": "orders-api", "namespace": "shop", "database": null,
    "autoscaler": {"kind": "HorizontalPodAutoscaler", "declared_min": 2, "current_min": 4, "max": 12, "replicas": 4},
    "pods": [], "rollout": null, "db": null
  },
  "level": {"level": "L3", "by_data": false},
  "flags": {
    "kill_switch": {"global": false, "cluster": false, "actions": []},
    "liveness_confirmed": true, "error_budget_exhausted": false, "degraded_mode": false,
    "runbook_preapproved": false, "degraded_policy_allows_r2": false, "policy_cache_expired": false,
    "lease_held": true, "human_engaged": false, "circuit_breaker_open": false
  },
  "history": {"actions_last_hour": 0, "seconds_since_last": null}
}`

func req(proposal, ctx string) string {
	return `{"proposal":` + proposal + `,"context":` + ctx + `}`
}

func TestRun_AllowAndDeterministic(t *testing.T) {
	in := req(cliProposal, cliContext)
	var first bytes.Buffer
	if err := run(strings.NewReader(in), &first); err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal(first.Bytes(), &v); err != nil {
		t.Fatalf("вывод не JSON: %v", err)
	}
	if v["schema"] != "aegisops/pep-verdict/v1" || v["mode"] != "dry-run" || v["decision"] != "allow" || v["effective_level"] != "L3" {
		t.Errorf("вердикт: %s", first.String())
	}
	for i := 0; i < 20; i++ {
		var again bytes.Buffer
		if err := run(strings.NewReader(in), &again); err != nil {
			t.Fatal(err)
		}
		if again.String() != first.String() {
			t.Fatalf("итерация %d: вывод изменился", i)
		}
	}
}

func TestRun_InvalidInputIsError(t *testing.T) {
	cases := map[string]string{
		"не JSON": `{`,
		"неизвестное поле верхнего уровня": `{"proposal":` + cliProposal + `,"context":` + cliContext + `,"extra":1}`,
		"неизвестное поле контекста":       strings.Replace(req(cliProposal, cliContext), `"level":`, `"levl":`, 1),
	}
	for name, in := range cases {
		var out bytes.Buffer
		if err := run(strings.NewReader(in), &out); err == nil {
			t.Errorf("%s: ошибка не возвращена, вывод: %s", name, out.String())
		}
	}
}

// Неверный action от модели — вердикт deny/proposal_invalid, а не ошибка процесса и не allow.
func TestRun_BadProposalIsDeny(t *testing.T) {
	var out bytes.Buffer
	if err := run(strings.NewReader(req(`{"type":"workload.scale_out"}`, cliContext)), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"decision": "deny"`) || !strings.Contains(out.String(), `"proposal_invalid"`) {
		t.Errorf("вывод: %s", out.String())
	}
}

// Лишние данные после JSON на stdin — ошибка входа, как и в разборе action.
func TestRun_TrailingDataIsError(t *testing.T) {
	var out bytes.Buffer
	in := req(cliProposal, cliContext) + ` {"x":1}`
	if err := run(strings.NewReader(in), &out); err == nil {
		t.Errorf("хвост на stdin принят, вывод: %s", out.String())
	}
}
