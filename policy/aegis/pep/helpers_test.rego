package aegis.pep_test

# Чистый вход: scale_out в staging, L3, все флаги спокойны, lease есть, лимиты не достигнуты.
base := {
	"action": {
		"type": "workload.scale_out",
		"version": "1.0.0",
		"reversibility": "R1",
		"lease": "required",
		"error_budget_exhausted": "allowed",
		"degraded_mode": "allowed",
		"rate_limit": {"per_target_per_hour": 4, "cooldown_seconds": 600},
		"computed": {},
		"params": {"scope": null, "pod_name": null, "reason": null, "parameter": null},
	},
	"target": {
		"environment": "staging",
		"namespace": "shop",
		"namespace_labels": {"aegisops.io/managed": "true"},
		"kind": "autoscaling/HorizontalPodAutoscaler",
		"analysis_verdict": "",
		"insufficient_data_policy": "",
	},
	"level": {"granted": "L3", "by_data": false},
	"flags": {
		"kill_switch": {"global": false, "cluster": false, "actions": []},
		"liveness_confirmed": true,
		"error_budget_exhausted": false,
		"degraded_mode": false,
		"runbook_preapproved": false,
		"degraded_policy_allows_r2": false,
		"policy_cache_expired": false,
		"lease_held": true,
		"human_engaged": false,
		"circuit_breaker_open": false,
	},
	"history": {"actions_last_hour": 0, "seconds_since_last": null},
}

# set(ops) — base с заменой значений по JSON-путям: [[path, value], ...].
patched(ops) := json.patch(base, [{"op": "add", "path": o[0], "value": o[1]} | some o in ops])

dec(inp) := d if {
	d := data.aegis.pep.decision with input as inp
}

cap_codes(inp) := codes if {
	codes := {c.code | some c in data.aegis.pep.caps} with input as inp
}

deny_codes(inp) := codes if {
	codes := {d.code | some d in data.aegis.pep.deny} with input as inp
}

effective(inp) := dec(inp).effective_level

# Действие scale_in R2/frozen/forbidden для проверок бюджета и деградации.
as_action(t, rev, budget, degraded) := [
	["/action/type", t],
	["/action/reversibility", rev],
	["/action/error_budget_exhausted", budget],
	["/action/degraded_mode", degraded],
]
