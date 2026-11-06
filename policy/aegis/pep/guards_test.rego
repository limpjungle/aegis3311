package aegis.pep_test

test_base_clean if {
	deny_codes(base) == set()
	cap_codes(base) == set()
	effective(base) == "L3"
}

# ---------- матрица ----------

test_matrix_ceiling_cap if {
	inp := patched(array.concat(as_action("workload.scale_in", "R2", "frozen", "forbidden"), [["/target/environment", "prod-cloud-hybrid"]]))
	cap_codes(inp) == {"matrix_ceiling"}
	effective(inp) == "L2"
	dec(inp).ceiling == "L2"
}

test_pgbouncer_by_data if {
	prod := array.concat(as_action("pgbouncer.resize_pool", "R2", "frozen", "forbidden"), [["/target/environment", "prod-cloud-hybrid"]])
	effective(patched(prod)) == "L2"
	effective(patched(array.concat(prod, [["/level/by_data", true]]))) == "L3"
	bm := array.concat(as_action("pgbouncer.resize_pool", "R2", "frozen", "forbidden"), [["/target/environment", "prod-baremetal"], ["/level/by_data", true]])
	effective(patched(bm)) == "L2"
}

test_r3_capped_to_l1_even_with_replaced_matrix if {
	inp := patched(as_action("postgres.set_restart_param", "R3", "frozen", "forbidden"))
	forged := {"postgres.set_restart_param": {"staging": {"max": "L3"}}}
	d := data.aegis.pep.decision with input as inp with data.aegis.autonomy.matrix as forged
	d.effective_level == "L1"
	some c in d.caps
	c.code == "reversibility_r3"
}

test_granted_l0 if {
	effective(patched([["/level/granted", "L0"]])) == "L0"
}

test_unknown_environment if {
	inp := patched([["/target/environment", "dev"]])
	"no_matrix_cell" in deny_codes(inp)
	effective(inp) == "L0"
	dec(inp).ceiling == "L0"
}

test_action_outside_matrix if {
	inp := patched([["/action/type", "workload.unknown"]])
	"no_matrix_cell" in deny_codes(inp)
}

# ---------- запреты ----------

test_forbidden_actions if {
	every t in ["storage.delete_volume", "audit.delete_record", "policy.update", "autonomy.set_level"] {
		inp := patched([["/action/type", t]])
		"forbidden_action" in deny_codes(inp)
		effective(inp) == "L0"
	}
}

test_forbidden_namespace if {
	inp := patched([["/target/namespace", "kube-system"]])
	"forbidden_namespace" in deny_codes(inp)
	effective(inp) == "L0"
}

test_namespace_not_managed if {
	"namespace_not_managed" in deny_codes(patched([["/target/namespace_labels", {}]]))
	"namespace_not_managed" in deny_codes(patched([["/target/namespace_labels", {"aegisops.io/managed": "false"}]]))
}

# ---------- error budget ----------

test_error_budget_exempt_pass if {
	every t in ["rollout.abort_and_rollback", "workload.scale_out"] {
		inp := patched([["/flags/error_budget_exhausted", true], ["/action/type", t]])
		not "error_budget_frozen" in cap_codes(inp)
	}
}

test_error_budget_frozen_actions if {
	every t in [["workload.scale_in", "R2"], ["workload.restart", "R2"], ["pgbouncer.resize_pool", "R2"], ["postgres.set_restart_param", "R3"]] {
		inp := patched(array.concat(as_action(t[0], t[1], "frozen", "forbidden"), [["/flags/error_budget_exhausted", true]]))
		"error_budget_frozen" in cap_codes(inp)
		effective(inp) == "L1"
	}
}

test_error_budget_forged_allowed_still_capped if {
	inp := patched([["/flags/error_budget_exhausted", true], ["/action/type", "workload.scale_in"], ["/action/error_budget_exhausted", "allowed"]])
	"error_budget_frozen" in cap_codes(inp)
	effective(inp) == "L1"
}

test_error_budget_frozen_by_catalog_even_if_exempt_name if {
	inp := patched([["/flags/error_budget_exhausted", true], ["/action/error_budget_exhausted", "frozen"]])
	"error_budget_frozen" in cap_codes(inp)
}

# ---------- деградационный режим ----------

test_degraded_allowed_needs_preapproval if {
	inp := patched([["/flags/degraded_mode", true]])
	"degraded_runbook_not_preapproved" in cap_codes(inp)
	effective(inp) == "L1"
	ok := patched([["/flags/degraded_mode", true], ["/flags/runbook_preapproved", true]])
	cap_codes(ok) == set()
	effective(ok) == "L3"
}

test_degraded_policy_r2 if {
	ops := array.concat(as_action("workload.restart", "R2", "frozen", "policy"), [["/flags/degraded_mode", true]])
	"degraded_r2_not_permitted" in cap_codes(patched(ops))
	ok := patched(array.concat(ops, [["/flags/degraded_policy_allows_r2", true]]))
	not "degraded_r2_not_permitted" in cap_codes(ok)
}

test_degraded_forbidden if {
	inp := patched(array.concat(as_action("workload.scale_in", "R2", "frozen", "forbidden"), [["/flags/degraded_mode", true]]))
	"degraded_forbidden" in cap_codes(inp)
	effective(inp) == "L1"
}

test_degraded_flag_off_ignores_catalog_mode if {
	inp := patched(as_action("workload.scale_in", "R2", "frozen", "forbidden"))
	not "degraded_forbidden" in cap_codes(inp)
}

test_degraded_unknown_mode_is_forbidden if {
	inp := patched([["/flags/degraded_mode", true], ["/action/degraded_mode", "whatever"]])
	"degraded_forbidden" in cap_codes(inp)
}

test_policy_cache_expired if {
	inp := patched([["/flags/policy_cache_expired", true]])
	cap_codes(inp) == {"policy_cache_expired"}
	effective(inp) == "L1"
}

# ---------- kill switch и liveness ----------

test_kill_switch_global if {
	inp := patched([["/flags/kill_switch/global", true]])
	cap_codes(inp) == {"kill_switch"}
	effective(inp) == "L1"
}

test_kill_switch_cluster if {
	cap_codes(patched([["/flags/kill_switch/cluster", true]])) == {"kill_switch"}
}

test_kill_switch_by_action if {
	inp := patched([["/flags/kill_switch/actions", ["workload.scale_out"]]])
	cap_codes(inp) == {"kill_switch"}
	other := patched([["/flags/kill_switch/actions", ["workload.restart"]]])
	cap_codes(other) == set()
}

test_liveness_unconfirmed if {
	inp := patched([["/flags/liveness_confirmed", false]])
	cap_codes(inp) == {"liveness_unconfirmed"}
	effective(inp) == "L1"
}

# ---------- lease, человек, circuit breaker ----------

test_lease_missing if {
	inp := patched([["/flags/lease_held", false]])
	cap_codes(inp) == {"lease_missing"}
	effective(inp) == "L1"
}

test_human_engaged if {
	cap_codes(patched([["/flags/human_engaged", true]])) == {"human_engaged"}
}

test_circuit_breaker_open if {
	cap_codes(patched([["/flags/circuit_breaker_open", true]])) == {"circuit_breaker_open"}
}

# ---------- rate limit и cooldown ----------

test_rate_limit_boundary if {
	cap_codes(patched([["/history/actions_last_hour", 3]])) == set()
	inp := patched([["/history/actions_last_hour", 4]])
	cap_codes(inp) == {"rate_limit_exceeded"}
	effective(inp) == "L1"
}

test_cooldown_boundary if {
	cap_codes(patched([["/history/seconds_since_last", 599]])) == {"cooldown_active"}
	cap_codes(patched([["/history/seconds_since_last", 600]])) == set()
	cap_codes(patched([["/history/seconds_since_last", null]])) == set()
}

test_cooldown_zero_never_caps if {
	cap_codes(patched([["/action/rate_limit/cooldown_seconds", 0], ["/history/seconds_since_last", 0]])) == set()
}

# ---------- история: отрицательные и нецелые счётчики ----------

test_history_invalid_counts_denied if {
	every o in [["/history/actions_last_hour", -1], ["/history/actions_last_hour", 1.5], ["/history/actions_last_hour", "1"], ["/history/seconds_since_last", -1], ["/history/seconds_since_last", "x"]] {
		"input_invalid" in deny_codes(patched([o]))
		effective(patched([o])) == "L0"
	}
}
