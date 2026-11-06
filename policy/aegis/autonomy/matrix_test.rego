package aegis.autonomy_test

import data.aegis.autonomy

# Ожидаемые ячейки записаны независимо от matrix.rego: architecture.md §4.4.
cells := [
	["rollout.abort_and_rollback", "staging", "L3", "L3"],
	["rollout.abort_and_rollback", "prod-cloud-hybrid", "L3", "L3"],
	["rollout.abort_and_rollback", "prod-baremetal", "L3", "L3"],
	["workload.scale_out", "staging", "L3", "L3"],
	["workload.scale_out", "prod-cloud-hybrid", "L3", "L3"],
	["workload.scale_out", "prod-baremetal", "L3", "L3"],
	["workload.scale_in", "staging", "L3", "L3"],
	["workload.scale_in", "prod-cloud-hybrid", "L2", "L2"],
	["workload.scale_in", "prod-baremetal", "L2", "L2"],
	["workload.restart", "staging", "L3", "L3"],
	["workload.restart", "prod-cloud-hybrid", "L2", "L2"],
	["workload.restart", "prod-baremetal", "L2", "L2"],
	["pgbouncer.resize_pool", "staging", "L3", "L3"],
	["pgbouncer.resize_pool", "prod-cloud-hybrid", "L2", "L3"],
	["pgbouncer.resize_pool", "prod-baremetal", "L2", "L2"],
	["postgres.set_restart_param", "staging", "L1", "L1"],
	["postgres.set_restart_param", "prod-cloud-hybrid", "L1", "L1"],
	["postgres.set_restart_param", "prod-baremetal", "L1", "L1"],
]

test_all_cells_without_data if {
	every c in cells {
		autonomy.ceiling(c[0], c[1], false) == c[2]
	}
}

test_all_cells_by_data if {
	every c in cells {
		autonomy.ceiling(c[0], c[1], true) == c[3]
	}
}

test_matrix_has_six_actions_three_envs if {
	count(autonomy.matrix) == 6
	every _, row in autonomy.matrix {
		object.keys(row) == autonomy.environments
	}
}

test_pgbouncer_by_data_only_in_cloud_hybrid if {
	autonomy.ceiling("pgbouncer.resize_pool", "prod-cloud-hybrid", false) == "L2"
	autonomy.ceiling("pgbouncer.resize_pool", "prod-cloud-hybrid", true) == "L3"
	autonomy.ceiling("pgbouncer.resize_pool", "prod-baremetal", true) == "L2"
}

test_unknown_cell_undefined if {
	not autonomy.ceiling("workload.scale_out", "dev", false)
	not autonomy.ceiling("workload.unknown", "staging", false)
}

test_invariants_hold if {
	count(autonomy.invariant_violations) == 0
}

test_invariant_prod_above_staging_detected if {
	bad := object.union(autonomy.matrix, {"workload.scale_in": {"staging": {"max": "L1"}}})
	v := autonomy.invariant_violations with data.aegis.autonomy.matrix as bad
	count(v) > 0
}

test_invariant_by_data_above_staging_detected if {
	bad := object.union(autonomy.matrix, {"pgbouncer.resize_pool": {"staging": {"max": "L2"}}})
	v := autonomy.invariant_violations with data.aegis.autonomy.matrix as bad
	count(v) > 0
}

test_invariant_r3_above_l1_detected if {
	bad := object.union(autonomy.matrix, {"postgres.set_restart_param": {
		"staging": {"max": "L3"},
		"prod-cloud-hybrid": {"max": "L3"},
		"prod-baremetal": {"max": "L1"},
	}})
	v := autonomy.invariant_violations with data.aegis.autonomy.matrix as bad
	count(v) >= 2
}

test_forbidden_patterns if {
	every name in ["storage.delete_volume", "backup.delete", "audit.delete_record", "audit.update", "policy.update", "autonomy.set_level"] {
		some p in autonomy.forbidden_patterns
		glob.match(p, ["."], name)
	}
}

test_catalog_actions_not_forbidden if {
	every name in object.keys(autonomy.matrix) {
		not _forbidden(name)
	}
}

_forbidden(name) if {
	some p in autonomy.forbidden_patterns
	glob.match(p, ["."], name)
}
