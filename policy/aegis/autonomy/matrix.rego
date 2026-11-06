# Матрица автономности: architecture.md §4.4 (копия — docs/03-autonomy/autonomy-matrix.md).
# Потолки уровней по действиям и средам, запреты и самопроверка инвариантов.
package aegis.autonomy

levels := {"L0": 0, "L1": 1, "L2": 2, "L3": 3}

level_names := {0: "L0", 1: "L1", 2: "L2", 3: "L3"}

environments := {"staging", "prod-cloud-hybrid", "prod-baremetal"}

# Ячейка: max — потолок; max_by_data — потолок при повышении по данным (§4.5).
# Нет ячейки — действие в этой среде запрещено матрицей («—»).
matrix := {
	"rollout.abort_and_rollback": {
		"staging": {"max": "L3"},
		"prod-cloud-hybrid": {"max": "L3"},
		"prod-baremetal": {"max": "L3"},
	},
	"workload.scale_out": {
		"staging": {"max": "L3"},
		"prod-cloud-hybrid": {"max": "L3"},
		"prod-baremetal": {"max": "L3"},
	},
	"workload.scale_in": {
		"staging": {"max": "L3"},
		"prod-cloud-hybrid": {"max": "L2"},
		"prod-baremetal": {"max": "L2"},
	},
	"workload.restart": {
		"staging": {"max": "L3"},
		"prod-cloud-hybrid": {"max": "L2"},
		"prod-baremetal": {"max": "L2"},
	},
	"pgbouncer.resize_pool": {
		"staging": {"max": "L3"},
		"prod-cloud-hybrid": {"max": "L2", "max_by_data": "L3"},
		"prod-baremetal": {"max": "L2"},
	},
	"postgres.set_restart_param": {
		"staging": {"max": "L1"},
		"prod-cloud-hybrid": {"max": "L1"},
		"prod-baremetal": {"max": "L1"},
	},
}

# Действия класса R3: не выше L1 в любой среде.
reversibility_r3 := {"postgres.set_restart_param"}

# Запрещённые имена действий (на любом уровне). Список синхронен с catalog.ForbiddenPatterns в Go.
forbidden_patterns := ["*.delete*", "*.delete", "audit.*", "policy.*", "autonomy.*"]

# Потолок для действия в среде; by_data включает max_by_data, если он есть в ячейке.
ceiling(action, env, by_data) := level if {
	cell := matrix[action][env]
	by_data == true
	level := cell.max_by_data
} else := matrix[action][env].max

# Наибольший уровень ячейки с учётом max_by_data.
cell_top(cell) := top if {
	ranks := {levels[cell.max]} | {r | r := levels[cell.max_by_data]}
	top := max(ranks)
}

# Нарушения инвариантов матрицы; в корректной политике множество пусто.
invariant_violations contains msg if {
	some action, _ in matrix
	some env in {"prod-cloud-hybrid", "prod-baremetal"}
	cell_top(matrix[action][env]) > levels[matrix[action].staging.max]
	msg := sprintf("%s: потолок в %s выше, чем в staging", [action, env])
}

invariant_violations contains msg if {
	some action in reversibility_r3
	some env, cell in matrix[action]
	cell_top(cell) > levels.L1
	msg := sprintf("%s: R3 выше L1 в %s", [action, env])
}
