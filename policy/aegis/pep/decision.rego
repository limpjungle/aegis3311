# Итоговое решение политики. Определено всегда: при любых проблемах входа — deny и L0.
package aegis.pep

import data.aegis.autonomy

policy_revision := "0.1.0"

# Нет ячейки матрицы — потолок L0 (и deny no_matrix_cell).
default matrix_ceiling := "L0"

matrix_ceiling := autonomy.ceiling(action_type, environment, by_data)

# Минимум из granted, потолка и всех cap; при deny — L0.
effective_rank := 0 if count(deny) > 0

else := min(ranks) if {
	ranks := {autonomy.levels[granted], autonomy.levels[matrix_ceiling]} | {autonomy.levels[c.level] | some c in caps}
}

default decision := {
	"ceiling": "L0",
	"effective_level": "L0",
	"deny": [{"code": "policy_undefined", "detail": "решение политики не определено"}],
	"caps": [],
	"policy_revision": "0.1.0",
}

decision := {
	"ceiling": matrix_ceiling,
	"effective_level": autonomy.level_names[effective_rank],
	"deny": deny,
	"caps": caps,
	"policy_revision": policy_revision,
}
