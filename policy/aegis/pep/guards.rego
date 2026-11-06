# Ограничители PEP (architecture.md §2.2, §4.5, §4.6, degraded-mode.md).
# deny — запрет (эффективный уровень L0); caps — потолок уровня (понижение, а не запрет).
package aegis.pep

import data.aegis.autonomy

forbidden_namespaces := {"kube-system", "aegisops-system"}

# Обязательные поля входа; отсутствие любого — deny (fail-closed).
required_paths := [
	["action", "type"], ["action", "reversibility"], ["action", "lease"],
	["action", "error_budget_exhausted"], ["action", "degraded_mode"],
	["action", "rate_limit", "per_target_per_hour"], ["action", "rate_limit", "cooldown_seconds"],
	["target", "environment"], ["target", "namespace"], ["target", "namespace_labels"],
	["level", "granted"], ["level", "by_data"],
	["flags", "kill_switch", "global"], ["flags", "kill_switch", "cluster"], ["flags", "kill_switch", "actions"],
	["flags", "liveness_confirmed"], ["flags", "error_budget_exhausted"], ["flags", "degraded_mode"],
	["flags", "runbook_preapproved"], ["flags", "degraded_policy_allows_r2"], ["flags", "policy_cache_expired"],
	["flags", "lease_held"], ["flags", "human_engaged"], ["flags", "circuit_breaker_open"],
	["history", "actions_last_hour"],
]

# Бюджет исчерпан: разрешены только rollback и scale out (§4.5). Набор дублирует поле каталога
# (эшелонированная защита: подмена error_budget_exhausted во входе не снимает ограничение).
budget_exempt := {"rollout.abort_and_rollback", "workload.scale_out"}

action_type := object.get(input, ["action", "type"], "")

environment := object.get(input, ["target", "environment"], "")

granted := object.get(input, ["level", "granted"], "")

by_data := object.get(input, ["level", "by_data"], false)

flag(name) := object.get(input, ["flags", name], false)

# ---------- deny ----------

deny contains {"code": "input_invalid", "detail": sprintf("нет поля %s", [concat(".", path)])} if {
	some path in required_paths
	object.get(input, path, null) == null
}

deny contains {"code": "input_invalid", "detail": sprintf("history.%s не неотрицательное целое", [name])} if {
	some name in ["actions_last_hour", "seconds_since_last"]
	v := object.get(input, ["history", name], null)
	v != null
	not valid_count(v)
}

valid_count(x) if {
	is_number(x)
	x >= 0
	round(x) == x
}

deny contains {"code": "input_invalid", "detail": sprintf("неизвестный уровень %q", [granted])} if {
	not granted in object.keys(autonomy.levels)
}

deny contains {"code": "forbidden_action", "detail": sprintf("%s совпадает с шаблоном %s", [action_type, pattern])} if {
	some pattern in autonomy.forbidden_patterns
	glob.match(pattern, ["."], action_type)
}

deny contains {"code": "forbidden_namespace", "detail": sprintf("namespace %s запрещён", [ns])} if {
	ns := object.get(input, ["target", "namespace"], "")
	ns in forbidden_namespaces
}

deny contains {"code": "namespace_not_managed", "detail": "у namespace нет метки aegisops.io/managed=true"} if {
	object.get(input, ["target", "namespace_labels", "aegisops.io/managed"], "") != "true"
}

deny contains {"code": "no_matrix_cell", "detail": sprintf("для %s в среде %q нет ячейки матрицы", [action_type, environment])} if {
	not autonomy.matrix[action_type][environment]
}

# ---------- caps (понижение до L1 или до потолка) ----------

caps contains {"code": "matrix_ceiling", "level": ceil, "detail": sprintf("потолок матрицы %s ниже запрошенного %s", [ceil, granted])} if {
	ceil := autonomy.ceiling(action_type, environment, by_data)
	autonomy.levels[granted] > autonomy.levels[ceil]
}

caps contains {"code": "reversibility_r3", "level": "L1", "detail": "R3 не выше L1 независимо от матрицы"} if {
	object.get(input, ["action", "reversibility"], "") == "R3"
}

caps contains {"code": "kill_switch", "level": "L1", "detail": "глобальный kill switch"} if flag_ks("global")

caps contains {"code": "kill_switch", "level": "L1", "detail": "kill switch кластера"} if flag_ks("cluster")

caps contains {"code": "kill_switch", "level": "L1", "detail": sprintf("kill switch действия %s", [action_type])} if {
	action_type in object.get(input, ["flags", "kill_switch", "actions"], [])
}

flag_ks(name) if object.get(input, ["flags", "kill_switch", name], false) == true

caps contains {"code": "liveness_unconfirmed", "level": "L1", "detail": "нет свежего подтверждения «не остановлен»"} if {
	flag("liveness_confirmed") != true
}

caps contains {"code": "error_budget_frozen", "level": "L1", "detail": "error budget исчерпан, действие заморожено"} if {
	flag("error_budget_exhausted") == true
	not action_type in budget_exempt
}

caps contains {"code": "error_budget_frozen", "level": "L1", "detail": "error budget исчерпан, каталог: frozen"} if {
	flag("error_budget_exhausted") == true
	object.get(input, ["action", "error_budget_exhausted"], "") != "allowed"
}

caps contains {"code": "degraded_forbidden", "level": "L1", "detail": "действие запрещено в деградационном режиме"} if {
	flag("degraded_mode") == true
	not degraded_mode_value in {"allowed", "policy"}
}

caps contains {"code": "degraded_runbook_not_preapproved", "level": "L1", "detail": "runbook не предодобрен"} if {
	flag("degraded_mode") == true
	degraded_mode_value == "allowed"
	flag("runbook_preapproved") != true
}

caps contains {"code": "degraded_r2_not_permitted", "level": "L1", "detail": "политика не разрешает R2 в деградационном режиме"} if {
	flag("degraded_mode") == true
	degraded_mode_value == "policy"
	flag("degraded_policy_allows_r2") != true
}

degraded_mode_value := object.get(input, ["action", "degraded_mode"], "")

caps contains {"code": "policy_cache_expired", "level": "L1", "detail": "истёк TTL кэша политик, режим read-only"} if {
	flag("policy_cache_expired") == true
}

caps contains {"code": "lease_missing", "level": "L1", "detail": "нет действующего lease"} if {
	object.get(input, ["action", "lease"], "") == "required"
	flag("lease_held") != true
}

caps contains {"code": "human_engaged", "level": "L1", "detail": "человек взял инцидент"} if {
	flag("human_engaged") == true
}

caps contains {"code": "circuit_breaker_open", "level": "L1", "detail": "circuit breaker открыт"} if {
	flag("circuit_breaker_open") == true
}

caps contains {"code": "rate_limit_exceeded", "level": "L1", "detail": sprintf("%d действий за час при лимите %d", [used, limit])} if {
	used := object.get(input, ["history", "actions_last_hour"], 0)
	limit := object.get(input, ["action", "rate_limit", "per_target_per_hour"], 0)
	used >= limit
}

caps contains {"code": "cooldown_active", "level": "L1", "detail": sprintf("прошло %d с при cooldown %d с", [since, cooldown])} if {
	since := object.get(input, ["history", "seconds_since_last"], null)
	since != null
	cooldown := object.get(input, ["action", "rate_limit", "cooldown_seconds"], 0)
	since < cooldown
}
