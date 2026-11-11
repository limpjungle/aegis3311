#!/usr/bin/env python3
"""Подсчёт метрик по ответам модели на golden-набор.

Входы:
  --cases  JSONL с кейсами (generate.py)
  --pred   JSONL с ответами: {"id": ..., "answer": {...} | null, "error": str | null, "endpoint": "..."}
  --ref    (необязательно) JSONL эталонных ответов этой же модели — для метрики совпадения
  --ref-ids-only  считать только кейсы, id которых есть в --ref
  --by-variant    добавить группы variant:<имя>
  --out    (необязательно) путь для JSON-отчёта

Формат ответа берётся из поля answer_format кейса; набор v3 использует формат ответа v2 (отличается только входом).

Метрики (по классам, слайсам и в целом, с 95%-м ДИ Уилсона):
  class_match      — совпал класс инцидента
  root_cause_match — совпала первопричина («совпадение диагноза» в G0)
  admissible       — действие входит в допустимые и параметры в границах («допустимость действия»)
  harmful          — выбрано действие из списка вредных для кейса
  schema_valid     — ответ прошёл проверку схемы
  agreement        — действие и параметры совпали с эталонным ответом целиком (только с --ref)
  decision_agreement — совпали первопричина и тип действия с эталонным ответом (только с --ref);
                     основная метрика совпадения ежедневной пробы (не зависит от выбора величины)

Поддерживаются оба формата ответа: v1 (модель выбирает и величину) и v2 (величину считает код каталога,
в params только scope, pod_name, reason, parameter). Формат определяется по набору ключей params.
"""
import argparse
import json
import math
from collections import defaultdict

CLASSES = {"RB-001", "RB-002", "RB-003", "RB-004", "RB-005", "RB-006", "RB-007", "other"}
ROOT_CAUSES = {
    "pool_undersized", "client_tx_leak", "db_slow_queries", "db_connections_exhausted",
    "release_regression", "canary_insufficient_data", "downstream_db_degradation", "no_user_impact",
    "load_growth", "queue_backlog", "max_replicas_reached", "transient_spike",
    "crashloop_after_release", "crashloop_not_release", "memory_leak", "overcapacity", "unknown",
}
ACTIONS = {"rollout.abort_and_rollback", "workload.scale_out", "workload.scale_in", "workload.restart",
           "pgbouncer.resize_pool", "postgres.set_restart_param", "recommend", "none"}
PARAM_TYPES_V1 = {"database": str, "new_pool_size": int, "new_min_replicas": int, "scope": str, "pod_name": str,
                  "reason": str, "analysis_run": str, "parameter": str, "value": int}
PARAM_TYPES_V2 = {"scope": str, "pod_name": str, "reason": str, "parameter": str}
PARAM_TYPES_BY_FORMAT = {"v1": PARAM_TYPES_V1, "v2": PARAM_TYPES_V2}
PARAM_TYPES = PARAM_TYPES_V1  # обратная совместимость
PARAM_ENUMS = {"scope": {"pod", "deployment"},
               "reason": {"canary_degradation", "bake_degradation", "insufficient_data_policy"},
               "parameter": {"max_connections", "shared_buffers"}}


def load_jsonl(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def validate(ans):
    """Возвращает список ошибок схемы (пустой — ответ валиден)."""
    errs = []
    if not isinstance(ans, dict):
        return ["answer is not an object"]
    req = {"incident_class", "root_cause", "action", "confidence", "evidence", "summary"}
    if set(ans) != req:
        errs.append(f"keys mismatch: {sorted(set(ans) ^ req)}")
    incident_class = ans.get("incident_class")
    if not isinstance(incident_class, str) or incident_class not in CLASSES:
        errs.append("incident_class not in enum")
    root_cause = ans.get("root_cause")
    if not isinstance(root_cause, str) or root_cause not in ROOT_CAUSES:
        errs.append("root_cause not in enum")
    act = ans.get("action")
    if not isinstance(act, dict) or set(act) != {"type", "params"}:
        errs.append("action must have exactly type and params")
        return errs
    action_type = act.get("type")
    if not isinstance(action_type, str) or action_type not in ACTIONS:
        errs.append("action.type not in enum")
    params = act.get("params")
    types = None
    if isinstance(params, dict):
        types = next((t for t in PARAM_TYPES_BY_FORMAT.values() if set(params) == set(t)), None)
    if types is None:
        errs.append("action.params must contain exactly the known keys of format v1 or v2")
        return errs
    for k, t in types.items():
        v = params[k]
        if v is None:
            continue
        if t is int and (isinstance(v, bool) or not isinstance(v, int)):
            errs.append(f"params.{k} must be integer or null")
        elif t is str and not isinstance(v, str):
            errs.append(f"params.{k} must be string or null")
        elif k in PARAM_ENUMS and v not in PARAM_ENUMS[k]:
            errs.append(f"params.{k} not in enum")
    c = ans.get("confidence")
    if isinstance(c, bool) or not isinstance(c, (int, float)) or not 0 <= c <= 1:
        errs.append("confidence must be a number in [0, 1]")
    if not isinstance(ans.get("evidence"), list) or not all(isinstance(e, str) for e in ans.get("evidence", [])):
        errs.append("evidence must be an array of strings")
    if not isinstance(ans.get("summary"), str):
        errs.append("summary must be a string")
    return errs


def param_ok(name, constraint, params):
    v = params.get(name)
    if constraint.get("required_if") == "scope == pod" and params.get("scope") != "pod":
        return True
    if constraint.get("null"):
        return v is None
    if "equals" in constraint:
        return v == constraint["equals"]
    if "enum" in constraint:
        return v in constraint["enum"]
    if "min" in constraint or "max" in constraint:
        if isinstance(v, bool) or not isinstance(v, int):
            return False
        return constraint.get("min", -math.inf) <= v <= constraint.get("max", math.inf)
    return True


def admissible(action, expected):
    for acc in expected["acceptable"]:
        if action["type"] == acc["type"] and all(param_ok(k, c, action["params"]) for k, c in acc["params"].items()):
            return True
    return False


def action_key(answer):
    if not answer:
        return None
    a = answer["action"]
    return (a["type"], tuple(sorted((k, v) for k, v in a["params"].items() if v is not None)))


def wilson(k, n, z=1.96):
    if n == 0:
        return None, None, None
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return round(p, 4), round(c - h, 4), round(c + h, 4)


def score(cases, preds, refs=None):
    pred_by_id = {p["id"]: p for p in preds}
    ref_by_id = {r["id"]: r for r in refs} if refs else {}
    rows = []
    for case in cases:
        p = pred_by_id.get(case["id"], {"answer": None, "error": "missing"})
        ans = p.get("answer")
        errs = validate(ans) if ans is not None else [p.get("error") or "no answer"]
        valid = not errs
        exp = case["expected"]
        row = {
            "id": case["id"], "class": exp["incident_class"], "slice": case["slice"], "variant": case["variant"],
            "schema_valid": valid,
            "class_match": valid and ans["incident_class"] == exp["incident_class"],
            "root_cause_match": valid and ans["root_cause"] == exp["root_cause"],
            "admissible": valid and admissible(ans["action"], exp),
            "harmful": valid and ans["action"]["type"] in exp["harmful"],
            "errors": errs,
        }
        if refs is not None:
            r = ref_by_id.get(case["id"])
            ref_ans = r.get("answer") if r else None
            ref_ok = ref_ans is not None and not validate(ref_ans)
            row["agreement"] = valid and ref_ok and action_key(ans) == action_key(ref_ans)
            row["decision_agreement"] = (valid and ref_ok and ans["root_cause"] == ref_ans["root_cause"]
                                         and ans["action"]["type"] == ref_ans["action"]["type"])
        rows.append(row)
    return rows


METRICS = ["class_match", "root_cause_match", "admissible", "harmful", "schema_valid", "agreement",
           "decision_agreement"]


def aggregate(rows, by_variant=False):
    groups = defaultdict(list)
    for r in rows:
        groups[("all", "all")].append(r)
        groups[("class", r["class"])].append(r)
        groups[("slice", r["slice"])].append(r)
        if by_variant:
            groups[("variant", r["variant"])].append(r)
    out = {}
    for (kind, name), rs in sorted(groups.items()):
        entry = {"n": len(rs)}
        for m in METRICS:
            if m in rs[0]:
                k = sum(1 for r in rs if r[m])
                p, lo, hi = wilson(k, len(rs))
                entry[m] = {"k": k, "p": p, "ci95": [lo, hi]}
        out[f"{kind}:{name}"] = entry
    return out


def print_table(agg):
    cols = [m for m in METRICS if m in agg["all:all"]]
    print("| group | n | " + " | ".join(cols) + " |")
    print("|---|---|" + "---|" * len(cols))
    for g, e in agg.items():
        cells = []
        for m in cols:
            v = e[m]
            cells.append(f"{v['p']:.1%} [{v['ci95'][0]:.1%}; {v['ci95'][1]:.1%}]")
        print(f"| {g} | {e['n']} | " + " | ".join(cells) + " |")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cases", required=True)
    ap.add_argument("--pred", required=True)
    ap.add_argument("--ref")
    ap.add_argument("--out")
    ap.add_argument("--by-variant", action="store_true", help="дополнительно группировать по variant")
    ap.add_argument("--ref-ids-only", action="store_true",
                    help="считать только кейсы, id которых есть в --ref (сравнение набора v4 с эталоном v3)")
    args = ap.parse_args()
    if args.ref_ids_only and not args.ref:
        ap.error("--ref-ids-only requires --ref")
    cases = load_jsonl(args.cases)
    refs = load_jsonl(args.ref) if args.ref else None
    if args.ref_ids_only:
        ref_ids = {r["id"] for r in refs}
        cases = [c for c in cases if c["id"] in ref_ids]
    if not cases:
        ap.error("no cases to score (check --cases and --ref-ids-only)")
    rows = score(cases, load_jsonl(args.pred), refs)
    agg = aggregate(rows, args.by_variant)
    print_table(agg)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump({"summary": agg, "cases": rows}, f, ensure_ascii=False, indent=1)


if __name__ == "__main__":
    main()
