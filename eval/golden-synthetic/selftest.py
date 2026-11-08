#!/usr/bin/env python3
"""Самопроверка генератора и скоринга. Запуск: python3 selftest.py

Проверяет:
  1. Детерминизм: два прогона генератора дают одинаковый хеш.
  2. Корректность разметки: «оракул», который выбирает первое допустимое действие, получает 100%,
     а ни одно допустимое действие не входит в список вредных.
  3. Скоринг различает плохие стратегии: «всегда none», «всегда scale_out».
  4. Размер входа кейса укладывается в потолок контекста 64k токенов с запасом под промпт.
"""
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import generate  # noqa: E402
import score  # noqa: E402

PARAMS = list(score.PARAM_TYPES)  # формат v1, для обратной совместимости
HERE = os.path.dirname(os.path.abspath(__file__))


def fmt_of(case):
    return case.get("answer_format", "v1")  # у наборов v2, v3, v4 и v5 формат ответа v2


def blank(fmt="v1"):
    return {k: None for k in score.PARAM_TYPES_BY_FORMAT[fmt]}


def satisfy(acc, fmt="v1"):
    params = blank(fmt)
    for k, c in acc["params"].items():
        if c.get("null"):
            params[k] = None
        elif "equals" in c:
            params[k] = c["equals"]
        elif "enum" in c:
            params[k] = c["enum"][0]
        elif "min" in c:
            params[k] = c["min"]
    if params.get("scope") == "deployment":
        params["pod_name"] = None
    return params


def answer(cls, root, a_type, params):
    return {"incident_class": cls, "root_cause": root, "action": {"type": a_type, "params": params},
            "confidence": 0.9, "evidence": ["selftest"], "summary": "selftest"}


def dump(cases):
    return ("\n".join(json.dumps(c, ensure_ascii=False, sort_keys=True, separators=(",", ":")) for c in cases)
            + "\n").encode()


NO_VERDICT_VARIANTS = {"prev_run_degradation_no_current", "prev_run_success_current_degrading", "analysis_running"}


def check_v4(set_name, cases):
    """Инварианты набора v4: надмножество v3, previous_analysis_run, computed.analysis_run, откат без вердикта."""
    bad = []
    v3 = {c["id"]: c for c in generate.build(set_name, generate.DEFAULT_SEED[set_name], "v3")}
    by_id = {c["id"]: c for c in cases}
    for cid, c3 in v3.items():
        c4 = by_id.get(cid)
        if c4 is None:
            bad.append(f"{cid}: v3 case is missing in v4")
        elif c4["input"] != c3["input"] or c4["expected"] != c3["expected"]:
            bad.append(f"{cid}: input/expected differ from v3")
    for c in cases:
        ro = c["input"].get("rollout")
        if ro and "previous_analysis_run" in ro and not (ro["analysis_run"] is None and ro["phase"] in ("Progressing", "Bake")):
            bad.append(f"{c['id']}: previous_analysis_run with a current analysis or outside Progressing/Bake")
        if ro and ro["analysis_run"] is None:
            for act in c["input"]["allowed_actions"]:
                if act["type"] == "rollout.abort_and_rollback" and act["computed"]["analysis_run"] != "":
                    bad.append(f"{c['id']}: abort_and_rollback computed.analysis_run is not empty without an analysis")
        if c["variant"] in NO_VERDICT_VARIANTS and any(
                x["type"] == "rollout.abort_and_rollback" for x in c["expected"]["acceptable"]):
            bad.append(f"{c['id']}: rollback is acceptable without a current verdict")
    return bad


ERROR_VARIANTS = {"analysis_error_no_impact", "analysis_error_current_degrading", "crashloop_analysis_error"}


def check_v5(set_name, cases):
    """Инварианты набора v5: надмножество v4, вердикт error только threshold без значимости, откат не допустим при error."""
    bad = []
    v4 = {c["id"]: c for c in generate.build(set_name, generate.DEFAULT_SEED[set_name], "v4")}
    by_id = {c["id"]: c for c in cases}
    for cid, c4 in v4.items():
        c5 = by_id.get(cid)
        if c5 is None:
            bad.append(f"{cid}: v4 case is missing in v5")
        elif c5["input"] != c4["input"] or c5["expected"] != c4["expected"]:
            bad.append(f"{cid}: input/expected differ from v4")
    for c in cases:
        ar = (c["input"].get("rollout") or {}).get("analysis_run")
        if ar and ar["verdict"] == "error":
            if c["variant"] not in ERROR_VARIANTS:
                bad.append(f"{c['id']}: verdict error outside the v5 variants")
            if any(m["test"] != "threshold" or m["holm_significant"] for m in ar["metrics"]):
                bad.append(f"{c['id']}: verdict error with a non-threshold or significant metric")
        elif c["variant"] in ERROR_VARIANTS:
            bad.append(f"{c['id']}: v5 variant without verdict error")
        if c["variant"] in ("analysis_error_no_impact", "analysis_error_current_degrading") and any(
                x["type"] == "rollout.abort_and_rollback" for x in c["expected"]["acceptable"]):
            bad.append(f"{c['id']}: rollback is acceptable with verdict error")
    return bad


def main():
    failures = []
    manifest = json.load(open(os.path.join(HERE, "data", "manifest.json"), encoding="utf-8"))
    for set_name, fmt in (("probe", "v1"), ("dev", "v1"), ("probe", "v2"), ("dev", "v2"), ("probe", "v3"), ("dev", "v3"),
                          ("probe", "v4"), ("dev", "v4"), ("probe", "v5"), ("dev", "v5")):
        afmt = generate.ANSWER_FORMAT[fmt]  # формат ответа модели; fmt — версия набора
        seed = generate.DEFAULT_SEED[set_name]
        a, b = generate.build(set_name, seed, fmt), generate.build(set_name, seed, fmt)
        if hashlib.sha256(dump(a)).hexdigest() != hashlib.sha256(dump(b)).hexdigest():
            failures.append(f"{set_name}/{fmt}: generator is not deterministic")
        # сохранённый файл набора совпадает с тем, что генерирует текущий код
        stored = os.path.join(HERE, "data", f"{set_name}-{fmt}.jsonl")
        if os.path.exists(stored) and open(stored, "rb").read() != dump(a):
            failures.append(f"{set_name}/{fmt}: data file differs from generator output")
        # запись набора: в актуальных sets, иначе в sets_history
        want_file = f"data/{set_name}-{fmt}.jsonl"
        entries = [manifest["sets"][set_name]] + [h["sets"][set_name] for h in manifest.get("sets_history", [])
                                                  if set_name in h.get("sets", {})]
        entries += [manifest["staged"]["sets"][set_name]] if set_name in manifest.get("staged", {}).get("sets", {}) else []
        entry = next((e for e in entries if e["file"] == want_file), None)
        if entry is None:
            failures.append(f"{set_name}/{fmt}: no manifest entry for {want_file}")
        elif entry["sha256"] != hashlib.sha256(dump(a)).hexdigest():
            failures.append(f"{set_name}/{fmt}: manifest sha256 differs from generator output")
        if fmt in ("v3", "v4", "v5"):
            for c in a:
                if any(k.startswith("_") for k in c["input"]):
                    failures.append(f"{c['id']}: input has service keys starting with '_'")
                if not isinstance(c["input"].get("service", {}).get("pods"), list):
                    failures.append(f"{c['id']}: no input.service.pods")
        if fmt in ("v4", "v5"):
            failures += check_v4(set_name, a)
        if fmt == "v5":
            failures += check_v5(set_name, a)
        ids = [c["id"] for c in a]
        if len(ids) != len(set(ids)):
            failures.append(f"{set_name}: duplicate ids")

        for c in a:
            exp = c["expected"]
            overlap = {x["type"] for x in exp["acceptable"]} & set(exp["harmful"])
            if overlap:
                failures.append(f"{c['id']}: acceptable action also harmful: {overlap}")

        oracle = [{"id": c["id"], "answer": answer(c["expected"]["incident_class"], c["expected"]["root_cause"],
                                                    c["expected"]["acceptable"][0]["type"],
                                                    satisfy(c["expected"]["acceptable"][0], fmt_of(c)))} for c in a]
        agg = score.aggregate(score.score(a, oracle, oracle))
        for m in ("class_match", "root_cause_match", "admissible", "schema_valid", "agreement", "decision_agreement"):
            if agg["all:all"][m]["p"] != 1.0:
                bad = [r["id"] for r in score.score(a, oracle) if not r.get(m, True)][:3]
                failures.append(f"{set_name}: oracle {m} = {agg['all:all'][m]['p']} (e.g. {bad})")
        if agg["all:all"]["harmful"]["k"] != 0:
            failures.append(f"{set_name}: oracle harmful > 0")

        none = [{"id": c["id"], "answer": answer("other", "unknown", "none", blank(afmt))} for c in a]
        if afmt == "v1":
            # v1: величину выбирает модель, параметр вне границ делает действие недопустимым
            scale_params = {**blank(afmt), "new_min_replicas": 500}
        else:
            # v2: величину считает код; «всегда scale_out» допустим только там, где scale_out правильный
            scale_params = blank(afmt)
        scale = [{"id": c["id"], "answer": answer("RB-006", "load_growth", "workload.scale_out", scale_params)}
                 for c in a]
        p_none = score.aggregate(score.score(a, none))["all:all"]["admissible"]["p"]
        p_scale = score.aggregate(score.score(a, scale))["all:all"]["admissible"]["p"]
        scale_limit = 0.0 if afmt == "v1" else 0.25
        if not p_none < 0.25 or p_scale > scale_limit:
            failures.append(f"{set_name}/{fmt}: weak discrimination (none={p_none}, scale_out -> {p_scale})")

        max_chars = max(len(json.dumps(c["input"], ensure_ascii=False)) for c in a)
        # грубо 1 токен ≈ 3 символа для JSON с числами; оставляем ≥ 40k токенов под промпт и каталог
        if max_chars / 3 > 24000:
            failures.append(f"{set_name}: case input too large ({max_chars} chars)")

        print(f"{set_name}/{fmt}: {len(a)} cases, oracle OK, baseline 'none' admissible={p_none:.1%}, "
              f"'always scale_out' admissible={p_scale:.1%}, max input {max_chars} chars")

    if failures:
        print("FAIL")
        for f in failures:
            print(" -", f)
        sys.exit(1)
    print("OK")


if __name__ == "__main__":
    main()
