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
    return case.get("answer_format", "v1")


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


def main():
    failures = []
    manifest = json.load(open(os.path.join(HERE, "data", "manifest.json"), encoding="utf-8"))
    for set_name, fmt in (("probe", "v1"), ("dev", "v1"), ("probe", "v2"), ("dev", "v2")):
        seed = generate.DEFAULT_SEED[set_name]
        a, b = generate.build(set_name, seed, fmt), generate.build(set_name, seed, fmt)
        if hashlib.sha256(dump(a)).hexdigest() != hashlib.sha256(dump(b)).hexdigest():
            failures.append(f"{set_name}/{fmt}: generator is not deterministic")
        # сохранённый файл набора совпадает с тем, что генерирует текущий код
        stored = os.path.join(HERE, "data", f"{set_name}-{fmt}.jsonl")
        if os.path.exists(stored) and open(stored, "rb").read() != dump(a):
            failures.append(f"{set_name}/{fmt}: data file differs from generator output")
        if manifest["sets"][set_name]["file"] == f"data/{set_name}-{fmt}.jsonl" and \
                manifest["sets"][set_name]["sha256"] != hashlib.sha256(dump(a)).hexdigest():
            failures.append(f"{set_name}/{fmt}: manifest sha256 differs from generator output")
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

        none = [{"id": c["id"], "answer": answer("other", "unknown", "none", blank(fmt))} for c in a]
        if fmt == "v1":
            # v1: величину выбирает модель, параметр вне границ делает действие недопустимым
            scale_params = {**blank(fmt), "new_min_replicas": 500}
        else:
            # v2: величину считает код; «всегда scale_out» допустим только там, где scale_out правильный
            scale_params = blank(fmt)
        scale = [{"id": c["id"], "answer": answer("RB-006", "load_growth", "workload.scale_out", scale_params)}
                 for c in a]
        p_none = score.aggregate(score.score(a, none))["all:all"]["admissible"]["p"]
        p_scale = score.aggregate(score.score(a, scale))["all:all"]["admissible"]["p"]
        scale_limit = 0.0 if fmt == "v1" else 0.25
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
