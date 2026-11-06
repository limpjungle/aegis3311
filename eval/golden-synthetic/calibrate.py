#!/usr/bin/env python3
"""Калибровка и контроль ежедневной eval-пробы (architecture.md §6.3). Только стандартная библиотека, без сети.

Команды:
  update  — найти новые прогоны пробы профиля, посчитать метрики против эталона, добавить точки
            в состояние calibration/<profile>.json и вынести вердикт по последней точке
  status  — показать состояние калибровки и последние точки
  freeze  — заморозить базу (среднее и σ по точкам калибровки); нужно ≥ --min-points точек

Правила (утверждены 05–06.11.2026):
  - основная метрика — decision_agreement (первопричина + тип действия совпали с эталоном);
    дополнительно контролируются root_cause_match, admissible, harmful; доля обрезанных ответов — только алерт;
  - пока база не заморожена: отклонение больше 5 п. п. от значения эталона → DOWNGRADE (проба ≥ 460 кейсов),
    иначе только ALERT;
  - после заморозки: σ_eff = max(σ, 0,5 п. п.), то есть порог понижения = max(3σ, 1,5 п. п.), двусторонний;
    медленный сдвиг — EWMA (λ = 0,2, L = 2,7) или две точки подряд за 2σ_eff по одну сторону → ALERT;
  - база не пересчитывается автоматически: повторная заморозка только с --force (утверждённое изменение).

Коды выхода: 0 — OK; 10 — ALERT; 20 — DOWNGRADE; 2 — ошибка конфигурации или данных.
"""
import argparse
import datetime as dt
import glob
import hashlib
import json
import math
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import score  # noqa: E402

CONTROLLED = ["decision_agreement", "root_cause_match", "admissible", "harmful"]
ALERT_ONLY = ["truncated_share"]
PRE_FREEZE_PP = 5.0
SIGMA_FLOOR_PP = 0.5          # 3 × 0,5 = 1,5 п. п. — нижний предел порога
EWMA_LAMBDA, EWMA_L = 0.2, 2.7
MIN_CASES_FOR_DOWNGRADE = 460
EXIT = {"OK": 0, "ALERT": 10, "DOWNGRADE": 20}


class CalibError(Exception):
    pass


def sha256_file(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def write_json_atomic(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = f"{path}.tmp{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1, sort_keys=True)
        f.write("\n")
    os.replace(tmp, path)


def find_reference(base, profile, set_sha):
    """Последний эталон профиля, записанный на текущем наборе (по sha256 из manifest)."""
    found = []
    for meta_path in glob.glob(os.path.join(base, "refs", profile, "*.jsonl.meta.json")):
        meta = load_json(meta_path)
        if meta.get("kind") == "reference" and meta.get("hashes", {}).get("set") == set_sha \
                and meta.get("status") == "completed":
            found.append((meta.get("frozen_at") or meta.get("finished_at") or "", meta_path[:-len(".meta.json")], meta))
    if not found:
        raise CalibError(f"no frozen reference for profile {profile!r} on the current set (sha {set_sha[:12]}…)")
    found.sort()
    return found[-1][1], found[-1][2]


def eligible_runs(base, profile, ref_meta):
    """Полные прогоны пробы с теми же набором, промптом, схемой, моделью и генерацией, что у эталона."""
    out = []
    for meta_path in sorted(glob.glob(os.path.join(base, "runs", profile, "*.jsonl.meta.json"))):
        meta = load_json(meta_path)
        h, rh = meta.get("hashes", {}), ref_meta.get("hashes", {})
        same = (meta.get("kind") == "run" and meta.get("status") in ("completed", "completed_with_errors")
                and all(h.get(k) == rh.get(k) for k in ("set", "prompt", "schema"))
                and meta.get("model") == ref_meta.get("model") and meta.get("generation") == ref_meta.get("generation")
                and meta.get("selected_ids_sha256") == ref_meta.get("selected_ids_sha256")
                and not meta.get("integrity_bypassed"))
        if same:
            out.append((meta.get("finished_at") or meta.get("started_at") or "", meta_path[:-len(".meta.json")], meta))
    out.sort()
    return out


def metrics_for(cases, pred_rows, ref_rows):
    rows = score.score(cases, pred_rows, ref_rows)
    agg = score.aggregate(rows)["all:all"]
    m = {k: round(agg[k]["p"] * 100, 3) for k in CONTROLLED}
    last = {}
    for r in pred_rows:
        last[r["id"]] = r
    m["truncated_share"] = round(100 * sum(1 for r in last.values() if r.get("status") == "truncated") / len(cases), 3)
    return m, len(cases)


def reference_levels(cases, ref_rows):
    """Значения, от которых считается отклонение до заморозки базы."""
    m, _ = metrics_for(cases, ref_rows, ref_rows)
    valid = sum(1 for r in ref_rows if r.get("answer") is not None and not score.validate(r["answer"]))
    m["decision_agreement"] = round(100 * valid / len(cases), 3)   # максимум, достижимый против этого эталона
    return m


def sigma_eff(sigma):
    return max(sigma, SIGMA_FLOOR_PP)


def judge(state, point):
    """Вердикт по точке: список (уровень, метрика, причина)."""
    findings = []
    frozen = state.get("frozen")
    n_cases = point["n_cases"]
    for metric in CONTROLLED + ALERT_ONLY:
        x = point["metrics"][metric]
        if not frozen:
            ref = state["reference_levels"][metric]
            dev = x - ref
            if abs(dev) > PRE_FREEZE_PP:
                level = "DOWNGRADE" if (metric in CONTROLLED and n_cases >= MIN_CASES_FOR_DOWNGRADE) else "ALERT"
                findings.append((level, metric, f"{x:.2f}% vs reference {ref:.2f}% (|Δ| {abs(dev):.2f} > {PRE_FREEZE_PP} pp, pre-freeze)"))
            continue
        base = frozen["metrics"][metric]
        mu, s = base["mean"], sigma_eff(base["sigma"])
        z = (x - mu) / s
        if abs(z) > 3:
            level = "DOWNGRADE" if metric in CONTROLLED else "ALERT"
            findings.append((level, metric, f"{x:.2f}% vs mean {mu:.2f}% (|z| {abs(z):.1f} > 3, σ_eff {s:.2f} pp)"))
            continue
        prev = [p for p in state["points"] if p.get("after_freeze") and p["run_id"] != point["run_id"]]
        if prev:
            zp = (prev[-1]["metrics"][metric] - mu) / s
            if abs(z) > 2 and abs(zp) > 2 and (z > 0) == (zp > 0):
                findings.append(("ALERT", metric, f"two consecutive points beyond 2σ_eff ({zp:+.1f}, {z:+.1f})"))
        e = state.setdefault("ewma", {}).get(metric, mu)
        e = EWMA_LAMBDA * x + (1 - EWMA_LAMBDA) * e
        limit = EWMA_L * s * math.sqrt(EWMA_LAMBDA / (2 - EWMA_LAMBDA))
        point.setdefault("ewma", {})[metric] = round(e, 4)
        if abs(e - mu) > limit:
            findings.append(("ALERT", metric, f"EWMA {e:.2f}% outside {mu:.2f} ± {limit:.2f} pp"))
    return findings


def overall(findings):
    levels = [f[0] for f in findings]
    return "DOWNGRADE" if "DOWNGRADE" in levels else "ALERT" if "ALERT" in levels else "OK"


def state_path(base, profile):
    return os.path.join(base, "calibration", f"{profile}.json")


def load_state(base, profile, ref_path, ref_meta, cases, ref_rows, set_sha):
    path = state_path(base, profile)
    if os.path.exists(path):
        st = load_json(path)
        if st["reference"]["sha256"] != sha256_file(ref_path):
            raise CalibError("calibration state belongs to another reference; a new reference needs an approved reset "
                             f"(move {os.path.relpath(path, base)} aside and start a new calibration)")
        return st
    return {"profile": profile, "created_at": now(), "set_sha256": set_sha,
            "reference": {"file": os.path.relpath(ref_path, base), "sha256": sha256_file(ref_path),
                          "run_id": ref_meta.get("run_id"), "hashes": ref_meta.get("hashes")},
            "reference_levels": reference_levels(cases, ref_rows), "points": [], "frozen": None, "ewma": {}}


def now():
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def context(base, profile):
    manifest = load_json(os.path.join(base, "data", "manifest.json"))
    entry = manifest["sets"]["probe"]
    set_path = os.path.join(base, entry["file"])
    if sha256_file(set_path) != entry["sha256"]:
        raise CalibError("probe set file does not match manifest")
    cases = score.load_jsonl(set_path)
    ref_path, ref_meta = find_reference(base, profile, entry["sha256"])
    ref_rows = score.load_jsonl(ref_path)
    return cases, ref_path, ref_meta, ref_rows, entry["sha256"]


def cmd_update(base, profile, out):
    cases, ref_path, ref_meta, ref_rows, set_sha = context(base, profile)
    st = load_state(base, profile, ref_path, ref_meta, cases, ref_rows, set_sha)
    known = {p["run_id"] for p in st["points"]}
    verdict, last_findings, added = "OK", [], 0
    for _, run_path, meta in eligible_runs(base, profile, ref_meta):
        if meta["run_id"] in known or meta["run_id"] == ref_meta.get("run_id"):
            continue
        m, n = metrics_for(cases, score.load_jsonl(run_path), ref_rows)
        point = {"run_id": meta["run_id"], "file": os.path.relpath(run_path, base), "finished_at": meta.get("finished_at"),
                 "n_cases": n, "metrics": m, "after_freeze": bool(st.get("frozen"))}
        findings = judge(st, point)
        if point.get("ewma"):
            st["ewma"].update(point["ewma"])
        point["verdict"] = overall(findings)
        point["findings"] = [{"level": a, "metric": b, "detail": c} for a, b, c in findings]
        st["points"].append(point)
        verdict, last_findings, added = point["verdict"], findings, added + 1
    st["updated_at"] = now()
    write_json_atomic(state_path(base, profile), st)
    phase = "frozen" if st.get("frozen") else f"calibrating ({len(st['points'])} points)"
    print(f"{profile}: {added} new point(s), {phase}", file=out)
    if not added:
        print("no new eligible probe runs", file=out)
        return 0
    last = st["points"][-1]
    print(f"last point {last['run_id']}: " + ", ".join(f"{k}={v:.2f}%" for k, v in last["metrics"].items()), file=out)
    print(f"verdict: {verdict}", file=out)
    for level, metric, detail in last_findings:
        print(f"  {level} {metric}: {detail}", file=out)
    return EXIT[verdict]


def cmd_freeze(base, profile, min_points, force, out):
    cases, ref_path, ref_meta, ref_rows, set_sha = context(base, profile)
    st = load_state(base, profile, ref_path, ref_meta, cases, ref_rows, set_sha)
    if st.get("frozen") and not force:
        raise CalibError("base is already frozen; re-freezing needs an approved change (--force)")
    pts = [p for p in st["points"] if not p.get("after_freeze")] if not force else st["points"]
    if len(pts) < min_points:
        raise CalibError(f"need at least {min_points} calibration points, have {len(pts)}")
    base_metrics = {}
    for metric in CONTROLLED + ALERT_ONLY:
        xs = [p["metrics"][metric] for p in pts]
        mean = sum(xs) / len(xs)
        sd = math.sqrt(sum((x - mean) ** 2 for x in xs) / (len(xs) - 1)) if len(xs) > 1 else 0.0
        base_metrics[metric] = {"mean": round(mean, 4), "sigma": round(sd, 4), "n": len(xs),
                                "threshold_pp": round(3 * sigma_eff(sd), 4)}
    st["frozen"] = {"frozen_at": now(), "points": [p["run_id"] for p in pts], "metrics": base_metrics}
    st["ewma"] = {m: v["mean"] for m, v in base_metrics.items()}
    write_json_atomic(state_path(base, profile), st)
    print(f"{profile}: base frozen on {len(pts)} points", file=out)
    for m, v in base_metrics.items():
        print(f"  {m}: mean {v['mean']:.2f}%, σ {v['sigma']:.2f} pp, downgrade threshold ±{v['threshold_pp']:.2f} pp", file=out)
    return 0


def cmd_status(base, profile, out):
    path = state_path(base, profile)
    if not os.path.exists(path):
        print(f"{profile}: no calibration state yet", file=out)
        return 0
    st = load_json(path)
    print(f"{profile}: reference {st['reference']['file']}", file=out)
    print("phase: " + ("frozen at " + st["frozen"]["frozen_at"] if st.get("frozen") else
                       f"calibrating, {len(st['points'])} point(s)"), file=out)
    for p in st["points"][-5:]:
        print(f"  {p['run_id']} {p['verdict']}: " + ", ".join(f"{k}={v:.2f}%" for k, v in p["metrics"].items()), file=out)
    return 0


def main(argv=None, out=sys.stdout, base=HERE):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["update", "status", "freeze"])
    ap.add_argument("--profile", required=True)
    ap.add_argument("--min-points", type=int, default=20)
    ap.add_argument("--force", action="store_true", help="re-freeze an already frozen base (approved change only)")
    ap.add_argument("--base-dir", default=base, help=argparse.SUPPRESS)
    args = ap.parse_args(argv)
    try:
        if args.command == "update":
            return cmd_update(args.base_dir, args.profile, out)
        if args.command == "freeze":
            return cmd_freeze(args.base_dir, args.profile, args.min_points, args.force, out)
        return cmd_status(args.base_dir, args.profile, out)
    except CalibError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
