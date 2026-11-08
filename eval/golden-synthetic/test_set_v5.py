#!/usr/bin/env python3
"""Тесты активных промпта и набора v5 (переключение 08.11.2026), без сети. Запуск: python3 -B -m unittest -v test_set_v5"""
import contextlib
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import calibrate  # noqa: E402
import generate  # noqa: E402
import run  # noqa: E402
import score  # noqa: E402
import selftest  # noqa: E402


def rb(path):
    with open(path, "rb") as f:
        return f.read()


MANIFEST = json.loads(rb(os.path.join(HERE, "data", "manifest.json")))
V4 = next(h for h in MANIFEST["sets_history"] if h.get("set_format") == "v4")
PROFILES = ("inceptron-fp8", "wafer-nvfp4")
NEW_VARIANTS = {v for _, v, _, _ in generate.COMPOSITION_V5_EXTRA["probe"]}
NO_ROLLBACK = {"analysis_error_no_impact", "analysis_error_current_degrading"}


def sha(path):
    return hashlib.sha256(rb(os.path.join(HERE, path))).hexdigest()


def refs_of(profile, version):
    import glob
    paths = glob.glob(os.path.join(HERE, "refs", profile, f"probe-{version}-*.jsonl"))
    assert len(paths) == 1, paths
    return {r["id"]: r for r in map(json.loads, rb(paths[0]).decode().splitlines())}


def cases_of(set_name, fmt="v5"):
    return generate.build(set_name, generate.DEFAULT_SEED[set_name], fmt)


class SetV5Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.probe = cases_of("probe")
        cls.dev = cases_of("dev")

    def test_deterministic(self):
        for name, first in (("probe", self.probe), ("dev", self.dev)):
            self.assertEqual(selftest.dump(first), selftest.dump(cases_of(name)))

    def test_sizes(self):
        self.assertEqual((len(self.probe), len(self.dev)), (635, 147))

    def test_files_match_generator_and_manifest(self):
        for name, cases in (("probe", self.probe), ("dev", self.dev)):
            entry = MANIFEST["sets"][name]
            raw = rb(os.path.join(HERE, entry["file"]))
            self.assertEqual(raw, selftest.dump(cases), f"{entry['file']} differs from generator output")
            self.assertEqual(hashlib.sha256(raw).hexdigest(), entry["sha256"])
            self.assertEqual(entry["cases"], len(cases))
            self.assertEqual(entry["seed"], generate.DEFAULT_SEED[name])
            self.assertEqual(entry["seed"], V4["sets"][name]["seed"])

    def test_active_is_v5(self):
        self.assertNotIn("staged", MANIFEST)
        self.assertEqual((MANIFEST["set_format"], MANIFEST["generator_version"], MANIFEST["answer_format"]), ("v5", "5.0.0", "v2"))
        self.assertEqual(MANIFEST["prompt"]["file"], "prompt/system-v5.md")
        self.assertEqual(MANIFEST["prompt"]["sha256"], sha("prompt/system-v5.md"))
        self.assertEqual(MANIFEST["answer_schema"]["sha256"], sha("schema/answer.schema-v2.json"))
        for name, cases in (("probe", self.probe), ("dev", self.dev)):
            by_class, by_slice = {}, {}
            for c in cases:
                by_class[c["expected"]["incident_class"]] = by_class.get(c["expected"]["incident_class"], 0) + 1
                by_slice[c["slice"]] = by_slice.get(c["slice"], 0) + 1
            self.assertEqual(MANIFEST["sets"][name]["by_class"], by_class)
            self.assertEqual(MANIFEST["sets"][name]["by_slice"], by_slice)

    def test_v4_archived(self):
        self.assertEqual((V4["until"], V4["answer_format"], V4["generator_version"]), ("2026-11-08", "v2", "4.0.0"))
        p4 = next(p for p in MANIFEST["prompt_history"] if p["file"] == "prompt/system-v4.md")
        self.assertEqual((p4["until"], p4["sha256"]), ("2026-11-08", sha("prompt/system-v4.md")))
        for name in ("probe", "dev"):
            self.assertEqual(V4["sets"][name]["file"], f"data/{name}-v4.jsonl")
            self.assertEqual(V4["sets"][name]["sha256"], sha(V4["sets"][name]["file"]))

    def test_v4_cases_unchanged_in_v5(self):
        for name, v5 in (("probe", self.probe), ("dev", self.dev)):
            by5 = {c["id"]: c for c in v5}
            v4 = cases_of(name, "v4")
            self.assertEqual(len(v4) + sum(n for _, _, _, n in generate.COMPOSITION_V5_EXTRA[name]), len(v5))
            for c4 in v4:
                c5 = by5[c4["id"]]
                self.assertEqual(c5["input"], c4["input"], c4["id"])
                self.assertEqual(c5["expected"], c4["expected"], c4["id"])
                self.assertEqual(c5["generator_version"], "5.0.0")
        # сохранённые файлы v4 и v3 не изменились после появления v5
        for name in ("probe", "dev"):
            self.assertEqual(rb(os.path.join(HERE, V4["sets"][name]["file"])), selftest.dump(cases_of(name, "v4")))
            v3 = next(h for h in MANIFEST["sets_history"] if h.get("set_format") == "v3")
            self.assertEqual(rb(os.path.join(HERE, v3["sets"][name]["file"])), selftest.dump(cases_of(name, "v3")))

    def test_error_verdict_invariants(self):
        phases, bake_null = set(), 0
        for c in self.probe:
            ro = c["input"].get("rollout")
            ar = ro["analysis_run"] if ro else None
            if ar is None or ar["verdict"] != "error":
                self.assertNotIn(c["variant"], NEW_VARIANTS, c["id"])
                continue
            self.assertIn(c["variant"], NEW_VARIANTS, c["id"])
            for m in ar["metrics"]:
                self.assertEqual((m["test"], m["baseline"], m["p_value"], m["holm_significant"]), ("threshold", None, None, False), c["id"])
            self.assertTrue(ar["name"], c["id"])
            for a in c["input"]["allowed_actions"]:
                if a["type"] == "rollout.abort_and_rollback":
                    self.assertEqual(a["computed"], {"analysis_run": ar["name"]}, c["id"])
            phases.add(ro["phase"])
            if ro["phase"] == "Bake":
                self.assertIsNone(ro["canary_revision"], c["id"])
                self.assertEqual(ro["canary_weight_pct"], 100, c["id"])
                bake_null += 1
        self.assertEqual(phases, {"Progressing", "Bake"})
        self.assertGreater(bake_null, 0)

    def test_markup(self):
        counts = {}
        for c in self.probe:
            v = c["variant"]
            if v not in NEW_VARIANTS:
                continue
            counts[v] = counts.get(v, 0) + 1
            exp = c["expected"]
            rollback = [a for a in exp["acceptable"] if a["type"] == "rollout.abort_and_rollback"]
            self.assertFalse(any(a["type"] == "rollout.abort_and_rollback" and a["params"].get("reason") == {"equals": "insufficient_data_policy"}
                                 for a in exp["acceptable"]), c["id"])
            self.assertNotEqual(exp["root_cause"], "canary_insufficient_data", c["id"])
            if v in NO_ROLLBACK:
                self.assertEqual(rollback, [], c["id"])
                self.assertEqual(exp["incident_class"], "RB-003")
            if v == "analysis_error_no_impact":
                self.assertEqual(exp["root_cause"], "no_user_impact")
                self.assertEqual([a["type"] for a in exp["acceptable"]], ["none", "recommend"])
                self.assertEqual(exp["harmful"], ["rollout.abort_and_rollback", "workload.restart"])
            if v == "analysis_error_current_degrading":
                self.assertEqual(exp["root_cause"], "release_regression")
                self.assertEqual(exp["acceptable"], [{"type": "recommend", "params": {}}])
                self.assertNotIn("rollout.abort_and_rollback", exp["harmful"])
            if v == "crashloop_analysis_error":
                self.assertEqual(exp["incident_class"], "RB-004")
                self.assertEqual(exp["root_cause"], "crashloop_after_release")
                self.assertEqual([a["params"]["reason"] for a in rollback], [{"equals": "canary_degradation"}])
        self.assertEqual(counts, {v: n for _, v, _, n in generate.COMPOSITION_V5_EXTRA["probe"]})

    def test_policy_rollback_present(self):
        pols = {c["input"]["service"]["insufficient_data_policy"] for c in self.probe if c["variant"] == "analysis_error_no_impact"}
        self.assertIn("rollback", pols)

    def test_default_format_is_v5(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "dev.jsonl")
            subprocess.run([sys.executable, "-B", os.path.join(HERE, "generate.py"), "--set", "dev", "--out", out],
                           check=True, capture_output=True)
            self.assertEqual(rb(out), rb(os.path.join(HERE, MANIFEST["sets"]["dev"]["file"])))


class RunnerV5Test(unittest.TestCase):
    def dry(self, profile, *extra):
        out, err = io.StringIO(), io.StringIO()
        code = run.run(["--profile", profile, "--set", "probe", "--dry-run", *extra], env={}, stdout=out, stderr=err)
        return code, out.getvalue(), err.getvalue()

    def emit(self, profile, *extra):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "r.jsonl")
            code, _, err = self.dry(profile, "--emit-requests", path, *extra)  # без ключа и сети
            self.assertEqual(code, 0, err)
            return {r["id"]: r for r in map(json.loads, rb(path).decode().splitlines())}

    def test_requests_match_v5_references(self):
        for p in PROFILES:
            got, ref = self.emit(p), refs_of(p, "v5")
            self.assertEqual(set(got), set(ref))
            for i, r in got.items():
                self.assertEqual((r["request_sha256"], r["est_input_tokens"]),
                                 (ref[i]["request_sha256"], ref[i]["est_input_tokens"]),
                                 f"{p} {i}: запрос не совпал с эталоном probe-v5; смена профиля, промпта или схемы требует новых эталонов")

    def test_active_takes_v5_prompt_and_set(self):
        act = run.check_integrity("probe", False)
        self.assertEqual(act["prompt"], rb(os.path.join(HERE, "prompt/system-v5.md")).decode())
        self.assertEqual(act["set_file"], "data/probe-v5.jsonl")
        self.assertEqual(len(act["cases"]), 635)

    def test_staged_without_candidate_is_refused(self):
        with self.assertRaisesRegex(run.IntegrityError, "no staged candidate"):
            run.check_integrity("probe", False, staged=True)
        code, _, err = self.dry(PROFILES[0], "--staged")
        self.assertEqual(code, 2, err)

    def test_v5_requests_differ_from_v4_references(self):
        got, r4 = self.emit(PROFILES[0]), refs_of(PROFILES[0], "v4")
        self.assertEqual((len(got), len(r4)), (635, 595))
        for i, r in r4.items():
            self.assertNotEqual(got[i]["request_sha256"], r["request_sha256"], f"{i}: промпт v5 должен менять каждый запрос")

    def test_calibration_finds_reference_by_set(self):
        # по хешу активного набора — эталон v5, по хешу архивного v4 — эталон v4; калибровка v5 — с нуля в своём состоянии
        for p in PROFILES:
            ref, _ = calibrate.find_reference(HERE, p, MANIFEST["sets"]["probe"]["sha256"])
            self.assertIn(os.sep + "probe-v5-", ref)
            ref, _ = calibrate.find_reference(HERE, p, V4["sets"]["probe"]["sha256"])
            self.assertIn(os.sep + "probe-v4-", ref)
            self.assertEqual(calibrate.state_path(HERE, p, calibrate.set_tag(MANIFEST["sets"]["probe"])),
                             os.path.join(HERE, "calibration", f"{p}-probe-v5.json"))
            self.assertFalse(os.path.exists(os.path.join(HERE, "calibration", f"{p}-probe-v5.json")))


class ScoreV5Test(unittest.TestCase):
    def preds(self, cases):
        return [{"id": c["id"], "answer": selftest.answer(
            c["expected"]["incident_class"], c["expected"]["root_cause"], c["expected"]["acceptable"][0]["type"],
            selftest.satisfy(c["expected"]["acceptable"][0], selftest.fmt_of(c)))} for c in cases]

    def run_score(self, *argv):
        old = sys.argv
        sys.argv = ["score.py", *argv]
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                score.main()
        finally:
            sys.argv = old

    def test_by_variant(self):
        cases = cases_of("dev")
        agg = score.aggregate(score.score(cases, self.preds(cases)), by_variant=True)
        for v in NEW_VARIANTS:
            self.assertEqual(agg[f"variant:{v}"]["n"], sum(1 for c in cases if c["variant"] == v))

    def test_ref_ids_only_against_v4(self):
        v5, v4 = cases_of("dev"), cases_of("dev", "v4")
        with tempfile.TemporaryDirectory() as d:
            def dump(name, rows):
                p = os.path.join(d, name)
                with open(p, "w") as f:
                    f.writelines(json.dumps(r) + "\n" for r in rows)
                return p
            cases_p, pred_p, ref_p = dump("c", v5), dump("p", self.preds(v5)), dump("r", self.preds(v4))
            only = os.path.join(d, "o.json")
            self.run_score("--cases", cases_p, "--pred", pred_p, "--ref", ref_p, "--ref-ids-only", "--out", only)
            self.assertEqual(json.loads(rb(only))["summary"]["all:all"]["n"], 138)


if __name__ == "__main__":
    unittest.main()
