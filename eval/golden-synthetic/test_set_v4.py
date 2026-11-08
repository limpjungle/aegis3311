#!/usr/bin/env python3
"""Тесты кандидата v4 (промпт и набор), без сети. Запуск: python3 -B -m unittest -v test_set_v4"""
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
STAGED = MANIFEST["staged"]
PROFILES = ("inceptron-fp8", "wafer-nvfp4")
NEW_VARIANTS = {v for _, v, _, _ in generate.COMPOSITION_V4_EXTRA["probe"]}
NO_VERDICT = {"prev_run_degradation_no_current", "prev_run_success_current_degrading", "analysis_running"}


def sha(path):
    return hashlib.sha256(rb(os.path.join(HERE, path))).hexdigest()


def cases_of(set_name, fmt="v4"):
    return generate.build(set_name, generate.DEFAULT_SEED[set_name], fmt)


class SetV4Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.probe = cases_of("probe")
        cls.dev = cases_of("dev")

    def test_deterministic(self):
        for name, first in (("probe", self.probe), ("dev", self.dev)):
            self.assertEqual(selftest.dump(first), selftest.dump(cases_of(name)))

    def test_sizes(self):
        self.assertEqual((len(self.probe), len(self.dev)), (595, 138))

    def test_files_match_generator_and_manifest(self):
        for name, cases in (("probe", self.probe), ("dev", self.dev)):
            entry = STAGED["sets"][name]
            raw = rb(os.path.join(HERE, entry["file"]))
            self.assertEqual(raw, selftest.dump(cases), f"{entry['file']} differs from generator output")
            self.assertEqual(hashlib.sha256(raw).hexdigest(), entry["sha256"])
            self.assertEqual(entry["cases"], len(cases))
            self.assertEqual(entry["seed"], generate.DEFAULT_SEED[name])
            self.assertEqual(entry["seed"], MANIFEST["sets"][name]["seed"])

    def test_staged_block(self):
        self.assertEqual(STAGED["status"], "candidate")
        self.assertEqual(STAGED["prompt"]["sha256"], sha("prompt/system-v4.md"))
        self.assertEqual(STAGED["answer_schema"], {"file": MANIFEST["answer_schema"]["file"],
                                                   "sha256": MANIFEST["answer_schema"]["sha256"]})

    def test_active_still_v3(self):
        self.assertEqual(MANIFEST["prompt"]["file"], "prompt/system-v3.md")
        self.assertEqual(MANIFEST["sets"]["probe"]["file"], "data/probe-v3.jsonl")
        self.assertEqual(MANIFEST["sets"]["dev"]["file"], "data/dev-v3.jsonl")

    def test_v3_cases_unchanged_in_v4(self):
        for name, v4 in (("probe", self.probe), ("dev", self.dev)):
            by4 = {c["id"]: c for c in v4}
            v3 = cases_of(name, "v3")
            self.assertEqual(len(v3) + sum(n for _, _, _, n in generate.COMPOSITION_V4_EXTRA[name]), len(v4))
            for c3 in v3:
                c4 = by4[c3["id"]]
                self.assertEqual(c4["input"], c3["input"], c3["id"])
                self.assertEqual(c4["expected"], c3["expected"], c3["id"])
                self.assertEqual(c4["generator_version"], "4.0.0")
        # сохранённые файлы v3 не изменились (кейсы v3 в v4 остаются теми же и после правок генератора)
        for name in ("probe", "dev"):
            self.assertEqual(rb(os.path.join(HERE, MANIFEST["sets"][name]["file"])),
                             selftest.dump(cases_of(name, "v3")))

    def test_previous_analysis_run_invariants(self):
        seen = set()
        for c in self.probe:
            ro = c["input"].get("rollout")
            if ro and "previous_analysis_run" in ro:
                self.assertIsNone(ro["analysis_run"], c["id"])
                self.assertIn(ro["phase"], ("Progressing", "Bake"), c["id"])
                seen.add(ro["phase"])
        self.assertEqual(seen, {"Progressing", "Bake"})

    def test_computed_analysis_run_empty_without_analysis(self):
        n = 0
        for c in self.probe:
            ro = c["input"].get("rollout")
            if ro and ro["phase"] in ("Progressing", "Bake") and ro["analysis_run"] is None:
                acts = [a for a in c["input"]["allowed_actions"] if a["type"] == "rollout.abort_and_rollback"]
                self.assertEqual([a["computed"] for a in acts], [{"analysis_run": ""}], c["id"])
                n += 1
        self.assertGreaterEqual(n, 55)

    def test_markup(self):
        counts = {}
        for c in self.probe:
            v = c["variant"]
            if v not in NEW_VARIANTS:
                continue
            counts[v] = counts.get(v, 0) + 1
            exp = c["expected"]
            rollback = [a for a in exp["acceptable"] if a["type"] == "rollout.abort_and_rollback"]
            if v in NO_VERDICT:
                self.assertEqual(rollback, [], c["id"])
            if v == "prev_run_success_current_degrading":
                self.assertEqual(exp["root_cause"], "release_regression")
                self.assertEqual(exp["acceptable"], [{"type": "recommend", "params": {}}])
                self.assertNotIn("rollout.abort_and_rollback", exp["harmful"])
            if v in ("prev_run_degradation_no_current", "analysis_running"):
                self.assertEqual(exp["root_cause"], "no_user_impact")
                self.assertIn("rollout.abort_and_rollback", exp["harmful"])
            if v == "crashloop_no_current_analysis":
                self.assertEqual(exp["incident_class"], "RB-004")
                self.assertEqual([a["params"]["reason"] for a in rollback], [{"equals": "canary_degradation"}])
            if v in ("canary_degradation_threshold", "bake_degradation_live"):
                self.assertEqual(len(rollback), 1)
        self.assertEqual(counts, {v: n for _, v, _, n in generate.COMPOSITION_V4_EXTRA["probe"]})

    def test_live_shapes(self):
        for c in self.probe:
            ro = c["input"].get("rollout")
            if c["variant"] == "bake_degradation_live":
                self.assertEqual((ro["phase"], ro["canary_revision"], ro["canary_weight_pct"]), ("Bake", None, 100))
                self.assertEqual(ro["stable_revision"], c["input"]["deploys"][0]["revision"])
            if c["variant"] == "analysis_running":
                self.assertEqual(ro["analysis_run"]["verdict"], "running")
            if c["variant"] in NEW_VARIANTS and ro and ro["analysis_run"]:
                for m in ro["analysis_run"]["metrics"]:
                    self.assertEqual((m["test"], m["baseline"], m["p_value"]), ("threshold", None, None), c["id"])
            if c["variant"] == "load_growth_series_gaps":
                gaps = 0
                for m in c["input"]["metrics"]:
                    self.assertTrue(all(v is not None for v in m["values"][-5:]), c["id"])
                    gaps += m["values"].count(None)
                self.assertGreaterEqual(gaps, 4)

    def test_default_format_is_v3(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "dev.jsonl")
            subprocess.run([sys.executable, "-B", os.path.join(HERE, "generate.py"), "--set", "dev", "--out", out],
                           check=True, capture_output=True)
            self.assertEqual(rb(out), rb(os.path.join(HERE, MANIFEST["sets"]["dev"]["file"])))


class RunnerV4Test(unittest.TestCase):
    def dry(self, profile, *extra):
        out, err = io.StringIO(), io.StringIO()
        code = run.run(["--profile", profile, "--set", "probe", "--dry-run", *extra], env={}, stdout=out, stderr=err)
        return code, out.getvalue(), err.getvalue()

    def test_request_fixtures_match_runner(self):
        for p in PROFILES:
            with tempfile.TemporaryDirectory() as d:
                path = os.path.join(d, "r.jsonl")
                code, _, err = self.dry(p, "--staged", "--emit-requests", path)  # без ключа и сети
                self.assertEqual(code, 0, err)
                self.assertEqual(rb(path), rb(os.path.join(HERE, "requests", p, "probe-v4.jsonl")),
                                 f"requests/{p}/probe-v4.jsonl устарела: python3 run.py --profile {p} --staged --set probe "
                                 f"--dry-run --emit-requests requests/{p}/probe-v4.jsonl")

    def test_emit_requests_needs_dry_run(self):
        out, err = io.StringIO(), io.StringIO()
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "r.jsonl")
            code = run.run(["--profile", PROFILES[0], "--set", "probe", "--staged", "--emit-requests", path],
                           env={"OPENROUTER_API_KEY": "sk-or-v1-TESTSECRETdeadbeef0123456789"}, stdout=out, stderr=err)
            self.assertEqual(code, 2)
            self.assertFalse(os.path.exists(path))

    def test_staged_takes_v4_prompt_and_set(self):
        st = run.check_integrity("probe", False, staged=True)
        self.assertEqual(st["prompt"], rb(os.path.join(HERE, "prompt/system-v4.md")).decode())
        self.assertEqual(st["set_file"], "data/probe-v4.jsonl")
        self.assertEqual(len(st["cases"]), 595)
        act = run.check_integrity("probe", False)
        self.assertEqual(act["prompt"], rb(os.path.join(HERE, "prompt/system-v3.md")).decode())
        self.assertEqual(act["set_file"], "data/probe-v3.jsonl")
        self.assertEqual(len(act["cases"]), 480)
        self.assertEqual(st["schema"], act["schema"])

    def test_staged_differs_from_active_requests(self):
        with tempfile.TemporaryDirectory() as d:
            a, b = os.path.join(d, "a"), os.path.join(d, "b")
            self.assertEqual(self.dry(PROFILES[0], "--emit-requests", a)[0], 0)
            self.assertEqual(self.dry(PROFILES[0], "--staged", "--emit-requests", b)[0], 0)
            r3 = {json.loads(x)["id"]: json.loads(x)["request_sha256"] for x in rb(a).decode().splitlines()}
            r4 = {json.loads(x)["id"]: json.loads(x)["request_sha256"] for x in rb(b).decode().splitlines()}
            self.assertEqual(len(r3), 480)
            self.assertEqual(len(r4), 595)
            self.assertTrue(all(r3[i] != r4[i] for i in r3), "промпт v4 должен менять каждый запрос")

    def test_request_digest_is_live_path(self):
        body = {"a": 1}
        self.assertEqual(run.request_digest(body), hashlib.sha256(run.body_bytes(body)).hexdigest())

    def test_calibration_does_not_see_v4_references(self):
        with tempfile.TemporaryDirectory() as d:
            ref_dir = os.path.join(d, "refs", PROFILES[0])
            os.makedirs(ref_dir)
            meta = {"kind": "reference", "status": "completed", "finished_at": "2026-11-10T00:00:00Z",
                    "hashes": {"set": STAGED["sets"]["probe"]["sha256"], "prompt": STAGED["prompt"]["sha256"]}}
            with open(os.path.join(ref_dir, "probe-v4-x.jsonl.meta.json"), "w") as f:
                json.dump(meta, f)
            with self.assertRaises(calibrate.NoReference):
                calibrate.find_reference(d, PROFILES[0], MANIFEST["sets"]["probe"]["sha256"])
            ref, _ = calibrate.find_reference(d, PROFILES[0], STAGED["sets"]["probe"]["sha256"])
            self.assertTrue(ref.endswith("probe-v4-x.jsonl"))
        # настоящие эталоны v3 по-прежнему находятся
        calibrate.find_reference(HERE, PROFILES[0], MANIFEST["sets"]["probe"]["sha256"])
        with self.assertRaises(calibrate.NoReference):
            calibrate.find_reference(HERE, PROFILES[0], STAGED["sets"]["probe"]["sha256"])


class ScoreV4Test(unittest.TestCase):
    def preds(self, cases):
        return [{"id": c["id"], "answer": selftest.answer(
            c["expected"]["incident_class"], c["expected"]["root_cause"], c["expected"]["acceptable"][0]["type"],
            selftest.satisfy(c["expected"]["acceptable"][0], selftest.fmt_of(c)))} for c in cases]

    def test_by_variant(self):
        cases = cases_of("dev")
        rows = score.score(cases, self.preds(cases))
        plain = score.aggregate(rows)
        self.assertFalse(any(k.startswith("variant:") for k in plain))
        agg = score.aggregate(rows, by_variant=True)
        self.assertEqual({k: v for k, v in agg.items() if not k.startswith("variant:")}, plain)
        for v in NEW_VARIANTS:
            self.assertEqual(agg[f"variant:{v}"]["n"], sum(1 for c in cases if c["variant"] == v))

    def run_score(self, *argv):
        old = sys.argv
        sys.argv = ["score.py", *argv]
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                score.main()
        finally:
            sys.argv = old

    def test_ref_ids_only(self):
        v4, v3 = cases_of("dev"), cases_of("dev", "v3")
        with tempfile.TemporaryDirectory() as d:
            def dump(name, rows):
                p = os.path.join(d, name)
                with open(p, "w") as f:
                    f.writelines(json.dumps(r) + "\n" for r in rows)
                return p
            cases_p, pred_p, ref_p = dump("c", v4), dump("p", self.preds(v4)), dump("r", self.preds(v3))
            full, only, byv = os.path.join(d, "f.json"), os.path.join(d, "o.json"), os.path.join(d, "v.json")
            self.run_score("--cases", cases_p, "--pred", pred_p, "--ref", ref_p, "--out", full)
            self.run_score("--cases", cases_p, "--pred", pred_p, "--ref", ref_p, "--ref-ids-only", "--out", only)
            self.run_score("--cases", cases_p, "--pred", pred_p, "--by-variant", "--out", byv)
            n = lambda p: json.loads(rb(p))["summary"]["all:all"]["n"]
            self.assertEqual((n(full), n(only)), (138, 113))
            self.assertIn("variant:analysis_running", json.loads(rb(byv))["summary"])
            with self.assertRaises(SystemExit):
                with contextlib.redirect_stderr(io.StringIO()):
                    self.run_score("--cases", cases_p, "--pred", pred_p, "--ref-ids-only")


if __name__ == "__main__":
    unittest.main()
