#!/usr/bin/env python3
"""Тесты calibrate.py на синтетических прогонах (без сети). Запуск: python3 -m unittest -v test_calibrate"""
import io
import json
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import calibrate  # noqa: E402
import score  # noqa: E402
import selftest  # noqa: E402

PROFILE = "inceptron-fp8"


class CalibTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = self.tmp.name
        shutil.copytree(os.path.join(HERE, "data"), os.path.join(self.base, "data"))
        m = json.load(open(os.path.join(self.base, "data", "manifest.json")))
        self.set_sha = m["sets"]["probe"]["sha256"]
        self.cases = score.load_jsonl(os.path.join(self.base, m["sets"]["probe"]["file"]))
        self.hashes = {"set": self.set_sha, "prompt": "p" * 64, "schema": "s" * 64}
        self.oracle = [{"id": c["id"], "status": "ok", "answer": selftest.answer(
            c["expected"]["incident_class"], c["expected"]["root_cause"], c["expected"]["acceptable"][0]["type"],
            selftest.satisfy(c["expected"]["acceptable"][0], selftest.fmt_of(c)))} for c in self.cases]
        self.n_run = 0
        self.write_ref()

    def meta(self, kind, run_id, **over):
        d = {"kind": kind, "status": "completed", "run_id": run_id, "hashes": dict(self.hashes),
             "model": "z-ai/glm-5.3-flash-20260826", "generation": {"temperature": 0, "seed": 1, "max_tokens": 4096},
             "selected_ids_sha256": "ids", "finished_at": f"2026-11-{10 + self.n_run:02d}T00:00:00Z",
             "frozen_at": "2026-11-06T00:00:00Z"}
        d.update(over)
        return d

    def write_jsonl(self, path, rows, meta):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write("".join(json.dumps(r) + "\n" for r in rows))
        json.dump(meta, open(path + ".meta.json", "w"))

    def write_ref(self):
        self.write_jsonl(os.path.join(self.base, "refs", PROFILE, "probe-v2-ref.jsonl"), self.oracle,
                         self.meta("reference", "REF"))

    def add_run(self, n_wrong=0, n_trunc=0, **meta_over):
        """Прогон, где n_wrong кейсов отвечают `none` с другой первопричиной (теряют decision_agreement)."""
        self.n_run += 1
        rows = json.loads(json.dumps(self.oracle))
        changed = 0
        for r, c in zip(rows, self.cases):
            if changed >= n_wrong:
                break
            if c["expected"]["acceptable"][0]["type"] != "none":
                r["answer"] = selftest.answer("other", "unknown", "none", selftest.blank("v2"))
                changed += 1
        for r in rows[len(rows) - n_trunc:] if n_trunc else []:
            r["answer"], r["status"] = None, "truncated"
        run_id = f"RUN{self.n_run:03d}"
        kind = meta_over.pop("kind", "run")
        self.write_jsonl(os.path.join(self.base, "runs", PROFILE, f"probe-{run_id}.jsonl"), rows,
                         self.meta(kind, run_id, **meta_over))
        return run_id

    def cmd(self, *argv):
        out = io.StringIO()
        code = calibrate.main([*argv, "--profile", PROFILE, "--base-dir", self.base], out=out)
        self.out = out.getvalue()
        return code

    def state(self):
        return json.load(open(os.path.join(self.base, "calibration", f"{PROFILE}.json")))

    def calibrate_flat(self, n=20, wrong=(0, 1, 0, 2, 1)):
        for i in range(n):
            self.add_run(n_wrong=wrong[i % len(wrong)])
        self.assertEqual(self.cmd("update"), 0, self.out)
        self.assertEqual(self.cmd("freeze"), 0, self.out)


class TestPreFreeze(CalibTestCase):
    def test_reference_levels_and_ok_point(self):
        self.add_run(n_wrong=3)
        self.assertEqual(self.cmd("update"), 0, self.out)
        st = self.state()
        self.assertEqual(st["reference_levels"]["decision_agreement"], 100.0)
        self.assertEqual(len(st["points"]), 1)
        self.assertEqual(st["points"][0]["verdict"], "OK")

    def test_more_than_5pp_is_downgrade(self):
        self.add_run(n_wrong=30)   # 6,25 п. п.
        self.assertEqual(self.cmd("update"), 20, self.out)
        self.assertIn("pre-freeze", self.out)

    def test_truncated_share_only_alerts(self):
        self.add_run(n_trunc=0)
        self.cmd("update")
        st = self.state()
        point = {"run_id": "X", "n_cases": 480, "metrics": dict(st["points"][0]["metrics"], truncated_share=7.0)}
        findings = calibrate.judge(st, point)
        self.assertEqual([f[0] for f in findings if f[1] == "truncated_share"], ["ALERT"])

    def test_idempotent_and_ineligible_runs_skipped(self):
        self.add_run()
        self.add_run(hashes={**self.hashes, "prompt": "other" * 12})
        self.add_run(kind="reference")
        self.add_run(integrity_bypassed=True)
        self.cmd("update")
        self.cmd("update")
        self.assertEqual(len(self.state()["points"]), 1)


class TestFreeze(CalibTestCase):
    def test_needs_min_points(self):
        for _ in range(5):
            self.add_run()
        self.cmd("update")
        self.assertEqual(self.cmd("freeze"), 2)

    def test_refreeze_needs_force(self):
        self.calibrate_flat()
        self.assertEqual(self.cmd("freeze"), 2)
        self.assertEqual(self.cmd("freeze", "--force"), 0)

    def test_frozen_base_and_floor(self):
        self.calibrate_flat(wrong=(0,))           # σ = 0 → σ_eff = 0,5 п. п., порог 1,5 п. п.
        da = self.state()["frozen"]["metrics"]["decision_agreement"]
        self.assertEqual((da["mean"], da["sigma"], da["threshold_pp"]), (100.0, 0.0, 1.5))
        self.add_run(n_wrong=1)                   # −0,21 п. п.: в пределах предела
        self.assertNotEqual(self.cmd("update"), 20, self.out)
        self.add_run(n_wrong=8)                   # −1,67 п. п.: за пределом
        self.assertEqual(self.cmd("update"), 20, self.out)


class TestAfterFreeze(CalibTestCase):
    def test_three_sigma_downgrade(self):
        self.calibrate_flat()
        self.add_run(n_wrong=15)
        self.assertEqual(self.cmd("update"), 20, self.out)
        self.assertIn("|z|", self.out)

    def test_two_consecutive_beyond_two_sigma_alert(self):
        self.calibrate_flat(wrong=(0,))           # σ_eff = 0,5 п. п.; 2σ = 1 п. п. ≈ 5 кейсов, 3σ ≈ 7
        self.add_run(n_wrong=6)                   # −1,25 п. п.: за 2σ, но не за 3σ
        self.cmd("update")
        self.add_run(n_wrong=6)
        code = self.cmd("update")
        self.assertEqual(code, 10, self.out)
        self.assertIn("two consecutive", self.out)

    def test_ewma_catches_slow_drift(self):
        self.calibrate_flat(wrong=(0,))
        codes = []
        for _ in range(6):
            self.add_run(n_wrong=4)               # −0,83 п. п. — меньше 2σ_eff, но устойчиво
            codes.append(self.cmd("update"))
        self.assertIn(10, codes)
        self.assertIn("EWMA", json.dumps(self.state()["points"][-1]["findings"]))


class TestReferenceGuard(CalibTestCase):
    def test_state_tied_to_reference(self):
        self.add_run()
        self.cmd("update")
        rows = json.loads(json.dumps(self.oracle))
        rows[0]["answer"] = selftest.answer("other", "unknown", "none", selftest.blank("v2"))
        self.write_jsonl(os.path.join(self.base, "refs", PROFILE, "probe-v2-ref.jsonl"), rows, self.meta("reference", "REF"))
        self.assertEqual(self.cmd("update"), 2)


if __name__ == "__main__":
    unittest.main()
