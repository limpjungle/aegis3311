#!/usr/bin/env python3
"""Тесты calibrate.py на синтетических прогонах (без сети). Запуск: python3 -m unittest -v test_calibrate"""
import io
import json
import math
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
        self.tag = calibrate.set_tag(m["sets"]["probe"])
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
        self.write_jsonl(os.path.join(self.base, "refs", PROFILE, f"{self.tag}-ref.jsonl"), self.oracle,
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

    def pp(self, x):
        """Число кейсов, дающее отклонение не меньше x п. п. на текущем наборе (тесты не привязаны к размеру пробы)."""
        return math.ceil(x * len(self.cases) / 100)

    def state(self):
        return json.load(open(calibrate.state_path(self.base, PROFILE, self.tag)))

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
        self.add_run(n_wrong=self.pp(6.25))
        self.assertEqual(self.cmd("update"), 20, self.out)
        self.assertIn("pre-freeze", self.out)

    def test_truncated_share_only_alerts(self):
        self.add_run(n_trunc=0)
        self.cmd("update")
        st = self.state()
        point = {"run_id": "X", "n_cases": len(self.cases), "metrics": dict(st["points"][0]["metrics"], truncated_share=7.0)}
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
        self.add_run(n_wrong=self.pp(1.67))       # −1,67 п. п.: за пределом
        self.assertEqual(self.cmd("update"), 20, self.out)


class TestAfterFreeze(CalibTestCase):
    def test_three_sigma_downgrade(self):
        self.calibrate_flat()
        self.add_run(n_wrong=self.pp(3.1))
        self.assertEqual(self.cmd("update"), 20, self.out)
        self.assertIn("|z|", self.out)

    def test_two_consecutive_beyond_two_sigma_alert(self):
        self.calibrate_flat(wrong=(0,))           # σ_eff = 0,5 п. п.; 2σ = 1 п. п., 3σ = 1,5 п. п.
        self.add_run(n_wrong=self.pp(1.25))       # −1,25 п. п.: за 2σ, но не за 3σ
        self.cmd("update")
        self.add_run(n_wrong=self.pp(1.25))
        code = self.cmd("update")
        self.assertEqual(code, 10, self.out)
        self.assertIn("two consecutive", self.out)

    def test_ewma_catches_slow_drift(self):
        self.calibrate_flat(wrong=(0,))
        codes = []
        for _ in range(6):
            self.add_run(n_wrong=self.pp(0.83))   # −0,83 п. п. — меньше 2σ_eff, но устойчиво
            codes.append(self.cmd("update"))
        self.assertIn(10, codes)
        self.assertIn("EWMA", json.dumps(self.state()["points"][-1]["findings"]))


class TestReferenceGuard(CalibTestCase):
    def test_state_tied_to_reference(self):
        self.add_run()
        self.cmd("update")
        rows = json.loads(json.dumps(self.oracle))
        rows[0]["answer"] = selftest.answer("other", "unknown", "none", selftest.blank("v2"))
        self.write_jsonl(os.path.join(self.base, "refs", PROFILE, f"{self.tag}-ref.jsonl"), rows, self.meta("reference", "REF"))
        self.assertEqual(self.cmd("update"), 2)


class TestStatePerSet(CalibTestCase):
    def test_no_reference_is_alert_without_state(self):
        shutil.rmtree(os.path.join(self.base, "refs"))
        self.add_run()
        self.assertEqual(self.cmd("update"), 10, self.out)
        self.assertIn("no_reference", self.out)
        self.assertFalse(os.path.exists(calibrate.state_path(self.base, PROFILE, self.tag)))
        self.assertFalse(os.path.exists(os.path.join(self.base, "calibration")))

    def test_no_reference_on_other_set_sha(self):
        # эталон есть, но записан на другом наборе (v2)
        self.write_jsonl(os.path.join(self.base, "refs", PROFILE, f"{self.tag}-ref.jsonl"), self.oracle,
                         self.meta("reference", "REF", hashes={**self.hashes, "set": "0" * 64}))
        self.assertEqual(self.cmd("update"), 10, self.out)
        self.assertIn("no_reference", self.out)

    def test_freeze_without_reference_is_error(self):
        shutil.rmtree(os.path.join(self.base, "refs"))
        self.assertEqual(self.cmd("freeze"), 2)

    def test_legacy_archive_untouched(self):
        legacy = calibrate.state_path(self.base, PROFILE, "probe-v2")
        self.assertEqual(legacy, os.path.join(self.base, "calibration", f"{PROFILE}.json"))
        os.makedirs(os.path.dirname(legacy))
        archive = b'{"archive": "v2"}\n'
        with open(legacy, "wb") as f:
            f.write(archive)
        self.add_run()
        self.assertEqual(self.cmd("update"), 0, self.out)
        self.assertEqual(open(legacy, "rb").read(), archive)
        self.assertEqual(len(self.state()["points"]), 1)
        self.assertTrue(os.path.exists(os.path.join(self.base, "calibration", f"{PROFILE}-{self.tag}.json")))
        self.cmd("status")
        self.assertIn(self.tag, self.out)

    def test_status_mentions_archive(self):
        legacy = calibrate.state_path(self.base, PROFILE, "probe-v2")
        os.makedirs(os.path.dirname(legacy))
        open(legacy, "w").write("{}\n")
        self.assertEqual(self.cmd("status"), 0)
        self.assertIn("archived probe-v2", self.out)

    def test_foreign_set_sha_in_state_is_error(self):
        self.add_run()
        self.assertEqual(self.cmd("update"), 0, self.out)
        path = calibrate.state_path(self.base, PROFILE, self.tag)
        st = json.load(open(path))
        st["set_sha256"] = "f" * 64
        json.dump(st, open(path, "w"))
        self.assertEqual(self.cmd("update"), 2)
        self.assertEqual(self.cmd("freeze"), 2)

    def test_no_reference_keeps_existing_v3_state_bytes(self):
        # состояние v3 уже есть; эталон пропал — update не трогает файл и не понижает (код 10, не 20)
        self.add_run()
        self.assertEqual(self.cmd("update"), 0, self.out)
        path = calibrate.state_path(self.base, PROFILE, self.tag)
        before = open(path, "rb").read()
        shutil.rmtree(os.path.join(self.base, "refs"))
        self.add_run(n_wrong=200)  # заведомо «плохой» прогон: без эталона он не должен дать DOWNGRADE
        self.assertEqual(self.cmd("update"), 10, self.out)
        self.assertIn("no_reference", self.out)
        self.assertEqual(open(path, "rb").read(), before)

    def test_v2_set_runs_are_not_points_of_v3(self):
        # прогон на наборе v2 (другой sha) в runs/ лежит, но в состояние v3 не попадает
        v2_sha = "97908de7e3962c09997fabc50e3d8e85e338580df625b258e73218e251dcf2f0"
        self.assertNotEqual(v2_sha, self.set_sha)
        self.add_run(n_wrong=200, hashes={**self.hashes, "set": v2_sha})
        self.assertEqual(self.cmd("update"), 0, self.out)
        self.assertEqual(len(self.state()["points"]), 0)
        self.assertIn("no new eligible probe runs", self.out)


if __name__ == "__main__":
    unittest.main()
