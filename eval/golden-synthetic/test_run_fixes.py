#!/usr/bin/env python3
"""Проверка исправлений итерации 1 (пункты 4–7 и связанные). Запуск: python3 -B -m unittest -v test_run_fixes

Сеть не используется: mock на 127.0.0.1 или поддельные транспорты.
"""
import contextlib
import io
import json
import os
import random
import stat
import sys
import unittest
from unittest import mock

from test_run import PROMPT_REL, DEV_REL, PROBE_REL, SCHEMA_REL, KEY, PROFILE, RunnerTestCase, FakeSleep, chat, oracle_answer, run, score
from test_run_audit import Base

PLAIN_KEY = "plainsecret-XYZ-7781"  # ключ без префикса sk-or-, чтобы regex не маскировал его


class TestStoppedInFlight(Base):
    """Пункт 4: остановка (stop) во время ретраев, после списанного таймаута."""

    def make_runner(self, out, transport, sleep):
        prof = run.validate_profile(self.cfg, PROFILE, for_network=True)
        prompt = open(os.path.join(self.dir, PROMPT_REL), encoding="utf-8").read()
        schema = json.load(open(os.path.join(self.dir, SCHEMA_REL)))
        writer = run.ResultWriter(out)
        meta = {"kind": "run", "run_id": "t", "profile": PROFILE}
        budget = run.Budget(100.0, 10 ** 9)
        r = run.Runner(transport=transport, url=self.cfg["api_url"], headers={}, cfg=self.cfg, profile=prof,
                       system_prompt=prompt, schema=schema, budget=budget, writer=writer, run_id="t",
                       sleep=sleep, rng=random.Random(1), clock=lambda: 0.0, secrets=[KEY],
                       con=run.Console(io.StringIO(), io.StringIO(), [KEY]), meta=meta,
                       meta_path=out + ".meta.json", prior_rows=[])
        return r, budget, writer

    def test_timeout_then_stop_writes_charged_row_and_resume_counts_it(self):
        out = self.outpath("stop.jsonl")
        case = self.cases[0]
        holder = {}

        class T:
            n = 0

            def post(self, url, headers, data, timeout):
                T.n += 1
                raise run.TransportError("timeout", "timeout")

        def sleep(_d):
            holder["r"].stop.set()  # другой кейс сообщил об abort, пока этот ждёт ретрая

        runner, budget, writer = self.make_runner(out, T(), sleep)
        holder["r"] = runner
        runner.send_case(case)
        writer.close()
        self.assertIsNone(runner.fatal, repr(runner.fatal))
        rows = run.read_rows(out)
        self.assertEqual(len(rows), 1, "остановленный после списанного таймаута кейс должен оставить строку")
        r = rows[0]
        self.assertFalse(r["final"])
        self.assertEqual(r["status"], "transport_error")
        self.assertGreater(r["cost_usd"], 0)
        self.assertGreater(r["charged_tokens"], 0)
        # бюджет, восстановленный из файла, совпадает с тем, что списано в процессе
        _, spent_usd, spent_tok, _ = run.load_existing(out)
        self.assertAlmostEqual(spent_usd, budget.spent_usd)
        self.assertEqual(spent_tok, budget.spent_tokens)

    def test_stop_before_any_attempt_writes_no_row(self):
        out = self.outpath("stop0.jsonl")

        class T:
            def post(self, *a):
                raise AssertionError("no request expected")

        runner, _, writer = self.make_runner(out, T(), FakeSleep())
        runner.stop.set()
        runner.send_case(self.cases[0])
        writer.close()
        self.assertEqual(run.read_rows(out), [])


class TestResumeAfterStopCli(Base):
    def test_resume_after_stopped_run_counts_spent_budget(self):
        """Пункт 4 end-to-end: прогон с провайдером-несоответствием и параллельными запросами, затем resume."""
        out = self.outpath()
        self.mock.default_delay = 0.05
        self.mock.default = lambda r: (200, {}, chat(oracle_answer(self.mock.case_of(r)), provider="Novita"), 0)
        self.assertEqual(self.go("--limit", "8", "--concurrency", "4", "--out", out), 3)
        spent = sum(r["cost_usd"] for r in self.rows(out))
        _, spent_usd, _, _ = run.load_existing(out)
        self.assertAlmostEqual(spent_usd, spent)
        self.assertTrue(all(not r["final"] for r in self.rows(out)))


class TestResumeHashes(Base):
    def test_changed_profiles_json_blocks_resume(self):
        out = self.outpath()
        self.assertEqual(self.go("--limit", "2", "--concurrency", "1", "--out", out), 0)
        self.cfg["concurrency"] = 2  # любое изменение profiles.json
        self.write_cfg()
        self.mock.requests.clear()
        self.assertEqual(self.go("--limit", "2", "--resume", out), 2, self.err)
        self.assertIn("hashes.config", self.err)
        self.assertEqual(self.mock.requests, [])

    def test_changed_runner_hash_blocks_resume(self):
        out = self.outpath()
        self.assertEqual(self.go("--limit", "2", "--concurrency", "1", "--out", out), 0)
        m = self.meta(out)
        m["hashes"]["runner"] = "0" * 64
        with open(out + ".meta.json", "w") as f:
            json.dump(m, f)
        self.assertEqual(self.go("--limit", "2", "--resume", out), 2)
        self.assertIn("hashes.runner", self.err)


class TestNonObjectAnswer(Base):
    def test_json_array_answer_is_null_schema_invalid(self):
        self.mock.default = lambda r: (200, {}, chat(content="[1]"), 0)
        out = self.outpath()
        self.assertEqual(self.go("--limit", "1", "--concurrency", "1", "--out", out), 0)
        r = self.rows(out)[0]
        self.assertEqual((r["status"], r["answer"], r["final"]), ("schema_invalid", None, True))
        self.assertEqual(r["raw_content"], "[1]")
        self.assertTrue(r["error"].startswith("schema_invalid"))

    def test_json_string_answer_is_null_schema_invalid(self):
        self.mock.default = lambda r: (200, {}, chat(content='"hello"'), 0)
        out = self.outpath()
        self.assertEqual(self.go("--limit", "1", "--concurrency", "1", "--out", out), 0)
        r = self.rows(out)[0]
        self.assertIsNone(r["answer"])
        self.assertEqual(r["status"], "schema_invalid")


class TestMalformedBodies(Base):
    def test_malformed_choices_is_retried_then_recorded(self):
        self.cfg["retry"]["max_attempts"] = 2
        self.write_cfg()
        self.mock.default = lambda r: (200, {}, {"choices": ["x"], "provider": "Open Inference"}, 0)
        out = self.outpath()
        self.assertEqual(self.go("--limit", "1", "--concurrency", "1", "--out", out), 4)
        r = self.rows(out)[0]
        self.assertEqual((r["attempts"], r["final"]), (2, False))
        self.assertIn("malformed", r["error"])


class TestSecretsFromFile(RunnerTestCase):
    def test_key_from_file_masked_in_all_outputs(self):
        keyfile = os.path.join(self.tmp.name, "k.txt")
        with open(keyfile, "w") as f:
            f.write(PLAIN_KEY + "\n")

        class Boom:
            def post(self, url, headers, data, timeout):
                raise RuntimeError(f"failed with {PLAIN_KEY}")

        out = self.outpath()
        err, so = io.StringIO(), io.StringIO()
        argv = ["run.py", "--profile", PROFILE, "--set", "dev", "--limit", "1", "--config",
                os.path.join(self.dir, "profiles.json"), "--out", out]
        env = {k: v for k, v in os.environ.items() if k != "OPENROUTER_API_KEY"}
        env["OPENROUTER_API_KEY_FILE"] = keyfile
        orig_t = run.UrllibTransport
        run.UrllibTransport = Boom
        self.addCleanup(setattr, run, "UrllibTransport", orig_t)
        orig_argv = sys.argv
        sys.argv = argv
        self.addCleanup(setattr, sys, "argv", orig_argv)
        with mock.patch.dict(os.environ, env, clear=True), contextlib.redirect_stderr(err), \
                contextlib.redirect_stdout(so):
            with self.assertRaises(SystemExit) as cm:
                run.main()
        self.assertEqual(cm.exception.code, 1)
        self.assertIn("RuntimeError", err.getvalue())
        self.assertNotIn(PLAIN_KEY, err.getvalue())
        self.assertNotIn(PLAIN_KEY, so.getvalue())
        for root, _, files in os.walk(self.tmp.name):
            for fn in files:
                if fn == "k.txt":
                    continue
                with open(os.path.join(root, fn), "rb") as f:
                    self.assertNotIn(PLAIN_KEY.encode(), f.read(), fn)

    def test_key_from_file_masked_in_normal_run(self):
        keyfile = os.path.join(self.tmp.name, "k2.txt")
        with open(keyfile, "w") as f:
            f.write(PLAIN_KEY)
        self.mock.default = lambda r: (400, {}, {"error": {"message": "bad " + PLAIN_KEY}}, 0)
        env = {"OPENROUTER_API_KEY_FILE": keyfile}
        out_io, err_io = io.StringIO(), io.StringIO()
        code = run.run(["--profile", PROFILE, "--set", "dev", "--limit", "1", "--concurrency", "1",
                        "--out", self.outpath()], env=env, stdout=out_io, stderr=err_io, sleep=self.sleep,
                       rng=random.Random(1), base_dir=self.dir)
        self.assertEqual(code, 4)
        self.assertNotIn(PLAIN_KEY, err_io.getvalue() + out_io.getvalue())
        self.assertNotIn(PLAIN_KEY, open(self.outpath(), encoding="utf-8").read())


if __name__ == "__main__":
    unittest.main()
