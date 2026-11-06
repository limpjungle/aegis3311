#!/usr/bin/env python3
"""Независимая проверка раннера (дополнение к test_run.py). Запуск: python3 -B -m unittest -v test_run_audit

Сеть не используется: только mock на 127.0.0.1 и поддельные транспорты.
"""
import contextlib
import io
import json
import os
import random
import shutil
import stat
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

from test_run import (PROMPT_REL, DEV_REL, PROBE_REL, SCHEMA_REL, KEY, PROFILE, PROVIDER, RunnerTestCase, FakeSleep, chat, oracle_answer, run, score, selftest,
                      HERE)

# Оригинальный метод транспорта (до того, как RunnerTestCase.setUp подменит его защитой от сети).
ORIG_POST = run.UrllibTransport.post


class Sink:
    """Второй loopback-сервер: фиксирует заголовки всех входящих запросов."""

    def __init__(self):
        self.hits = []
        sink = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                self.rfile.read(n)
                sink.hits.append(dict(self.headers))
                data = b"{}"
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class Base(RunnerTestCase):
    def go(self, *argv, key=KEY, transport=None, setname="dev", profile=PROFILE, **kw):
        # Каждый вызов получает свой RNG: run_id строится из него, и одинаковые run_id дали бы коллизию файлов.
        self._calls = getattr(self, "_calls", 0) + 1
        out, err = io.StringIO(), io.StringIO()
        env = {"OPENROUTER_API_KEY": key} if key else {}
        args = ["--profile", profile, *(["--set", setname] if setname else []), *argv]
        code = run.run(args, env=env, stdout=out, stderr=err, sleep=self.sleep,
                       rng=random.Random(1000 + self._calls), base_dir=self.dir, transport=transport, **kw)
        self.out, self.err = out.getvalue(), err.getvalue()
        return code

    def reserve(self, case):
        prof = run.validate_profile(self.cfg, PROFILE, for_network=True)
        sch = json.load(open(os.path.join(self.dir, SCHEMA_REL)))
        prompt = open(os.path.join(self.dir, PROMPT_REL), encoding="utf-8").read()
        body = run.build_request(case["input"], prompt, sch, self.cfg, prof)
        est, mt = run.estimate_input_tokens(body, self.cfg), body["max_tokens"]
        return est + mt, run.cost_of(est, mt, run.unit_prices(prof))

    def exact_usage(self):
        """Ответ с usage ровно равным резерву: стоимость списывается точно по резерву."""
        def default(req):
            c = self.mock.case_of(req)
            est = self.reserve(c)[0] - self.cfg["generation"]["max_tokens"]
            mt = self.cfg["generation"]["max_tokens"]
            u = {"prompt_tokens": est, "completion_tokens": mt, "total_tokens": est + mt}
            return 200, {}, chat(oracle_answer(c), usage=u), 0
        self.mock.default = default


class TestUrlRules(unittest.TestCase):
    def test_accepted(self):
        for url in (run.API_URL, "http://127.0.0.1:9/x", "http://localhost:1/x", "http://[::1]:1/x"):
            with self.subTest(url=url):
                run.check_api_url(url)

    def test_rejected(self):
        bad = ["https://127.0.0.1/x", "http://127.0.0.1.evil.example/x", "http://localhost@evil.example/x",
               "http://127.0.0.1@evil.example/x", "https://openrouter.ai.evil.example/api/v1/chat/completions",
               "http://openrouter.ai/api/v1/chat/completions", "https://OPENROUTER.ai/api/v1/chat/completions",
               "https://openrouter.ai/api/v1/chat/completions?x=1", "file:///etc/passwd", "", None, 5]
        for url in bad:
            with self.subTest(url=url):
                with self.assertRaises(run.ConfigError):
                    run.check_api_url(url)

    def test_transport_refuses_foreign_host_without_network(self):
        t = run.UrllibTransport()
        with self.assertRaises(run.TransportError):
            ORIG_POST(t, "https://evil.example/api/v1/chat/completions", {}, b"", 1)
        with self.assertRaises(run.TransportError):
            t.get("https://evil.example/api/v1/models", {}, 1)


class TestRedirects(Base):
    def test_authorization_not_forwarded_on_redirect(self):
        sink = Sink()
        self.addCleanup(sink.close)
        self.cfg["retry"]["max_attempts"] = 1
        self.write_cfg()
        self.mock.default = lambda r: (307, {"Location": f"http://127.0.0.1:{sink.port}/steal"}, b"", 0)
        out = self.outpath()
        code = self.go("--limit", "1", "--concurrency", "1", "--out", out)
        self.assertEqual(sink.hits, [], "redirect target received a request")
        self.assertEqual(code, 4, self.err)
        self.assertNotIn(KEY, self.all_text())


class TestSecretsAudit(Base):
    def test_key_from_file_does_not_leak_through_unexpected_exception(self):
        """Ключ из OPENROUTER_API_KEY_FILE не должен попасть в stderr, даже если неожиданное исключение
        содержит его текст (main() редактирует только OPENROUTER_API_KEY из окружения)."""
        keyfile = os.path.join(self.tmp.name, "key.txt")
        with open(keyfile, "w") as f:
            f.write(KEY + "\n")

        class Boom:
            def __init__(self, *a, **kw):
                pass

            def post(self, url, headers, data, timeout):
                raise RuntimeError(f"unexpected failure with header {headers.get('Authorization')}")

            def get(self, *a):
                raise RuntimeError("x")

        out = self.outpath()
        err = io.StringIO()
        argv = ["run.py", "--profile", PROFILE, "--set", "dev", "--limit", "1", "--config",
                os.path.join(self.dir, "profiles.json"), "--out", out]
        env = {k: v for k, v in os.environ.items() if k != "OPENROUTER_API_KEY"}
        env["OPENROUTER_API_KEY_FILE"] = keyfile
        orig_t, orig_argv = run.UrllibTransport, sys.argv
        run.UrllibTransport = Boom
        self.addCleanup(setattr, run, "UrllibTransport", orig_t)
        sys.argv = argv
        self.addCleanup(setattr, sys, "argv", orig_argv)
        with mock.patch.dict(os.environ, env, clear=True), contextlib.redirect_stderr(err), \
                contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as cm:
                run.main()
        self.assertEqual(cm.exception.code, 1)
        self.assertNotIn(KEY, err.getvalue())
        self.assertNotIn("TESTSECRET", err.getvalue())

    def test_key_in_401_body_and_raw_content_is_masked(self):
        self.mock.default = lambda r: (401, {}, {"error": {"message": "bad key " + KEY}}, 0)
        out = self.outpath()
        self.assertEqual(self.go("--limit", "1", "--concurrency", "1", "--out", out), 3)
        self.assertNotIn(KEY, self.err)
        self.assertNotIn(KEY, open(out, encoding="utf-8").read())
        self.assertNotIn(KEY, open(out + ".meta.json", encoding="utf-8").read())

    def test_key_in_raw_content_is_masked(self):
        self.mock.default = lambda r: (200, {}, chat(content="not json " + KEY), 0)
        out = self.outpath()
        self.assertEqual(self.go("--limit", "1", "--concurrency", "1", "--out", out), 0)
        rows = self.rows(out)
        self.assertEqual(rows[0]["status"], "invalid_json")
        self.assertNotIn(KEY, rows[0]["raw_content"])
        self.assertNotIn(KEY, self.all_text())

    def test_key_passed_in_argv_is_rejected_and_not_echoed(self):
        self.assertEqual(self.go("--limit", "1", "--api-key", KEY, "--out", self.outpath(), key=None), 2)
        self.assertNotIn(KEY, self.err)
        self.assertNotIn(KEY, self.out)
        self.assertEqual(self.mock.requests, [])

    def test_key_not_in_stdout_on_success(self):
        self.assertEqual(self.go("--limit", "2", "--out", self.outpath()), 0)
        self.assertNotIn(KEY, self.out)
        self.assertNotIn(KEY, self.err)


class TestRequestAudit(Base):
    def test_only_input_reaches_wire(self):
        self.assertEqual(self.go("--limit", "3", "--concurrency", "1", "--out", self.outpath()), 0)
        for req in self.mock.requests:
            body = req["body"]
            self.assertEqual(set(body), {"model", "messages", "response_format", "provider", "temperature",
                                         "seed", "max_tokens", "usage"})
            case = self.mock.case_of(req)
            self.assertEqual(json.loads(body["messages"][1]["content"]), case["input"])
            self.assertEqual(body["provider"]["zdr"], True)
            self.assertEqual(body["provider"]["data_collection"], "deny")
            self.assertEqual(body["provider"]["allow_fallbacks"], False)
            self.assertEqual(body["provider"]["only"], ["open-inference"])
            self.assertEqual(body["response_format"]["json_schema"]["strict"], True)
            self.assertNotIn("$schema", body["response_format"]["json_schema"]["schema"])
            self.assertEqual(body["model"], self.cfg["model"])

    def test_wafer_profile_endpoint_label_and_provider(self):
        self.mock.default = lambda r: (200, {}, chat(oracle_answer(self.mock.case_of(r)), provider="Wafer"), 0)
        out = self.outpath()
        self.assertEqual(self.go("--limit", "2", "--concurrency", "1", "--out", out, profile="wafer-nvfp4"), 0,
                         self.err)
        for r in self.rows(out):
            self.assertEqual(r["endpoint"], "wafer/us")
        self.assertEqual(self.meta(out)["endpoint_label"], "wafer/us")
        for req in self.mock.requests:
            self.assertEqual(req["body"]["provider"]["only"], ["wafer"])
            self.assertEqual(req["body"]["provider"]["quantizations"], ["nvfp4"])

    def test_wafer_provider_mismatch_with_open_inference(self):
        out = self.outpath()
        self.assertEqual(self.go("--limit", "2", "--concurrency", "1", "--out", out, profile="wafer-nvfp4"), 3)
        self.assertEqual(self.rows(out)[0]["status"], "provider_mismatch")

    def test_incomplete_profile_refused_for_network_and_dry_run_passes(self):
        self.cfg["profiles"]["placeholder"] = {
            "endpoint_label": None, "expected_provider_names": [], "send_seed": True, "price_usd_per_mtok": None,
            "provider": {"only": [], "quantizations": ["fp8"], "allow_fallbacks": False,
                         "zdr": True, "data_collection": "deny", "require_parameters": True}}
        self.write_cfg()
        self.assertEqual(self.go("--limit", "1", "--out", self.outpath(), profile="placeholder"), 2)
        self.assertEqual(self.mock.requests, [])
        self.assertEqual(self.go("--limit", "1", "--dry-run", profile="placeholder"), 0)

    def test_fp8_compare_requests_pinned_to_inceptron(self):
        out = self.outpath()
        self.go("--limit", "1", "--concurrency", "1", "--out", out, profile="inceptron-fp8")
        self.assertTrue(self.mock.requests)
        for req in self.mock.requests:
            p = req["body"]["provider"]
            self.assertEqual((p["only"], p["quantizations"], p["zdr"], p["data_collection"], p["allow_fallbacks"]),
                             (["inceptron"], ["fp8"], True, "deny", False))


class TestProviderFailClosed(Base):
    def test_mismatch_stops_all_workers(self):
        self.mock.default = lambda r: (200, {}, chat(oracle_answer(self.mock.case_of(r)), provider="Novita"), 0)
        self.mock.default_delay = 0.05
        out = self.outpath()
        code = self.go("--limit", "20", "--concurrency", "4", "--out", out)
        self.assertEqual(code, 3)
        self.assertLessEqual(len(self.mock.requests), 4)
        self.assertEqual(self.meta(out)["abort_reason"], "provider_mismatch")
        for r in self.rows(out):
            self.assertIsNone(r["answer"])
            self.assertFalse(r["final"])

    def test_dropped_provider_field_is_mismatch(self):
        self.mock.default = lambda r: (200, {}, chat(oracle_answer(self.mock.case_of(r)), with_provider=False), 0)
        out = self.outpath()
        self.assertEqual(self.go("--limit", "2", "--concurrency", "1", "--out", out), 3)
        self.assertEqual(self.rows(out)[0]["status"], "provider_mismatch")


class TestBudgetAudit(Base):
    def test_concurrent_reservations_never_exceed_cap(self):
        self.exact_usage()
        self.mock.default_delay = 0.05
        reserves = [self.reserve(c) for c in self.cases[:12]]
        cap = sum(r[1] for r in reserves[:3]) + 1e-9
        out = self.outpath()
        code = self.go("--limit", "12", "--concurrency", "8", "--max-usd", repr(cap), "--out", out)
        self.assertEqual(code, 3, self.err)
        sent = [self.mock.case_of(r)["id"] for r in self.mock.requests]
        sent_reserve = sum(self.reserve(self.mock.case_of(r))[1] for r in self.mock.requests)
        self.assertLessEqual(sent_reserve, cap)
        self.assertGreaterEqual(len(sent), 2)
        spent = sum(r["cost_usd"] for r in self.rows(out))
        self.assertLessEqual(spent, cap)

    def test_concurrent_token_cap(self):
        self.exact_usage()
        self.mock.default_delay = 0.05
        cap = sum(self.reserve(c)[0] for c in self.cases[:3]) + 1
        out = self.outpath()
        code = self.go("--limit", "12", "--concurrency", "8", "--max-tokens-total", str(cap), "--out", out)
        self.assertEqual(code, 3)
        sent_tok = sum(self.reserve(self.mock.case_of(r))[0] for r in self.mock.requests)
        self.assertLessEqual(sent_tok, cap)

    def test_resume_after_budget_stop_completes_remaining(self):
        self.exact_usage()
        cap = self.reserve(self.cases[0])[1] + self.reserve(self.cases[1])[1] + 1e-7
        out = self.outpath()
        self.assertEqual(self.go("--limit", "3", "--concurrency", "1", "--max-usd", repr(cap), "--out", out), 3)
        self.assertEqual(len(self.mock.requests), 2)
        self.mock.requests.clear()
        self.assertEqual(self.go("--limit", "3", "--concurrency", "1", "--resume", out), 0, self.err)
        self.assertEqual(len(self.mock.requests), 1)
        self.assertEqual(score.aggregate(score.score(self.cases[:3], score.load_jsonl(out)))["all:all"]
                         ["schema_valid"]["p"], 1.0)

    def test_usage_missing_charges_full_reserve(self):
        class T:
            def post(self, *a):
                return run.Response(200, {}, json.dumps({"choices": [{"message": {"content": "{}"}}]}).encode())
        b = run.Budget(100, 10 ** 9)
        cr = run.call_with_retries(T(), "u", {}, b"", self.cfg["retry"], b, (100, 1.0, (0.03, 0.22)),
                                   FakeSleep(), random.Random(), lambda: 0.0)
        self.assertEqual((cr.kind, cr.tokens), ("ok", 100))
        self.assertAlmostEqual(cr.cost_usd, 1.0)

    def test_cli_cannot_raise_budget_and_negative_is_refused(self):
        self.assertEqual(self.go("--limit", "1", "--max-usd", "-1", "--out", self.outpath()), 2)
        self.assertEqual(self.mock.requests, [])

    def test_zero_tokens_cli_is_refused(self):
        self.assertEqual(self.go("--limit", "1", "--max-tokens-total", "0", "--out", self.outpath()), 2)
        self.assertEqual(self.mock.requests, [])


class TestRetriesAudit(Base):
    def test_huge_retry_after_is_capped(self):
        self.mock.scenarios = [lambda r: (429, {"Retry-After": "3600"}, {"error": {}}, 0)]
        out = self.outpath()
        self.assertEqual(self.go("--limit", "1", "--out", out), 0)
        self.assertTrue(self.sleep.delays)
        self.assertLessEqual(max(self.sleep.delays), self.cfg["retry"]["max_delay_s"])

    def test_non_numeric_retry_after_ignored(self):
        self.mock.scenarios = [lambda r: (503, {"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"}, b"x", 0)]
        out = self.outpath()
        self.assertEqual(self.go("--limit", "1", "--out", out), 0)
        self.assertLessEqual(max(self.sleep.delays), self.cfg["retry"]["max_delay_s"])

    def test_malformed_choices_do_not_crash_run(self):
        self.mock.default = lambda r: (200, {}, {"choices": ["x"], "provider": PROVIDER}, 0)
        out = self.outpath()
        code = self.go("--limit", "1", "--concurrency", "1", "--out", out)
        self.assertIn(code, (3, 4), f"exit {code}; stderr: {self.err}")
        self.assertEqual(len(self.rows(out)), 1)

    def test_message_not_object_does_not_crash_run(self):
        self.mock.default = lambda r: (200, {}, {"choices": [{"message": "str"}], "provider": PROVIDER}, 0)
        out = self.outpath()
        code = self.go("--limit", "1", "--concurrency", "1", "--out", out)
        self.assertIn(code, (3, 4), f"exit {code}; stderr: {self.err}")


class TestCliAudit(Base):
    def test_unknown_ids_refused(self):
        self.assertEqual(self.go("--ids", "NOPE-1", "--out", self.outpath()), 2)
        self.assertEqual(self.mock.requests, [])

    def test_limit_zero_refused(self):
        self.assertEqual(self.go("--limit", "0", "--out", self.outpath()), 2)

    def test_dry_run_creates_nothing_even_with_reference(self):
        before = set(os.listdir(self.dir))
        self.assertEqual(self.go("--limit", "2", "--dry-run", "--reference", setname="probe"), 2)
        self.assertEqual(set(os.listdir(self.dir)), before)


class TestReferenceAudit(Base):
    def shrink_probe(self, n=4):
        src = score.load_jsonl(os.path.join(HERE, PROBE_REL))[:n]
        raw = ("\n".join(run.canon_json(c) for c in src) + "\n").encode()
        with open(os.path.join(self.dir, PROBE_REL), "wb") as f:
            f.write(raw)
        mp = os.path.join(self.dir, "data", "manifest.json")
        m = json.load(open(mp))
        m["sets"]["probe"].update(cases=n, sha256=run.sha256_bytes(raw))
        json.dump(m, open(mp, "w"))
        self.mock.by_user.update({run.canonical_input(c["input"]): c for c in src})
        return src

    def ref_files(self):
        out = []
        for root, _, files in os.walk(os.path.join(self.dir, "refs")):
            out += [os.path.join(root, f) for f in files if f.endswith(".jsonl")]
        return out

    def test_incomplete_reference_not_frozen_then_resume_freezes(self):
        self.shrink_probe()
        self.cfg["retry"]["max_attempts"] = 1
        self.write_cfg()
        self.mock.default = lambda r: (500, {}, b"x", 0)
        self.assertEqual(self.go("--reference", "--concurrency", "1", setname="probe"), 4)
        (ref,) = self.ref_files()
        self.assertTrue(os.stat(ref).st_mode & stat.S_IWUSR)
        self.assertNotIn("frozen_at", self.meta(ref))
        # восстановить сервер и докрутить
        self.mock.default = lambda r: (200, {}, chat(oracle_answer(self.mock.case_of(r))), 0)
        self.assertEqual(self.go("--reference", "--resume", ref, setname="probe"), 0, self.err)
        self.assertEqual(stat.S_IMODE(os.stat(ref).st_mode), 0o444)
        self.assertIn("frozen_at", self.meta(ref))
        self.assertEqual(len(self.rows(ref)), 4)

    def test_rerun_reference_does_not_overwrite_frozen(self):
        self.shrink_probe()
        self.assertEqual(self.go("--reference", setname="probe"), 0, self.err)
        (ref,) = self.ref_files()
        before = open(ref, "rb").read()
        self.assertEqual(self.go("--reference", setname="probe"), 0, self.err)  # новый run_id => новый файл
        self.assertEqual(open(ref, "rb").read(), before)
        self.assertEqual(len(self.ref_files()), 2)
        self.assertEqual(self.go("--reference", "--resume", ref, setname="probe"), 2)

    def test_reference_with_resume_on_frozen_file_refused(self):
        self.shrink_probe()
        self.assertEqual(self.go("--reference", setname="probe"), 0, self.err)
        (ref,) = self.ref_files()
        self.assertEqual(self.go("--reference", "--resume", ref, setname="probe"), 2)
        self.assertEqual(self.go("--reference", "--out", ref, setname="probe"), 2)


class TestConcurrencyIntegrity(Base):
    def test_concurrency_16_file_is_intact(self):
        self.mock.default = lambda r: (200, {}, chat(oracle_answer(self.mock.case_of(r))),
                                       random.Random(id(r) & 0xffff).uniform(0, 0.02))
        out = self.outpath()
        self.assertEqual(self.go("--concurrency", "16", "--out", out), 0, self.err)
        with open(out, "rb") as f:
            data = f.read()
        self.assertTrue(data.endswith(b"\n"))
        lines = data.split(b"\n")[:-1]
        rows = [json.loads(line) for line in lines]  # любая перемешанная строка здесь упадёт
        ids = [r["id"] for r in rows]
        self.assertEqual(len(ids), len(self.cases))
        self.assertEqual(set(ids), {c["id"] for c in self.cases})
        self.assertTrue(all(r["final"] and r["status"] == "ok" for r in rows))
        self.assertEqual(self.meta(out)["status"], "completed")

    def test_concurrent_meta_writes_do_not_corrupt(self):
        """META_EVERY=1 заставляет каждую строку писать .meta.json из разных потоков одновременно."""
        self.mock.default = lambda r: (200, {}, chat(oracle_answer(self.mock.case_of(r))),
                                       random.Random(id(r) & 0xffff).uniform(0, 0.01))
        out = self.outpath()
        with mock.patch.object(run, "META_EVERY", 1):
            code = self.go("--concurrency", "16", "--out", out)
        self.assertEqual(code, 0, self.err)
        self.assertEqual(self.meta(out)["status"], "completed")

    def test_score_py_subprocess_exit_zero_on_run_output(self):
        import subprocess
        out = self.outpath()
        self.assertEqual(self.go("--limit", "5", "--out", out), 0)
        cases_path = self.outpath("cases5.jsonl")
        with open(cases_path, "w") as f:
            f.write("\n".join(json.dumps(c) for c in self.cases[:5]) + "\n")
        p = subprocess.run([sys.executable, "-B", os.path.join(HERE, "score.py"), "--cases", cases_path,
                            "--pred", out], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("100.0%", p.stdout)


class TestMiscAudit(Base):
    def test_duplicate_rows_last_wins_in_score(self):
        out = self.outpath()
        self.assertEqual(self.go("--limit", "1", "--out", out), 0)
        row = self.rows(out)[0]
        bad = dict(row, answer=None, final=False, status="http_error", error="x")
        with open(out, "a", encoding="utf-8") as f:
            f.write(json.dumps(bad) + "\n")
        preds = score.load_jsonl(out)
        rows = score.score(self.cases[:1], preds)
        self.assertFalse(rows[0]["schema_valid"])  # последняя строка побеждает — как и ожидает score.py

    def test_resume_does_not_resend_after_recorded_ok_and_keeps_run_id(self):
        out = self.outpath()
        self.assertEqual(self.go("--limit", "2", "--out", out), 0)
        rid = self.meta(out)["run_id"]
        self.mock.requests.clear()
        self.assertEqual(self.go("--limit", "2", "--resume", out), 0)
        self.assertEqual(self.mock.requests, [])
        self.assertEqual(self.meta(out)["run_id"], rid)

    def test_resume_of_missing_file_refused(self):
        self.assertEqual(self.go("--limit", "1", "--resume", self.outpath("nope.jsonl")), 2)


if __name__ == "__main__":
    unittest.main()
