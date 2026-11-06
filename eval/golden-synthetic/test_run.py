#!/usr/bin/env python3
"""Тесты раннера. Запуск: python3 -B -m unittest -v test_run

Сеть не используется: запросы идут на mock-сервер 127.0.0.1 или в поддельный транспорт; любой другой
хост в тестах вызывает ошибку.
"""
import hashlib
import io
import json
import os
import random
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
# Активный промпт берётся из manifest (сейчас prompt/system-v2.md), а не из жёстко прописанного пути.
_MANIFEST = json.load(open(os.path.join(HERE, "data", "manifest.json"), encoding="utf-8"))
PROMPT_REL = _MANIFEST["prompt"]["file"]
# Активные файлы наборов и схемы тоже берутся из manifest (сейчас формат v2).
DEV_REL = _MANIFEST["sets"]["dev"]["file"]
PROBE_REL = _MANIFEST["sets"]["probe"]["file"]
SCHEMA_REL = _MANIFEST["answer_schema"]["file"]
sys.path.insert(0, HERE)
import run  # noqa: E402
import score  # noqa: E402
import selftest  # noqa: E402

KEY = "sk-or-v1-TESTSECRETdeadbeef0123456789"
PROVIDER = "Open Inference"
PROFILE = "open-inference-fp4"


def oracle_answer(case):
    acc = case["expected"]["acceptable"][0]
    return selftest.answer(case["expected"]["incident_class"], case["expected"]["root_cause"], acc["type"],
                           selftest.satisfy(acc, selftest.fmt_of(case)))


def chat(answer=None, *, content=None, provider=PROVIDER, finish="stop", usage=None, model="z-ai/glm-5.3-flash-20260826",
         refusal=None, with_provider=True):
    if content is None:
        content = json.dumps(answer)
    d = {"id": "gen-test", "model": model,
         "choices": [{"finish_reason": finish, "message": {"role": "assistant", "content": content, "refusal": refusal}}],
         "usage": usage if usage is not None else {"prompt_tokens": 4000, "completion_tokens": 100, "total_tokens": 4100}}
    if with_provider:
        d["provider"] = provider
    return d


class MockOpenRouter:
    """Сервер с очередью сценариев. Сценарий: fn(req) -> (status, headers, body, delay) | None (= ответ по умолчанию)."""

    def __init__(self, cases):
        self.by_user = {run.canonical_input(c["input"]): c for c in cases}
        self.requests, self.scenarios = [], []
        self.lock = threading.Lock()
        self.active = self.max_active = 0
        self.default_delay = 0
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                req = {"path": self.path, "headers": {k: v for k, v in self.headers.items()}, "raw": raw,
                       "body": json.loads(raw)}
                with outer.lock:
                    outer.requests.append(req)
                    outer.active += 1
                    outer.max_active = max(outer.max_active, outer.active)
                    fn = outer.scenarios.pop(0) if outer.scenarios else None
                try:
                    res = fn(req) if fn else None
                    if res == "drop":
                        self.connection.close()
                        return
                    status, headers, body, delay = res or outer.default(req)
                    import time
                    time.sleep(delay or outer.default_delay)
                    data = body if isinstance(body, bytes) else json.dumps(body).encode()
                    self.send_response(status)
                    for k, v in headers.items():
                        self.send_header(k, v)
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                except (BrokenPipeError, ConnectionError):
                    pass
                finally:
                    with outer.lock:
                        outer.active -= 1

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def default(self, req):
        case = self.case_of(req)
        return 200, {}, chat(oracle_answer(case)), 0

    def case_of(self, req):
        return self.by_user[req["body"]["messages"][1]["content"]]

    def url(self):
        return f"http://127.0.0.1:{self.port}/api/v1/chat/completions"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class FakeSleep:
    def __init__(self):
        self.delays = []

    def __call__(self, d):
        self.delays.append(d)


class RunnerTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = os.path.join(self.tmp.name, "base")
        for d in ("data", "prompt", "schema"):
            shutil.copytree(os.path.join(HERE, d), os.path.join(self.dir, d))
        self.cases = score.load_jsonl(os.path.join(self.dir, DEV_REL))
        self.mock = MockOpenRouter(self.cases)
        self.addCleanup(self.mock.close)
        self.cfg = run.load_config(os.path.join(HERE, "profiles.json"))
        self.cfg["api_url"] = self.mock.url()
        self.cfg["retry"].update(base_delay_s=0.01, max_delay_s=1.0, timeout_s=5)
        self.write_cfg()
        orig = run.UrllibTransport.post

        def guarded(inst, url, headers, data, timeout):
            host = run.urllib.parse.urlsplit(url).hostname
            if host != "127.0.0.1":
                raise AssertionError(f"test tried to reach {host}")
            return orig(inst, url, headers, data, timeout)
        run.UrllibTransport.post = guarded
        self.addCleanup(setattr, run.UrllibTransport, "post", orig)
        self.sleep = FakeSleep()

    def write_cfg(self):
        with open(os.path.join(self.dir, "profiles.json"), "w") as f:
            json.dump(self.cfg, f)

    def go(self, *argv, key=KEY, transport=None, setname="dev", profile=PROFILE, **kw):
        out, err = io.StringIO(), io.StringIO()
        env = {"OPENROUTER_API_KEY": key} if key else {}
        args = ["--profile", profile, *(["--set", setname] if setname else []), *argv]
        code = run.run(args, env=env, stdout=out, stderr=err, sleep=self.sleep, rng=random.Random(1),
                       base_dir=self.dir, transport=transport, **kw)
        self.out, self.err = out.getvalue(), err.getvalue()
        return code

    def outpath(self, name="o.jsonl"):
        return os.path.join(self.tmp.name, name)

    def rows(self, path):
        return run.read_rows(path)

    def meta(self, path):
        with open(path + ".meta.json") as f:
            return json.load(f)

    def all_text(self):
        parts = [self.out, self.err]
        for root, _, files in os.walk(self.tmp.name):
            for fn in files:
                with open(os.path.join(root, fn), "rb") as f:
                    parts.append(f.read().decode("utf-8", "replace"))
        return "\n".join(parts)


class TestRequest(RunnerTestCase):
    def test_body_contents(self):
        c = self.cases[0]
        prompt_bytes = open(os.path.join(self.dir, PROMPT_REL), "rb").read().decode()
        schema = json.load(open(os.path.join(self.dir, SCHEMA_REL)))
        prof = run.validate_profile(self.cfg, PROFILE, for_network=True)
        body = run.build_request(c["input"], prompt_bytes, schema, self.cfg, prof)
        self.assertEqual(body["messages"][1]["content"], run.canonical_input(c["input"]))
        self.assertEqual(body["messages"][0]["content"], prompt_bytes)
        ser = run.body_bytes(body).decode()
        self.assertNotIn(c["id"], ser)
        user = json.loads(body["messages"][1]["content"])
        self.assertEqual(user, c["input"])
        for k in ("expected", "variant", "slice", "meta", "set", "id"):
            self.assertNotIn(k, body)
            self.assertNotIn(k, user)
        rf = body["response_format"]
        self.assertEqual((rf["type"], rf["json_schema"]["strict"]), ("json_schema", True))
        self.assertEqual(rf["json_schema"]["schema"], {k: v for k, v in schema.items() if k not in ("$schema", "$id")})
        self.assertEqual(body["provider"], prof["provider"])
        self.assertEqual(body["temperature"], 0)
        self.assertIn("seed", body)
        for k in ("tools", "plugins", "web_search_options", "transforms"):
            self.assertNotIn(k, body)
        prof["send_seed"] = False
        self.assertNotIn("seed", run.build_request(c["input"], prompt_bytes, schema, self.cfg, prof))

    def test_mock_received_clean_request(self):
        self.assertEqual(self.go("--limit", "2", "--out", self.outpath()), 0)
        self.assertEqual(len(self.mock.requests), 2)
        for req in self.mock.requests:
            c = self.mock.case_of(req)
            self.assertNotIn(c["id"], req["raw"].decode())
            self.assertEqual(req["body"]["provider"]["zdr"], True)
            self.assertEqual(req["headers"]["Authorization"], f"Bearer {KEY}")
            self.assertNotIn(KEY, req["raw"].decode())
            self.assertEqual(set(req["body"]) - run.ALLOWED_BODY_KEYS, set())
            self.assertEqual(hashlib.sha256(req["raw"]).hexdigest(),
                             [r for r in self.rows(self.outpath()) if r["id"] == c["id"]][0]["request_sha256"])
        for k in ("expected", "variant", "slice"):
            self.assertNotIn(f'"{k}"', self.mock.requests[0]["body"]["messages"][1]["content"])


class TestRefusals(RunnerTestCase):
    def check_refused(self, mutate, **kw):
        mutate(self.cfg)
        self.write_cfg()
        self.assertEqual(self.go("--limit", "1", "--out", self.outpath(), **kw), 2, self.err)
        self.assertEqual(self.mock.requests, [])

    def test_unsafe_profiles(self):
        def prov(fn):
            return lambda cfg: fn(cfg["profiles"][PROFILE]["provider"])

        def delete(k):
            return prov(lambda p: p.pop(k))

        def setk(k, v):
            return prov(lambda p: p.__setitem__(k, v))
        cases = {
            "zdr missing": delete("zdr"), "zdr false": setk("zdr", False), "zdr str": setk("zdr", "true"),
            "dc missing": delete("data_collection"), "dc allow": setk("data_collection", "allow"),
            "fallbacks missing": delete("allow_fallbacks"), "fallbacks true": setk("allow_fallbacks", True),
            "only empty": setk("only", []), "unknown key": setk("sort", "price"),
            "slug online": lambda c: c.__setitem__("model", "z-ai/glm-5.3-flash-20260826:online"),
            "slug undated": lambda c: c.__setitem__("model", "z-ai/glm-5.3-flash"),
            "evil host": lambda c: c.__setitem__("api_url", "https://evil.example/api/v1/chat/completions"),
            "http openrouter": lambda c: c.__setitem__("api_url", "http://openrouter.ai/api/v1/chat/completions"),
            "ceiling": lambda c: c.__setitem__("context_ceiling_tokens", 128000),
        }
        for name, mut in cases.items():
            with self.subTest(name):
                self.cfg = run.load_config(os.path.join(HERE, "profiles.json"))
                self.cfg["api_url"] = self.mock.url()
                self.check_refused(mut)

    def test_body_tampered_after_build(self):
        orig = run.build_request

        def evil(*a, **kw):
            b = orig(*a, **kw)
            b["provider"]["zdr"] = False
            return b
        run.build_request = evil
        self.addCleanup(setattr, run, "build_request", orig)
        self.assertEqual(self.go("--limit", "2", "--out", self.outpath()), 2)
        self.assertEqual(self.mock.requests, [])
        with self.assertRaises(run.SafetyError):
            run.assert_request_safe(evil(self.cases[0]["input"], "p", {}, self.cfg,
                                         run.validate_profile(self.cfg, PROFILE, for_network=True)), self.cfg,
                                    run.validate_profile(self.cfg, PROFILE, for_network=True))

    def test_incomplete_profile(self):
        # Незаполненная заготовка профиля (как fp8-compare до выбора провайдера): в боевом режиме отказ, dry-run проходит.
        self.cfg["profiles"]["placeholder"] = {
            "endpoint_label": None, "expected_provider_names": [], "send_seed": True, "price_usd_per_mtok": None,
            "provider": {"only": [], "quantizations": ["fp8"], "allow_fallbacks": False,
                         "zdr": True, "data_collection": "deny", "require_parameters": True}}
        self.write_cfg()
        self.assertEqual(self.go("--limit", "1", "--out", self.outpath(), profile="placeholder"), 2)
        self.assertIn("incomplete", self.err)
        self.assertEqual(self.mock.requests, [])
        self.assertEqual(self.go("--limit", "1", "--dry-run", profile="placeholder"), 0, self.err)

    def test_fp8_compare_profile_pinned(self):
        # inceptron-fp8 — основной endpoint с 06.11.2026: Inceptron fp8, с ZDR и без fallback'а.
        prof = run.validate_profile(self.cfg, "inceptron-fp8", for_network=True)
        self.assertEqual(prof["endpoint_label"], "inceptron/fp8")
        self.assertEqual(prof["provider"]["only"], ["inceptron"])
        self.assertEqual(prof["provider"]["quantizations"], ["fp8"])
        self.assertIs(prof["provider"]["zdr"], True)
        self.assertEqual(prof["provider"]["data_collection"], "deny")
        self.assertIs(prof["provider"]["allow_fallbacks"], False)
        self.assertTrue(run.provider_matches("Inceptron", prof))

    def test_no_key(self):
        self.assertEqual(self.go("--limit", "1", "--out", self.outpath(), key=None), 2)
        self.assertIn("OPENROUTER_API_KEY is not set", self.err)

    def test_bad_flag_combinations(self):
        self.assertEqual(self.go("--limit", "1", "--allow-hash-mismatch", setname="probe"), 2)
        self.assertEqual(self.go("--reference", "--limit", "1", setname="probe"), 2)
        self.assertEqual(self.go("--reference", "--allow-hash-mismatch", setname="dev"), 2)
        self.assertEqual(self.mock.requests, [])


class TestProvider(RunnerTestCase):
    def test_mismatch_stops_run(self):
        self.mock.default = lambda req: (200, {}, chat(oracle_answer(self.mock.case_of(req)), provider="Novita"), 0)
        out = self.outpath()
        self.assertEqual(self.go("--limit", "4", "--concurrency", "1", "--out", out), 3)
        self.assertEqual(len(self.mock.requests), 1)
        r = self.rows(out)[0]
        self.assertEqual((r["status"], r["final"], r["answer"]), ("provider_mismatch", False, None))
        self.assertEqual(self.meta(out)["abort_reason"], "provider_mismatch")

    def test_missing_provider_field(self):
        self.mock.default = lambda req: (200, {}, chat(oracle_answer(self.mock.case_of(req)), with_provider=False), 0)
        out = self.outpath()
        self.assertEqual(self.go("--limit", "3", "--concurrency", "1", "--out", out), 3)
        self.assertEqual(self.rows(out)[0]["status"], "provider_mismatch")
        self.assertEqual(len(self.mock.requests), 1)

    def test_normalized_match(self):
        prof = run.validate_profile(self.cfg, PROFILE, for_network=True)
        for ok in ("Open Inference", "open-inference", "OpenInference"):
            self.assertTrue(run.provider_matches(ok, prof))
        for bad in (None, "", "Novita"):
            self.assertFalse(run.provider_matches(bad, prof))


class TestRetries(RunnerTestCase):
    def test_429_503_200(self):
        self.mock.scenarios = [lambda r: (429, {"Retry-After": "0.5"}, {"error": {}}, 0),
                               lambda r: (503, {}, b"down", 0)]
        out = self.outpath()
        self.assertEqual(self.go("--limit", "1", "--out", out), 0)
        r = self.rows(out)[0]
        self.assertEqual((r["attempts"], r["status"]), (3, "ok"))
        d = self.sleep.delays
        self.assertEqual(len(d), 2)
        self.assertGreaterEqual(d[0], 0.5)
        self.assertLessEqual(max(d), self.cfg["retry"]["max_delay_s"])

    def test_backoff_growth_and_cap(self):
        class T:
            n = 0

            def post(self, *a):
                T.n += 1
                return run.Response(503, {}, b"x")
        self.cfg["retry"].update(max_attempts=6, base_delay_s=1.0, max_delay_s=5.0)
        sl = FakeSleep()
        cr = run.call_with_retries(T(), "u", {}, b"", self.cfg["retry"], run.Budget(10, 10 ** 9), (1, 0.0, (0, 0)),
                                   sl, random.Random(3), lambda: 0.0)
        self.assertEqual((cr.kind, cr.attempts), ("exhausted", 6))
        for i, d in enumerate(sl.delays, 1):
            top = min(5.0, 2 ** (i - 1))
            self.assertTrue(top * 0.5 <= d <= top, (i, d))

    def test_timeout_then_ok(self):
        self.cfg["retry"]["timeout_s"] = 0.2
        self.write_cfg()
        self.mock.scenarios = [lambda r: (200, {}, chat(oracle_answer(self.mock.case_of(r))), 0.6)]
        out = self.outpath()
        self.assertEqual(self.go("--limit", "1", "--out", out), 0)
        self.assertEqual(self.rows(out)[0]["attempts"], 2)

    def test_200_with_error_body(self):
        self.mock.scenarios = [lambda r: (200, {}, {"error": {"code": 502, "message": "upstream"}}, 0)]
        out = self.outpath()
        self.assertEqual(self.go("--limit", "1", "--out", out), 0)
        self.assertEqual(self.rows(out)[0]["attempts"], 2)

    def test_400_not_retried(self):
        self.mock.default = lambda r: (400, {}, {"error": {"message": "bad"}}, 0)
        out = self.outpath()
        self.assertEqual(self.go("--limit", "1", "--out", out), 4)
        r = self.rows(out)[0]
        self.assertEqual((r["attempts"], r["final"], r["status"]), (1, False, "http_error"))
        self.assertEqual(len(self.mock.requests), 1)

    def test_abort_statuses(self):
        for st, reason in ((401, "auth/credits/forbidden"), (402, "auth/credits/forbidden"), (404, "no_endpoint")):
            with self.subTest(st):
                self.mock.requests.clear()
                self.mock.default = lambda r, st=st: (st, {}, {"error": {"message": "x"}}, 0)
                out = self.outpath(f"a{st}.jsonl")
                self.assertEqual(self.go("--limit", "3", "--concurrency", "1", "--out", out), 3)
                self.assertEqual(self.meta(out)["abort_reason"], reason)
                self.assertEqual(len(self.mock.requests), 1)

    def test_exhaustion(self):
        self.cfg["retry"]["max_attempts"] = 2
        self.write_cfg()
        self.mock.default = lambda r: (500, {}, b"boom", 0)
        out = self.outpath()
        self.assertEqual(self.go("--limit", "2", "--out", out), 4)
        rows = self.rows(out)
        self.assertTrue(all(r["final"] is False and r["attempts"] == 2 for r in rows))
        self.assertEqual(self.meta(out)["status"], "completed_with_errors")


class TestResume(RunnerTestCase):
    def test_resume_only_nonfinal(self):
        self.cfg["retry"]["max_attempts"] = 1
        self.write_cfg()
        first = {}

        def fail_last(req):
            c = self.mock.case_of(req)
            if c["id"] in first.get("bad", ()):
                return 500, {}, b"x", 0
            return 200, {}, chat(oracle_answer(c)), 0
        first["bad"] = {c["id"] for c in self.cases[3:6]}
        self.mock.default = fail_last
        out = self.outpath()
        self.assertEqual(self.go("--limit", "6", "--concurrency", "1", "--out", out), 4)
        self.mock.requests.clear()
        first["bad"] = set()
        self.assertEqual(self.go("--limit", "6", "--resume", out), 0, self.err)
        sent = {self.mock.case_of(r)["id"] for r in self.mock.requests}
        self.assertEqual(sent, {c["id"] for c in self.cases[3:6]})
        preds = score.load_jsonl(out)
        rows = score.score(self.cases[:6], preds)
        self.assertTrue(all(r["schema_valid"] and r["admissible"] for r in rows))
        self.assertEqual(self.meta(out)["status"], "completed")

    def test_truncated_line_trimmed(self):
        out = self.outpath()
        self.assertEqual(self.go("--limit", "3", "--out", out), 0)
        with open(out, "ab") as f:
            f.write(b'{"id": "partial", "ans')
        run.ResultWriter(out).close()
        with open(out, "rb") as f:
            self.assertTrue(f.read().endswith(b"\n"))
        self.assertEqual(len(self.rows(out)), 3)

    def test_mismatches_rejected(self):
        out = self.outpath()
        self.assertEqual(self.go("--limit", "2", "--out", out), 0)
        self.assertEqual(self.go("--limit", "2", "--resume", out, profile="wafer-nvfp4"), 2)
        self.cfg["generation"]["max_tokens"] = 2048
        self.write_cfg()
        self.assertEqual(self.go("--limit", "2", "--resume", out), 2)
        self.assertIn("generation", self.err)
        self.assertEqual(self.go("--limit", "2", "--out", out), 2)  # существующий файл без --resume

    def test_final_failures_not_resent(self):
        seq = [chat(content="not json"), chat({"incident_class": "other"}), chat(content="{", finish="length")]
        it = iter(seq)
        self.mock.default = lambda r: (200, {}, next(it), 0)
        out = self.outpath()
        self.assertEqual(self.go("--limit", "3", "--concurrency", "1", "--out", out), 0)
        self.assertEqual(sorted(r["status"] for r in self.rows(out)), ["invalid_json", "schema_invalid", "truncated"])
        n = len(self.mock.requests)
        self.assertEqual(self.go("--limit", "3", "--resume", out), 0)
        self.assertEqual(len(self.mock.requests), n)


class TestBudget(RunnerTestCase):
    def reserve_of(self, case):
        prof = run.validate_profile(self.cfg, PROFILE, for_network=True)
        sch = json.load(open(os.path.join(self.dir, SCHEMA_REL)))
        prompt = open(os.path.join(self.dir, PROMPT_REL), encoding="utf-8").read()
        body = run.build_request(case["input"], prompt, sch, self.cfg, prof)
        est, mt = run.estimate_input_tokens(body, self.cfg), body["max_tokens"]
        return est, mt, run.cost_of(est, mt, run.unit_prices(prof))

    def exact_usage_mock(self):
        def default(req):
            c = self.mock.case_of(req)
            est, mt, _ = self.reserve_of(c)
            u = {"prompt_tokens": est, "completion_tokens": mt, "total_tokens": est + mt}
            return 200, {}, chat(oracle_answer(c), usage=u), 0
        self.mock.default = default

    def test_usd_limit(self):
        self.exact_usage_mock()
        cap = self.reserve_of(self.cases[0])[2] + self.reserve_of(self.cases[1])[2] + 1e-7
        out = self.outpath()
        self.assertEqual(self.go("--limit", "5", "--concurrency", "1", "--max-usd", repr(cap), "--out", out), 3)
        self.assertEqual(len(self.mock.requests), 2)
        self.assertEqual(self.meta(out)["abort_reason"], "budget")
        self.assertEqual(self.rows(out)[-1]["status"], "budget_skipped")

    def test_token_limit(self):
        self.exact_usage_mock()
        cap = sum(sum(self.reserve_of(c)[:2]) for c in self.cases[:2]) + 1
        self.assertEqual(self.go("--limit", "5", "--concurrency", "1", "--max-tokens-total", str(cap),
                                 "--out", self.outpath()), 3)
        self.assertEqual(len(self.mock.requests), 2)

    def test_cost_reported_wins_and_timeout_charges_reserve(self):
        prices = (0.03, 0.22)
        data = chat({}, usage={"prompt_tokens": 10, "completion_tokens": 10, "cost": 5.0})
        body = json.dumps(data).encode()

        class T:
            def post(self, *a):
                return run.Response(200, {}, body)
        b = run.Budget(100, 10 ** 9)
        cr = run.call_with_retries(T(), "u", {}, b"", self.cfg["retry"], b, (100, 1.0, prices), FakeSleep(),
                                   random.Random(), lambda: 0.0)
        self.assertEqual(cr.cost_usd, 5.0)

        class TO:
            def post(self, *a):
                raise run.TransportError("timeout")
        self.cfg["retry"]["max_attempts"] = 2
        b = run.Budget(100, 10 ** 9)
        cr = run.call_with_retries(TO(), "u", {}, b"", self.cfg["retry"], b, (100, 1.0, prices), FakeSleep(),
                                   random.Random(), lambda: 0.0)
        self.assertAlmostEqual(cr.cost_usd, 2.0)
        self.assertAlmostEqual(b.spent_usd, 2.0)

    def test_resume_counts_prior_spend_and_cli_cannot_raise(self):
        self.exact_usage_mock()
        e0 = self.reserve_of(self.cases[0])
        self.cfg["budget"]["max_usd_per_run"] = e0[2] * 1.5
        self.write_cfg()
        out = self.outpath()
        self.assertEqual(self.go("--limit", "3", "--concurrency", "1", "--max-usd", "1000", "--out", out), 3)
        self.assertEqual(len(self.mock.requests), 1)
        self.assertEqual(self.go("--limit", "3", "--concurrency", "1", "--resume", out), 3)
        self.assertEqual(len(self.mock.requests), 1)  # прошлый расход учтён, новых запросов нет

    def test_budget_class(self):
        b = run.Budget(1.0, 100)
        r1 = b.reserve(60, 0.5)
        self.assertIsNone(b.reserve(60, 0.1))
        b.settle(r1, 10, 0.1)
        self.assertIsNotNone(b.reserve(60, 0.5))


class TestContext(RunnerTestCase):
    def make_big_set(self):
        big = json.loads(json.dumps(self.cases[0]))
        big["id"] = "GS-dev-big"
        big["input"] = {"blob": "x" * 200000}
        path = os.path.join(self.dir, DEV_REL)
        with open(path, "ab") as f:
            f.write((json.dumps(big) + "\n").encode())
        self.cases.append(big)
        self.mock.by_user[run.canonical_input(big["input"])] = big

    def test_ceiling_row(self):
        self.make_big_set()
        out = self.outpath()
        code = self.go("--allow-hash-mismatch", "--ids", f"{self.cases[0]['id']},GS-dev-big", "--out", out)
        self.assertEqual(code, 0, self.err)
        rows = {r["id"]: r for r in self.rows(out)}
        self.assertEqual((rows["GS-dev-big"]["status"], rows["GS-dev-big"]["final"]), ("context_ceiling", True))
        self.assertEqual(len(self.mock.requests), 1)
        self.assertTrue(self.meta(out)["integrity_bypassed"])

    def test_boundary(self):
        c = self.cases[0]
        prof = run.validate_profile(self.cfg, PROFILE, for_network=True)
        sch = json.load(open(os.path.join(self.dir, SCHEMA_REL)))
        prompt = open(os.path.join(self.dir, PROMPT_REL), encoding="utf-8").read()
        est = run.estimate_input_tokens(run.build_request(c["input"], prompt, sch, self.cfg, prof), self.cfg)
        mt = self.cfg["generation"]["max_tokens"]
        for ceiling, expect_sent in ((est + mt, 1), (est + mt - 1, 0)):
            with self.subTest(ceiling=ceiling):
                self.mock.requests.clear()
                self.cfg["context_ceiling_tokens"] = ceiling
                self.write_cfg()
                self.go("--limit", "1", "--ids", c["id"], "--out", self.outpath(f"b{ceiling}.jsonl"))
                self.assertEqual(len(self.mock.requests), expect_sent)

    def test_actual_over_ceiling(self):
        self.mock.default = lambda r: (200, {}, chat(oracle_answer(self.mock.case_of(r)),
                                                      usage={"prompt_tokens": 70000, "completion_tokens": 10}), 0)
        out = self.outpath()
        self.assertEqual(self.go("--limit", "3", "--concurrency", "1", "--out", out), 3)
        self.assertEqual(self.rows(out)[0]["status"], "context_ceiling_actual")
        self.assertEqual(len(self.mock.requests), 1)


class TestManifest(RunnerTestCase):
    def flip(self, rel):
        p = os.path.join(self.dir, rel)
        b = bytearray(open(p, "rb").read())
        b[len(b) // 2] ^= 1
        open(p, "wb").write(bytes(b))

    def test_tampered_files(self):
        for rel in (DEV_REL, PROMPT_REL, SCHEMA_REL):
            with self.subTest(rel):
                shutil.rmtree(self.dir)
                for d in ("data", "prompt", "schema"):
                    shutil.copytree(os.path.join(HERE, d), os.path.join(self.dir, d))
                self.write_cfg()
                self.flip(rel)
                self.assertEqual(self.go("--limit", "1", "--out", self.outpath()), 2)
                self.assertEqual(self.go("--limit", "1", "--dry-run"), 2)
                self.assertEqual(self.mock.requests, [])

    def test_bypass_only_dev(self):
        self.flip(PROMPT_REL)
        self.assertEqual(self.go("--limit", "1", "--allow-hash-mismatch", "--out", self.outpath()), 0, self.err)
        self.assertTrue(self.meta(self.outpath())["integrity_bypassed"])
        self.assertIn("WARNING", self.err)
        self.assertEqual(self.go("--limit", "1", "--allow-hash-mismatch", setname="probe"), 2)

    def test_wrong_case_count(self):
        p = os.path.join(self.dir, DEV_REL)
        lines = open(p).read().splitlines()
        # хеш при этом тоже не совпадёт; важно, что прогон отклонён
        open(p, "w").write("\n".join(lines[:-1]) + "\n")
        self.assertEqual(self.go("--limit", "1", "--out", self.outpath()), 2)


class TestSecrets(RunnerTestCase):
    def test_key_does_not_leak(self):
        echo = lambda r: (400, {}, json.dumps({"error": {"message": "bad", "echo": r["headers"]["Authorization"]}}).encode(), 0)
        self.mock.scenarios = [echo, lambda r: (500, {}, ("oops " + r["headers"]["Authorization"]).encode(), 0), lambda r: "drop"]
        self.cfg["retry"]["max_attempts"] = 2
        self.write_cfg()
        self.go("--limit", "3", "--concurrency", "1", "--out", self.outpath())
        self.go("--limit", "1", "--dry-run")
        self.go("--limit", "1", "--out", self.outpath("x.jsonl"), key=None)
        text = self.all_text()
        self.assertNotIn(KEY, text)
        self.assertNotIn("TESTSECRET", text)

    def test_dry_run_masks(self):
        self.assertEqual(self.go("--limit", "1", "--dry-run"), 0)
        self.assertIn("Bearer ***", self.out)

    def test_redact(self):
        self.assertEqual(run.redact("a Bearer abc.def b sk-or-v1-xyz", ["zz"]), "a Bearer *** b ***")


class TestScoreCompat(RunnerTestCase):
    def test_oracle_scores_100(self):
        out = self.outpath()
        self.assertEqual(self.go("--limit", "8", "--out", out), 0)
        sub = self.cases[:8]
        agg = score.aggregate(score.score(sub, score.load_jsonl(out), score.load_jsonl(out)))["all:all"]
        for m in ("schema_valid", "admissible", "root_cause_match", "class_match", "agreement"):
            self.assertEqual(agg[m]["p"], 1.0, m)
        cases_path = self.outpath("cases.jsonl")
        with open(cases_path, "w") as f:
            f.write("\n".join(json.dumps(c) for c in sub) + "\n")
        p = subprocess.run([sys.executable, "-B", os.path.join(HERE, "score.py"), "--cases", cases_path, "--pred", out,
                            "--ref", out], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("100.0%", p.stdout)

    def test_bad_answers(self):
        a = oracle_answer(self.cases[0])
        no_summary = {k: v for k, v in a.items() if k != "summary"}
        it = iter([chat(no_summary), chat(content="not json")])
        self.mock.default = lambda r: (200, {}, next(it), 0)
        out = self.outpath()
        self.assertEqual(self.go("--limit", "2", "--concurrency", "1", "--out", out), 0)
        rows = score.score(self.cases[:2], score.load_jsonl(out))
        self.assertFalse(rows[0]["schema_valid"])
        self.assertFalse(rows[1]["schema_valid"])
        r = self.rows(out)
        self.assertEqual((r[0]["status"], r[1]["status"], r[1]["answer"]), ("schema_invalid", "invalid_json", None))

    def test_refusal_and_filter(self):
        it = iter([chat(content="", refusal="no"), chat(content="x", finish="content_filter")])
        self.mock.default = lambda r: (200, {}, next(it), 0)
        out = self.outpath()
        self.go("--limit", "2", "--concurrency", "1", "--out", out)
        self.assertEqual([r["status"] for r in self.rows(out)], ["refusal", "content_filter"])


class TestDryRun(RunnerTestCase):
    def test_no_transport_no_files(self):
        class Boom:
            def post(self, *a):
                raise AssertionError("transport used")
        before = set(os.listdir(self.dir))
        self.assertEqual(self.go("--limit", "3", "--dry-run", key=None, transport=Boom()), 0, self.err)
        self.assertEqual(set(os.listdir(self.dir)), before)
        self.assertIn('"zdr": true', self.out)
        self.assertIn("est input tokens", self.out)
        self.assertIn("cost USD", self.out)
        self.assertEqual(self.mock.requests, [])


class TestReference(RunnerTestCase):
    def shrink_probe(self, n=4):
        src = score.load_jsonl(os.path.join(HERE, PROBE_REL))[:n]
        raw = ("\n".join(run.canon_json(c) for c in src) + "\n").encode()
        with open(os.path.join(self.dir, PROBE_REL), "wb") as f:
            f.write(raw)
        mp = os.path.join(self.dir, "data", "manifest.json")
        m = json.load(open(mp))
        m["sets"]["probe"].update(cases=n, sha256=hashlib.sha256(raw).hexdigest())
        json.dump(m, open(mp, "w"))
        self.mock.by_user.update({run.canonical_input(c["input"]): c for c in src})
        return src

    def test_reference_frozen(self):
        self.shrink_probe()
        self.assertEqual(self.go("--reference", setname="probe"), 0, self.err)
        refs = []
        for root, _, files in os.walk(os.path.join(self.dir, "refs")):
            refs += [os.path.join(root, f) for f in files if f.endswith(".jsonl")]
        self.assertEqual(len(refs), 1)
        ref = refs[0]
        rows = self.rows(ref)
        self.assertEqual(len(rows), len({r["id"] for r in rows}))
        self.assertEqual(len(rows), 4)
        m = self.meta(ref)
        for k in ("kind", "profile", "hashes", "frozen_at"):
            self.assertIn(k, m)
        self.assertEqual(m["kind"], "reference")
        self.assertEqual(stat.S_IMODE(os.stat(ref).st_mode), 0o444)
        self.assertEqual(self.go("--reference", "--out", ref, setname="probe"), 2)

    def test_reference_not_frozen_on_errors(self):
        self.shrink_probe()
        self.cfg["retry"]["max_attempts"] = 1
        self.write_cfg()
        self.mock.default = lambda r: (500, {}, b"x", 0)
        self.assertEqual(self.go("--reference", "--concurrency", "1", setname="probe"), 4)
        for root, _, files in os.walk(os.path.join(self.dir, "refs")):
            for f in files:
                if f.endswith(".jsonl"):
                    self.assertTrue(os.stat(os.path.join(root, f)).st_mode & stat.S_IWUSR)
                else:
                    self.assertEqual(self.meta(os.path.join(root, f[:-10]))["kind"], "reference")


class TestConcurrency(RunnerTestCase):
    def test_max_parallel(self):
        self.mock.default_delay = 0.05
        self.assertEqual(self.go("--limit", "9", "--concurrency", "3", "--out", self.outpath()), 0)
        self.assertLessEqual(self.mock.max_active, 3)
        self.assertGreaterEqual(self.mock.max_active, 2)
        self.assertEqual(self.go("--limit", "9", "--concurrency", "99", "--out", self.outpath("z.jsonl")), 2)


class TestPreflight(RunnerTestCase):
    class T:
        def __init__(self, eps):
            self.eps = eps

        def get(self, url, headers, timeout):
            return run.Response(200, {}, json.dumps({"data": {"endpoints": self.eps}}).encode())

    def ep(self, quant="fp4", name="Open Inference"):
        return {"provider_name": name, "tag": "open-inference/fp4", "quantization": quant,
                "supported_parameters": ["response_format", "structured_outputs", "seed"],
                "pricing": {"prompt": "0.00000003", "completion": "0.00000022"}}

    def test_ok_and_mismatch(self):
        self.assertEqual(self.go("--preflight", setname=None, transport=self.T([self.ep(), self.ep("fp8", "Other")])), 0, self.err)
        self.assertIn("preflight OK", self.out)
        self.assertEqual(self.go("--preflight", setname=None, transport=self.T([self.ep("fp8")])), 2)


if __name__ == "__main__":
    unittest.main()
