#!/usr/bin/env python3
"""Раннер golden-набора: прогоняет кейсы через OpenRouter и пишет ответы в формате score.py.

Примеры:
  python3 run.py --profile open-inference-fp4 --set probe --dry-run
  OPENROUTER_API_KEY=... python3 run.py --profile open-inference-fp4 --set probe
  OPENROUTER_API_KEY=... python3 run.py --profile open-inference-fp4 --set probe --resume runs/.../probe-<run_id>.jsonl
  OPENROUTER_API_KEY=... python3 run.py --profile open-inference-fp4 --set probe --reference

Модели уходит только `input` кейса. Каждый запрос несёт флаги ZDR / data_collection=deny / без fallback'ов;
без них (и при чужом хосте API) раннер ничего не отправляет. Ключ берётся из OPENROUTER_API_KEY
(или файла OPENROUTER_API_KEY_FILE), через argv не принимается.

Коды выхода: 0 — все кейсы получили окончательный ответ; 2 — отказ (конфиг, целостность, безопасность);
3 — прогон прерван (бюджет, провайдер не совпал, 401/402/403/404); 4 — есть неокончательные ошибки, нужен --resume.
"""
import argparse
import collections
import concurrent.futures
import copy
import datetime
import hashlib
import http.client
import json
import math
import os
import random
import re
import socket
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)
import score  # noqa: E402

API_URL = "https://openrouter.ai/api/v1/chat/completions"
LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}
ALLOWED_PROVIDER_KEYS = {"only", "quantizations", "allow_fallbacks", "zdr", "data_collection", "require_parameters"}
ALLOWED_BODY_KEYS = {"model", "messages", "response_format", "provider", "temperature", "seed", "max_tokens", "usage"}
SLUG_RE = re.compile(r"^[a-z0-9-]+/[a-z0-9.-]+-\d{8}$")
RETRY_STATUS = {408, 429, 500, 502, 503, 504, 520, 521, 522, 523, 524}
ABORT_STATUS = {401, 402, 403}
MAX_CONCURRENCY = 16
RAW_LIMIT = 2000
META_EVERY = 25
OVERHEAD_TOKENS = 64

Response = collections.namedtuple("Response", "status headers body")
CallResult = collections.namedtuple("CallResult", "data attempts last_error latency_ms latency_total_ms cost_usd tokens kind")


class ConfigError(Exception):
    pass


class IntegrityError(Exception):
    pass


class SafetyError(Exception):
    pass


class AbortRun(Exception):
    def __init__(self, reason, message=None):
        super().__init__(message or reason)
        self.reason = reason


class TransportError(Exception):
    def __init__(self, kind, message=""):
        super().__init__(message or kind)
        self.kind = kind  # "timeout" | "network"


# ---------------------------------------------------------------- утилиты

def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def canon_json(obj):
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def redact(text, secrets=()):
    text = str(text)
    for s in secrets:
        if s:
            text = text.replace(s, "***")
    text = re.sub(r"Bearer\s+\S+", "Bearer ***", text)
    return re.sub(r"sk-or-[A-Za-z0-9_-]+", "***", text)


def hget(headers, name):
    if headers is None:
        return None
    items = headers.items() if hasattr(headers, "items") else []
    for k, v in items:
        if k.lower() == name.lower():
            return v
    return None


class Console:
    def __init__(self, stdout, stderr, secrets):
        self.stdout, self.stderr, self.secrets = stdout, stderr, secrets

    def say(self, text=""):
        print(redact(text, self.secrets), file=self.stdout)

    def warn(self, text):
        print(redact(text, self.secrets), file=self.stderr)


# ---------------------------------------------------------------- конфиг и профиль

def read_config(path):
    try:
        with open(path, "rb") as f:
            raw = f.read()
        return json.loads(raw.decode("utf-8")), sha256_bytes(raw)
    except (OSError, ValueError) as e:
        raise ConfigError(f"cannot read config {path}: {e}")


def load_config(path):
    return read_config(path)[0]


def _host_local(url):
    p = urllib.parse.urlsplit(url)
    return p.scheme == "http" and p.hostname in LOCAL_HOSTS


def check_api_url(url):
    if url == API_URL or (isinstance(url, str) and _host_local(url)):
        return
    raise ConfigError(f"api_url is not allowed: {url!r} (only {API_URL} or a loopback http URL)")


def _num(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def validate_profile(cfg, name, *, for_network):
    profiles = cfg.get("profiles") or {}
    if name not in profiles:
        raise ConfigError(f"unknown profile {name!r}; known: {sorted(profiles)}")
    prof = profiles[name]
    if not isinstance(cfg.get("model"), str) or not SLUG_RE.match(cfg["model"]):
        raise ConfigError("model must be a dated slug without suffixes (e.g. vendor/name-20260826)")
    check_api_url(cfg.get("api_url"))
    ceil = cfg.get("context_ceiling_tokens")
    if not isinstance(ceil, int) or isinstance(ceil, bool) or not 0 < ceil <= 64000:
        raise ConfigError("context_ceiling_tokens must be an integer <= 64000")
    gen = cfg.get("generation") or {}
    mt = gen.get("max_tokens")
    if not isinstance(mt, int) or isinstance(mt, bool) or not 256 <= mt <= 16000:
        raise ConfigError("generation.max_tokens must be an integer in [256, 16000]")
    if not _num(gen.get("temperature")) or gen["temperature"] != 0:
        raise ConfigError("generation.temperature must be 0")
    if prof.get("send_seed") and (not isinstance(gen.get("seed"), int) or isinstance(gen.get("seed"), bool)):
        raise ConfigError("generation.seed must be an integer when send_seed is true")
    if not _num(cfg.get("chars_per_token_estimate")) or cfg["chars_per_token_estimate"] <= 0:
        raise ConfigError("chars_per_token_estimate must be > 0")
    r = cfg.get("retry") or {}
    if not (isinstance(r.get("max_attempts"), int) and r["max_attempts"] >= 1
            and all(_num(r.get(k)) and r[k] > 0 for k in ("base_delay_s", "max_delay_s", "timeout_s"))):
        raise ConfigError("retry: max_attempts >= 1 and positive base_delay_s, max_delay_s, timeout_s required")
    b = cfg.get("budget") or {}
    if not (_num(b.get("max_usd_per_run")) and b["max_usd_per_run"] > 0
            and _num(b.get("max_tokens_per_run")) and b["max_tokens_per_run"] > 0):
        raise ConfigError("budget.max_usd_per_run and budget.max_tokens_per_run must be positive")
    conc = cfg.get("concurrency")
    if not isinstance(conc, int) or isinstance(conc, bool) or not 1 <= conc <= MAX_CONCURRENCY:
        raise ConfigError(f"concurrency must be an integer in [1, {MAX_CONCURRENCY}]")

    prov = prof.get("provider")
    if not isinstance(prov, dict):
        raise ConfigError(f"profile {name}: provider is missing")
    extra = set(prov) - ALLOWED_PROVIDER_KEYS
    if extra:
        raise ConfigError(f"profile {name}: unknown provider keys {sorted(extra)}")
    if prov.get("zdr") is not True:
        raise ConfigError(f"profile {name}: provider.zdr must be true")
    if prov.get("data_collection") != "deny":
        raise ConfigError(f"profile {name}: provider.data_collection must be 'deny'")
    if prov.get("allow_fallbacks") is not False:
        raise ConfigError(f"profile {name}: provider.allow_fallbacks must be false")
    for k in ("only", "quantizations"):
        v = prov.get(k)
        if not isinstance(v, list) or not all(isinstance(x, str) and x for x in v):
            raise ConfigError(f"profile {name}: provider.{k} must be a list of strings")
    if not prov["quantizations"]:
        raise ConfigError(f"profile {name}: provider.quantizations must not be empty")
    if for_network:
        problems = []
        if not prov["only"]:
            problems.append("provider.only")
        if not isinstance(prof.get("endpoint_label"), str) or not prof["endpoint_label"]:
            problems.append("endpoint_label")
        names = prof.get("expected_provider_names")
        if not isinstance(names, list) or not names or not all(isinstance(x, str) and x for x in names):
            problems.append("expected_provider_names")
        pr = prof.get("price_usd_per_mtok")
        if not isinstance(pr, dict) or not all(_num(pr.get(k)) and pr[k] >= 0 for k in ("input", "output")):
            problems.append("price_usd_per_mtok")
        if problems:
            raise ConfigError(f"profile {name} is incomplete (profile incomplete): fill {', '.join(problems)}")
    out = dict(prof)
    out["name"] = name
    return out


# ---------------------------------------------------------------- целостность

def check_integrity(set_name, allow_mismatch, base=BASE, staged=False):
    """Читает manifest, набор, промпт и схему; сверяет хеши по тем же байтам, что потом используются.
    staged — берёт набор, промпт и схему кандидата из manifest["staged"] вместо активных."""
    def read(rel):
        path = os.path.realpath(os.path.join(base, rel))
        if not path.startswith(os.path.realpath(base) + os.sep):
            raise IntegrityError(f"path escapes the base directory: {rel}")
        try:
            with open(path, "rb") as f:
                return f.read()
        except OSError as e:
            raise IntegrityError(f"cannot read {rel}: {e}")

    mbytes = read("data/manifest.json")
    try:
        manifest = json.loads(mbytes.decode("utf-8"))
        if staged and "staged" not in manifest:
            raise IntegrityError("manifest has no staged candidate (--staged needs manifest.staged)")
        track = manifest["staged"] if staged else manifest
        entry = track["sets"][set_name]
        files = {"set": (entry["file"], entry["sha256"]), "prompt": (track["prompt"]["file"], track["prompt"]["sha256"]),
                 "schema": (track["answer_schema"]["file"], track["answer_schema"]["sha256"])}
        expected_cases = entry["cases"]
    except (ValueError, KeyError, TypeError) as e:
        raise IntegrityError(f"manifest is malformed: {e!r}")
    raw, hashes, problems = {}, {"manifest": sha256_bytes(mbytes)}, []
    for key, (rel, want) in files.items():
        raw[key] = read(rel)
        hashes[key] = sha256_bytes(raw[key])
        if hashes[key] != want:
            problems.append(f"{key} ({rel}): sha256 {hashes[key][:12]} != manifest {want[:12]}")
    try:
        cases = [json.loads(line) for line in raw["set"].decode("utf-8").splitlines() if line.strip()]
        schema = json.loads(raw["schema"].decode("utf-8"))
        prompt = raw["prompt"].decode("utf-8")
    except ValueError as e:
        raise IntegrityError(f"cannot parse data files: {e}")
    if len(cases) != expected_cases:
        problems.append(f"set has {len(cases)} cases, manifest says {expected_cases}")
    bypassed = False
    if problems:
        if not (allow_mismatch and set_name == "dev"):
            raise IntegrityError("manifest check failed: " + "; ".join(problems))
        bypassed = True
    return {"hashes": hashes, "cases": cases, "prompt": prompt, "schema": schema, "set_file": files["set"][0],
            "problems": problems, "bypassed": bypassed}


# ---------------------------------------------------------------- запрос

def canonical_input(inp):
    return canon_json(inp)


def request_schema(schema):
    return {k: copy.deepcopy(v) for k, v in schema.items() if k not in ("$schema", "$id")}


def build_request(case_input, system_prompt, schema, cfg, profile):
    gen = cfg["generation"]
    body = {
        "model": cfg["model"],
        "messages": [{"role": "system", "content": system_prompt},
                     {"role": "user", "content": canonical_input(case_input)}],
        "response_format": {"type": "json_schema",
                            "json_schema": {"name": "aegisops_answer_v1", "strict": True, "schema": request_schema(schema)}},
        "provider": copy.deepcopy(profile["provider"]),
        "temperature": gen["temperature"],
        "max_tokens": gen["max_tokens"],
        "usage": {"include": True},
    }
    if profile.get("send_seed"):
        body["seed"] = gen["seed"]
    return body


def body_bytes(body):
    return canon_json(body).encode("utf-8")


def request_digest(body):
    """sha256 канонического тела запроса: тот же хеш пишется в строку результата и в фикстуру --emit-requests."""
    return sha256_bytes(body_bytes(body))


def assert_request_safe(body, cfg, profile):
    if not isinstance(body, dict) or set(body) - ALLOWED_BODY_KEYS:
        raise SafetyError(f"request has disallowed keys: {sorted(set(body) - ALLOWED_BODY_KEYS) if isinstance(body, dict) else body!r}")
    prov = body.get("provider")
    if not isinstance(prov, dict) or prov.get("zdr") is not True or prov.get("data_collection") != "deny" \
            or prov.get("allow_fallbacks") is not False:
        raise SafetyError("request provider flags are not zdr=true / data_collection=deny / allow_fallbacks=false")
    if prov != profile["provider"]:
        raise SafetyError("request provider differs from the profile")
    if body.get("model") != cfg["model"]:
        raise SafetyError("request model differs from the config")
    rf = body.get("response_format")
    if not isinstance(rf, dict) or rf.get("type") != "json_schema" \
            or not isinstance(rf.get("json_schema"), dict) or rf["json_schema"].get("strict") is not True:
        raise SafetyError("response_format must be json_schema with strict=true")
    msgs = body.get("messages")
    if not isinstance(msgs, list) or [m.get("role") if isinstance(m, dict) else None for m in msgs] != ["system", "user"]:
        raise SafetyError("messages must be exactly one system and one user message")
    if body.get("temperature") != 0 or ("seed" in body) != bool(profile.get("send_seed")):
        raise SafetyError("temperature/seed differ from the profile")


def estimate_input_tokens(body, cfg):
    sysm, user = body["messages"][0]["content"], body["messages"][1]["content"]
    sch = json.dumps(body["response_format"]["json_schema"]["schema"])
    return math.ceil(len((sysm + user + sch).encode("utf-8")) / cfg["chars_per_token_estimate"]) + OVERHEAD_TOKENS


def unit_prices(profile):
    p = profile.get("price_usd_per_mtok")
    return (p["input"], p["output"]) if p else None


def cost_of(prompt_tokens, completion_tokens, prices):
    return (prompt_tokens * prices[0] + completion_tokens * prices[1]) / 1e6


# ---------------------------------------------------------------- бюджет

class Reservation:
    def __init__(self, tokens, usd):
        self.tokens, self.usd = tokens, usd


class Budget:
    def __init__(self, max_usd, max_tokens, spent_usd=0.0, spent_tokens=0):
        self.max_usd, self.max_tokens = max_usd, max_tokens
        self.spent_usd, self.spent_tokens = spent_usd, spent_tokens
        self.held_usd, self.held_tokens = 0.0, 0
        self._lock = threading.Lock()

    def reserve(self, tokens, usd):
        with self._lock:
            if (self.spent_usd + self.held_usd + usd > self.max_usd + 1e-9
                    or self.spent_tokens + self.held_tokens + tokens > self.max_tokens):
                return None
            self.held_usd += usd
            self.held_tokens += tokens
            return Reservation(tokens, usd)

    def settle(self, res, tokens, usd):
        with self._lock:
            self.held_usd -= res.usd
            self.held_tokens -= res.tokens
            self.spent_usd += usd
            self.spent_tokens += tokens


# ---------------------------------------------------------------- транспорт

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):
        return None  # заголовок Authorization не должен уйти на другой адрес


class UrllibTransport:
    def _open(self, req, timeout):
        local = _host_local(req.full_url)
        handlers = [_NoRedirect()] + ([urllib.request.ProxyHandler({})] if local else [])
        opener = urllib.request.build_opener(*handlers)
        try:
            with opener.open(req, timeout=timeout) as r:
                return Response(r.status, r.headers, r.read())
        except urllib.error.HTTPError as e:
            try:
                return Response(e.code, e.headers, e.read())
            finally:
                e.close()
        except (socket.timeout, TimeoutError) as e:
            raise TransportError("timeout", "timeout")
        except urllib.error.URLError as e:
            if isinstance(e.reason, (socket.timeout, TimeoutError)):
                raise TransportError("timeout", "timeout")
            raise TransportError("network", f"{type(e.reason).__name__}")
        except (ConnectionError, http.client.HTTPException, OSError) as e:
            raise TransportError("network", type(e).__name__)

    def post(self, url, headers, data, timeout):
        if not (url == API_URL or _host_local(url)):
            raise TransportError("network", "host is not allowed")
        return self._open(urllib.request.Request(url, data=data, headers=headers, method="POST"), timeout)

    def get(self, url, headers, timeout):
        if not (url.startswith("https://openrouter.ai/api/v1/") or _host_local(url)):
            raise TransportError("network", "host is not allowed")
        return self._open(urllib.request.Request(url, headers=headers, method="GET"), timeout)


# ---------------------------------------------------------------- ретраи

def _classify(resp):
    """-> (kind, detail, data): kind in ok | retry | abort | case_error."""
    s = resp.status
    body_txt = resp.body.decode("utf-8", "replace")[:500] if resp.body else ""
    if s == 200:
        try:
            data = json.loads(resp.body)
        except ValueError:
            return "retry", "200 with non-JSON body", None
        if not isinstance(data, dict):
            return "retry", "200 with non-object body", None
        err = data.get("error")
        if isinstance(err, dict):
            try:
                code = int(err.get("code"))
            except (TypeError, ValueError):
                code = None
            if code in RETRY_STATUS:
                return "retry", f"200 with error code {code}", None
        if not isinstance(data.get("choices"), list) or not data["choices"]:
            return "retry", "200 without choices", None
        if not isinstance(data["choices"][0], dict) or not isinstance(data["choices"][0].get("message"), dict):
            return "retry", "200 with malformed choices", None
        return "ok", None, data
    if s in RETRY_STATUS:
        return "retry", f"http {s}: {body_txt}", None
    if s in ABORT_STATUS:
        return "abort", "auth/credits/forbidden", f"http {s}: {body_txt}"
    if s == 404:
        return "abort", "no_endpoint", f"http 404: {body_txt}"
    return "case_error", f"http {s}: {body_txt}", None


def _usage_numbers(data):
    u = data.get("usage") if isinstance(data, dict) else None
    if isinstance(u, dict) and _num(u.get("prompt_tokens")) and _num(u.get("completion_tokens")):
        return u
    return None


def call_with_retries(transport, url, headers, payload, retry_cfg, budget, reserve_args, sleep, rng, clock,
                      stop_event=None):
    """reserve_args = (tokens, usd, (price_in, price_out)). Резерв берётся на каждую попытку."""
    rtok, rusd, prices = reserve_args
    t_start, cost, toks, last_error, lat = clock(), 0.0, 0, None, 0
    attempts = 0

    def result(kind, data=None):
        return CallResult(data, attempts, last_error, lat, int((clock() - t_start) * 1000), cost, toks, kind)

    for attempt in range(1, retry_cfg["max_attempts"] + 1):
        if stop_event is not None and stop_event.is_set():
            return result("stopped")
        res = budget.reserve(rtok, rusd)
        if res is None:
            return result("budget")
        attempts = attempt
        t1 = clock()
        retry_after = None
        try:
            resp = transport.post(url, headers, payload, retry_cfg["timeout_s"])
        except TransportError as e:
            lat = int((clock() - t1) * 1000)
            full = e.kind == "timeout"  # запрос мог быть обработан и оплачен
            budget.settle(res, rtok if full else 0, rusd if full else 0.0)
            if full:
                cost, toks = cost + rusd, toks + rtok
            last_error = f"transport_{e.kind}: {e}"
            kind = "retry"
        else:
            lat = int((clock() - t1) * 1000)
            kind, detail, data = _classify(resp)
            if kind == "ok":
                u = _usage_numbers(data)
                if u is None:
                    c, t = rusd, rtok
                else:
                    t = int(u["prompt_tokens"] + u["completion_tokens"])
                    c = cost_of(u["prompt_tokens"], u["completion_tokens"], prices)
                    if _num(u.get("cost")):
                        c = max(c, float(u["cost"]))
                budget.settle(res, t, c)
                cost, toks = cost + c, toks + t
                return result("ok", data)
            budget.settle(res, 0, 0.0)
            if kind == "abort":
                raise AbortRun(detail, f"{detail}: {data}")
            last_error = detail
            if kind == "case_error":
                return result("case_error")
            retry_after = hget(resp.headers, "Retry-After")
        if attempt >= retry_cfg["max_attempts"]:
            break
        delay = min(retry_cfg["max_delay_s"], retry_cfg["base_delay_s"] * 2 ** (attempt - 1)) * rng.uniform(0.5, 1.0)
        try:
            ra = float(retry_after) if retry_after is not None else None
        except (TypeError, ValueError):
            ra = None
        if ra is not None and ra >= 0:
            delay = min(max(delay, ra), retry_cfg["max_delay_s"])
        sleep(delay)
    return result("exhausted")


# ---------------------------------------------------------------- разбор ответа

def _norm(s):
    return re.sub(r"[^a-z0-9]", "", str(s).lower())


def provider_matches(actual, profile):
    if not isinstance(actual, str) or not actual:
        return False
    allowed = {_norm(x) for x in list(profile.get("expected_provider_names") or []) + list(profile["provider"]["only"])}
    return _norm(actual) in allowed


def parse_response(resp_json, profile, cfg):
    """-> поля строки результата: status, answer, error, final, schema_errors, raw_content, usage и метаданные."""
    ch = (resp_json.get("choices") or [{}])[0]
    ch = ch if isinstance(ch, dict) else {}
    msg = ch.get("message") if isinstance(ch.get("message"), dict) else {}
    u = resp_json.get("usage") if isinstance(resp_json.get("usage"), dict) else {}
    details = u.get("completion_tokens_details") if isinstance(u.get("completion_tokens_details"), dict) else {}
    out = {
        "answer": None, "error": None, "final": True, "schema_errors": [], "raw_content": None,
        "provider_actual": resp_json.get("provider"), "model_reported": resp_json.get("model"),
        "generation_id": resp_json.get("id"), "finish_reason": ch.get("finish_reason"),
        "usage": {"prompt_tokens": u.get("prompt_tokens"), "completion_tokens": u.get("completion_tokens"),
                  "total_tokens": u.get("total_tokens"), "reasoning_tokens": details.get("reasoning_tokens"),
                  "cost_reported": u.get("cost") if _num(u.get("cost")) else None},
    }
    if not provider_matches(out["provider_actual"], profile):
        out.update(status="provider_mismatch", final=False,
                   error=f"provider_mismatch: got {out['provider_actual']!r}, pinned {profile['provider']['only']}")
        return out  # содержимое не разбираем и не сохраняем
    content = msg.get("content")
    content = content if isinstance(content, str) else ("" if content is None else json.dumps(content))
    if msg.get("refusal"):
        out.update(status="refusal", error="refusal", raw_content=str(msg["refusal"])[:RAW_LIMIT])
    elif out["finish_reason"] == "content_filter":
        out.update(status="content_filter", error="content_filter", raw_content=content[:RAW_LIMIT])
    elif out["finish_reason"] == "length":
        out.update(status="truncated", error="truncated: finish_reason=length", raw_content=content[:RAW_LIMIT])
    else:
        try:
            ans = json.loads(content)
        except ValueError as e:
            ans = None
            out.update(status="invalid_json", error=f"invalid_json: {e}", raw_content=content[:RAW_LIMIT])
        else:
            if ans is None:
                out.update(status="invalid_json", error="invalid_json: null", raw_content=content[:RAW_LIMIT])
            elif not isinstance(ans, dict):
                out.update(status="schema_invalid", error="schema_invalid: answer is not an object",
                           schema_errors=["answer is not an object"], raw_content=content[:RAW_LIMIT])
            else:
                errs = score.validate(ans)
                out["answer"] = ans
                if errs:
                    out.update(status="schema_invalid", error="schema_invalid: " + "; ".join(errs), schema_errors=errs)
                else:
                    out["status"] = "ok"
    return out


# ---------------------------------------------------------------- запись и возобновление

class ResultWriter:
    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        try:
            self._f = open(path, "a+b")
        except PermissionError:
            raise ConfigError(f"{path} is not writable (frozen reference?)")
        self._f.seek(0)
        data = self._f.read()
        if data and not data.endswith(b"\n"):  # недописанная строка после падения
            self._f.truncate(data.rfind(b"\n") + 1)
            self._f.flush()

    def write(self, row):
        line = (json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
        with self._lock:
            self._f.write(line)
            self._f.flush()
            os.fsync(self._f.fileno())

    def close(self):
        self._f.close()


def read_rows(path, warn=None):
    rows = []
    with open(path, "rb") as f:
        data = f.read()
    lines = data.split(b"\n")
    if lines and lines[-1] != b"":
        lines = lines[:-1]  # последняя строка без \n — недописанная
    for i, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line.decode("utf-8"))
            if not isinstance(row, dict) or "id" not in row:
                raise ValueError("not a result row")
            rows.append(row)
        except ValueError:
            if warn:
                warn(f"warning: {path}:{i}: unparseable line skipped")
    return rows


def row_tokens(row):
    if _num(row.get("charged_tokens")):
        return int(row["charged_tokens"])
    t = (row.get("usage") or {}).get("total_tokens")
    return int(t) if _num(t) else 0


def load_existing(path, warn=None):
    rows = read_rows(path, warn)
    last = {}
    for r in rows:
        last[r["id"]] = r
    final_ids = {i for i, r in last.items() if r.get("final") is True}
    spent_usd = sum(r["cost_usd"] for r in rows if _num(r.get("cost_usd")))
    return final_ids, spent_usd, sum(row_tokens(r) for r in rows), len(rows)


def compute_totals(rows):
    last = {}
    for r in rows:
        last[r["id"]] = r
    tot = {"final": 0, "ok": 0, "schema_invalid": 0, "errors_nonfinal": 0, "prompt_tokens": 0, "completion_tokens": 0,
           "cost_usd": round(sum(r["cost_usd"] for r in rows if _num(r.get("cost_usd"))), 8)}
    by_status = collections.Counter()
    for r in last.values():
        by_status[r.get("status")] += 1
        if r.get("final"):
            tot["final"] += 1
        else:
            tot["errors_nonfinal"] += 1
        tot["ok"] += r.get("status") == "ok"
        tot["schema_invalid"] += r.get("status") == "schema_invalid"
        u = r.get("usage") or {}
        tot["prompt_tokens"] += u.get("prompt_tokens") or 0
        tot["completion_tokens"] += u.get("completion_tokens") or 0
    providers = collections.Counter(r["provider_actual"] for r in rows if r.get("provider_actual"))
    ratios = [r["usage"]["prompt_tokens"] / r["est_input_tokens"] for r in rows
              if r.get("est_input_tokens") and _num((r.get("usage") or {}).get("prompt_tokens"))]
    calib = {"mean_actual_over_estimate": round(sum(ratios) / len(ratios), 4) if ratios else None}
    return tot, dict(by_status), dict(providers), calib


def write_json_atomic(path, obj, mode=None):
    fd, tmp = tempfile.mkstemp(prefix=os.path.basename(path) + ".tmp", dir=os.path.dirname(os.path.abspath(path)))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=1)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o644 if mode is None else mode)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def freeze_reference(out_path, meta):
    """Сжимает файл до одной (последней окончательной) строки на id, ставит 0444 и дописывает meta."""
    rows = read_rows(out_path)
    last = {}
    for r in rows:
        if r.get("final") is True:
            last[r["id"]] = r
    tmp = f"{out_path}.tmp{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as f:
        for r in last.values():
            f.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, 0o444)
    os.replace(tmp, out_path)
    meta.update(kind="reference", frozen_at=now_iso(),
                valid_answers=sum(1 for r in last.values() if r.get("status") == "ok"),
                schema_invalid=sum(1 for r in last.values() if r.get("status") == "schema_invalid"))
    write_json_atomic(out_path + ".meta.json", meta, mode=0o444)


# ---------------------------------------------------------------- исполнитель

class Runner:
    def __init__(self, *, transport, url, headers, cfg, profile, system_prompt, schema, budget, writer, run_id,
                 sleep, rng, clock, secrets, con, meta, meta_path, prior_rows):
        self.__dict__.update(locals())
        del self.__dict__["self"]
        self.stop = threading.Event()
        self.abort_reason = None
        self.fatal = None
        self.rows = list(prior_rows)
        self._lock = threading.Lock()
        self._meta_lock = threading.Lock()
        self.written = 0

    def _abort(self, reason):
        with self._lock:
            if self.abort_reason is None:
                self.abort_reason = reason
        self.stop.set()

    def record(self, row):
        for k in ("error", "raw_content"):
            if isinstance(row.get(k), str):
                row[k] = redact(row[k], self.secrets)
        self.writer.write(row)
        with self._lock:
            self.rows.append(row)
            self.written += 1
            n = self.written
        if n % META_EVERY == 0:
            self.write_meta()
            self.con.warn(f"progress: {n} rows written")

    def write_meta(self, **update):
        with self._meta_lock:  # снимок и запись целиком: старый снимок не перезапишет новый
            with self._lock:
                rows = list(self.rows)
                tot, _, providers, calib = compute_totals(rows)
                self.meta.update(update)
                self.meta.update(totals=tot, providers_seen=providers, estimate_calibration=calib, updated_at=now_iso())
                snapshot = copy.deepcopy(self.meta)
            write_json_atomic(self.meta_path, snapshot)

    def _row(self, case, body, est, sha, **kw):
        row = {"id": case["id"], "endpoint": self.profile["endpoint_label"], "answer": None, "error": None,
               "final": False, "status": None, "schema_errors": [], "run_id": self.run_id,
               "profile": self.profile["name"], "model_requested": self.cfg["model"], "model_reported": None,
               "provider_actual": None, "generation_id": None,
               "usage": {"prompt_tokens": None, "completion_tokens": None, "total_tokens": None,
                         "reasoning_tokens": None, "cost_reported": None},
               "cost_usd": 0.0, "charged_tokens": 0, "est_input_tokens": est, "latency_ms": 0, "latency_total_ms": 0,
               "attempts": 0, "http_status": None, "finish_reason": None, "request_sha256": sha,
               "raw_content": None, "ts": now_iso()}
        row.update(kw)
        return row

    def send_case(self, case):
        if self.stop.is_set():
            return
        try:
            self._send_case(case)
        except AbortRun as e:
            self._abort(e.reason)
            self.record(self._row(case, None, 0, None, status="http_error", error=f"abort: {e}"))
        except Exception as e:  # SafetyError и непредвиденное: прогон останавливается, ошибка поднимается наверх
            with self._lock:
                self.fatal = self.fatal or e
            self._abort("safety" if isinstance(e, SafetyError) else "internal_error")

    def _send_case(self, case):
        cfg, profile = self.cfg, self.profile
        body = build_request(case["input"], self.system_prompt, self.schema, cfg, profile)
        assert_request_safe(body, cfg, profile)
        data = body_bytes(body)
        sha = request_digest(body)
        est = estimate_input_tokens(body, cfg)
        max_tokens = body["max_tokens"]
        if est + max_tokens > cfg["context_ceiling_tokens"]:
            self.record(self._row(case, body, est, sha, status="context_ceiling", final=True,
                                  error=f"context_ceiling: est {est} + max_tokens {max_tokens} > {cfg['context_ceiling_tokens']}"))
            return
        prices = unit_prices(profile)
        assert_request_safe(body, cfg, profile)  # непосредственно перед отправкой
        cr = call_with_retries(self.transport, cfg["api_url"], self.headers, data, cfg["retry"], self.budget,
                               (est + max_tokens, cost_of(est, max_tokens, prices), prices), self.sleep, self.rng,
                               self.clock, self.stop)
        common = dict(cost_usd=cr.cost_usd, charged_tokens=cr.tokens, attempts=cr.attempts,
                      latency_ms=cr.latency_ms, latency_total_ms=cr.latency_total_ms)
        if cr.kind == "stopped" and not cr.attempts:
            return
        if cr.kind == "budget":
            self._abort("budget")
            self.record(self._row(case, body, est, sha, status="budget_skipped", error="budget_skipped", **common))
            return
        if cr.kind in ("exhausted", "case_error", "stopped"):  # stopped с попытками: расход уже списан, пишем строку
            msg = redact(cr.last_error or "", self.secrets)[:500]
            status = "transport_error" if msg.startswith("transport_") else "http_error"
            self.record(self._row(case, body, est, sha, status=status,
                                  error=msg if status == "transport_error" else f"http_error: {msg}", **common))
            return
        parsed = parse_response(cr.data, profile, cfg)
        if parsed["status"] == "provider_mismatch":
            self._abort("provider_mismatch")
        u = parsed["usage"]
        if _num(u["prompt_tokens"]) and _num(u["completion_tokens"]) \
                and u["prompt_tokens"] + u["completion_tokens"] > cfg["context_ceiling_tokens"]:
            parsed.update(status="context_ceiling_actual", answer=None, final=False, schema_errors=[], raw_content=None,
                          error=f"context_ceiling_actual: {u['prompt_tokens']}+{u['completion_tokens']} tokens "
                                f"> {cfg['context_ceiling_tokens']}; the token estimator is wrong")
            self._abort("context_ceiling_actual")
        self.record(self._row(case, body, est, sha, http_status=200, **common, **parsed))


# ---------------------------------------------------------------- CLI

class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ConfigError(message)


def make_parser():
    ap = _Parser(description="Прогон golden-набора AegisOps через OpenRouter", prog="run.py")
    ap.add_argument("--profile", required=True)
    ap.add_argument("--set", dest="set_name", choices=["probe", "dev"])
    ap.add_argument("--config")
    ap.add_argument("--out")
    ap.add_argument("--resume")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--staged", action="store_true", help="набор, промпт и схема кандидата из manifest.staged")
    ap.add_argument("--emit-requests", metavar="PATH", help="с --dry-run: JSONL id, request_sha256, est_input_tokens")
    ap.add_argument("--show-full", action="store_true")
    ap.add_argument("--limit", type=int)
    ap.add_argument("--ids")
    ap.add_argument("--concurrency", type=int)
    ap.add_argument("--max-usd", type=float)
    ap.add_argument("--max-tokens-total", type=int)
    ap.add_argument("--reference", action="store_true")
    ap.add_argument("--allow-hash-mismatch", action="store_true")
    ap.add_argument("--preflight", action="store_true")
    ap.add_argument("--base-dir", help=argparse.SUPPRESS)
    return ap


def read_key(env):
    key = env.get("OPENROUTER_API_KEY")
    if not key and env.get("OPENROUTER_API_KEY_FILE"):
        try:
            with open(env["OPENROUTER_API_KEY_FILE"], encoding="utf-8") as f:
                key = f.read().strip()
        except OSError as e:
            raise ConfigError(f"cannot read OPENROUTER_API_KEY_FILE: {e.strerror}")
    if not key:
        raise ConfigError("OPENROUTER_API_KEY is not set")
    key = key.strip()
    if not key or re.search(r"\s", key):
        raise ConfigError("OPENROUTER_API_KEY is malformed")
    return key


def print_dry_run(con, cfg, profile, body0, ests, show_full):
    shown = copy.deepcopy(body0)
    s = shown["messages"][0]["content"]
    if not show_full and len(s) > 300:
        shown["messages"][0]["content"] = s[:300] + f"...[+{len(s) - 300} chars, use --show-full]"
    con.say(f"POST {cfg['api_url']}")
    con.say("Authorization: Bearer ***")
    con.say("Content-Type: application/json")
    con.say(json.dumps(shown, ensure_ascii=False, indent=1))
    n = len(ests)
    con.say(f"cases selected: {n}; est input tokens min/mean/max: {min(ests)}/{sum(ests) // n}/{max(ests)}")
    mt = cfg["generation"]["max_tokens"]
    con.say(f"cases over context ceiling ({cfg['context_ceiling_tokens']}): {sum(1 for e in ests if e + mt > cfg['context_ceiling_tokens'])}")
    prices = unit_prices(profile)
    if not prices:
        con.say("cost: n/a (profile has no prices)")
        return
    expected = sum(cost_of(e, 1000, prices) for e in ests)
    worst = sum(cost_of(e, mt, prices) for e in ests)
    con.say(f"cost USD: expected (1000 output tokens/case) {expected:.4f}, worst case (max_tokens) {worst:.4f}; "
            f"budget {cfg['budget']['max_usd_per_run']}")
    if worst > cfg["budget"]["max_usd_per_run"]:
        con.say("WARNING: worst-case cost exceeds the budget; the run may stop early")


def preflight(args, cfg, profile, transport, key, con):
    slug = cfg["model"]
    url = cfg["api_url"].rsplit("/chat/completions", 1)[0] + f"/models/{slug}/endpoints"
    headers = {"Authorization": f"Bearer {key}"} if key else {}
    try:
        resp = transport.get(url, headers, cfg["retry"]["timeout_s"])
    except TransportError as e:
        raise AbortRun("preflight_failed", f"preflight request failed: {e}")
    if resp.status != 200:
        raise AbortRun("preflight_failed", f"preflight: http {resp.status}")
    try:
        eps = json.loads(resp.body)["data"]["endpoints"]
    except (ValueError, KeyError, TypeError):
        raise AbortRun("preflight_failed", "preflight: unexpected response")
    allowed = {_norm(x) for x in profile["expected_provider_names"] + profile["provider"]["only"]}
    need = ["response_format", "structured_outputs"] + (["seed"] if profile.get("send_seed") else [])
    good = 0
    for e in eps:
        sp = e.get("supported_parameters") or []
        pr = e.get("pricing") or {}
        match = _norm(e.get("provider_name", "")) in allowed and e.get("quantization") in profile["provider"]["quantizations"]
        has = {k: k in sp for k in ("response_format", "structured_outputs", "seed")}
        ok = match and all(has[k] for k in need)
        good += ok
        try:
            price = f"{float(pr['prompt']) * 1e6:.4f}/{float(pr['completion']) * 1e6:.4f}"
        except (KeyError, TypeError, ValueError):
            price = "?"
        con.say(f"{'*' if ok else ' '} {e.get('provider_name')} tag={e.get('tag')} quant={e.get('quantization')} "
                f"response_format={has['response_format']} structured_outputs={has['structured_outputs']} "
                f"seed={has['seed']} usd/Mtok in/out={price}")
    if not good:
        raise ConfigError("preflight: no endpoint matches the profile (provider, quantization, parameters)")
    con.say(f"preflight OK: {good} matching endpoint(s)")


def run(argv, *, transport=None, sleep=time.sleep, rng=None, clock=time.monotonic, env=None,
        stdout=None, stderr=None, base_dir=None):
    env = os.environ if env is None else env
    stdout, stderr = stdout or sys.stdout, stderr or sys.stderr
    rng = rng or random.Random()
    secrets = [env.get("OPENROUTER_API_KEY")] if env.get("OPENROUTER_API_KEY") else []
    con = Console(stdout, stderr, secrets)
    try:
        return _run(argv, con, transport, sleep, rng, clock, env, base_dir)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 2
    except (ConfigError, IntegrityError, SafetyError) as e:
        con.warn(f"error: {e}")
        return 2
    except AbortRun as e:
        con.warn(f"aborted: {e.reason}: {e}")
        return 3


def _run(argv, con, transport, sleep, rng, clock, env, base_dir):
    args = make_parser().parse_args(argv)
    base = base_dir or args.base_dir or BASE
    if not args.set_name and not args.preflight:
        raise ConfigError("--set is required")
    if args.resume and args.out:
        raise ConfigError("--resume and --out are mutually exclusive")
    if args.reference:
        if args.limit or args.ids or args.allow_hash_mismatch:
            raise ConfigError("--reference forbids --limit, --ids and --allow-hash-mismatch")
        if args.set_name != "probe":
            raise ConfigError("--reference is only allowed with --set probe")
    if args.allow_hash_mismatch and args.set_name != "dev":
        raise ConfigError("--allow-hash-mismatch is only allowed with --set dev")
    if args.limit is not None and args.limit < 1:
        raise ConfigError("--limit must be >= 1")
    if args.emit_requests and not args.dry_run:
        raise ConfigError("--emit-requests is only allowed with --dry-run")

    cfg_path = args.config or os.path.join(base, "profiles.json")
    cfg, cfg_sha = read_config(cfg_path)
    network = not args.dry_run
    profile = validate_profile(cfg, args.profile, for_network=network)
    conc = args.concurrency if args.concurrency is not None else cfg["concurrency"]
    if not 1 <= conc <= MAX_CONCURRENCY:
        raise ConfigError(f"--concurrency must be in [1, {MAX_CONCURRENCY}]")
    max_usd = min(cfg["budget"]["max_usd_per_run"], args.max_usd if args.max_usd is not None else math.inf)
    if (args.max_usd is not None and not args.max_usd > 0) or (args.max_tokens_total is not None and args.max_tokens_total <= 0):
        raise ConfigError("--max-usd and --max-tokens-total must be positive")
    max_tok = min(cfg["budget"]["max_tokens_per_run"], args.max_tokens_total if args.max_tokens_total is not None else math.inf)

    key = None
    if network:
        key = read_key(env)
        con.secrets = [key]
    if args.preflight:
        if args.dry_run:
            raise ConfigError("--preflight needs the network; do not combine with --dry-run")
        preflight(args, cfg, profile, transport or UrllibTransport(), key, con)
        return 0

    integ = check_integrity(args.set_name, args.allow_hash_mismatch, base, args.staged)
    for p in integ["problems"]:
        con.warn(f"WARNING: integrity bypassed (--allow-hash-mismatch): {p}")
    cases = integ["cases"]
    if args.ids:
        want = [x for x in args.ids.split(",") if x]
        have = {c["id"] for c in cases}
        unknown = [x for x in want if x not in have]
        if unknown:
            raise ConfigError(f"unknown ids: {unknown[:3]}")
        cases = [c for c in cases if c["id"] in set(want)]
    if args.limit:
        cases = cases[:args.limit]
    if not cases:
        raise ConfigError("no cases selected")
    ids_sha = sha256_bytes("\n".join(c["id"] for c in cases).encode())

    if args.dry_run:
        bodies = [build_request(c["input"], integ["prompt"], integ["schema"], cfg, profile) for c in cases]
        for b in bodies:
            assert_request_safe(b, cfg, profile)
        ests = [estimate_input_tokens(b, cfg) for b in bodies]
        if args.emit_requests:
            lines = [json.dumps({"id": c["id"], "request_sha256": request_digest(b), "est_input_tokens": e},
                                sort_keys=True, separators=(",", ":")) for c, b, e in zip(cases, bodies, ests)]
            os.makedirs(os.path.dirname(os.path.abspath(args.emit_requests)), exist_ok=True)
            with open(args.emit_requests, "w", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")
        print_dry_run(con, cfg, profile, bodies[0], ests, args.show_full)
        return 0

    with open(os.path.join(BASE, "run.py"), "rb") as f:
        runner_sha = sha256_bytes(f.read())
    generation = {"temperature": cfg["generation"]["temperature"], "max_tokens": cfg["generation"]["max_tokens"]}
    if profile.get("send_seed"):
        generation["seed"] = cfg["generation"]["seed"]
    profile_sha = sha256_bytes(canon_json({"name": profile["name"], "profile": profile}).encode())
    hashes = dict(integ["hashes"], runner=runner_sha, config=cfg_sha)
    kind = "reference" if args.reference else "run"

    prior_final, prior_usd, prior_tok, prior_rows = set(), 0.0, 0, []
    if args.resume:
        out_path = args.resume
        mpath = out_path + ".meta.json"
        if not os.path.exists(out_path) or not os.path.exists(mpath):
            raise ConfigError("--resume: output file or its .meta.json does not exist")
        old = load_config(mpath)
        checks = {"profile_sha256": profile_sha, "model": cfg["model"], "generation": generation,
                  "selected_ids_sha256": ids_sha, "set": args.set_name, "kind": kind}
        bad = [k for k, v in checks.items() if old.get(k) != v]
        bad += [f"hashes.{k}" for k in ("set", "prompt", "schema", "config", "runner") if (old.get("hashes") or {}).get(k) != hashes[k]]
        if bad:
            raise ConfigError(f"--resume: run does not match the original ({', '.join(bad)})")
        run_id = old["run_id"]
        prior_final, prior_usd, prior_tok, _ = load_existing(out_path, con.warn)
        prior_rows = read_rows(out_path)
    else:
        run_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + f"-{rng.getrandbits(16):04x}"
        if args.out:
            out_path = args.out
        elif args.reference:
            # имя набора с версией берётся из файла набора в manifest (data/probe-v2.jsonl -> probe-v2)
            set_tag = os.path.splitext(os.path.basename(integ["set_file"]))[0]
            out_path = os.path.join(base, "refs", profile["name"],
                                    f"{set_tag}-{time.strftime('%Y%m%d', time.gmtime())}-{run_id}.jsonl")
        else:
            out_path = os.path.join(base, "runs", profile["name"], f"{args.set_name}-{run_id}.jsonl")
        if os.path.exists(out_path) or os.path.exists(out_path + ".meta.json"):
            raise ConfigError(f"{out_path} already exists; use --resume to continue it")
        os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    meta_path = out_path + ".meta.json"

    todo = [c for c in cases if c["id"] not in prior_final]
    meta = {"kind": kind, "run_id": run_id, "profile": profile["name"], "profile_sha256": profile_sha,
            "endpoint_label": profile["endpoint_label"], "model": cfg["model"],
            "api_host": urllib.parse.urlsplit(cfg["api_url"]).hostname, "generation": generation,
            "provider_request": profile["provider"], "set": args.set_name, "set_file": integ["set_file"],
            "cases_total": len(cases), "selected_ids_sha256": ids_sha, "hashes": hashes,
            "integrity_bypassed": integ["bypassed"], "track": "staged" if args.staged else "active", "started_at": now_iso(), "updated_at": None, "finished_at": None,
            "status": "running", "abort_reason": None}
    if args.resume:
        meta["started_at"] = old.get("started_at", meta["started_at"])
    writer = ResultWriter(out_path)
    budget = Budget(max_usd, max_tok, prior_usd, prior_tok)
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json",
               "User-Agent": "aegisops-golden-runner/1"}
    runner = Runner(transport=transport or UrllibTransport(), url=cfg["api_url"], headers=headers, cfg=cfg,
                    profile=profile, system_prompt=integ["prompt"], schema=integ["schema"], budget=budget,
                    writer=writer, run_id=run_id, sleep=sleep, rng=rng, clock=clock, secrets=con.secrets, con=con,
                    meta=meta, meta_path=meta_path, prior_rows=prior_rows)
    runner.write_meta()
    con.say(f"run {run_id}: profile {profile['name']}, set {args.set_name}, {len(todo)} of {len(cases)} cases to send"
            f" (concurrency {conc}, budget ${max_usd:g} / {max_tok:g} tokens)")
    interrupted = False
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=conc)
    try:
        futs = [pool.submit(runner.send_case, c) for c in todo]
        concurrent.futures.wait(futs)
    except KeyboardInterrupt:
        interrupted = True
        runner.stop.set()
        runner._abort("interrupted")
        pool.shutdown(wait=True, cancel_futures=True)
    finally:
        pool.shutdown(wait=True)
        writer.close()

    last = {}
    for r in runner.rows:
        last[r["id"]] = r
    pending = [c["id"] for c in cases if not (last.get(c["id"]) or {}).get("final")]
    if runner.abort_reason:
        status = "aborted"
    elif pending:
        status = "completed_with_errors"
    else:
        status = "completed"
    runner.write_meta(status=status, abort_reason=runner.abort_reason, finished_at=now_iso())
    if runner.fatal is not None:
        raise runner.fatal  # SafetyError -> код 2, остальное -> main

    tot, by_status, providers, _ = compute_totals(runner.rows)
    con.say(f"status: {status}" + (f" ({runner.abort_reason})" if runner.abort_reason else ""))
    con.say(f"cases: {len(cases)}, final: {tot['final']}, ok: {tot['ok']}, schema_invalid: {tot['schema_invalid']}, "
            f"non-final: {tot['errors_nonfinal']}, not attempted: {len([i for i in pending if i not in last])}")
    con.say(f"by status: {by_status}")
    con.say(f"tokens: prompt {tot['prompt_tokens']}, completion {tot['completion_tokens']}; cost USD {tot['cost_usd']:.6f}")
    con.say(f"providers seen: {providers}")
    mm = sorted({r["model_reported"] for r in runner.rows if r.get("model_reported") not in (None, cfg["model"])})
    if mm:
        con.say(f"WARNING: model reported differs from requested {cfg['model']}: {mm}")
    con.say(f"output: {out_path}")
    if runner.abort_reason:
        if interrupted:
            return 130
        con.say(f"resume: python3 run.py --profile {profile['name']} --set {args.set_name} --resume {out_path}")
        return 3
    if pending:
        con.say(f"{len(pending)} case(s) without a final answer; resume: python3 run.py --profile {profile['name']} "
                f"--set {args.set_name} --resume {out_path}")
        return 4
    if args.reference:
        freeze_reference(out_path, runner.meta)
        con.say(f"reference frozen (read-only): {out_path}")
    con.say(f"score: python3 score.py --cases {integ['set_file']} --pred {out_path}")
    return 0


def main():
    key = os.environ.get("OPENROUTER_API_KEY")
    if not key and os.environ.get("OPENROUTER_API_KEY_FILE"):
        try:
            with open(os.environ["OPENROUTER_API_KEY_FILE"], encoding="utf-8") as f:
                key = f.read().strip()
        except OSError:
            pass
    try:
        code = run(sys.argv[1:])
    except KeyboardInterrupt:
        code = 130
    except Exception as e:  # без traceback: в нём могли бы оказаться заголовки с ключом
        print(redact(f"{type(e).__name__}: {e}", [key]), file=sys.stderr)
        code = 1
    sys.exit(code)


if __name__ == "__main__":
    main()
