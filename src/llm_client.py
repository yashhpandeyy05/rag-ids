"""
One small client for both LLM providers (Groq and Google Gemini).

Both offer an OpenAI-compatible endpoint, so the `openai` package is used for
both, with a different base URL, key and model name per ROLE ("answering",
"judge", ...). The roles are defined in configs/llm.yaml.

What this module adds on top of a plain API call:
 - pacing: waits so that the per-minute request and token limits are not exceeded
 - retry with back-off when the provider says "too many requests" (HTTP 429)
 - a disk cache (cache/llm_cache.sqlite): the same request is never sent twice,
   which makes runs repeatable and lets an interrupted evaluation resume
 - a call log (cache/llm_calls.jsonl) with model names, dates and token counts
"""

import hashlib
import json
import logging
import re
import sqlite3
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from src.config import CACHE_DIR, api_key_for, get_llm_config

logger = logging.getLogger("llm_client")

CACHE_DB = CACHE_DIR / "llm_cache.sqlite"
CALL_LOG = CACHE_DIR / "llm_calls.jsonl"
FALLBACK_ENABLED = False   # the web app sets this True; the evaluation never does
MAX_ATTEMPTS = 6
LONG_WAIT_SECONDS = 120   # if the provider asks us to wait longer, it is a daily limit
OPTIONAL_PARAMS = ("response_format", "parallel_tool_calls", "reasoning_effort")


class LLMError(RuntimeError):
    """The call failed for good (after retries)."""


class DailyLimitReached(LLMError):
    """The provider's daily quota is used up: stop now and resume tomorrow."""


# ---------------------------------------------------------------------------
# Disk cache
# ---------------------------------------------------------------------------
def _db():
    conn = sqlite3.connect(CACHE_DB)
    conn.execute("CREATE TABLE IF NOT EXISTS cache (key TEXT PRIMARY KEY, role TEXT, model TEXT, "
                 "request TEXT, response TEXT, created_at TEXT)")
    return conn


def cache_key(request: Dict[str, Any]) -> str:
    """Hash of EVERY request parameter (model, messages, tools, temperature, ...)."""
    return hashlib.sha256(json.dumps(request, sort_keys=True).encode()).hexdigest()


def cache_get(key: str) -> Optional[Dict[str, Any]]:
    with _db() as conn:
        row = conn.execute("SELECT response FROM cache WHERE key = ?", (key,)).fetchone()
    return json.loads(row[0]) if row else None


def cache_put(key: str, role: str, request: Dict[str, Any], result: Dict[str, Any]) -> None:
    with _db() as conn:
        conn.execute("INSERT OR REPLACE INTO cache VALUES (?, ?, ?, ?, ?, ?)",
                     (key, role, request["model"], json.dumps(request), json.dumps(result),
                      datetime.now(timezone.utc).isoformat(timespec="seconds")))


# ---------------------------------------------------------------------------
# Pacing: a sliding one-minute window of requests and tokens per role
# ---------------------------------------------------------------------------
class Pacer:
    def __init__(self, rpm: int, tpm: int):
        self.rpm, self.tpm = rpm, tpm
        self.events: deque = deque()   # (timestamp, tokens)

    def _trim(self, now):
        while self.events and now - self.events[0][0] >= 60:
            self.events.popleft()

    def wait_for(self, tokens: int) -> None:
        """Sleep until one more request of about `tokens` tokens fits in the last minute."""
        tokens = min(tokens, self.tpm)
        while True:
            now = time.time()
            self._trim(now)
            used = sum(t for _, t in self.events)
            if len(self.events) < self.rpm and used + tokens <= self.tpm:
                return
            wait = 60 - (now - self.events[0][0]) + 0.5
            logger.info("Pacing: waiting %.0f s to stay under %d tokens/min", wait, self.tpm)
            time.sleep(max(wait, 1))

    def record(self, tokens: int) -> None:
        self.events.append((time.time(), tokens))


_PACERS: Dict[str, Pacer] = {}
_CLIENTS: Dict[str, Any] = {}
_NO_JSON_MODE: set = set()   # roles whose provider rejected response_format


def role_settings(role: str) -> Dict[str, Any]:
    cfg = get_llm_config()
    if role not in cfg["roles"]:
        raise ValueError(f"Unknown LLM role '{role}' (see configs/llm.yaml)")
    r = dict(cfg["roles"][role])
    r.update(cfg["providers"][r["provider"]])
    return r


def judge_role() -> str:
    """The role used as judge in the evaluation (one choice for the whole run)."""
    return get_llm_config().get("judge_role", "judge")


def _client(role: str):
    if role not in _CLIENTS:
        from openai import OpenAI
        s = role_settings(role)
        key = api_key_for(s["provider"])
        if not key:
            raise LLMError(f"{s['api_key_env']} is missing. Put it in the .env file (see README).")
        # max_retries=0: retries are handled below, so pacing and logging stay in one place
        _CLIENTS[role] = OpenAI(base_url=s["base_url"], api_key=key, max_retries=0, timeout=120)
    return _CLIENTS[role]


def estimate_tokens(messages, tools=None) -> int:
    """Rough token estimate (about 4 characters per token) for pacing only."""
    chars = len(json.dumps(messages)) + (len(json.dumps(tools)) if tools else 0)
    return chars // 4


def _parse_seconds(value: Optional[str]) -> Optional[float]:
    """Groq reset headers look like '7.66s', '2m59.56s' or '1h2m3s'."""
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        pass
    total, found = 0.0, False
    for num, unit in re.findall(r"([\d.]+)(ms|h|m|s)", value):
        total += float(num) * {"h": 3600, "m": 60, "s": 1, "ms": 0.001}[unit]
        found = True
    return total if found else None


def _wait_from_error(err) -> Optional[float]:
    headers = getattr(getattr(err, "response", None), "headers", None) or {}
    for h in ("retry-after", "x-ratelimit-reset-tokens", "x-ratelimit-reset-requests"):
        secs = _parse_seconds(headers.get(h))
        if secs is not None:
            return secs
    return None


def _log_call(entry: Dict[str, Any]) -> None:
    with open(CALL_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


# ---------------------------------------------------------------------------
# The one public function
# ---------------------------------------------------------------------------
def _chat_one(role: str, messages: List[Dict[str, Any]], tools: Optional[List[Dict[str, Any]]] = None,
              tool_choice: str = "auto", use_cache: bool = True, refresh: bool = False) -> Dict[str, Any]:
    """Send a chat request for a role and return
    {"content", "tool_calls", "model", "usage", "cached"}.
    tool_choice="none" offers the tools but forbids calling them (used to force a final answer).
    refresh=True skips the cached reply but stores the new one (used when a cached reply was unusable).

    Raises LLMError if it keeps failing, DailyLimitReached if the daily quota is used up.
    """
    import openai

    s = role_settings(role)
    request: Dict[str, Any] = {"model": s["model"], "messages": messages,
                               "temperature": s.get("temperature", 0.0),
                               "max_tokens": s.get("max_tokens", 1024)}
    if s.get("reasoning_effort"):
        request["reasoning_effort"] = s["reasoning_effort"]
    if tools:
        request["tools"] = tools
        request["tool_choice"] = tool_choice
        if tool_choice != "none":
            request["parallel_tool_calls"] = False   # one tool call at a time
    if s.get("json_output") and role not in _NO_JSON_MODE:
        request["response_format"] = {"type": "json_object"}

    key = cache_key(request)
    if use_cache and not refresh:
        hit = cache_get(key)
        if hit is not None:
            return {**hit, "cached": True}

    if role not in _PACERS:
        _PACERS[role] = Pacer(s.get("requests_per_minute", 30), s.get("tokens_per_minute", 8000))
    pacer = _PACERS[role]
    estimate = estimate_tokens(messages, tools) + request["max_tokens"] // 2

    last_err = None
    raised_max_tokens = False
    for attempt in range(1, MAX_ATTEMPTS + 1):
        pacer.wait_for(estimate)
        t0 = time.time()
        try:
            resp = _client(role).chat.completions.create(**request)
        except openai.RateLimitError as e:
            pacer.record(estimate)
            wait = _wait_from_error(e)
            if wait is not None and wait > LONG_WAIT_SECONDS:
                raise DailyLimitReached(f"{s['model']}: daily limit reached, resets in {wait/3600:.1f} h") from e
            wait = wait if wait is not None else 2 ** attempt
            logger.warning("Rate limited by %s (attempt %d/%d); waiting %.0f s", s["model"], attempt, MAX_ATTEMPTS, wait)
            time.sleep(wait + 1)
            last_err = e
            continue
        except openai.BadRequestError as e:
            # If the provider rejects one of the optional settings, drop it and retry.
            dropped = next((p for p in OPTIONAL_PARAMS if p in request and p in str(e)), None)
            if dropped:
                logger.warning("%s does not accept '%s'; continuing without it", s["model"], dropped)
                if dropped == "response_format":
                    _NO_JSON_MODE.add(role)
                request.pop(dropped)
                continue
            raise LLMError(f"{s['model']} rejected the request: {e}") from e
        except (openai.APIConnectionError, openai.APITimeoutError, openai.InternalServerError) as e:
            logger.warning("%s: %s (attempt %d/%d)", s["model"], type(e).__name__, attempt, MAX_ATTEMPTS)
            time.sleep(2 ** attempt)
            last_err = e
            continue

        msg = resp.choices[0].message
        usage = resp.usage.model_dump() if resp.usage else {}
        pacer.record(usage.get("total_tokens") or estimate)
        content = msg.content or ""
        # Some reasoning models put their thinking inside <think> tags; drop it.
        content = re.sub(r"<think>.*?</think>", "", content, flags=re.S).strip()
        tool_calls = [tc.model_dump() for tc in (msg.tool_calls or [])]
        result = {"content": content, "tool_calls": tool_calls, "model": resp.model, "usage": usage,
                  "finish_reason": resp.choices[0].finish_reason}
        _log_call({"time": datetime.now(timezone.utc).isoformat(timespec="seconds"), "role": role,
                   "model_requested": s["model"], "model_served": resp.model, "usage": usage,
                   "seconds": round(time.time() - t0, 2), "finish_reason": result["finish_reason"]})
        if not content and not tool_calls:
            # Never cached. Usually the hidden reasoning used up max_tokens; the same
            # request would fail the same way, so try ONCE with twice the room, then give up.
            if result["finish_reason"] == "length" and not raised_max_tokens:
                raised_max_tokens = True
                request["max_tokens"] *= 2
                logger.warning("%s used all %d tokens before answering; retrying once with %d",
                               s["model"], request["max_tokens"] // 2, request["max_tokens"])
                continue
            raise LLMError(f"{s['model']} returned an empty answer (finish_reason={result['finish_reason']})")
        if use_cache:
            cache_put(key, role, request, result)
        return {**result, "cached": False}

    raise LLMError(f"{s['model']} failed after {MAX_ATTEMPTS} attempts: {last_err}")


def chat(role: str, messages: List[Dict[str, Any]], tools: Optional[List[Dict[str, Any]]] = None,
         tool_choice: str = "auto", use_cache: bool = True, refresh: bool = False,
         allow_fallback: Optional[bool] = None) -> Dict[str, Any]:
    """Send a chat request for a role (see _chat_one). If that fails and fallbacks are allowed
    (allow_fallback, default FALLBACK_ENABLED), try the role's fallbacks from configs/llm.yaml in
    order, skipping any whose API key is missing. The result then carries "fallback_from"."""
    allow = FALLBACK_ENABLED if allow_fallback is None else allow_fallback
    try:
        return _chat_one(role, messages, tools, tool_choice, use_cache, refresh)
    except LLMError as first:
        if not allow:
            raise
        error: LLMError = first
        for fb in get_llm_config().get("fallbacks", {}).get(role, []):
            s = role_settings(fb)
            if not api_key_for(s["provider"]):
                continue
            logger.warning("%s failed (%s); trying fallback %s", role, error, s["model"])
            try:
                res = _chat_one(fb, messages, tools, tool_choice, use_cache, refresh)
                return {**res, "fallback_from": role}
            except LLMError as e:
                error = e
        raise error
