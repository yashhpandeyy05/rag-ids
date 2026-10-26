"""
Check the LLM set-up: keys, model names and YOUR actual rate limits.

    python -m src.check_llm

For each role in configs/llm.yaml it:
 1. lists the provider's models and confirms the configured model is there,
 2. sends one tiny request and prints the rate-limit headers the provider returns
    (Groq sends them; Google does not - see https://aistudio.google.com/rate-limit).
The result is saved to cache/llm_check.json as the record of model names and dates.
"""

import json
from datetime import datetime, timezone

from openai import OpenAI

from src.config import CACHE_DIR, api_key_for, get_llm_config


def main():
    cfg = get_llm_config()
    record = {"checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "roles": {}}
    for role, r in cfg["roles"].items():
        prov = cfg["providers"][r["provider"]]
        print(f"\n=== role '{role}': {r['model']} on {r['provider']}")
        key = api_key_for(r["provider"])
        if not key:
            print(f"  {prov['api_key_env']} is not set in .env - skipped")
            continue
        client = OpenAI(base_url=prov["base_url"], api_key=key, max_retries=1, timeout=60)
        try:
            names = sorted(m.id.removeprefix("models/") for m in client.models.list())
        except Exception as e:  # noqa: BLE001
            print(f"  could not list models: {e}")
            continue
        listed = r["model"] in names
        print(f"  model listed by provider: {'YES' if listed else 'NO'}  ({len(names)} models available)")
        if not listed:
            print("  available:", ", ".join(names))
        kwargs = {"model": r["model"], "max_tokens": 200,
                  "messages": [{"role": "user", "content": "Reply with the single word OK."}]}
        if r.get("reasoning_effort"):
            kwargs["reasoning_effort"] = r["reasoning_effort"]
        try:
            raw = client.chat.completions.with_raw_response.create(**kwargs)
            resp = raw.parse()
            limits = {k: v for k, v in raw.headers.items() if k.lower().startswith("x-ratelimit")}
            print(f"  test reply: {resp.choices[0].message.content!r}  (served by {resp.model})")
            for k, v in sorted(limits.items()):
                print(f"    {k}: {v}")
            if not limits:
                print("    no rate-limit headers; check https://aistudio.google.com/rate-limit")
            record["roles"][role] = {"model": r["model"], "served_by": resp.model, "listed": listed,
                                     "rate_limit_headers": limits}
        except Exception as e:  # noqa: BLE001
            print(f"  test request FAILED: {e}")
            record["roles"][role] = {"model": r["model"], "listed": listed, "error": str(e)}
    (CACHE_DIR / "llm_check.json").write_text(json.dumps(record, indent=1))
    print(f"\nSaved to {CACHE_DIR / 'llm_check.json'}")
    print("Groq headers: x-ratelimit-limit-requests = requests per DAY, x-ratelimit-limit-tokens = tokens per MINUTE.")


if __name__ == "__main__":
    main()
