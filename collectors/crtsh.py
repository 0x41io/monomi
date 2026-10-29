"""
crt.sh subdomain collector.

crt.sh is a public search engine for Certificate Transparency logs. Every
publicly trusted TLS certificate gets logged, and certificates list the
hostnames they cover, so searching for "%.example.com" reveals subdomains
the organization has requested certificates for. This is 100% passive:
we only query crt.sh, never the target itself.
"""

import time

import requests

from common import USER_AGENT, now_utc, subdomains_in, wildcards_in
from ui import warn

CRTSH_URL = "https://crt.sh/"

DEFAULT_BUDGET = 200  # seconds; roomy enough for all 3 tries (the old worst case was 195s)


def fetch_raw(domain: str, budget: float = DEFAULT_BUDGET, retries: int = 3, timeout: int = 60, light: bool = False) -> list[dict]:
    """Query crt.sh for all certificates matching *.domain.

    crt.sh is free and often slow or overloaded (502/503/timeouts),
    so we retry with a growing delay before giving up.

    budget is the total number of seconds we're allowed to spend across all
    tries and waits. The CLI uses the roomy default; the MCP server passes a
    short one so the whole call finishes before the 60s bridge limit.
    """
    params = {"q": f"%.{domain}", "output": "json", "deduplicate": "Y"}
    if light:
        params["exclude"] = "expired"
    headers = {"User-Agent": USER_AGENT}
    last_error = "time budget used up"
    deadline = time.monotonic() + budget
    tries = 0

    for attempt in range(1, retries + 1):
        remaining = deadline - time.monotonic()
        if remaining < 5:
            break  # too little time left for a useful try
        tries += 1
        try:
            resp = requests.get(CRTSH_URL, params=params, headers=headers,
                                timeout=min(timeout, remaining))
            if resp.status_code == 200:
                # crt.sh returns an empty body (not "[]") when nothing matches
                return resp.json() if resp.text.strip() else []
            last_error = f"HTTP {resp.status_code}"
        except (requests.RequestException, ValueError) as e:
            last_error = str(e)

        if attempt < retries:
            wait = attempt * 5
            if deadline - time.monotonic() - wait < 5:
                break  # waiting would eat the rest of the budget
            warn(f"crt.sh attempt {attempt} failed ({last_error}), retrying in {wait}s...")
            time.sleep(wait)

    raise RuntimeError(f"crt.sh gave up after {tries} tries ({budget:.0f}s budget): {last_error}")

def parse_subdomains(records: list[dict], domain: str) -> list[str]:
    """Turn raw crt.sh records into a clean, sorted, de-duplicated list."""
    # One certificate can cover many names, separated by newlines
    names = [name for rec in records for name in rec.get("name_value", "").splitlines()]
    return subdomains_in(names, domain)

def parse_wildcards(records: list[dict], domain: str) -> list[str]:
    """Pull the wildcard cert names (*.domain) out of raw crt.sh records."""
    names = [name for rec in records for name in rec.get("name_value", "").splitlines()]
    return wildcards_in(names, domain)
def collect(domain: str, budget: float = DEFAULT_BUDGET, light: bool = False) -> dict:
    """Run the collector and return a structured result for the report/AI layer."""
    records = fetch_raw(domain, budget=budget, light=light)
    collected_at = now_utc()
    subdomains = parse_subdomains(records, domain)
    wildcards = parse_wildcards(records, domain)
    return {
        "source": "crt.sh",
        "expired_excluded": light,
        "collected_at": collected_at,
        "domain": domain,
        "certificates_seen": len(records),
        "subdomain_count": len(subdomains),
        "subdomains": subdomains,
        "wildcards": wildcards,
    }
