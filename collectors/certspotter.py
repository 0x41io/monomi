"""
Cert Spotter subdomain collector (backup / second source to crt.sh).

Cert Spotter (by SSLMate) also watches Certificate Transparency logs and has
a free API that works without a key for light use. It only returns
certificates that are currently valid, so it usually finds fewer names than
crt.sh, but it's much more reliable. Still 100% passive.
"""

import time

import requests

from collectors.pacing import CERTSPOTTER as PACER, Paced
from common import USER_AGENT, now_utc, subdomains_in, wildcards_in
from ui import warn

API_URL = "https://api.certspotter.com/v1/issuances"
MAX_PAGES = 5  # be gentle with the free tier (no API key)
MAX_RATE_WAIT = 10  # most seconds we'll wait on a rate limit (the MCP call has 60s in total)
RATE_RETRIES = 2    # how many times we'll wait and try again after a rate limit
DEFAULT_COOLDOWN = 900  # seconds to skip Cert Spotter after a 429 that doesn't say how long
MAX_COOLDOWN = 3600     # the free quota is per hour, so never skip longer than that


def rate_limit_wait(resp) -> float | None:
    """Seconds Cert Spotter asks us to wait (its Retry-After header).

    Returns None if that's longer than we're willing to wait. If the header
    is missing or isn't a plain number of seconds, use a short default.
    """
    try:
        wait = float(resp.headers.get("Retry-After", ""))
    except ValueError:
        wait = 5.0
    return wait if 0 <= wait <= MAX_RATE_WAIT else None


def cooldown_seconds(resp) -> float:
    """How long every later scan should skip Cert Spotter after we give up on a 429.

    Uses its Retry-After header when that's a plain number of seconds,
    otherwise DEFAULT_COOLDOWN; never more than MAX_COOLDOWN.
    """
    try:
        wait = float(resp.headers.get("Retry-After", ""))
    except ValueError:
        return DEFAULT_COOLDOWN
    return min(wait, MAX_COOLDOWN) if wait > 0 else DEFAULT_COOLDOWN


def fetch_raw(domain: str, timeout: int = 30) -> list[dict]:
    """Fetch issuances for domain + subdomains, following pagination."""
    params = {"domain": domain, "include_subdomains": "true", "expand": "dns_names"}
    headers = {"User-Agent": USER_AGENT}
    records = []
    pages = 0
    rate_waits = 0

    while pages < MAX_PAGES:
        try:
            # Every page is one query against the shared free-tier quota
            PACER.acquire(max_wait=MAX_RATE_WAIT)
        except Paced:
            if records:
                break  # out of quota mid-way: keep what we already have
            raise
        try:
            resp = requests.get(API_URL, params=params, headers=headers, timeout=timeout)
        except requests.RequestException as e:
            raise RuntimeError(f"Cert Spotter request failed: {e}")

        if resp.status_code == 429:
            wait = rate_limit_wait(resp)
            if wait is not None and rate_waits < RATE_RETRIES:
                rate_waits += 1
                warn(f"Cert Spotter rate limit hit, waiting {wait:.0f}s and trying again...")
                time.sleep(wait)
                continue  # ask for the same page again
            # Giving up: tell later scans to skip Cert Spotter instead of hitting the limit again
            PACER.cool_down(cooldown_seconds(resp))
            if records:
                break  # rate limited mid-way: keep what we already have
            raise RuntimeError("Cert Spotter rate limit hit (free tier). Try again later.")
        try:
            page = resp.json()
        except ValueError:  # HTML error page or cut-off body instead of JSON
            if records:
                break  # keep the pages we already got
            raise RuntimeError("Cert Spotter returned invalid JSON")
        if not page:
            break
        records.extend(page)
        pages += 1
        params["after"] = page[-1]["id"]  # next page starts after the last id

    return records


def parse_subdomains(records: list[dict], domain: str) -> list[str]:
    """Turn raw Cert Spotter records into a clean, sorted, de-duplicated list."""
    names = [name for rec in records for name in rec.get("dns_names", [])]
    return subdomains_in(names, domain)

def parse_wildcards(records: list[dict], domain: str) -> list[str]:
    """Pull the wildcard cert names (*.domain) out of raw Cert Spotter records."""
    names = [name for rec in records for name in rec.get("dns_names", [])]
    return wildcards_in(names, domain)

def collect(domain: str) -> dict:
    records = fetch_raw(domain)
    collected_at = now_utc()
    subdomains = parse_subdomains(records, domain)
    wildcards = parse_wildcards(records, domain)
    return {
        "source": "certspotter",
        "collected_at": collected_at,
        "domain": domain,
        "certificates_seen": len(records),
        "subdomain_count": len(subdomains),
        "subdomains": subdomains,
        "wildcards": wildcards,
    }
