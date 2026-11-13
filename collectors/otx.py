"""
AlienVault OTX subdomain collector (passive DNS).

OTX (Open Threat Exchange) keeps passive DNS records: hostnames that DNS
sensors around the world have seen answer, with the address and the first
and last time each was seen. That finds hosts certificate logs never list
(anything without its own HTTPS certificate). Still 100% passive: the
target's own servers are never contacted.

It works without a key, but keyless requests are rate-limited harder. A
free key (otx.alienvault.com -> Settings -> API Integration) in the
OTX_API_KEY environment variable raises the limit.
"""

import os

import requests

from collectors.pacing import OTX as PACER
from common import USER_AGENT, now_utc, subdomains_in

API_URL = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
KEY_VAR = "OTX_API_KEY"
TIMEOUT = 30            # OTX is slow on big domains; the MCP call's total budget still applies
MAX_WAIT = 10           # most seconds we'll wait for a pacing slot
DEFAULT_COOLDOWN = 900  # seconds to skip OTX after a 429 that doesn't say how long
MAX_COOLDOWN = 3600


def api_key() -> str | None:
    """The OTX key from the environment, or None (keyless)."""
    key = os.environ.get(KEY_VAR, "").strip()
    return key or None


def headers() -> dict:
    h = {"User-Agent": USER_AGENT}
    key = api_key()
    if key:
        h["X-OTX-API-KEY"] = key
    return h


def cooldown_seconds(resp) -> float:
    """How long later scans should skip OTX after a 429 (its Retry-After, capped)."""
    try:
        wait = float(resp.headers.get("Retry-After", ""))
    except ValueError:
        return DEFAULT_COOLDOWN
    return min(wait, MAX_COOLDOWN) if wait > 0 else DEFAULT_COOLDOWN


def fetch_raw(domain: str, timeout: int = TIMEOUT) -> list[dict]:
    """OTX's passive DNS records for the domain and its subdomains."""
    PACER.acquire(max_wait=MAX_WAIT)  # raises Paced (a RuntimeError) when over the limit
    try:
        resp = requests.get(API_URL.format(domain=domain), headers=headers(), timeout=timeout)
    except requests.RequestException as e:
        raise RuntimeError(f"AlienVault OTX request failed: {e}")
    if resp.status_code == 429:
        PACER.cool_down(cooldown_seconds(resp))
        hint = "" if api_key() else f" (a free key in {KEY_VAR} raises the limit)"
        raise RuntimeError(f"AlienVault OTX rate limit hit{hint}. Try again later.")
    if resp.status_code in (401, 403):
        if api_key():
            raise RuntimeError(f"AlienVault OTX refused the key in {KEY_VAR} (HTTP {resp.status_code})")
        raise RuntimeError(f"AlienVault OTX wants an API key (HTTP {resp.status_code}): "
                           f"set {KEY_VAR} (free at otx.alienvault.com)")
    if resp.status_code != 200:
        raise RuntimeError(f"AlienVault OTX returned HTTP {resp.status_code}")
    try:
        body = resp.json()
    except ValueError:  # HTML error page or cut-off body instead of JSON
        raise RuntimeError("AlienVault OTX returned invalid JSON")
    records = body.get("passive_dns") if isinstance(body, dict) else None
    if not isinstance(records, list):
        raise RuntimeError("AlienVault OTX answered without a passive DNS list")
    return [r for r in records if isinstance(r, dict)]


def parse_subdomains(records: list[dict], domain: str) -> list[str]:
    """The domain's own hostnames from the records (OTX can list other names too)."""
    # Passive DNS names can end in a dot (the DNS root); certificate names never do
    names = [r["hostname"].strip().rstrip(".") for r in records if isinstance(r.get("hostname"), str)]
    return subdomains_in(names, domain)


def collect(domain: str) -> dict:
    records = fetch_raw(domain)
    collected_at = now_utc()
    subdomains = parse_subdomains(records, domain)
    return {
        "source": "otx",
        "collected_at": collected_at,
        "domain": domain,
        "records_seen": len(records),  # passive DNS records, not certificates
        "subdomain_count": len(subdomains),
        "subdomains": subdomains,
        "keyed": api_key() is not None,
    }
