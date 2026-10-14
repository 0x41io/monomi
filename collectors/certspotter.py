"""
Cert Spotter subdomain collector (backup / second source to crt.sh).

Cert Spotter (by SSLMate) also watches Certificate Transparency logs and has
a free API that works without a key for light use. It only returns
certificates that are currently valid, so it usually finds fewer names than
crt.sh, but it's much more reliable. Still 100% passive.
"""

import requests

API_URL = "https://api.certspotter.com/v1/issuances"
from collectors import USER_AGENT, is_hostname
MAX_PAGES = 5  # be gentle with the free tier (no API key)


def fetch_raw(domain: str, timeout: int = 30) -> list[dict]:
    """Fetch issuances for domain + subdomains, following pagination."""
    params = {"domain": domain, "include_subdomains": "true", "expand": "dns_names"}
    headers = {"User-Agent": USER_AGENT}
    records = []

    for _ in range(MAX_PAGES):
        try:
            resp = requests.get(API_URL, params=params, headers=headers, timeout=timeout)
        except requests.RequestException as e:
            raise RuntimeError(f"Cert Spotter request failed: {e}")

        if resp.status_code == 429:
            if records:
                break  # rate limited mid-way: keep what we already have
            raise RuntimeError("Cert Spotter rate limit hit (free tier). Try again later.")
        if resp.status_code != 200:
            raise RuntimeError(f"Cert Spotter returned HTTP {resp.status_code}")

        try:
            page = resp.json()
        except ValueError:  # HTML error page or cut-off body instead of JSON
            if records:
                break  # keep the pages we already got
            raise RuntimeError("Cert Spotter returned invalid JSON")
        if not page:
            break
        records.extend(page)
        params["after"] = page[-1]["id"]  # next page starts after the last id

    return records


def parse_subdomains(records: list[dict], domain: str) -> list[str]:
    domain = domain.lower()
    found = set()
    for rec in records:
        for name in rec.get("dns_names", []):
            name = name.strip().lower()
            if name.startswith("*."):
                name = name[2:]
            if not is_hostname(name):
                continue
            if name == domain or name.endswith("." + domain):
                found.add(name)
    return sorted(found)


def collect(domain: str) -> dict:
    records = fetch_raw(domain)
    subdomains = parse_subdomains(records, domain)
    return {
        "source": "certspotter",
        "domain": domain,
        "certificates_seen": len(records),
        "subdomain_count": len(subdomains),
        "subdomains": subdomains,
    }
