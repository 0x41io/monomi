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

CRTSH_URL = "https://crt.sh/"
from collectors import USER_AGENT, is_hostname


def fetch_raw(domain: str, retries: int = 3, timeout: int = 60) -> list[dict]:
    """Query crt.sh for all certificates matching *.domain.

    crt.sh is free and often slow or overloaded (502/503/timeouts),
    so we retry with a growing delay before giving up.
    """
    params = {"q": f"%.{domain}", "output": "json"}
    headers = {"User-Agent": USER_AGENT}
    last_error = None

    for attempt in range(1, retries + 1):
        try:
            resp = requests.get(CRTSH_URL, params=params, headers=headers, timeout=timeout)
            if resp.status_code == 200:
                # crt.sh returns an empty body (not "[]") when nothing matches
                return resp.json() if resp.text.strip() else []
            last_error = f"HTTP {resp.status_code}"
        except (requests.RequestException, ValueError) as e:
            last_error = str(e)

        if attempt < retries:
            wait = attempt * 5
            print(f"  [!] crt.sh attempt {attempt} failed ({last_error}), retrying in {wait}s...")
            time.sleep(wait)

    raise RuntimeError(f"crt.sh query failed after {retries} attempts: {last_error}")


def parse_subdomains(records: list[dict], domain: str) -> list[str]:
    """Turn raw crt.sh records into a clean, sorted, de-duplicated list."""
    domain = domain.lower()
    found = set()

    for rec in records:
        # One certificate can cover many names, separated by newlines
        for name in rec.get("name_value", "").splitlines():
            name = name.strip().lower()
            if name.startswith("*."):
                name = name[2:]  # wildcard cert -> the base it covers
            if not is_hostname(name):
                continue  # skip blanks, email addresses and anything that isn't a hostname
            if name == domain or name.endswith("." + domain):
                found.add(name)

    return sorted(found)


def collect(domain: str) -> dict:
    """Run the collector and return a structured result for the report/AI layer."""
    records = fetch_raw(domain)
    subdomains = parse_subdomains(records, domain)
    return {
        "source": "crt.sh",
        "domain": domain,
        "certificates_seen": len(records),
        "subdomain_count": len(subdomains),
        "subdomains": subdomains,
    }
