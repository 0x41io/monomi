"""
HTTP tech fingerprinting: what software is a host running?

This is monomi's one opt-in ACTIVE check. For each host we make a single,
normal request for the homepage (the same thing a browser does) and read
the response headers. Headers like Server and X-Powered-By often name the
web server and language (nginx, Apache, PHP, ASP.NET...).

Only runs with --fingerprint. Passive stays the default.
"""

import ipaddress
import re
from concurrent.futures import ThreadPoolExecutor

import requests

from common import USER_AGENT, now_utc

# A version number like 2.4.41 or 7.4: digits, then one or more ".digits".
VERSION_RE = re.compile(r"\d+(?:\.\d+)+")

# Headers whose VALUE names the software, e.g. "server: nginx/1.18.0".
NAMING_HEADERS = ["server", "x-powered-by", "x-generator"]

# Headers whose mere PRESENCE gives the platform away. Header -> tech.
TELLTALE_HEADERS = {
    "cf-ray": "Cloudflare",
    "x-vercel-id": "Vercel",
    "x-amz-cf-id": "AWS CloudFront",
    "x-shopify-stage": "Shopify",
    "x-drupal-cache": "Drupal",
    "x-aspnet-version": "ASP.NET",
    "x-litespeed-cache": "LiteSpeed",
}

# Cookie names that give away the language or app behind the site.
TELLTALE_COOKIES = {
    "phpsessid": "PHP",
    "jsessionid": "Java",
    "asp.net_sessionid": "ASP.NET",
    "laravel_session": "Laravel (PHP)",
    "ci_session": "CodeIgniter (PHP)",
    "wordpress_": "WordPress",
    "wp-settings": "WordPress",
}

# Cap on hosts per run: keeps the active check small and polite.
MAX_HOSTS = 100
def fetch_headers(host: str, timeout: int = 10) -> dict:
    """Request https://host/ once and return what came back.

    Returns {"host", "url", "status", "headers", "collected_at"}.
    Raises requests.RequestException if the host can't be reached.
    """
    url = f"https://{host}/"
    resp = requests.get(
        url,
        headers={"User-Agent": USER_AGENT},
        timeout=timeout,
        allow_redirects=False,
        stream=True,
    )
    resp.close()
    return {
        "host": host,
        "url": url,
        "status": resp.status_code,
        "headers": {name.lower(): value for name, value in resp.headers.items()},
        "collected_at": now_utc(),
    }


def _base(tech: str) -> str:
    """'PHP/7.4.3' -> 'php', 'Apache/2.4.41 (Ubuntu)' -> 'apache'. Used to spot repeats."""
    return tech.split("/")[0].split(" ")[0].lower()


def _add(found: list, tech: str, evidence: str) -> None:
    """Add one detected tech to the list, unless it's already there."""
    for item in found:
        if _base(item["tech"]) == _base(tech):
            return  # already have it (keeps the first, most detailed one)
    match = VERSION_RE.search(tech)
    found.append({
        "tech": tech,
        "version": match.group() if match else None,
        "evidence": evidence,
    })


def detect(result: dict) -> list[dict]:
    """Turn fetch_headers() output into a list of detected technologies.

    Each item: {"tech", "version" (or None), "evidence"}.
    """
    headers = result["headers"]
    found = []

    for name in NAMING_HEADERS:
        if name in headers:
            _add(found, headers[name], f"{name}: {headers[name]}")

    for name, tech in TELLTALE_HEADERS.items():
        if name in headers:
            _add(found, tech, f"{name} header present")

    cookies = headers.get("set-cookie", "").lower()
    for cookie, tech in TELLTALE_COOKIES.items():
        if cookie in cookies:
            _add(found, tech, f"set-cookie has {cookie}")

    return found

def _safe_fetch(host: str):
    """fetch_headers() that never crashes: returns (host, result, error)."""
    try:
        return host, fetch_headers(host), None
    except requests.RequestException as e:
        return host, None, type(e).__name__


def fingerprint_all(enrichment: dict, workers: int = 8) -> dict:
    """Fingerprint every host from --enrich that has a public IP.

    Returns {"hosts": {host: result + "techs"}, "checked", "errors", "skipped"}.
    """
    hosts = sorted(
        host for host, e in enrichment["hosts"].items()
        if any(ipaddress.ip_address(ip).is_global for ip in e["ips"])
    )
    skipped = max(0, len(hosts) - MAX_HOSTS)
    hosts = hosts[:MAX_HOSTS]

    found, errors = {}, {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for host, result, err in pool.map(_safe_fetch, hosts):
            if err:
                errors[host] = err
                continue
            result["techs"] = detect(result)
            found[host] = result
    return {"hosts": found, "checked": len(hosts), "errors": errors, "skipped": skipped}

if __name__ == "__main__":
    import sys

    result = fetch_headers(sys.argv[1])
    print(f"{result['url']}  ->  HTTP {result['status']}  ({result['collected_at']})")
    if "location" in result["headers"]:
        print(f"  redirects to: {result['headers']['location']}")
    techs = detect(result)
    if not techs:
        print("  no technology clues in the headers")
    for item in techs:
        version = f"  [version {item['version']}]" if item["version"] else ""
        print(f"  {item['tech']}{version}  <-  {item['evidence']}")
