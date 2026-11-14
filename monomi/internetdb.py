"""
Exposure lookup via Shodan InternetDB: open ports and known CVEs per IP.

Shodan scans the whole internet continuously. InternetDB is its free,
no-key API that answers "what did Shodan last see on this IP?": open ports,
software fingerprints (CPEs), tags, and CVEs matched to those software
versions. We only ask Shodan about IPs we already found, so the target
itself never receives any traffic from us.

Two things to keep in mind:
- CVEs here are inferred from version banners, not confirmed. Treat them as
  leads to verify (kaidoku can triage them).
- InternetDB is free for non-commercial use. A commercial product built on
  it needs a Shodan license.
"""

import ipaddress
import re
from concurrent.futures import ThreadPoolExecutor

import requests

from monomi.common import USER_AGENT

API_URL = "https://internetdb.shodan.io/{ip}"
MAX_IPS = 200  # be polite to a free service

# Services that usually shouldn't face the internet. Port -> label.
RISKY_PORTS = {
    21: "FTP", 23: "Telnet", 445: "SMB", 1433: "MSSQL", 2375: "Docker API",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
}

# Providers whose IPs are shared edge servers. Their open ports belong to
# the CDN, not to the target's own server.
SHARED_EDGE = {"Cloudflare", "Fastly", "Akamai", "Imperva", "AWS CloudFront", "Vercel"}

# Services that host the target's site on their own servers (a store, a blog,
# a help desk, a forum). The site may be the target's, but the server isn't:
# what it shows belongs to the vendor. Names as enrich.py's KNOWN_PROVIDERS gives them.
THIRD_PARTY_HOSTING = {"GitHub", "Salesforce", "Shopify", "Squarespace", "WordPress.com",
                       "Netlify", "HubSpot", "Zendesk", "Discourse (CDCK)"}

# A shared front door that forwards to servers behind it, but isn't a CDN
SHARED_FRONT_DOOR = {"AWS Global Accelerator"}

# Shodan CPE names (software fingerprints) that mean "this IP is a shared
# edge server", even when the network owner isn't a CDN: e.g. Cloudflare
# serving from a customer's own IP range, or Okta running on AWS.
EDGE_CPES = {
    "cloudflare": "Cloudflare",
    "amazon_cloudfront": "AWS CloudFront",
    "fastly": "Fastly",
    "akamai": "Akamai",
    "okta": "Okta",
}


def edge_from_cpes(cpes: list[str]) -> tuple[str, str] | None:
    """Which shared-edge vendor Shodan's CPEs point to, if any.

    'cpe:/a:cloudflare:cloudflare' -> ('Cloudflare', 'cpe:/a:cloudflare:cloudflare')
    Matches whole CPE parts only, so 'cpe:/a:cloudflarex:thing' doesn't count.
    """
    for cpe in cpes:
        parts = cpe.lower().split(":")
        for key, vendor in EDGE_CPES.items():
            if key in parts:
                return vendor, cpe
    return None


# CNAME endings that mean "this hostname is served by a shared edge
# network", even when the network owner and Shodan don't say so, e.g.
# Okta's login servers on plain AWS IPs. Each entry: (ending, vendor).
EDGE_CNAMES = [
    (".cloudfront.net", "AWS CloudFront"),
    (".okta.com", "Okta"),
    (".fastly.net", "Fastly"),
    (".fastlylb.net", "Fastly"),
    (".akamaiedge.net", "Akamai"),
    (".edgekey.net", "Akamai"),
    (".edgesuite.net", "Akamai"),
    (".cdn.cloudflare.net", "Cloudflare"),
    (".incapdns.net", "Imperva"),
    (".azurefd.net", "Azure Front Door"),
    (".azureedge.net", "Azure CDN"),
    (".vercel.app", "Vercel"),
]


# CNAME endings with a changing number in them, which a plain ending
# can't catch: Vercel gives each domain its own numbered target, under
# vercel-dns-NNN (e.g. vercel-dns-017)
EDGE_CNAME_PATTERNS = [
    (re.compile(r"\.vercel-dns(-\d+)?\.com$"), "Vercel"),
]


def edge_from_cname(names) -> tuple[str, str] | None:
    """Which shared-edge vendor a hostname's CNAME points to, if any.

    'meli.customdomains.okta.com' -> ('Okta', 'meli.customdomains.okta.com')
    Endings start with a dot, so 'evilcloudfront.net' doesn't count.
    """
    for name in sorted(names):  # sorted: same answer every run
        for ending, vendor in EDGE_CNAMES:
            if name.endswith(ending):
                return vendor, name
        for pattern, vendor in EDGE_CNAME_PATTERNS:
            if pattern.search(name):
                return vendor, name
    return None


# IP blocks that are a shared edge network even when the network owner
# says otherwise. Vercel's blocks are announced through AWS (AS16509), so
# Team Cymru calls them "AWS". From Vercel's ARIN records (VERCEL-01..11).
VERCEL_RANGES = [
    "64.29.17.0/24",
    "64.239.109.0/24",
    "64.239.123.0/24",
    "66.33.60.0/24",
    "76.76.21.0/24",
    "198.169.1.0/24",
    "198.169.2.0/24",
    "216.150.1.0/24",
    "216.150.16.0/24",
    "216.198.79.0/24",
    "216.230.84.0/24",
    "216.230.86.0/24",
]
EDGE_RANGES = [(ipaddress.ip_network(c), "Vercel") for c in VERCEL_RANGES]


def edge_from_ip(ip) -> tuple[str, str] | None:
    """Which shared-edge vendor's IP block an IP is in, if any.

    '216.150.1.1' -> ('Vercel', '216.150.1.0/24')
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for net, vendor in EDGE_RANGES:
        if addr in net:  # an IPv6 address is never "in" an IPv4 block
            return vendor, str(net)
    return None


def edge_reason(provider: str | None, cpes: list[str], cnames=(), ip=None) -> str | None:
    """Why an IP counts as a shared edge server, or None if it doesn't."""
    if provider in SHARED_EDGE:
        return f"network owner is {provider}"
    found = edge_from_cpes(cpes)
    if found:
        vendor, cpe = found
        return f"Shodan identifies the service as {vendor} ({cpe})"
    found = edge_from_cname(cnames)
    if found:
        vendor, name = found
        return f"hostname's CNAME points to {vendor} ({name})"
    found = edge_from_ip(ip) if ip else None
    if found:
        vendor, net = found
        return f"IP is in {vendor}'s edge range ({net})"
    return None


def lookup_one(ip: str, timeout: int = 15) -> dict | None:
    """Return Shodan's data for one IP, or None if Shodan has nothing on it."""
    resp = requests.get(API_URL.format(ip=ip), headers={"User-Agent": USER_AGENT}, timeout=timeout)
    if resp.status_code == 404:
        return None  # Shodan hasn't seen anything on this IP
    resp.raise_for_status()
    data = resp.json()
    return {
        "ports": sorted(data.get("ports") or []),
        "vulns": sorted(data.get("vulns") or []),
        "tags": data.get("tags") or [],
        "cpes": data.get("cpes") or [],
    }


def _safe_lookup(ip: str):
    try:
        return ip, lookup_one(ip), None
    except (requests.RequestException, ValueError) as e:
        return ip, None, str(e)


def lookup(enrichment: dict, workers: int = 8) -> dict:
    """Look up every public IP from the --enrich step.

    Returns {"ips": {ip: {...}}, "unique_cves": [...], "risky": [...], "errors": n, "skipped": n}.
    """
    # Group hostnames by IP. Each IP gets its OWN provider from enrich's ip_info,
    # so a host's CDN edge IP and its cloud origin IP are judged separately.
    ip_info = enrichment.get("ip_info", {})
    by_ip: dict[str, dict] = {}
    for host, e in enrichment["hosts"].items():
        for ip in e["ips"]:
            if not ipaddress.ip_address(ip).is_global:
                continue  # private/internal: Shodan can't see it
            provider = ip_info.get(ip, {}).get("provider", e.get("provider"))
            entry = by_ip.setdefault(ip, {"hosts": [], "provider": provider, "canonicals": set()})
            entry["hosts"].append(host)
            if e.get("canonical"):
                entry["canonicals"].add(e["canonical"])
    ips = sorted(by_ip)
    skipped = max(0, len(ips) - MAX_IPS)
    ips = ips[:MAX_IPS]

    found, quiet, errors = {}, {}, 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for ip, data, err in pool.map(_safe_lookup, ips):
            if err:
                errors += 1
                continue
            meta = by_ip[ip]
            if not data or not (data["ports"] or data["vulns"]):
                # Shodan has nothing on this IP (yet). Still list it, so a
                # report can't mistake "no data" for "no server here".
                reason = edge_reason(meta["provider"], [], meta["canonicals"], ip)
                quiet[ip] = {"hosts": sorted(meta["hosts"]), "provider": meta["provider"],
                             "shared_edge": reason is not None}
                continue
            data["hosts"] = sorted(meta["hosts"])
            data["provider"] = meta["provider"]
            data["edge_reason"] = edge_reason(meta["provider"], data["cpes"], meta["canonicals"], ip)
            data["shared_edge"] = data["edge_reason"] is not None
            data["risky"] = [f"{p}/{RISKY_PORTS[p]}" for p in data["ports"] if p in RISKY_PORTS]
            found[ip] = data

    own = [d for d in found.values() if not d["shared_edge"]]
    return {
        "ips": found,
        "nothing_seen": quiet,
        "checked": len(ips),
        "unique_cves": sorted({c for d in own for c in d["vulns"]}),
        "risky": [(ip, d["risky"]) for ip, d in found.items() if d["risky"] and not d["shared_edge"]],
        "errors": errors,
        "skipped": skipped,
    }
