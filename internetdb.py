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

from concurrent.futures import ThreadPoolExecutor

import requests

from collectors import USER_AGENT

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
SHARED_EDGE = {"Cloudflare", "Fastly", "Akamai", "Imperva"}


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
    # Group hostnames by IP, using the provider info enrich already found
    by_ip: dict[str, dict] = {}
    for host, e in enrichment["hosts"].items():
        provider = e.get("provider")
        if not e["ips"] or provider == "PRIVATE IP":
            continue
        for ip in e["ips"]:
            entry = by_ip.setdefault(ip, {"hosts": [], "provider": provider})
            entry["hosts"].append(host)

    ips = sorted(by_ip)
    skipped = max(0, len(ips) - MAX_IPS)
    ips = ips[:MAX_IPS]

    found, errors = {}, 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for ip, data, err in pool.map(_safe_lookup, ips):
            if err:
                errors += 1
                continue
            if not data or not (data["ports"] or data["vulns"]):
                continue  # nothing exposed that Shodan knows of
            meta = by_ip[ip]
            data["hosts"] = sorted(meta["hosts"])
            data["provider"] = meta["provider"]
            data["shared_edge"] = meta["provider"] in SHARED_EDGE
            data["risky"] = [f"{p}/{RISKY_PORTS[p]}" for p in data["ports"] if p in RISKY_PORTS]
            found[ip] = data

    own = [d for d in found.values() if not d["shared_edge"]]
    return {
        "ips": found,
        "checked": len(ips),
        "unique_cves": sorted({c for d in own for c in d["vulns"]}),
        "risky": [(ip, d["risky"]) for ip, d in found.items() if d["risky"] and not d["shared_edge"]],
        "errors": errors,
        "skipped": skipped,
    }
