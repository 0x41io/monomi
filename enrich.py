"""
Host enrichment: resolve hostnames to IPs, then look up who hosts each IP.

- DNS: uses your normal system resolver (a standard DNS lookup, the same
  thing a browser does). This asks DNS servers, not the target's web
  servers, but it is less passive than reading CT logs, so it's opt-in
  via --enrich.
- ASN / provider: Team Cymru's free IP-to-ASN whois service (bulk mode,
  no API key). Tells you the network owner (e.g. AMAZON-02, CLOUDFLARENET)
  and country for each IP.
"""

import ipaddress
import socket
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

CYMRU_HOST = ("whois.cymru.com", 43)


def _resolve_one(host: str) -> list[str]:
    try:
        _, _, ips = socket.gethostbyname_ex(host)
        return sorted(set(ips))
    except (socket.gaierror, socket.herror, UnicodeError, OSError):
        return []


def resolve(hosts: list[str], workers: int = 32) -> dict[str, list[str]]:
    """Resolve many hostnames in parallel. Unresolvable hosts map to []."""
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return dict(zip(hosts, pool.map(_resolve_one, hosts)))


def asn_lookup(ips: list[str], timeout: int = 20) -> dict[str, dict]:
    """Bulk IP -> ASN lookup via Team Cymru whois. Returns {ip: info}."""
    if not ips:
        return {}
    query = "begin\nverbose\n" + "\n".join(ips) + "\nend\n"
    try:
        with socket.create_connection(CYMRU_HOST, timeout=timeout) as s:
            s.sendall(query.encode())
            chunks = []
            while chunk := s.recv(65536):
                chunks.append(chunk)
    except OSError as e:
        raise RuntimeError(f"Team Cymru ASN lookup failed: {e}")
    return parse_cymru("".join(c.decode(errors="replace") for c in chunks))


# Raw ASN names are noisy ("AMAZON-02, US", "FASTLY - Fastly, Inc., US").
# Map the big providers to names people recognize.
KNOWN_PROVIDERS = [
    ("AMAZON", "AWS"),
    ("CLOUDFLARE", "Cloudflare"),
    ("FASTLY", "Fastly"),
    ("GOOGLE-CLOUD", "Google Cloud"),
    ("GOOGLE", "Google"),
    ("MICROSOFT", "Microsoft/Azure"),
    ("AKAMAI", "Akamai"),
    ("LINODE", "Akamai/Linode"),
    ("DIGITALOCEAN", "DigitalOcean"),
    ("HETZNER", "Hetzner"),
    ("OVH", "OVH"),
    ("VULTR", "Vultr"),
    ("ORACLE", "Oracle Cloud"),
    ("GITHUB", "GitHub"),
    ("INCAPSULA", "Imperva"),
    ("SALESFORCE", "Salesforce"),
    ("SHOPIFY", "Shopify"),
    ("SQUARESPACE", "Squarespace"),
    ("AUTOMATTIC", "WordPress.com"),
    ("VERCEL", "Vercel"),
    ("NETLIFY", "Netlify"),
    ("HUBSPOT", "HubSpot"),
    ("ZENDESK", "Zendesk"),
]


def friendly_name(as_name: str) -> str:
    upper = as_name.upper()
    for key, nice in KNOWN_PROVIDERS:
        if upper.startswith(key) or f" {key}" in upper:
            return nice
    # Fallback: "SOME-ISP - Some ISP Inc., US" -> "SOME-ISP"
    return as_name.split(" - ")[0].rsplit(",", 1)[0].strip()


def parse_cymru(text: str) -> dict[str, dict]:
    """Parse lines like:
    15169   | 8.8.8.8 | 8.8.8.0/24 | US | arin | 2023-12-28 | GOOGLE, US
    """
    out = {}
    for line in text.splitlines():
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 7 or parts[0] in ("AS", "") or line.startswith("Bulk mode"):
            continue
        asn, ip, prefix, cc, registry, _, as_name = parts[:7]
        if asn == "NA":
            continue
        out[ip] = {"asn": f"AS{asn}", "as_name": friendly_name(as_name), "raw_as_name": as_name,
                   "prefix": prefix, "country": cc}
    return out


def enrich(hosts: list[str]) -> dict:
    """Resolve + ASN-enrich hosts. Returns per-host data, per-IP data and a provider summary."""
    resolved = resolve(hosts)

    all_ips = sorted({ip for ips in resolved.values() for ip in ips})
    public_ips = [ip for ip in all_ips if ipaddress.ip_address(ip).is_global]
    asn_error = None
    try:
        asn = asn_lookup(public_ips)
    except RuntimeError as e:
        asn, asn_error = {}, str(e)

    # Owner of EVERY IP, not just one per host. A host can sit on several
    # providers (e.g. a Cloudflare edge IP plus an AWS origin IP), and later
    # steps (Shodan's CDN filter) must judge each IP on its own.
    ip_info = {}
    for ip in all_ips:
        if not ipaddress.ip_address(ip).is_global:
            ip_info[ip] = {"provider": "PRIVATE IP"}  # internal address in public DNS
        else:
            info = asn.get(ip, {})
            ip_info[ip] = {**info, "provider": info.get("as_name", "unknown")}

    per_host = {}
    for host in hosts:
        ips = resolved.get(host, [])
        entry = {"ips": ips}
        if not ips:
            entry["provider"] = None  # in CT logs but no DNS record now
            entry["providers"] = []
            per_host[host] = entry
            continue

        public = [ip for ip in ips if ip_info[ip]["provider"] != "PRIVATE IP"]
        entry["private_ips"] = [ip for ip in ips if ip_info[ip]["provider"] == "PRIVATE IP"]
        if not public:
            entry["provider"] = "PRIVATE IP"
            entry["providers"] = ["PRIVATE IP"]
        else:
            # Main label = the provider holding most of this host's public IPs
            counts = Counter(ip_info[ip]["provider"] for ip in public)
            entry["providers"] = [p for p, _ in counts.most_common()]
            main = entry["providers"][0]
            first = next(ip for ip in public if ip_info[ip]["provider"] == main)
            entry.update({k: v for k, v in ip_info[first].items() if k != "provider"})
            entry["provider"] = main
        per_host[host] = entry

    providers = Counter(e["provider"] or "no DNS record" for e in per_host.values())
    return {
        "hosts": per_host,
        "ip_info": ip_info,
        "providers": dict(providers.most_common()),
        "resolved": sum(1 for e in per_host.values() if e["ips"]),
        "unique_ips": len({ip for e in per_host.values() for ip in e["ips"]}),
        # Any internal IP counts, even if the host also has public ones
        "private_ip_hosts": [h for h, e in per_host.items() if e.get("private_ips")],
        "asn_error": asn_error,
    }
