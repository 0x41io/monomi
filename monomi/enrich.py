"""
Host enrichment: resolve hostnames to IPs, then look up who hosts each IP.

- DNS: uses your normal system resolver (a standard DNS lookup, the same
  thing a browser does). This asks DNS servers, not the target's web
  servers, but it is less passive than reading CT logs, so it's opt-in
  via --enrich.
- ASN / provider: Team Cymru's free IP-to-ASN whois service (bulk mode,
  no API key). Tells you the network owner (e.g. AMAZON-02, CLOUDFLARENET)
  and country for each IP.
- Wildcards (v1.18): a zone with a wildcard record (*.example.com) answers
  for ANY name, so junk names from passive DNS look live. Monomi asks DNS
  about a few made-up names in each zone; hosts whose answer matches the
  wildcard's are set aside in "wildcard_only" instead of counted as hosts.
"""

import ipaddress
import secrets
import socket

from monomi import aws_ranges
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from monomi.dnscheck import DNSLookupError, NoSuchHost, get_cname, host_status
from monomi.scope import SHARED_SUFFIXES

CYMRU_HOST = ("whois.cymru.com", 43)

# Made-up names asked per zone. A CDN wildcard hands out a different few
# IPs each time, so one answer would miss part of its pool.
WILDCARD_PROBES = 3
WILDCARD_EXAMPLES = 5   # set-aside hosts named per wildcard (the rest are in --json)


def _resolve_one(host: str) -> dict:
    """IPv4 addresses for one host, plus where its CNAME chain ends.

    gethostbyname_ex returns (canonical_name, aliases, ips). The canonical
    name is the last name in the CNAME chain, e.g. 'd3rx...cloudfront.net'
    for gslink.hackerone.com. If the host has no CNAME, it's the host itself,
    so we store None.
    """
    try:
        canonical, _, ips = socket.gethostbyname_ex(host)
    except (socket.gaierror, socket.herror, UnicodeError, OSError):
        return {"ips": [], "canonical": None}
    canonical = canonical.rstrip(".").lower()
    if canonical == host.rstrip(".").lower():
        canonical = None
    return {"ips": sorted(set(ips)), "canonical": canonical}


def resolve(hosts: list[str], workers: int = 32) -> dict[str, dict]:
    """Resolve many hostnames in parallel: {host: {"ips": [...], "canonical": ...}}.
    Unresolvable hosts get "ips": []."""
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


# Why a host has no IPv4 address, as short labels for the provider summary.
# The status words come from dnscheck.host_status(), shared by every check.
DNS_LABELS = {
    "no_such_host": "no DNS record",            # NXDOMAIN, double-checked over HTTPS
    "dangling_cname": "CNAME to a deleted name",  # host exists, its CNAME target doesn't
    "ipv6_only": "IPv6 only",                   # live, just no IPv4 address
    "no_address": "no IP address",              # no A or AAAA record (may still be retired: Cloudflare never says NXDOMAIN)
    "conflicting": "conflicting DNS answers",   # system DNS and DNS-over-HTTPS disagree: unknown
    "servfail": "DNS server failure",           # SERVFAIL even after a retry: unknown
    "lookup_failed": "DNS lookup failed",       # no DNS server answered: unknown
    "gone": "no DNS record",                    # pre-v1.8 name for no_such_host (old saved scans)
}


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
    ("CDCK", "Discourse (CDCK)"),  # Civilized Discourse Construction Kit: hosted Discourse forums
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


def _random_label() -> str:
    """A label no real host has, e.g. "monomi-wc-3f9a1c0b7d2e"."""
    return "monomi-wc-" + secrets.token_hex(6)


def _zone_of(host: str) -> str | None:
    """The zone a host sits in (everything after its first label), or None
    when that would be a TLD or a shared suffix like co.uk: never probed."""
    parts = host.rstrip(".").lower().split(".", 1)
    if len(parts) < 2 or "." not in parts[1] or parts[1] in SHARED_SUFFIXES:
        return None
    return parts[1]


def wildcard_answers(zones: list[str], workers: int = 32) -> tuple[dict, str | None]:
    """Find the zones with a wildcard record, by asking DNS about made-up names.

    A made-up name can only resolve through a wildcard, so a zone where any
    of WILDCARD_PROBES random names answers has one. Returns
    ({zone: {"ips": [...], "canonicals": [...]}}, None): every IP and CNAME
    end the made-up names got. Returns ({}, reason) when the check can't be
    trusted: some resolvers (ISPs, VPNs) answer for names that don't exist,
    which would make every zone look like a wildcard, so that's tested first
    with a made-up domain right under the TLD. Same lookups as resolve():
    DNS only, never the target's servers.
    """
    if not zones:
        return {}, None
    tld = zones[0].rsplit(".", 1)[-1]
    if _resolve_one(f"{_random_label()}-{_random_label()}.{tld}")["ips"]:
        return {}, "your DNS resolver answers for names that don't exist, so wildcards can't be told apart"
    names = {z: [f"{_random_label()}.{z}" for _ in range(WILDCARD_PROBES)] for z in zones}
    flat = [n for ns in names.values() for n in ns]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        answers = dict(zip(flat, pool.map(_resolve_one, flat)))
    found = {}
    for zone, ns in names.items():
        got = [answers[n] for n in ns if answers[n]["ips"]]
        if got:
            found[zone] = {"ips": sorted({ip for a in got for ip in a["ips"]}),
                           "canonicals": sorted({a["canonical"] for a in got if a["canonical"]})}
    return found, None


def through_wildcard(entry: dict, wildcard: dict) -> bool:
    """True when a host's DNS answer is what its zone's wildcard gives any
    made-up name, so DNS can't tell the host apart from a name that was never
    set up. A wildcard that's a CNAME is matched by where the chain ends (the
    exact answer); one that's plain A records by sharing an IP with its pool
    (a CDN rotates IPs), and only for hosts with no CNAME of their own."""
    if not entry.get("ips"):
        return False
    if wildcard["canonicals"]:
        return entry.get("canonical") in wildcard["canonicals"]
    return entry.get("canonical") is None and bool(set(entry["ips"]) & set(wildcard["ips"]))


def _cname_target(host: str) -> str | None:
    """Where a dangling host's CNAME points, or None if DNS won't say now."""
    try:
        return get_cname(host)
    except (NoSuchHost, DNSLookupError):
        return None


def enrich(hosts: list[str]) -> dict:
    """Resolve + ASN-enrich hosts. Returns per-host data, per-IP data and a provider summary."""
    resolved = resolve(hosts)
    unresolved = [h for h in hosts if not resolved[h]["ips"]]
    # Second look at hosts the fast lookup couldn't resolve. The shared DNS
    # helper says why, and finds the IPs if the fast lookup just failed
    # (e.g. WSL's DNS cache replaying a stale "no such name").
    with ThreadPoolExecutor(max_workers=16) as pool:
        second = dict(zip(unresolved, pool.map(host_status, unresolved)))
    status = {}
    for host, (word, ips) in second.items():
        if ips:
            resolved[host]["ips"] = ips   # live after all: keep the IPs
        else:
            status[host] = word
            if word == "dangling_cname":
                resolved[host]["cname"] = _cname_target(host)
    # Wildcards: probe every zone a live host sits in. Their IPs join the ASN
    # lookup below, so a wildcard's provider can be named.
    zones = sorted({z for h in hosts if resolved[h]["ips"] and (z := _zone_of(h))})
    wildcards, wildcard_error = wildcard_answers(zones)
    all_ips = sorted({ip for r in resolved.values() for ip in r["ips"]}
                     | {ip for w in wildcards.values() for ip in w["ips"]})
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

    # Amazon's ASN covers both CloudFront edges and normal AWS servers; use
    # Amazon's published range list to tell them apart. Only downloaded when
    # the scan actually has AWS IPs.
    cdn_error = None
    aws_ips = [ip for ip, i in ip_info.items() if i["provider"] == "AWS"]
    if aws_ips:
        try:
            nets = aws_ranges.cloudfront_networks()
            accelerators = aws_ranges.accelerator_networks()
        except RuntimeError as e:
            cdn_error = str(e)
        else:
            for ip in aws_ips:
                if aws_ranges.in_networks(ip, nets):
                    ip_info[ip]["provider"] = "AWS CloudFront"
                elif aws_ranges.in_networks(ip, accelerators):
                    ip_info[ip]["provider"] = "AWS Global Accelerator"

    per_host = {}
    for host in hosts:
        ips = resolved[host]["ips"]
        entry = {"ips": ips, "canonical": resolved[host]["canonical"],
                 "dns": status.get(host, "live")}
        if not ips:
            entry["provider"] = None  # in CT logs, but no IPv4 address now
            entry["providers"] = []
            if "cname" in resolved[host]:
                entry["cname"] = resolved[host]["cname"]   # where the dangling CNAME points
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

    # Set aside the hosts that only resolve through their zone's wildcard:
    # kept in "wildcard_only" (host -> zone), left out of every count below
    # and of "hosts", which is what every later step reads.
    wildcard_only = {}
    for host in hosts:
        zone = _zone_of(host)
        if zone in wildcards and through_wildcard(per_host[host], wildcards[zone]):
            wildcard_only[host] = zone
    per_host = {h: e for h, e in per_host.items() if h not in wildcard_only}
    wildcard_info = {}
    for zone, w in wildcards.items():
        members = sorted(h for h, z in wildcard_only.items() if z == zone)
        provs = Counter(ip_info[ip]["provider"] for ip in w["ips"] if ip in ip_info)
        wildcard_info[zone] = {
            **w,
            "provider": provs.most_common(1)[0][0] if provs else None,
            "private": any(ip_info.get(ip, {}).get("provider") == "PRIVATE IP" for ip in w["ips"]),
            "hosts": len(members),
            "examples": members[:WILDCARD_EXAMPLES],
        }

    providers = Counter(e["provider"] or DNS_LABELS.get(e["dns"], "no IPv4 address")
                        for e in per_host.values())
    not_resolving = {}
    for host, e in per_host.items():
        if not e["ips"]:
            not_resolving.setdefault(e["dns"], []).append(host)
    return {
        "hosts": per_host,
        "ip_info": ip_info,
        "providers": dict(providers.most_common()),
        "resolved": sum(1 for e in per_host.values() if e["ips"]),
        "not_resolving": not_resolving,
        "unique_ips": len({ip for e in per_host.values() for ip in e["ips"]}),
        # Any internal IP counts, even if the host also has public ones
        "private_ip_hosts": [h for h, e in per_host.items() if e.get("private_ips")],
        "asn_error": asn_error,
        "cdn_error": cdn_error,
        "wildcards": wildcard_info,           # zone -> its answer, provider, how many hosts set aside
        "wildcard_only": wildcard_only,       # host -> zone, for hosts set aside
        "wildcard_error": wildcard_error,     # why the wildcard check was skipped, or None
    }
