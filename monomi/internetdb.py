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
MAX_IPS = 200       # be polite to a free service: CDN edges are looked up only within this
MAX_OWN_IPS = 1000  # the target's own servers, all of them in practice (v1.29.2: PlayStation has ~236)

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
                       "Netlify", "HubSpot", "Zendesk", "Discourse (CDCK)", "Zoho"}

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
    # Front Door's CNAME chain ends on these, not on azurefd.net (v1.23, the
    # Superdrug dev portal: ...azurefd.net -> mr-a02.tm-azurefd.net)
    (".tm-azurefd.net", "Azure Front Door"),
    (".t-msedge.net", "Azure Front Door"),
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


# Addresses where the provider runs a shared service for many customers,
# inside networks it also rents out as customers' own servers. The network
# owner ("Google", "Microsoft/Azure") can't tell the two apart, so the
# address decides (v1.22.1, from the Marionnaud field run: autodiscover and
# ecom-data pointed here and made 8 of 9 around-the-CDN leads).
#   Google's shared front end for custom domains: the four A records Google's
#   "Configure A records" help page gives (exact IPs only: the rest of
#   216.239.32.0/19 is other Google services)
#   Microsoft 365 Exchange Online: the IPv4 blocks Microsoft's "Microsoft 365
#   URLs and IP address ranges" page lists for outlook.office365.com
GOOGLE_FRONT_END = ["216.239.32.21/32", "216.239.34.21/32", "216.239.36.21/32", "216.239.38.21/32"]
EXCHANGE_ONLINE = [
    "13.107.6.152/31",
    "13.107.18.10/31",
    "13.107.128.0/22",
    "23.103.160.0/20",
    "40.96.0.0/13",
    "40.104.0.0/15",
    "52.96.0.0/14",
    "131.253.33.215/32",
    "132.245.0.0/16",
    "150.171.32.0/22",
    "204.79.197.215/32",
]
#   Shopify's storefront block: its help pages give 23.227.38.65, and stores
#   are moved between addresses in this block (.32, .36, .65...) (v1.23)
SHOPIFY_STOREFRONT = ["23.227.38.0/24"]
THIRD_PARTY_RANGES = ([(ipaddress.ip_network(c), "Google front end") for c in GOOGLE_FRONT_END]
                      + [(ipaddress.ip_network(c), "Microsoft 365") for c in EXCHANGE_ONLINE]
                      + [(ipaddress.ip_network(c), "Shopify") for c in SHOPIFY_STOREFRONT])


def third_party_from_ip(ip) -> tuple[str, str] | None:
    """Which shared service's addresses an IP is in, if any.

    '52.96.79.8' -> ('Microsoft 365', '52.96.0.0/14')
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for net, vendor in THIRD_PARTY_RANGES:
        if addr in net:
            return vendor, str(net)
    return None


# CNAME endings that mean "a shared service hosts this name for many
# customers": the server isn't the target's own, even though the network
# owner ("Microsoft/Azure") also rents out servers that are (v1.23, from the
# Superdrug run: appt and appt-uat sat on Static Web Apps, gp11022025-api on
# an App Service front end). Each entry: (ending, vendor).
THIRD_PARTY_CNAMES = [
    (".azurestaticapps.net", "Azure Static Web Apps"),
    (".azurewebsites.net", "Azure App Service"),
    (".myshopify.com", "Shopify"),
    # Hosted careers sites, help desks, status pages and email platforms: the
    # around-the-CDN noise in every v1.22 field run. A vendor found in a field
    # run that isn't listed shows up set aside with its CNAME named, so it can be added
    (".myworkdayjobs.com", "Workday"),
    (".greenhouse.io", "Greenhouse"),
    (".lever.co", "Lever"),
    (".smartrecruiters.com", "SmartRecruiters"),
    (".icims.com", "iCIMS"),
    (".taleo.net", "Oracle Taleo"),
    (".zendesk.com", "Zendesk"),
    (".freshdesk.com", "Freshdesk"),
    (".statuspage.io", "Atlassian Statuspage"),
    (".hs-sites.com", "HubSpot"),
    (".mktoweb.com", "Marketo"),
    (".sendgrid.net", "SendGrid"),
    (".mailgun.org", "Mailgun"),
]

# App Service names end on a shared front end ("scale unit") such as
# waws-prod-ln1-175-3cf9.uksouth.cloudapp.azure.com. Only waws-prod names:
# any other cloudapp.azure.com name is a customer's own VM or load balancer.
THIRD_PARTY_CNAME_PATTERNS = [
    (re.compile(r"(^|\.)waws-prod-[a-z0-9-]+\.[a-z0-9-]+\.cloudapp\.azure\.com$"), "Azure App Service"),
]


# CNAME endings that are cloud infrastructure the target rents for itself: a
# load balancer, a VM. A host pointing here is outside the target's domain by
# name but runs on the target's own server, the classic origin behind a CDN,
# so rule F keeps it as a lead and ranks it first (v1.23). Patterns, since the
# region sits in the middle of the name.
CLOUD_INFRA_CNAMES = [
    (re.compile(r"\.elb\.amazonaws\.com$"), "AWS load balancer"),
    (re.compile(r"\.elb\.[a-z0-9-]+\.amazonaws\.com$"), "AWS load balancer"),
    (re.compile(r"\.compute(-1)?\.amazonaws\.com$"), "AWS EC2"),
    (re.compile(r"\.cloudapp\.azure\.com$"), "Azure VM or load balancer"),
    (re.compile(r"\.cloudapp\.net$"), "Azure VM or load balancer"),
    (re.compile(r"\.googleusercontent\.com$"), "Google Cloud VM"),
]


def cloud_infra_from_cname(names) -> tuple[str, str] | None:
    """Which rented cloud server a CNAME points to, if any. App Service's
    shared front ends match third_party_from_cname first: callers check that one before this.

    'web-1a2b.eu-west-1.elb.amazonaws.com' -> ('AWS load balancer', 'web-1a2b.eu-west-1.elb.amazonaws.com')
    """
    for name in sorted(n.lower().rstrip(".") for n in names if n):
        for pattern, kind in CLOUD_INFRA_CNAMES:
            if pattern.search(name):
                return kind, name
    return None


def third_party_from_cname(names) -> tuple[str, str] | None:
    """Which shared hosting service a hostname's CNAME points to, if any.

    'x.azurestaticapps.net' -> ('Azure Static Web Apps', 'x.azurestaticapps.net')
    Endings start with a dot, so 'evilazurestaticapps.net' doesn't count.
    """
    for name in sorted(n.lower().rstrip(".") for n in names if n):  # sorted: same answer every run
        for ending, vendor in THIRD_PARTY_CNAMES:
            if name.endswith(ending):
                return vendor, name
        for pattern, vendor in THIRD_PARTY_CNAME_PATTERNS:
            if pattern.search(name):
                return vendor, name
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


def is_own(d: dict) -> bool:
    """Whether an IP's Shodan data (from lookup()) belongs to the target: not a
    shared CDN edge and not someone else's server (third-party hosting, a
    shared front door). Only these count as the target's CVEs and risky
    services (v1.23.1: CVEs on Google's shared front end were counted as the
    target's, and 0x41's report listed them as such)."""
    return not d.get("shared_edge") and not d.get("not_own")


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

    Returns {"ips": {ip: {...}}, "unique_cves": [...], "risky": [...], "errors": n, "skipped": n,
    "skipped_edges": n, "checked_own": n}. The target's own servers are looked
    up first, up to MAX_OWN_IPS; CDN edges only within MAX_IPS in all.
    An IP that's someone else's server (not a CDN edge) has "not_own": what it is
    (v1.23.1); unique_cves and risky are the target's own IPs only (is_own).
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
    # The target's own servers first, CDN edges last (v1.29.2, from PlayStation:
    # 655 IPs in text order, so a cut at 200 skipped zitadel.sit.pcs while
    # checking Akamai edges, whose open ports belong to the CDN anyway). Whether
    # an IP is an edge is known before any lookup, from its provider, CNAMEs and
    # address; a vendor that only Shodan's own data reveals is still found after.

    def is_edge(ip):
        meta = by_ip[ip]
        return edge_reason(meta["provider"], [], meta["canonicals"], ip) is not None
    # The target's own servers are checked up to MAX_OWN_IPS; CDN edges only in
    # the room left under MAX_IPS, since what they show belongs to the CDN.
    own_ips = sorted(ip for ip in by_ip if not is_edge(ip))
    edge_ips = sorted(ip for ip in by_ip if is_edge(ip))
    room = max(0, MAX_IPS - min(len(own_ips), MAX_OWN_IPS))
    ips = own_ips[:MAX_OWN_IPS] + edge_ips[:room]
    skipped_own, skipped_edges = max(0, len(own_ips) - MAX_OWN_IPS), max(0, len(edge_ips) - room)
    skipped = skipped_own + skipped_edges

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

    # Someone else's server, though not a CDN edge (v1.23.1): labeled with what
    # it is, the same words the gate uses (gate.not_own_ips decides, in one place)
    from monomi import gate  # here, not at the top: gate imports this module
    not_own = gate.not_own_ips({"enrichment": enrichment})
    for ip, d in [*found.items(), *quiet.items()]:
        if not d["shared_edge"] and ip in not_own:
            d["not_own"] = not_own[ip]

    own = [d for d in found.values() if is_own(d)]
    return {
        "ips": found,
        "nothing_seen": quiet,
        "checked": len(ips),
        "unique_cves": sorted({c for d in own for c in d["vulns"]}),
        "risky": [(ip, d["risky"]) for ip, d in found.items() if d["risky"] and is_own(d)],
        "errors": errors,
        "skipped": skipped,
        "skipped_edges": skipped_edges,   # of the skipped, how many are CDN edges (v1.29.2)
        "checked_own": min(len(own_ips), MAX_OWN_IPS),
    }
