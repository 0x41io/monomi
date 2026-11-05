"""
Monomi MCP server: lets AI agents (Claude Desktop, Claude Code, etc.)
run Monomi's passive checks as tools.

Run it with:  python mcp_server.py
It talks over stdin/stdout, so it prints nothing and waits for an agent.
"""
import contextlib
import re
import sys

from monomi import clean_domain, collect_ct
from categorize import categorize_all
from emailauth import check_email
from takeover import check_hosts
from enrich import enrich
import internetdb
import threatintel
from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

# The server itself. "monomi" is the name agents will see.
mcp = MCPServer("monomi")

# The Claude app's bridge gives up after 60s, so crt.sh gets at most 50s.
# That leaves room for Cert Spotter (which runs after it) plus overhead.
CRTSH_BUDGET = 50
TOTAL_BUDGET = 45  # whole find_subdomains call; leaves room under the Claude app's 60s limit

# Max hostnames one tool call handles, to stay under the 60s limit.
MAX_HOSTS = 200
MAX_IPS = 10  # investigate_ip asks 4 sources per IP, one IP at a time
MAX_PORT_HOSTS = 100  # check_ports also queries Shodan per IP, so it's slower


# One DNS label (the parts between dots): letters, digits, hyphens (not at
# either end) and underscores (used in names like _dmarc), 1-63 characters
LABEL_RE = re.compile(r"[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?")


def hostname_problem(host: str) -> str | None:
    """Why this (already lowercased) input isn't a hostname, or None if it is."""
    if any(c in host for c in "[]()"):
        return "contains brackets: looks like a pasted Markdown link"
    if "://" in host or "/" in host:
        return "looks like a URL: pass just the hostname, without https:// or a path"
    if "*" in host:
        return "a wildcard name can't be looked up: pass real hostnames"
    if len(host) > 253:
        return "too long to be a hostname (253 characters max)"
    if not all(LABEL_RE.fullmatch(label) for label in host.split(".")):
        return "not a valid hostname (only letters, digits, hyphens and dots)"
    return None


def clean_hosts(hostnames: list[str], limit: int = MAX_HOSTS) -> tuple[list[str], int, list[dict]]:
    """Normalize, dedupe, validate and cap a hostname list sent by an agent.
    Returns (hosts to check, how many were skipped over the cap,
    inputs that aren't hostnames, each with the reason, at most 20)."""
    hosts, rejected = set(), []
    for raw in hostnames:
        h = raw.strip().lower().rstrip(".")
        if not h:
            continue
        problem = hostname_problem(h)
        if problem:
            rejected.append({"host": raw[:100], "reason": problem})  # cut long junk short
        else:
            hosts.add(h)
    hosts = sorted(hosts)
    return hosts[:limit], max(len(hosts) - limit, 0), rejected[:20]

@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False))
def ping(name: str = "world") -> str:
    """Say hello. Used to check that the Monomi MCP server is connected."""
    return f"hello {name}, monomi MCP server is running"


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=True))
def find_subdomains(domain: str) -> dict:
    """Find a domain's subdomains from public Certificate Transparency logs
    (crt.sh and Cert Spotter). Passive: never contacts the target itself.
    Also returns wildcard cert names (*.example.com): a wildcard means there
    are likely more subdomains that CT logs can't list.
    Usually under a minute. If crt.sh is too slow, results come from
    Cert Spotter alone and "errors" says crt.sh timed out.
    Each hostname also gets a rule-based category (non-production, legacy,
    access, iot-ot, partner-portal, internal-tools, app-api, email, marketing, content, apex,
    uncategorized) with the reason
    it matched: facts from naming patterns, not confirmed by contacting hosts."""
    domain = clean_domain(domain)

    results = {"sources": {}, "errors": {}}
    with contextlib.redirect_stdout(sys.stderr):
        collect_ct(results, domain, crtsh_budget=CRTSH_BUDGET, crtsh_light=True, total_budget=TOTAL_BUDGET)
    hostnames = sorted({h for r in results["sources"].values() for h in r["subdomains"]})
    wildcards = sorted({w for r in results["sources"].values() for w in r.get("wildcards", [])})
    categories = categorize_all(hostnames, domain)

    return {
        "domain": domain,
        "hostname_count": len(hostnames),
        "hostnames": hostnames,
        "wildcards": wildcards,
        "categories": categories,
        "sources": {
            name: {
                "found": r["subdomain_count"],
                "certificates_seen": r.get("certificates_seen"),
                "collected_at": r["collected_at"],
            }
            for name, r in results["sources"].items()
        },
        "errors": results["errors"],
    }


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=True))
def check_email_auth(domain: str) -> dict:
    """Check whether a domain can be spoofed in email, from its public DNS
    records: SPF, DMARC and DKIM (common selectors only), plus an overall
    verdict. Passive: only reads DNS, never contacts the domain's servers.
    A missing DKIM result can mean the domain uses a selector Monomi
    didn't try, not that DKIM is absent."""
    domain = clean_domain(domain)
    with contextlib.redirect_stdout(sys.stderr):
        result = check_email(domain)
    return {"domain": domain, **result}


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=True))
def check_takeover(hostnames: list[str], domain: str | None = None) -> dict:
    """Check hostnames for dangling CNAMEs that could allow a subdomain
    takeover: a CNAME pointing at a cloud service (e.g. Azure, Elastic
    Beanstalk) whose target no longer exists and could be claimed by
    someone else. Pass the hostnames from find_subdomains.
    Passive: DNS lookups only, never contacts the hosts themselves.
    A flagged host is a lead to verify, not a confirmed takeover.
    Every host gets a status in "results": no_such_host, no_cname, cname_ok, stale, lead
    conflicting or error ("conflicting": system DNS and DNS-over-HTTPS disagreed, so unknown). "stale" means the target was deleted but its name can't be
    claimed again (e.g. an AWS load balancer): an old DNS record, not a
    takeover risk, listed in "stale" instead of "leads".
    Pass the scanned domain as "domain" (e.g. "example.com"): a CNAME that
    points back inside it is also "stale", since only its owner can create
    that name.
    Checks at most 200 hostnames per call. Inputs that aren't hostnames come back in "rejected" with the reason."""
    checked, skipped, rejected = clean_hosts(hostnames)
    with contextlib.redirect_stdout(sys.stderr):
        result = check_hosts(checked, domain=domain.strip().lower().rstrip(".") if domain else None)
    result.pop("checked", None)  # same number as hosts_checked; check_hosts() keeps it for the CLI
    return {"hosts_checked": len(checked), "hosts_skipped": skipped, "rejected": rejected, **result}


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=True))
def enrich_hosts(hostnames: list[str]) -> dict:
    """Resolve hostnames to IP addresses and look up who hosts each IP:
    ASN, hosting provider and country, with private IPs flagged.
    Pass the hostnames from find_subdomains. Passive: DNS and public
    IP-to-ASN data only, never contacts the hosts themselves.
    Checks at most 200 hostnames per call. Inputs that aren't hostnames come back in "rejected" with the reason."""
    checked, skipped, rejected = clean_hosts(hostnames)
    with contextlib.redirect_stdout(sys.stderr):
        result = enrich(checked)
    return {"hosts_checked": len(checked), "hosts_skipped": skipped, "rejected": rejected, **result}


def ports_summary(enrichment: dict, exposure: dict) -> dict:
    """Short counts for the top of check_ports' result, read before the per-IP details."""
    found = exposure["ips"]
    edge = sum(1 for d in found.values() if d["shared_edge"])
    not_resolving = enrichment.get("not_resolving", {})
    return {
        "hosts_resolved": enrichment.get("resolved", 0),
        "hosts_not_resolving": sum(len(hosts) for hosts in not_resolving.values()),
        "edge_ips": edge,
        "origin_ips": len(found) - edge,
        "ips_nothing_seen": exposure["ips_checked"] - exposure["ip_errors"] - len(found),
        "origin_cves": len(exposure.get("unique_cves", [])),
        "origin_ips_with_risky_ports": len(exposure.get("risky", [])),
    }

@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=True))
def check_ports(hostnames: list[str]) -> dict:
    """Look up open ports, risky services and known CVEs for the IPs
    behind hostnames, from Shodan InternetDB (what Shodan's own internet
    scans last saw). Resolves the hostnames first, so pass the hostnames
    from find_subdomains. Passive: asks Shodan about the IPs, never
    contacts the hosts themselves. CVEs are inferred from version
    banners, not confirmed: treat them as leads to verify. Ports on
    shared CDN edge IPs (e.g. Cloudflare) belong to the CDN, not the
    target. Starts with a "summary" of counts: CDN edge vs origin IPs,
    CVEs and risky ports on origin IPs only, and hostnames that don't
    resolve (listed by DNS status in "not_resolving").
    Checks at most 100 hostnames per call. Inputs that aren't hostnames come back in "rejected" with the reason."""
    checked, skipped, rejected = clean_hosts(hostnames, MAX_PORT_HOSTS)
    with contextlib.redirect_stdout(sys.stderr):
        enrichment = enrich(checked)
        exposure = internetdb.lookup(enrichment)
    exposure["ips_checked"] = exposure.pop("checked")
    exposure["ip_errors"] = exposure.pop("errors")
    exposure["ips_skipped"] = exposure.pop("skipped")


    return {"summary": ports_summary(enrichment, exposure),
            "hosts_checked": len(checked), "hosts_skipped": skipped, "rejected": rejected,
            "not_resolving": enrichment.get("not_resolving", {}), **exposure}


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=True))
def investigate_ip(ips: list[str]) -> dict:
    """Look into suspicious IP addresses (e.g. from logs or alerts): is each
    one a Tor exit, VPN/proxy, hosting/cloud server or CDN edge? Returns
    facts from the Tor exit list, Team Cymru (network owner, ASN), reverse
    DNS and Shodan InternetDB, rule-based labels with their source, and a
    numbered evidence list (E1, E2...) to cite.
    Passive: asks these public sources about the IPs, never contacts the
    IPs themselves. Private/internal IPs are rejected, each with a reason.
    When explaining results: "country" is where the network is registered,
    NOT where the person using the IP is. Never claim or guess a person's
    location or identity from an IP. A failed lookup ("errors") means
    unknown, not "no". Checks at most 10 IPs per call."""
    cleaned, rejected = [], []
    for raw in ips:
        ip = threatintel.clean_ip(raw)
        if ip is None:
            rejected.append({"ip": raw[:100],  # cut long junk short
                             "reason": threatintel.reject_reason(raw)})
        elif ip not in cleaned:
            cleaned.append(ip)
    checked, skipped = cleaned[:MAX_IPS], max(len(cleaned) - MAX_IPS, 0)

    with contextlib.redirect_stdout(sys.stderr):
        results = {"ips": {ip: threatintel.investigate(ip) for ip in checked}}
    results["evidence"] = threatintel.build_evidence(results)
    return {"ips_checked": len(checked), "ips_skipped": skipped,
            "rejected": rejected[:20], **results}


if __name__ == "__main__":
    mcp.run()
