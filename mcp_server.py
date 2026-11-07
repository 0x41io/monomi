"""
Monomi MCP server: lets AI agents (Claude Desktop, Claude Code, etc.)
run Monomi's passive checks as tools.

Run it with:  python mcp_server.py
It talks over stdin/stdout, so it prints nothing and waits for an agent.
"""
import contextlib
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime
from monomi import clean_domain, collect_ct
from categorize import categorize_all
from emailauth import check_email
from takeover import check_hosts
from enrich import enrich
from evidence import OWNERS
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


def owners(*keys: str) -> list[str]:
    """Owner role names from evidence.py's OWNERS table, so the MCP tools
    and the CLI report always name the same roles."""
    return [OWNERS[k] for k in keys]

# --- Summary mode -------------------------------------------------------
# Big sweeps return thousands of hosts, which fills up the agent's chat.
# By default each tool returns a short summary (counts + the hosts that
# matter) and saves the full result to a file the agent can point to.

RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scans", "mcp")
LIST_CAP = 20  # max names in any summary list; the full list is in the file
RISKY_CATEGORIES = ("non-production", "legacy", "access", "internal-tools",
                    "iot-ot", "partner-portal")


def save_full(tool: str, result: dict) -> str:
    """Save a tool's full result as scans/mcp/<date_time>_<tool>.json, return the path."""
    os.makedirs(RESULTS_DIR, exist_ok=True)
    stamp = datetime.now().strftime("%Y-%m-%d_%H%M%S_%f")
    path = os.path.join(RESULTS_DIR, f"{stamp}_{tool}.json")
    with open(path, "w") as f:
        json.dump(result, f, indent=2, default=list)  # default=list: sets/tuples
    return path


def finish(tool: str, full: dict, summary: dict, detail: str) -> dict:
    """Save the full result, then return it (detail="full") or the summary."""
    path = save_full(tool, full)
    if detail == "full":
        return {**full, "full_results_file": path}
    return {"detail": "summary", **summary, "full_results_file": path}


def first(names, cap: int = LIST_CAP) -> list:
    """The first `cap` names of a list (summary lists never grow past this)."""
    return sorted(names)[:cap]


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
def find_subdomains(domain: str, detail: str = "summary") -> dict:
    """Find a domain's subdomains from public Certificate Transparency logs
    (crt.sh and Cert Spotter). Passive: never contacts the target itself.
    Also returns wildcard cert names (*.example.com): a wildcard means there
    are likely more subdomains that CT logs can't list.
    Usually under a minute. If crt.sh is too slow, results come from
    Cert Spotter alone and "errors" says crt.sh timed out.
    Each hostname also gets a rule-based category (non-production, legacy,
    access, iot-ot, partner-portal, internal-tools, app-api, email, marketing, content, apex,
    uncategorized) with the reason
    it matched: facts from naming patterns, not confirmed by contacting hosts.
    detail="summary" (default): counts per category plus up to 20 example
    hosts per risky category; the full list is saved to "full_results_file".
    detail="full": every hostname and category in the reply."""
    domain = clean_domain(domain)

    results = {"sources": {}, "errors": {}}
    with contextlib.redirect_stdout(sys.stderr):
        collect_ct(results, domain, crtsh_budget=CRTSH_BUDGET, crtsh_light=True, total_budget=TOTAL_BUDGET)
    hostnames = sorted({h for r in results["sources"].values() for h in r["subdomains"]})
    wildcards = sorted({w for r in results["sources"].values() for w in r.get("wildcards", [])})
    categories = categorize_all(hostnames, domain)

    full = {
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
    return finish("find_subdomains", full, subdomains_summary(full), detail)


def subdomains_summary(full: dict) -> dict:
    """find_subdomains in short: counts per category, examples of risky ones."""
    by_cat = {}
    for host, c in full["categories"].items():
        by_cat.setdefault(c["category"], []).append(host)
    risky = {cat: {"count": len(by_cat[cat]), "hosts": first(by_cat[cat])}
             for cat in RISKY_CATEGORIES if cat in by_cat}
    return {
        "domain": full["domain"],
        "hostname_count": full["hostname_count"],
        "category_counts": dict(Counter({c: len(h) for c, h in by_cat.items()}).most_common()),
        "risky_categories": risky,
        "wildcards": full["wildcards"],
        "sources": full["sources"],
        "errors": full["errors"],
    }


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=True))
def check_email_auth(domain: str) -> dict:
    """Check whether a domain can be spoofed in email, from its public DNS
    records: SPF, DMARC and DKIM (common selectors only), plus an overall
    verdict. Passive: only reads DNS, never contacts the domain's servers.
    A missing DKIM result can mean the domain uses a selector Monomi
    didn't try, not that DKIM is absent.
    "owners" names the roles that would fix email findings, never people."""
    domain = clean_domain(domain)
    with contextlib.redirect_stdout(sys.stderr):
        result = check_email(domain)
    return {"domain": domain, "owners": owners("dns", "email"), **result}

@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=True))
def check_takeover(hostnames: list[str], domain: str | None = None, detail: str = "summary") -> dict:
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
    Each lead and stale record has "owners": the roles that would fix it, never people.
    Checks at most 200 hostnames per call. Inputs that aren't hostnames come back in "rejected" with the reason.
    detail="summary" (default): counts per status, every lead and stale record,
    and up to 20 hosts whose check failed; the full per-host "results" are
    saved to "full_results_file". detail="full": everything in the reply."""
    checked, skipped, rejected = clean_hosts(hostnames)
    with contextlib.redirect_stdout(sys.stderr):
        result = check_hosts(checked, domain=domain.strip().lower().rstrip(".") if domain else None)
    for lead in result["leads"]:
        lead["owners"] = owners("dns", "cloud") if lead["claimable"] else owners("dns")
    for record in result.get("stale", []):
        record["owners"] = owners("dns")
    result.pop("checked", None)  # same number as hosts_checked; check_hosts() keeps it for the CLI
    full = {"hosts_checked": len(checked), "hosts_skipped": skipped, "rejected": rejected, **result}
    return finish("check_takeover", full, takeover_summary(full), detail)


def takeover_summary(full: dict) -> dict:
    """check_takeover in short: drop the per-host results, keep what to act on."""
    results = full.get("results", {})
    unknown = [h for h, r in results.items() if r["status"] in ("error", "conflicting")]
    return {
        "hosts_checked": full["hosts_checked"],
        "hosts_skipped": full["hosts_skipped"],
        "rejected": full["rejected"],
        "status_counts": dict(Counter(r["status"] for r in results.values()).most_common()),
        "leads": full["leads"],
        "stale": full.get("stale", []),
        "unknown_count": len(unknown),
        "unknown_hosts": first(unknown),
    }

@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=True))
def enrich_hosts(hostnames: list[str], detail: str = "summary") -> dict:
    """Resolve hostnames to IP addresses and look up who hosts each IP:
    ASN, hosting provider and country, with private IPs flagged.
    Pass the hostnames from find_subdomains. Passive: DNS and public
    IP-to-ASN data only, never contacts the hosts themselves.
    Hosts with something to fix (a dangling CNAME, or a private IP in
    public DNS) have "owners": the roles that would fix it, never people.
    Checks at most 200 hostnames per call. Inputs that aren't hostnames come back in "rejected" with the reason.
    detail="summary" (default): counts (resolved, providers, not resolving by
    DNS status), every dangling-CNAME host, and up to 20 private-IP hosts; the
    full per-host and per-IP data is saved to "full_results_file".
    detail="full": everything in the reply."""
    checked, skipped, rejected = clean_hosts(hostnames)
    with contextlib.redirect_stdout(sys.stderr):
        result = enrich(checked)
    for entry in result["hosts"].values():
        if entry.get("dns") == "dangling_cname" or entry.get("private_ips"):
            entry["owners"] = owners("dns")
    full = {"hosts_checked": len(checked), "hosts_skipped": skipped, "rejected": rejected, **result}
    return finish("enrich_hosts", full, enrich_summary(full), detail)


def enrich_summary(full: dict) -> dict:
    """enrich_hosts in short: counts, plus the hosts with something to fix."""
    hosts = full.get("hosts", {})
    private = full.get("private_ip_hosts", [])
    return {
        "hosts_checked": full["hosts_checked"],
        "hosts_skipped": full["hosts_skipped"],
        "rejected": full["rejected"],
        "resolved": full.get("resolved", 0),
        "unique_ips": full.get("unique_ips", 0),
        "providers": full.get("providers", {}),
        "not_resolving_counts": {s: len(h) for s, h in full.get("not_resolving", {}).items()},
        "dangling_cnames": {h: {"cname": e.get("cname"), "owners": e.get("owners", [])}
                            for h, e in hosts.items() if e.get("dns") == "dangling_cname"},
        "private_ip_host_count": len(private),
        "private_ip_hosts": first(private),
        "private_ip_owners": owners("dns") if private else [],
        "asn_error": full.get("asn_error"),
        "cdn_error": full.get("cdn_error"),
    }

def ports_summary(enrichment: dict, exposure: dict) -> dict:
    """Short counts for the top of check_ports' result, read before the per-IP details."""
    found = exposure["ips"]
    every = list(found.values()) + list(exposure.get("nothing_seen", {}).values())
    edge = sum(1 for d in every if d["shared_edge"])
    not_resolving = enrichment.get("not_resolving", {})
    return {
        "hosts_resolved": enrichment.get("resolved", 0),
        "hosts_not_resolving": sum(len(hosts) for hosts in not_resolving.values()),
        "edge_ips": edge,
        "origin_ips": len(every) - edge,
        "ips_nothing_seen": exposure["ips_checked"] - exposure["ip_errors"] - len(found),
        "origin_cves": len(exposure.get("unique_cves", [])),
        "origin_ips_with_risky_ports": len(exposure.get("risky", [])),
    }

@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=True))
def check_ports(hostnames: list[str], detail: str = "summary") -> dict:
    """Look up open ports, risky services and known CVEs for the IPs
    behind hostnames, from Shodan InternetDB (what Shodan's own internet
    scans last saw). Resolves the hostnames first, so pass the hostnames
    from find_subdomains. Passive: asks Shodan about the IPs, never
    contacts the hosts themselves. CVEs are inferred from version
    banners, not confirmed: treat them as leads to verify. Ports on
    shared CDN edge IPs (e.g. Cloudflare) belong to the CDN, not the
    target. Starts with a "summary" of counts: CDN edge vs origin IPs,
    CVEs and risky ports on origin IPs only, and hostnames that don't
    resolve (listed by DNS status in "not_resolving"). IPs Shodan has
    no data on are listed in "nothing_seen": no data is not proof that
    nothing is running there.
    Origin (non-edge) IPs in "ips" have "owners": the roles that would fix them, never people.
    Checks at most 100 hostnames per call. Inputs that aren't hostnames come back in "rejected" with the reason.
    detail="summary" (default): the "summary" counts, origin IPs in full (up to
    20 hostnames each), and CDN edge IPs only as counts per provider; the full
    result is saved to "full_results_file". detail="full": everything in the reply."""
    checked, skipped, rejected = clean_hosts(hostnames, MAX_PORT_HOSTS)
    with contextlib.redirect_stdout(sys.stderr):
        enrichment = enrich(checked)
        exposure = internetdb.lookup(enrichment)
    exposure["ips_checked"] = exposure.pop("checked")
    exposure["ip_errors"] = exposure.pop("errors")
    exposure["ips_skipped"] = exposure.pop("skipped")
    for d in exposure["ips"].values():
        if not d["shared_edge"]:
            d["owners"] = owners("server")  # CDN edge ports belong to the CDN, not the target

    full = {"summary": ports_summary(enrichment, exposure),
            "hosts_checked": len(checked), "hosts_skipped": skipped, "rejected": rejected,
            "not_resolving": enrichment.get("not_resolving", {}), **exposure}
    return finish("check_ports", full, ports_brief(full), detail)


def ports_brief(full: dict) -> dict:
    """check_ports in short: origin IPs in full, CDN edge IPs only counted."""
    def short(d):  # one IP's data with its hostname list cut to LIST_CAP
        return {**d, "hosts": first(d.get("hosts", [])), "host_count": len(d.get("hosts", []))}
    every = {**full.get("nothing_seen", {}), **full.get("ips", {})}
    edge = Counter(d.get("provider", "unknown") for d in every.values() if d["shared_edge"])
    return {
        "summary": full["summary"],
        "hosts_checked": full["hosts_checked"],
        "hosts_skipped": full["hosts_skipped"],
        "rejected": full["rejected"],
        "ips_checked": full["ips_checked"],
        "ip_errors": full["ip_errors"],
        "ips_skipped": full["ips_skipped"],
        "unique_cves": full.get("unique_cves", []),
        "risky": full.get("risky", []),
        "origin_ips": {ip: short(d) for ip, d in full.get("ips", {}).items()
                       if not d["shared_edge"]},
        "origin_ips_nothing_seen": {ip: short(d) for ip, d in full.get("nothing_seen", {}).items()
                                    if not d["shared_edge"]},
        "edge_ips_by_provider": dict(edge.most_common()),
        "not_resolving_counts": {s: len(h) for s, h in full["not_resolving"].items()},
    }


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
