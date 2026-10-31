"""
Monomi MCP server: lets AI agents (Claude Desktop, Claude Code, etc.)
run Monomi's passive checks as tools.

Run it with:  python mcp_server.py
It talks over stdin/stdout, so it prints nothing and waits for an agent.
"""
import contextlib
import sys

from monomi import clean_domain, collect_ct
from categorize import categorize_all
from emailauth import check_email
from takeover import check_hosts
from enrich import enrich
import internetdb
from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

# The server itself. "monomi" is the name agents will see.
mcp = MCPServer("monomi")

# The Claude app's bridge gives up after 60s, so crt.sh gets at most 50s.
# That leaves room for Cert Spotter (which runs after it) plus overhead.
CRTSH_BUDGET = 50

# Max hostnames one tool call handles, to stay under the 60s limit.
MAX_HOSTS = 200
MAX_PORT_HOSTS = 100  # check_ports also queries Shodan per IP, so it's slower


def clean_hosts(hostnames: list[str], limit: int = MAX_HOSTS) -> tuple[list[str], int]:
    """Normalize, dedupe and cap a hostname list sent by an agent.
    Returns (hosts to check, how many were skipped over the cap)."""
    hosts = sorted({h.strip().lower().rstrip(".") for h in hostnames if h.strip()})
    return hosts[:limit], max(len(hosts) - limit, 0)


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
    Each hostname also gets a rule-based category (app-api, email, access,
    non-production, marketing, content, apex, uncategorized) with the reason
    it matched: facts from naming patterns, not confirmed by contacting hosts."""
    domain = clean_domain(domain)

    results = {"sources": {}, "errors": {}}
    with contextlib.redirect_stdout(sys.stderr):
        collect_ct(results, domain, crtsh_budget=CRTSH_BUDGET, crtsh_light=True)
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
def check_takeover(hostnames: list[str]) -> dict:
    """Check hostnames for dangling CNAMEs that could allow a subdomain
    takeover: a CNAME pointing at a cloud service (e.g. Azure, Elastic
    Beanstalk) whose target no longer exists and could be claimed by
    someone else. Pass the hostnames from find_subdomains.
    Passive: DNS lookups only, never contacts the hosts themselves.
    A flagged host is a lead to verify, not a confirmed takeover.
    Every host gets a status in "results": no_cname, cname_ok, lead or error.
    Checks at most 200 hostnames per call."""
    checked, skipped = clean_hosts(hostnames)
    with contextlib.redirect_stdout(sys.stderr):
        result = check_hosts(checked)
    return {"hosts_checked": len(checked), "hosts_skipped": skipped, **result}


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=True))
def enrich_hosts(hostnames: list[str]) -> dict:
    """Resolve hostnames to IP addresses and look up who hosts each IP:
    ASN, hosting provider and country, with private IPs flagged.
    Pass the hostnames from find_subdomains. Passive: DNS and public
    IP-to-ASN data only, never contacts the hosts themselves.
    Checks at most 200 hostnames per call."""
    checked, skipped = clean_hosts(hostnames)
    with contextlib.redirect_stdout(sys.stderr):
        result = enrich(checked)
    return {"hosts_checked": len(checked), "hosts_skipped": skipped, **result}


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=True))
def check_ports(hostnames: list[str]) -> dict:
    """Look up open ports, risky services and known CVEs for the IPs
    behind hostnames, from Shodan InternetDB (what Shodan's own internet
    scans last saw). Resolves the hostnames first, so pass the hostnames
    from find_subdomains. Passive: asks Shodan about the IPs, never
    contacts the hosts themselves. CVEs are inferred from version
    banners, not confirmed: treat them as leads to verify. Ports on
    shared CDN edge IPs (e.g. Cloudflare) belong to the CDN, not the
    target. Checks at most 100 hostnames per call."""
    checked, skipped = clean_hosts(hostnames, MAX_PORT_HOSTS)
    with contextlib.redirect_stdout(sys.stderr):
        enrichment = enrich(checked)
        exposure = internetdb.lookup(enrichment)
    return {"hosts_checked": len(checked), "hosts_skipped": skipped, **exposure}


if __name__ == "__main__":
    mcp.run()
