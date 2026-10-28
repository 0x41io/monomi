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
from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

# The server itself. "monomi" is the name agents will see.
mcp = MCPServer("monomi")

# The Claude app's bridge gives up after 60s, so crt.sh gets at most 40s.
# That leaves room for Cert Spotter (which runs after it) plus overhead.
CRTSH_BUDGET = 40


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False))
def ping(name: str = "world") -> str:
    """Say hello. Used to check that the Monomi MCP server is connected."""
    return f"hello {name}, monomi MCP server is running"

@mcp.tool()
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
        collect_ct(results, domain, crtsh_budget=CRTSH_BUDGET)

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

if __name__ == "__main__":
    mcp.run()
