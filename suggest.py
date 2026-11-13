"""
Next checks: which check is worth running next, worked out from what this
scan found.

Suggestions only. Nothing here runs a check, sends a request or changes a
result: it reads the results and names the flags (and the MCP tool, when
there is one) that would add something, each with the reason from this
scan. A check that already ran is never suggested again.
"""

import paths


def _own_ips(results: dict) -> dict:
    """The target's own public IPs -> the hosts on them (CDN edges, third-party
    hosting, shared front doors and private IPs left out)."""
    edge = paths._not_own_ips(results)
    own = {}
    for host, d in ((results.get("enrichment") or {}).get("hosts") or {}).items():
        for ip in d.get("ips", []):
            if ip not in edge and ip not in d.get("private_ips", []):
                own.setdefault(ip, []).append(host)
    return own


def _count(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


def next_checks(results: dict, cves_saved: bool = False) -> list[dict]:
    """[{"flag", "mcp_tool", "active", "why"}], most useful first. Empty = nothing to add.

    active: True when the check sends requests to the target's own servers
    (only --fingerprint does), so it should only be run where that's allowed.
    """
    out = []

    def add(flag, mcp_tool, why, active=False):
        out.append({"flag": flag, "mcp_tool": mcp_tool, "active": active, "why": why})

    hosts = results.get("subdomains", [])
    target = results.get("target", "the domain")
    enr = results.get("enrichment")
    if enr is None:
        if hosts:
            add("--enrich", "enrich_hosts",
                f"{_count(len(hosts), 'hostname was', 'hostnames were')} found but not looked up: "
                "this shows which are live, their IPs and who hosts them")
    else:
        own = _own_ips(results)
        if own and "exposure" not in results:
            add("--ports", "check_ports",
                f"{_count(len(own), 'IP is a server', 'IPs are servers')} of the target's own, not a CDN: "
                "Shodan's records show open ports and known CVEs there (passive)")
        cnames = [h for h, d in enr["hosts"].items()
                  if d.get("canonical") or d.get("dns") == "dangling_cname"]
        if cnames and "takeover" not in results:
            add("--takeover", "check_takeover",
                f"{_count(len(cnames), 'hostname is a CNAME', 'hostnames are CNAMEs')} to another name: "
                "this checks whether any points at something deleted that an attacker could claim")
        on_own = sorted({h for hs in own.values() for h in hs})
        if on_own and "fingerprint" not in results:
            add("--fingerprint", "fingerprint_hosts",
                f"{_count(len(on_own), 'host sits', 'hosts sit')} on the target's own servers: one homepage "
                "request each shows the web server, its version and its security headers", active=True)
    fp = results.get("fingerprint") or {}
    if fp.get("hosts") and "exposed_files" not in results:
        add("--exposed-files", "check_exposed_files",
            f"{_count(len(fp['hosts']), 'host served', 'hosts served')} a real page: this checks whether "
            "any serve a public API spec (OpenAPI/Swagger) or a JavaScript source map", active=True)
    if "email" not in results:
        add("--email", "check_email_auth",
            f"not checked yet: whether someone can send email pretending to be {target} (DNS lookups only)")
    exp = results.get("exposure") or {}
    cves = {c for d in exp.get("ips", {}).values() if not d.get("shared_edge") for c in d.get("vulns", [])}
    if cves and not cves_saved:
        add("--cves FILE", None,
            f"{_count(len(cves), 'known CVE was', 'known CVEs were')} found: this saves them to a file "
            "that kaidoku --file FILE can explain")
    return out
