"""
Monomi MCP server: lets AI agents (Claude Desktop, Claude Code, etc.)
run Monomi's passive checks as tools.

Run it with:  python mcp_server.py
It talks over stdin/stdout, so it prints nothing and waits for an agent.

Active tools (they send requests to the target's own servers) are off
unless the server is started with --allow-active. Only the person who
writes the Claude app's config can add that flag: an agent can't turn
it on through any tool. Every active request is written to scans/active.log.
"""
import argparse
import contextlib
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime
from monomi import clean_domain, collect_ct
import suggest
from categorize import categorize_all
from emailauth import check_email
from takeover import check_hosts
from enrich import enrich
from evidence import OWNERS
import activelog
import fingerprint
import gate
import exposed
import scope
import internetdb
import threatintel
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
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
# fingerprint_hosts: 30 hosts, 15 at a time, 8s each = at most ~16s of
# requests, so it finishes well under the 60s limit even on slow hosts
MAX_FP_HOSTS = 30
FP_WORKERS = 15
FP_TIMEOUT = 8
# check_exposed_files sends up to 13 requests per host, so it stays small
MAX_EXP_HOSTS = 10
EXP_WORKERS = 8
EXP_TIMEOUT = 8


def owners(*keys: str) -> list[str]:
    """Owner role names from evidence.py's OWNERS table, so the MCP tools
    and the CLI report always name the same roles."""
    return [OWNERS[k] for k in keys]


# --- Summary mode -------------------------------------------------------
# Big sweeps return thousands of hosts, which fills up the agent's chat.
# By default each tool returns a short summary (counts + the hosts that
# matter) and saves the full result to a file the agent can point to.

RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scans", "mcp")
SCANS_DIR = os.path.dirname(RESULTS_DIR)  # the only folder hosts_file may read from
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
        return {"detail": "full", **full, "full_results_file": path}
    return {"detail": "summary", **summary, "full_results_file": path}


# --- Next checks ----------------------------------------------------------
# Each MCP call sees only its own results, never what the agent ran before.
# So each tool suggests only what follows from its own results, and the
# agent can pass "already_ran" to leave out the checks it already did.

TOOL_NAMES = ("ping", "find_subdomains", "check_email_auth", "check_takeover",
              "enrich_hosts", "check_ports", "investigate_ip", "fingerprint_hosts",
              "check_exposed_files")
FOLLOWS_FROM = {  # tool -> the suggest.py flags its own results can back up
    "find_subdomains": ("--enrich", "--email"),
    "check_email_auth": (),
    "check_takeover": (),
    "enrich_hosts": ("--ports", "--takeover", "--fingerprint"),
    "check_ports": ("--takeover", "--fingerprint", "--cves FILE"),
    "fingerprint_hosts": ("--ports", "--takeover", "--exposed-files"),
    # one-directional: fingerprint points here, here points only at passive follow-ups
    "check_exposed_files": ("--ports", "--takeover"),
}
NEXT_CHECKS_NOTE = ("Suggestions only, nothing was run. Based on this call's results only: "
                    "pass the tools you already called as already_ran to leave them out.")


def check_already_ran(already_ran: list[str] | None) -> set[str]:
    """The tool names in already_ran, checked before any lookup runs.
    A misspelled name would quietly leave a repeat suggestion in, so it's refused."""
    names = set(already_ran or [])
    unknown = sorted(names - set(TOOL_NAMES))
    if unknown:
        raise ToolError(f"already_ran has unknown tool names {unknown}; "
                        f"use these names: {', '.join(TOOL_NAMES)}")
    return names


def attach_next_checks(tool: str, full: dict, summary: dict, results_for_suggest: dict,
                       already_ran: set[str]) -> None:
    """Add next_checks (and a note saying what it's based on) to the full and summary results.
    Suggestions only: nothing is run. Keeps only the checks this tool's own results
    back up (FOLLOWS_FROM), drops tools in already_ran, and marks the ones only
    the CLI can run as cli_only. If suggest.py fails, the list is empty and
    next_checks_error says why (also printed to stderr: stdout carries MCP)."""
    ran = already_ran | {tool}
    error = None
    try:
        checks = suggest.next_checks(results_for_suggest)
    except (AttributeError, KeyError, TypeError) as e:
        checks = []
        error = f"next checks couldn't be worked out ({type(e).__name__}: {e})"
        print(f"monomi {tool}: {error}", file=sys.stderr)
    checks = [dict(c, cli_only=c["mcp_tool"] is None) for c in checks
              if c["flag"] in FOLLOWS_FROM[tool] and c["mcp_tool"] not in ran]
    for out in (full, summary):
        out["next_checks"] = checks
        out["next_checks_note"] = NEXT_CHECKS_NOTE
        if error:
            out["next_checks_error"] = error


# --- Active tools ----------------------------------------------------------
# Off unless the server was started with --allow-active (set in __main__).
# The refusal happens in Monomi itself, so it holds even when the Claude
# app is set to "Always allow" the tool.

ALLOW_ACTIVE = False
# The approved scope file, read once at startup (see main). Until then, and
# whenever it's missing, edited after approval or empty, SCOPE_PROBLEM says
# why and every active check refuses. Fail-closed by default.
SCOPE = None
SCOPE_PROBLEM = scope.NO_SCOPE
ACTIVE_LOG = os.path.join(SCANS_DIR, "active.log")


def require_active(tool: str) -> None:
    """Refuse an active tool unless the server was started with --allow-active
    AND an approved scope file that still matches its approved hash."""
    if not ALLOW_ACTIVE:
        log_refusal(tool, "active checks are off")
        raise ToolError(
            f"{tool} is an ACTIVE check (it sends requests to the target's own servers) "
            "and active checks are turned off, so nothing was sent. Only the person "
            "running Monomi can turn them on: run `python monomi.py mcp setup --allow-active`, "
            "then fully restart the Claude app (the setting is read when the server starts).")
    if SCOPE_PROBLEM:
        log_refusal(tool, SCOPE_PROBLEM)
        raise ToolError(
            f"{tool} is an ACTIVE check and nothing was sent: {SCOPE_PROBLEM}. "
            "Only the person running Monomi can approve a scope (the scope can't be "
            "passed to a tool), then fully restart the Claude app.")


def log_request(tool: str, host: str, url: str, scope_rule: str | None) -> None:
    """One line in scans/active.log for every active request, before it's sent:
    the rule that allowed it and the approved scope's hash (see activelog.py)."""
    activelog.request(ACTIVE_LOG, "mcp", tool, host, url, scope_rule, SCOPE)


def log_refusal(tool: str, reason: str, host: str | None = None) -> None:
    """One line in scans/active.log for everything refused: a whole call
    (host None) or one out-of-scope host."""
    activelog.refused(ACTIVE_LOG, "mcp", tool, reason, host, SCOPE)


def scope_filter(tool: str, hosts: list[str]) -> tuple[list[str], list[dict]]:
    """Drop out-of-scope hosts BEFORE any DNS lookup, logging each one.
    Returns (hosts to check, [{"host", "reason"}] that were refused)."""
    inside, outside = scope.split(SCOPE, hosts)
    for o in outside:
        log_refusal(tool, o["reason"], o["host"])
    return inside, outside


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


def load_hosts_file(path: str) -> list[str]:
    """Hostnames from a file in Monomi's scans folder: a .json file with a
    "hostnames" list (what find_subdomains saves) or a .txt file with one
    host per line ("#" starts a comment). Files anywhere else are refused,
    so an agent can't be tricked into reading other files (like ~/.bashrc)."""
    if not os.path.isabs(path):
        path = os.path.join(SCANS_DIR, path)  # "mcp/x.json" means scans/mcp/x.json
    real = os.path.realpath(path)  # follows ../ and symlinks to where the file really is
    scans = os.path.realpath(SCANS_DIR)
    if os.path.commonpath([real, scans]) != scans:
        raise ToolError(f"hosts_file must be inside Monomi's scans folder ({scans})")
    if not real.lower().endswith((".json", ".txt")):
        raise ToolError("hosts_file must be a .json or .txt file")
    if not os.path.isfile(real):
        raise ToolError(f"hosts_file not found: {path}")
    with open(real) as f:
        if not real.lower().endswith(".json"):
            return [line.split("#")[0] for line in f]
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            raise ToolError("hosts_file isn't valid JSON")
    hosts = data.get("hostnames") if isinstance(data, dict) else None
    if not isinstance(hosts, list):
        raise ToolError('a .json hosts_file needs a "hostnames" list, like the file find_subdomains saves')
    return [str(h) for h in hosts]


def pick_hosts(hostnames: list[str] | None, hosts_file: str | None,
               start: int, limit: int) -> tuple[list[str], int, list[dict], dict]:
    """The hosts one tool call checks: from "hostnames" or "hosts_file"
    (exactly one), cleaned, then at most `limit` of them from `start` on.
    Returns (hosts, how many are left after this batch, rejected inputs,
    batch info for the reply)."""
    if (hostnames is None) == (hosts_file is None):
        raise ToolError("pass either hostnames or hosts_file, not both")
    raw = load_hosts_file(hosts_file) if hosts_file else hostnames
    hosts, _, rejected = clean_hosts(raw, limit=len(raw))  # clean them all, batch below
    start = max(start, 0)
    batch = hosts[start:start + limit]
    end = start + len(batch)
    info = {"start": start, "size": len(batch), "total": len(hosts),
            "next_start": end if end < len(hosts) else None}
    return batch, len(hosts) - end, rejected, info


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False))
def ping(name: str = "world") -> str:
    """Say hello. Used to check that the Monomi MCP server is connected."""
    return f"hello {name}, monomi MCP server is running"


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=True))
def find_subdomains(domain: str, detail: str = "summary", already_ran: list[str] | None = None) -> dict:
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
    detail="full": every hostname and category in the reply.
    Pass "full_results_file" as "hosts_file" to the other tools instead of
    copying the hostnames into them.
    Results include "next_checks": checks worth running next, from this
    call's results (suggestions only, nothing runs). Pass the tools you
    already called as "already_ran" (e.g. ["check_takeover"]) to leave
    them out. "cli_only" suggestions need the Monomi CLI, not a tool.
    """
    ran = check_already_ran(already_ran)
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
                "from_saved": r.get("from_saved", False),
            }
            for name, r in results["sources"].items()
        },
        "errors": results["errors"],
    }
    summary = subdomains_summary(full)
    attach_next_checks("find_subdomains", full, summary, {"target": domain, "subdomains": hostnames}, ran)
    return finish("find_subdomains", full, summary, detail)


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
def check_email_auth(domain: str, already_ran: list[str] | None = None) -> dict:
    """Check whether a domain can be spoofed in email, from its public DNS
    records: SPF, DMARC and DKIM (common selectors only), plus an overall
    verdict. Passive: only reads DNS, never contacts the domain's servers.
    A missing DKIM result can mean the domain uses a selector Monomi
    didn't try, not that DKIM is absent.
    "owners" names the roles that would fix email findings, never people.
    Results include "next_checks": checks worth running next, from this
    call's results (suggestions only, nothing runs). Pass the tools you
    already called as "already_ran" (e.g. ["check_takeover"]) to leave
    them out. "cli_only" suggestions need the Monomi CLI, not a tool.
    """
    ran = check_already_ran(already_ran)
    domain = clean_domain(domain)
    with contextlib.redirect_stdout(sys.stderr):
        result = check_email(domain)
    out = {"domain": domain, "owners": owners("dns", "email"), **result}
    attach_next_checks("check_email_auth", out, out, {"target": domain, "email": result}, ran)
    return out


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=True))
def check_takeover(hostnames: list[str] | None = None, domain: str | None = None, detail: str = "summary",
                   hosts_file: str | None = None, start: int = 0,
                   already_ran: list[str] | None = None) -> dict:
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
    Each lead also has a "gate" (Monomi's validation gate, checks 4 and 6):
    result "finding" only when DNS-over-HTTPS confirmed the target doesn't
    exist (not system DNS alone; see "nxdomain_confirmed_by") and the
    service is known to let deleted names be claimed again; otherwise
    "lead", with each failed check and why. Even a "finding" is still
    unconfirmed until someone verifies it: Monomi never claims the name.
    Checks at most 200 hostnames per call. Inputs that aren't hostnames come back in "rejected" with the reason.
    detail="summary" (default): counts per status, every lead and stale record,
    and up to 20 hosts whose check failed; the full per-host "results" are
    saved to "full_results_file". detail="full": everything in the reply.
    Pass the hosts as "hostnames", or as "hosts_file": a file in Monomi's
    scans folder, like the "full_results_file" from find_subdomains (.json)
    or a .txt list with one host per line. A big file goes in batches of
    200: call again with "start" set to the reply's batch.next_start
    until it is null.
    Results include "next_checks": checks worth running next, from this
    call's results (suggestions only, nothing runs). Pass the tools you
    already called as "already_ran" (e.g. ["check_takeover"]) to leave
    them out. "cli_only" suggestions need the Monomi CLI, not a tool.
    """
    ran = check_already_ran(already_ran)
    domain = domain.strip().lower().rstrip(".") if domain else None
    checked, skipped, rejected, batch = pick_hosts(hostnames, hosts_file, start, MAX_HOSTS)
    with contextlib.redirect_stdout(sys.stderr):
        result = check_hosts(checked, domain=domain)
    for lead in result["leads"]:
        lead["owners"] = owners("dns", "cloud") if lead["claimable"] else owners("dns")
        lead["gate"] = gate.takeover_gate(lead, domain)  # checks 4 and 6 (v1.13)
    for record in result.get("stale", []):
        record["owners"] = owners("dns")
    result.pop("checked", None)  # same number as hosts_checked; check_hosts() keeps it for the CLI
    full = {"hosts_checked": len(checked), "hosts_skipped": skipped, "rejected": rejected,
            "batch": batch, **result}
    summary = takeover_summary(full)
    found = {"subdomains": checked, "takeover": result}
    if domain:
        found["target"] = domain
    attach_next_checks("check_takeover", full, summary, found, ran)
    return finish("check_takeover", full, summary, detail)


def takeover_summary(full: dict) -> dict:
    """check_takeover in short: drop the per-host results, keep what to act on."""
    results = full.get("results", {})
    unknown = [h for h, r in results.items() if r["status"] in ("error", "servfail", "conflicting")]
    return {
        "hosts_checked": full["hosts_checked"],
        "hosts_skipped": full["hosts_skipped"],
        "rejected": full["rejected"],
        "batch": full["batch"],
        "status_counts": dict(Counter(r["status"] for r in results.values()).most_common()),
        "leads_passing_gate": sum(1 for lead in full["leads"] if lead.get("gate", {}).get("result") == "finding"),
        "leads": full["leads"],
        "stale": full.get("stale", []),
        "unknown_count": len(unknown),
        "unknown_hosts": first(unknown),
    }


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=True))
def enrich_hosts(hostnames: list[str] | None = None, detail: str = "summary",
                 hosts_file: str | None = None, start: int = 0,
                 already_ran: list[str] | None = None) -> dict:
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
    detail="full": everything in the reply.
    Pass the hosts as "hostnames", or as "hosts_file": a file in Monomi's
    scans folder, like the "full_results_file" from find_subdomains (.json)
    or a .txt list with one host per line. A big file goes in batches of
    200: call again with "start" set to the reply's batch.next_start
    until it is null.
    Results include "next_checks": checks worth running next, from this
    call's results (suggestions only, nothing runs). Pass the tools you
    already called as "already_ran" (e.g. ["check_takeover"]) to leave
    them out. "cli_only" suggestions need the Monomi CLI, not a tool.
    """
    ran = check_already_ran(already_ran)
    checked, skipped, rejected, batch = pick_hosts(hostnames, hosts_file, start, MAX_HOSTS)
    with contextlib.redirect_stdout(sys.stderr):
        result = enrich(checked)
    for entry in result["hosts"].values():
        if entry.get("dns") == "dangling_cname" or entry.get("private_ips"):
            entry["owners"] = owners("dns")
    full = {"hosts_checked": len(checked), "hosts_skipped": skipped, "rejected": rejected,
            "batch": batch, **result}
    summary = enrich_summary(full)
    attach_next_checks("enrich_hosts", full, summary, {"subdomains": checked, "enrichment": result}, ran)
    return finish("enrich_hosts", full, summary, detail)


def enrich_summary(full: dict) -> dict:
    """enrich_hosts in short: counts, plus the hosts with something to fix."""
    hosts = full.get("hosts", {})
    private = full.get("private_ip_hosts", [])
    return {
        "hosts_checked": full["hosts_checked"],
        "hosts_skipped": full["hosts_skipped"],
        "rejected": full["rejected"],
        "batch": full["batch"],
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
def check_ports(hostnames: list[str] | None = None, detail: str = "summary",
                hosts_file: str | None = None, start: int = 0,
                already_ran: list[str] | None = None) -> dict:
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
    result is saved to "full_results_file". detail="full": everything in the reply.
    Pass the hosts as "hostnames", or as "hosts_file": a file in Monomi's
    scans folder, like the "full_results_file" from find_subdomains (.json)
    or a .txt list with one host per line. A big file goes in batches of
    100: call again with "start" set to the reply's batch.next_start
    until it is null.
    Results include "next_checks": checks worth running next, from this
    call's results (suggestions only, nothing runs). Pass the tools you
    already called as "already_ran" (e.g. ["check_takeover"]) to leave
    them out. "cli_only" suggestions need the Monomi CLI, not a tool.
    """
    ran = check_already_ran(already_ran)
    checked, skipped, rejected, batch = pick_hosts(hostnames, hosts_file, start, MAX_PORT_HOSTS)
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
            "batch": batch, "not_resolving": enrichment.get("not_resolving", {}), **exposure}
    summary = ports_brief(full)
    attach_next_checks("check_ports", full, summary, {
        "subdomains": checked,
        "enrichment": enrichment,
        "exposure": exposure,
    }, ran)
    return finish("check_ports", full, summary, detail)


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
        "batch": full["batch"],
        "ips_checked": full["ips_checked"],
        "ip_errors": full["ip_errors"],
        "ips_skipped": full["ips_skipped"],
        "unique_cves": full.get("unique_cves", []),
        "risky": full.get("risky", []),
        "origin_ips": {ip: short(d) for ip, d in full.get("ips", {}).items()
                       if not d["shared_edge"]},
        "nothing_seen": {ip: short(d) for ip, d in full.get("nothing_seen", {}).items()
                         if not d["shared_edge"]},
        "edge_ips_by_provider": dict(edge.most_common()),
        "not_resolving_counts": {s: len(h) for s, h in full["not_resolving"].items()},
    }


@mcp.tool(annotations=ToolAnnotations(
    title="ACTIVE: fingerprint hosts",
    readOnlyHint=False,     # it reaches out to the target, so not read-only...
    destructiveHint=False,  # ...but a homepage GET changes nothing there
    idempotentHint=True,
    openWorldHint=True))
def fingerprint_hosts(hostnames: list[str] | None = None, detail: str = "summary",
                      hosts_file: str | None = None, start: int = 0,
                      already_ran: list[str] | None = None) -> dict:
    """ACTIVE: sends one normal homepage request (https://host/) to each
    host with a public IP, the same request a browser makes. Unlike every
    other Monomi tool, this contacts the target's own servers, so only use
    it on targets you're allowed to test (in scope). It is off unless the
    person running Monomi turned active checks on; if it's off, it refuses
    and nothing is sent. Every request is written to scans/active.log.
    Only hosts allowed by the scope file the person running Monomi approved
    are contacted (the scope can't be passed in or changed by a tool); any
    other host comes back in "out_of_scope" with the reason, and gets no
    DNS lookup and no request.
    From the response headers it reports the web software (Server,
    X-Powered-By...), any exact version shown ("version leaks": match them
    to CVEs, but a version alone is a lead, not proof of a flaw) and
    missing or weak security headers (HSTS, CSP, X-Frame-Options,
    X-Content-Type-Options, Referrer-Policy). Headers are only judged on
    real pages (HTTP 2xx); redirects are listed in "not_judged".
    If HTTPS fails with a TLS error or is refused (not on a timeout), it
    tries http://host/ once, a second request that is logged too; that
    host's result keeps the HTTPS failure in "https_error" and gets an
    "HTTPS broken" issue instead of an HSTS one ("requests_sent" counts
    every request).
    Resolves the hostnames first; hosts without a public IP get no request
    and are listed in "not_requested". Version leaks and header issues
    have "owners": the roles that would fix them, never people.
    Checks at most 30 hostnames per call. Inputs that aren't hostnames come back in "rejected" with the reason.
    detail="summary" (default): counts, every version leak, header issues
    grouped by header (up to 20 hosts each) and failed requests; the full
    per-host result is saved to "full_results_file". detail="full": everything in the reply.
    Pass the hosts as "hostnames", or as "hosts_file": a file in Monomi's
    scans folder, like the "full_results_file" from find_subdomains (.json)
    or a .txt list with one host per line. A big file goes in batches of
    30: call again with "start" set to the reply's batch.next_start
    until it is null.
    Results include "next_checks": checks worth running next, from this
    call's results (suggestions only, nothing runs). Pass the tools you
    already called as "already_ran" (e.g. ["check_takeover"]) to leave
    them out. "cli_only" suggestions need the Monomi CLI, not a tool.
    """
    ran = check_already_ran(already_ran)
    require_active("fingerprint_hosts")  # before any lookup or request
    checked, skipped, rejected, batch = pick_hosts(hostnames, hosts_file, start, MAX_FP_HOSTS)
    checked, out_of_scope = scope_filter("fingerprint_hosts", checked)  # before any lookup
    with contextlib.redirect_stdout(sys.stderr):
        enrichment = enrich(checked)
        fp = fingerprint.fingerprint_all(
            enrichment, workers=FP_WORKERS, max_hosts=MAX_FP_HOSTS, timeout=FP_TIMEOUT,
            scope=SCOPE,  # checked again before every request
            on_request=lambda host, url, rule: log_request("fingerprint_hosts", host, url, rule))
    for r in fp["hosts"].values():
        for t in r["techs"]:
            if t["version"]:
                t["owners"] = owners("server")
        for issue in r["header_issues"]:
            # broken HTTPS is a server/certificate fix; missing headers are the app's
            if issue["header"] == "HTTPS":
                issue["owners"] = owners("server", "cdn")
            else:
                issue["owners"] = owners("web", "cdn")
    requested = set(fp["hosts"]) | set(fp["errors"])
    full = {"hosts_checked": len(checked), "hosts_skipped": skipped, "rejected": rejected,
            "out_of_scope": out_of_scope,
            "batch": batch, "requests_sent": fp["requests"], "active_log": ACTIVE_LOG,
            "not_requested": sorted(set(checked) - requested),
            "hosts": fp["hosts"], "errors": fp["errors"]}
    summary = fingerprint_summary(full)
    attach_next_checks("fingerprint_hosts", full, summary, {
        "subdomains": checked, "enrichment": enrichment, "fingerprint": fp}, ran)
    return finish("fingerprint_hosts", full, summary, detail)


def fingerprint_summary(full: dict) -> dict:
    """fingerprint_hosts in short: counts, every version leak, header issues by header."""
    hosts = full["hosts"]
    leaks, by_header = [], {}
    for host, r in sorted(hosts.items()):
        for t in r["techs"]:
            if t["version"]:
                leaks.append({"host": host, "tech": t["tech"], "version": t["version"],
                              "evidence": t["evidence"], "owners": t["owners"]})
        for issue in r["header_issues"]:
            entry = by_header.setdefault(issue["header"], {"problems": Counter(), "hosts": [],
                                                           "owners": issue["owners"]})
            entry["problems"][issue["problem"]] += 1
            entry["hosts"].append(host)
    not_judged = {h: r["status"] for h, r in hosts.items() if not 200 <= r["status"] < 300}
    return {
        "hosts_checked": full["hosts_checked"],
        "hosts_skipped": full["hosts_skipped"],
        "rejected": full["rejected"],
        "out_of_scope_count": len(full["out_of_scope"]),
        "out_of_scope": full["out_of_scope"][:LIST_CAP],
        "batch": full["batch"],
        "requests_sent": full["requests_sent"],
        "active_log": full["active_log"],
        "answered": len(hosts),
        "status_counts": dict(Counter(r["status"] for r in hosts.values()).most_common()),
        "version_leaks": leaks,
        "header_issues": {
            header: {"problems": dict(e["problems"]), "host_count": len(e["hosts"]),
                     "hosts": first(e["hosts"]), "owners": e["owners"]}
            for header, e in sorted(by_header.items())},
        "not_judged": dict(sorted(not_judged.items())[:LIST_CAP]),
        "errors": dict(sorted(full["errors"].items())[:LIST_CAP]),
        "error_count": len(full["errors"]),
        "not_requested_count": len(full["not_requested"]),
        "not_requested": first(full["not_requested"]),
    }


@mcp.tool(annotations=ToolAnnotations(
    title="ACTIVE: check exposed files",
    readOnlyHint=False,     # it reaches out to the target, so not read-only...
    destructiveHint=False,  # ...but every request is a GET, nothing changes there
    idempotentHint=True,
    openWorldHint=True))
def check_exposed_files(hostnames: list[str] | None = None, detail: str = "summary",
                        hosts_file: str | None = None, start: int = 0,
                        already_ran: list[str] | None = None) -> dict:
    """ACTIVE: looks for developer files a host serves to anyone: an API
    spec (OpenAPI/Swagger) or a JavaScript source map. Like fingerprint_hosts
    it contacts the target's own servers, so only run it on targets you're
    allowed to test (in scope). It is off unless active checks were turned
    on; if off, it refuses and nothing is sent. Every request goes to
    scans/active.log. Only hosts allowed by the approved scope file are
    contacted (the scope can't be passed in or changed by a tool); any other
    host comes back in "out_of_scope" with the reason, with no DNS lookup
    and no request. Every URL is checked against the scope again before it's
    fetched.
    Per host it sends only GETs, a small fixed set: a short list of
    well-known spec paths (/openapi.json, /swagger.json, /v3/api-docs...),
    then the homepage, a few of its same-host scripts, and the .map files
    those scripts name. At most 13 requests per host. It never POSTs, never
    follows a spec to call the API, and never leaves the hosts you pass in.
    A file is reported only when it really parses as what it claims to be,
    so a site that returns a page for every path isn't mistaken for a spec.
    For a spec it reports the URL, type/version, title, endpoint and method
    counts, the first paths, any server URLs it lists (these can name
    internal hosts) and whether it declares a login scheme. For a source
    map it reports the map URL, how many source files it lists, the first
    few names, and whether the original source CODE is embedded
    (has_source_content) — the bigger leak. The code itself is never
    returned or saved. Findings have "owners": the roles that would fix
    them, never people.
    Checks at most 10 hostnames per call. Inputs that aren't hostnames come
    back in "rejected"; hosts with no public IP are in "not_requested".
    detail="summary" (default): counts plus the specs and maps found; the
    full per-host result is saved to "full_results_file". detail="full":
    everything in the reply.
    Pass the hosts as "hostnames", or "hosts_file" (a .json/.txt file in
    Monomi's scans folder). A big file goes in batches of 10: call again
    with "start" set to the reply's batch.next_start until it is null.
    Results include "next_checks" (suggestions only, nothing runs); pass
    "already_ran" to leave out checks you already did.
    """
    ran = check_already_ran(already_ran)
    require_active("check_exposed_files")  # before any lookup or request
    checked, skipped, rejected, batch = pick_hosts(hostnames, hosts_file, start, MAX_EXP_HOSTS)
    checked, out_of_scope = scope_filter("check_exposed_files", checked)  # before any lookup
    with contextlib.redirect_stdout(sys.stderr):
        enrichment = enrich(checked)
        ex = exposed.check_all(
            enrichment, workers=EXP_WORKERS, max_hosts=MAX_EXP_HOSTS, timeout=EXP_TIMEOUT,
            scope=SCOPE,  # checked again before every request
            on_request=lambda host, url, rule: log_request("check_exposed_files", host, url, rule))
    for finding in ex["hosts"].values():
        if finding["spec"]:
            finding["spec"]["owners"] = owners("web", "cdn")
        for m in finding["source_maps"]:
            m["owners"] = owners("web")
    full = {"hosts_checked": len(checked), "hosts_skipped": skipped, "rejected": rejected,
            "out_of_scope": out_of_scope,
            "batch": batch, "requests_sent": ex["requests"], "active_log": ACTIVE_LOG,
            "not_requested": sorted(set(checked) - set(ex["requested"])),
            "hosts": ex["hosts"]}
    summary = exposed_summary(full)
    attach_next_checks("check_exposed_files", full, summary, {
        "subdomains": checked, "enrichment": enrichment, "exposed_files": ex}, ran)
    return finish("check_exposed_files", full, summary, detail)


def exposed_summary(full: dict) -> dict:
    """check_exposed_files in short: the specs and source maps found, by host."""
    specs, maps = [], []
    for host, f in sorted(full["hosts"].items()):
        s = f["spec"]
        if s:
            specs.append({"host": host, "url": s["url"], "type": s["type"],
                          "version": s["version"], "endpoints": s["endpoint_count"],
                          "declares_auth": s["declares_auth"], "owners": s["owners"]})
        for m in f["source_maps"]:
            maps.append({"host": host, "map_url": m["map_url"],
                         "source_count": m["source_count"],
                         "has_source_content": m["has_source_content"], "owners": m["owners"]})
    return {
        "hosts_checked": full["hosts_checked"],
        "hosts_skipped": full["hosts_skipped"],
        "rejected": full["rejected"],
        "out_of_scope_count": len(full["out_of_scope"]),
        "out_of_scope": full["out_of_scope"][:LIST_CAP],
        "batch": full["batch"],
        "requests_sent": full["requests_sent"],
        "active_log": full["active_log"],
        "hosts_with_findings": len(full["hosts"]),
        "specs_found": len(specs),
        "specs": specs[:LIST_CAP],
        "source_maps_found": len(maps),
        "source_maps": maps[:LIST_CAP],
        # hosts whose maps embed the original source code: the bigger leak
        "maps_with_source_code": sorted({m["host"] for m in maps if m["has_source_content"]}),
        "not_requested_count": len(full["not_requested"]),
        "not_requested": first(full["not_requested"]),
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


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description="Monomi MCP server (talks over stdin/stdout)")
    parser.add_argument("--allow-active", action="store_true",
                        help="allow ACTIVE tools (fingerprint_hosts, check_exposed_files), "
                             "which send requests to targets")
    parser.add_argument("--scope", metavar="FILE",
                        help="the approved scope file: active tools only reach hosts it allows")
    parser.add_argument("--scope-sha256", metavar="HEX",
                        help="the file's sha256 when it was approved (set by mcp setup)")
    args = parser.parse_args(argv)
    global ALLOW_ACTIVE, SCOPE, SCOPE_PROBLEM
    ALLOW_ACTIVE = args.allow_active
    SCOPE, SCOPE_PROBLEM = scope.check_pinned(args.scope, args.scope_sha256)
    # stderr, never stdout: stdout carries the MCP messages
    print(f"monomi MCP server: active tools {'ON' if ALLOW_ACTIVE else 'off'}; "
          f"{scope_status()}", file=sys.stderr)
    mcp.run()


def scope_status() -> str:
    """One line about the scope for the startup message (hash in full)."""
    if SCOPE_PROBLEM:
        return f"scope REFUSED: {SCOPE_PROBLEM}"
    return (f"scope {SCOPE.path} sha256 {SCOPE.sha256} "
            f"({len(SCOPE.inclusions)} in, {len(SCOPE.exclusions)} excluded)")


if __name__ == "__main__":
    main()
