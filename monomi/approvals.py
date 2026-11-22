"""
Approvals: active checks that an agent asks for over MCP, but that run only
after a person's typed yes at a real terminal (issue #27 part B).

    request()  (MCP: fingerprint_hosts / check_exposed_files)
               records the tool and the hostnames asked for. Sends
               nothing, looks nothing up, returns an approval id.
    approve()  (terminal: `python monomi.py approve RID --scope FILE`)
               applies the scope file, shows every host, every fixed URL,
               the rules for the rest and the request cap, and asks for a
               typed yes. Locks it all in.
    claim()    (MCP: active_run, which takes only the id)
               every check again, then marks it used BEFORE anything is
               sent. Single use.

An approval covers one tool, the exact in-scope hosts shown, the request
rules and cap shown, and the scope / research files as they were (sha256).
Any difference, an expiry, a second use or a missing piece means refuse:
nothing is sent. No MCP tool can supply a scope file, a research file or a
yes; claim() takes only the id.

What can be listed in advance depends on the tool. fingerprint_hosts sends
fixed URLs (https://host/, and http://host/ only if HTTPS fails). For
check_exposed_files the homepage and spec paths are fixed (over http:// only
if the HTTPS homepage fails the same way, v1.24), but the scripts
and .map files come from the homepage itself, so the approval locks the
rule ("same host only") and a hard cap instead of URLs; every URL is
still checked against the scope and the approved hosts before it's sent.

Each approval is one JSON file, scans/approvals/<rid>.json, with every
event in it (refusals too), so it's its own audit trail. "Used" is a
second file, <rid>.used, created in one step that only one process can
win (O_EXCL), so two MCP servers can't both run the same approval.

Since v1.21 the record keeping, the typed yes and the single-use claim
live in approvalcore.py, shared with the rest of the 0x41 suite. This
module keeps what is Monomi's own: which tools are active, what each may
send (TOOLS), the plan shown before the yes, and the pinned-file check.

Honest limit: an agent with a shell on this machine can fake a terminal.
The gate is against agents that only have MCP tools.
"""

import os
import sys

from monomi import exposed, home, research, scope
from monomi.approvalcore import (APPROVAL_TTL, ALPHABET, RID, REQUEST_TTL,  # noqa: F401 (re-exported)
                                 ApprovalError, Store, expired as _expired, now_utc as _now, typed_yes)

# What each active tool may send per host: the URLs known in advance, the
# rule for anything else, and the hard cap.
TOOLS = {
    "fingerprint_hosts": {
        "fixed": lambda h: [f"https://{h}/"],
        "more": "http://{host}/ once, only if HTTPS fails with a TLS error or is refused",
        "max_per_host": 2,
    },
    "check_exposed_files": {
        "fixed": lambda h: [f"https://{h}/"] + [f"https://{h}{p}" for p in exposed.SPEC_PATHS],
        "more": ("http://{host}/ once, only if HTTPS fails with a TLS error or is refused, and then the "
                 "spec paths over http:// instead; "
                 f"up to {exposed.MAX_SCRIPTS} scripts the homepage loads from {{host}} itself, and up to "
                 f"{exposed.MAX_MAPS} .map files they name on {{host}}: never another host"),
        "max_per_host": exposed.MAX_REQUESTS,
    },
}


def approvals_dir() -> str:
    return home.data_dir("scans", "approvals")


def _store() -> Store:
    """Looked up on every call, so the folder can be moved (MONOMI_HOME, tests)."""
    return Store(approvals_dir(), "Monomi", lambda rid: f"`python monomi.py approve {rid} --scope FILE`")


def request(tool: str, hosts: list[str], now=None) -> dict:
    """A pending approval for these hosts. Sends nothing, looks nothing up."""
    if tool not in TOOLS:
        raise ApprovalError(f"{tool} isn't an active tool")
    hosts = sorted({scope.normalize_host(h) or h for h in hosts})
    if not hosts:
        raise ApprovalError("no hostnames to approve")
    rec = _store().create({"tool": tool, "hosts": hosts}, now, hosts=len(hosts))
    return {"approval_id": rec["rid"], "tool": tool, "hosts": hosts, "expires": rec["expires"],
            "max_requests": len(hosts) * TOOLS[tool]["max_per_host"]}


def plan_lines(tool: str, inside: list[str], outside: list[dict]) -> list[str]:
    """What the person is approving, host by host."""
    spec = TOOLS[tool]
    out = [f"{tool}: {len(inside)} host(s) in scope, at most {spec['max_per_host']} GET request(s) each "
           f"({len(inside) * spec['max_per_host']} at most in total)"]
    for h in inside:
        out.append(f"  {h}")
        out += [f"      GET {url}" for url in spec["fixed"](h)]
        out.append("      and " + spec["more"].format(host=h))
    if outside:
        out.append(f"Not in scope, will get no request and no DNS lookup ({len(outside)}):")
        out += [f"  {o['host']}: {o['reason']}" for o in outside]
    return out


def approve(rid: str, scope_path: str, research_path: str | None = None, *, ask=input, out=print,
            interactive=None, now=None) -> int:
    """`monomi.py approve RID --scope FILE [--research FILE]`: show the
    plan, ask for a typed yes at a real terminal. 0 approved, 1 not."""
    now = now or _now()
    store = _store()
    rec = store.pending(rid, now, interactive, expired_hint="ask the agent to call the tool again")
    s = scope.load(scope_path)
    if s.problem():
        raise ApprovalError(f"scope file can't be used: {s.problem()}")
    r = None
    if research_path:
        try:
            r = research.load(research_path)
        except research.ResearchError as e:
            raise ApprovalError(str(e))
    inside, outside = scope.split(s, rec["hosts"])
    for line in plan_lines(rec["tool"], inside, outside):
        out(line)
    out(f"Scope: {s.path} (sha256 {s.sha256[:12]}...)")
    out(f"Research header: {r.summary} (sha256 {r.sha256[:12]}...)" if r else "Research header: none")
    if not inside:
        raise store.refuse(rec, "none of the hosts is in scope, so there's nothing to approve", now)
    if not typed_yes(ask, f"Approve {rid}? It can be used once, within {int(APPROVAL_TTL.total_seconds() // 60)} "
                          "minutes. Type yes to approve: "):
        store.decline(rec, now)
        out("Not approved. Nothing will be sent.")
        return 1
    rec = store.lock_in(rec, {
        "approved_hosts": inside, "out_of_scope": outside,
        "scope": {"path": os.path.abspath(s.path), "sha256": s.sha256},
        "research": {"path": os.path.abspath(r.path), "sha256": r.sha256} if r else None,
        "max_per_host": TOOLS[rec["tool"]]["max_per_host"],
    }, now, hosts=len(inside))
    out(f"Approved {rid}: tell the agent to call active_run with this id (single use, until {rec['expires']}).")
    return 0


def _pinned_files(rec: dict) -> tuple:
    """(scope, research, problem): the approved files, checked to be exactly
    what was approved."""
    s, problem = scope.check_pinned(rec["scope"]["path"], rec["scope"]["sha256"])
    if problem:
        return None, None, f"scope file: {problem}"
    r = None
    if rec["research"]:
        r, problem = research.check_pinned(rec["research"]["path"], rec["research"]["sha256"])
        if problem:
            return None, None, f"research file: {problem}"
    return s, r, None


def claim(rid: str, now=None) -> dict:
    """Check everything again and mark the approval used, BEFORE anything
    is sent. Returns {"tool", "hosts", "scope", "research", "max_per_host"}."""
    files = {}

    def check(rec):
        s, r, problem = _pinned_files(rec)
        files.update(scope=s, research=r)
        return problem

    rec = _store().claim(rid, now, check)
    return {"tool": rec["tool"], "hosts": rec["approved_hosts"], "scope": files["scope"],
            "research": files["research"], "max_per_host": rec["max_per_host"]}


def main(argv=None) -> int:
    import argparse
    p = argparse.ArgumentParser(prog="monomi.py approve",
                                description="approve active checks an agent asked for (typed yes)")
    p.add_argument("rid", help="the approval id the agent gave you, e.g. k7m2-x9pq")
    p.add_argument("--scope", metavar="FILE", required=True, help="scope file: only hosts it allows are touched")
    p.add_argument("--research", metavar="FILE", help="research header file, sent on every request")
    args = p.parse_args(argv)
    try:
        return approve(args.rid, args.scope, args.research)
    except ApprovalError as e:
        print(f"monomi: {e}. Nothing will be sent.", file=sys.stderr)
        return 2
