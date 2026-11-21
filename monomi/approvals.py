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
check_exposed_files the spec paths and homepage are fixed, but the scripts
and .map files come from the homepage itself, so the approval locks the
rule ("same host only") and a hard cap instead of URLs; every URL is
still checked against the scope and the approved hosts before it's sent.

Each approval is one JSON file, scans/approvals/<rid>.json, with every
event in it (refusals too), so it's its own audit trail. "Used" is a
second file, <rid>.used, created in one step that only one process can
win (O_EXCL), so two MCP servers can't both run the same approval.

Honest limit: an agent with a shell on this machine can fake a terminal.
The gate is against agents that only have MCP tools.
"""

import json
import os
import re
import secrets
import sys
from datetime import datetime, timedelta, timezone

from monomi import exposed, home, research, scope

REQUEST_TTL = timedelta(hours=1)       # a pending request nobody approved
APPROVAL_TTL = timedelta(minutes=15)   # an approval nobody used
ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"  # no 0/o, 1/l/i: easy to type
RID = re.compile(r"[a-z2-9]{4}-[a-z2-9]{4}")

# What each active tool may send per host: the URLs known in advance, the
# rule for anything else, and the hard cap.
TOOLS = {
    "fingerprint_hosts": {
        "fixed": lambda h: [f"https://{h}/"],
        "more": "http://{host}/ once, only if HTTPS fails with a TLS error or is refused",
        "max_per_host": 2,
    },
    "check_exposed_files": {
        "fixed": lambda h: [f"https://{h}{p}" for p in exposed.SPEC_PATHS] + [f"https://{h}/"],
        "more": (f"up to {exposed.MAX_SCRIPTS} scripts the homepage loads from {{host}} itself, and up to "
                 f"{exposed.MAX_MAPS} .map files they name on {{host}}: never another host"),
        "max_per_host": exposed.MAX_REQUESTS,
    },
}


class ApprovalError(ValueError):
    """Refused; the message says why. Nothing was sent."""


def approvals_dir() -> str:
    return home.data_dir("scans", "approvals")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(t: datetime) -> str:
    return t.isoformat(timespec="seconds")


def _path(rid: str) -> str:
    if not RID.fullmatch(rid or ""):
        raise ApprovalError(f"{rid!r} isn't an approval id (they look like k7m2-x9pq)")
    return os.path.join(approvals_dir(), f"{rid}.json")


def _used_path(rid: str) -> str:
    return os.path.join(approvals_dir(), f"{rid}.used")


def _load(rid: str) -> dict:
    try:
        with open(_path(rid), encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        raise ApprovalError(f"no approval {rid}")


def _save(rec: dict) -> None:
    """Write the record whole (temp file + replace), so a reader never sees half."""
    path = _path(rec["rid"])
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(rec, f, indent=2)
    os.replace(tmp, path)


def _event(rec: dict, event: str, now: datetime, **extra) -> None:
    rec["events"].append({"at": _iso(now), "event": event, **extra})


def _refuse(rec: dict, reason: str, now: datetime) -> ApprovalError:
    """Record the refusal in the approval's own file, then return the error."""
    try:
        _event(rec, "refused", now, reason=reason)
        _save(rec)
    except OSError:
        pass  # the refusal stands even if it can't be written down
    return ApprovalError(reason)


def request(tool: str, hosts: list[str], now: datetime | None = None) -> dict:
    """A pending approval for these hosts. Sends nothing, looks nothing up."""
    if tool not in TOOLS:
        raise ApprovalError(f"{tool} isn't an active tool")
    hosts = sorted({scope.normalize_host(h) or h for h in hosts})
    if not hosts:
        raise ApprovalError("no hostnames to approve")
    now = now or _now()
    os.makedirs(approvals_dir(), exist_ok=True)
    while True:
        rid = "".join(secrets.choice(ALPHABET) for _ in range(4)) + "-" + \
              "".join(secrets.choice(ALPHABET) for _ in range(4))
        if not os.path.exists(_path(rid)):
            break
    rec = {"rid": rid, "tool": tool, "state": "pending", "hosts": hosts,
           "created": _iso(now), "expires": _iso(now + REQUEST_TTL), "events": []}
    _event(rec, "requested", now, hosts=len(hosts))
    _save(rec)
    return {"approval_id": rid, "tool": tool, "hosts": hosts, "expires": rec["expires"],
            "max_requests": len(hosts) * TOOLS[tool]["max_per_host"]}


def _expired(rec: dict, now: datetime) -> bool:
    return now >= datetime.fromisoformat(rec["expires"])


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
            interactive=None, now: datetime | None = None) -> int:
    """`monomi.py approve RID --scope FILE [--research FILE]`: show the
    plan, ask for a typed yes at a real terminal. 0 approved, 1 not."""
    now = now or _now()
    interactive = interactive or (lambda: sys.stdin.isatty())
    rec = _load(rid)
    if rec["state"] != "pending":
        raise ApprovalError(f"approval {rid} is {rec['state']}, not waiting for a yes")
    if _expired(rec, now):
        raise _refuse(rec, f"request {rid} expired at {rec['expires']}; ask the agent to call the tool again", now)
    if not interactive():
        raise _refuse(rec, "approving needs a person at a real terminal (stdin isn't one)", now)
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
        raise _refuse(rec, "none of the hosts is in scope, so there's nothing to approve", now)
    try:
        answer = ask(f"Approve {rid}? It can be used once, within {int(APPROVAL_TTL.total_seconds() // 60)} "
                     "minutes. Type yes to approve: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        answer = ""
    if answer != "yes":
        rec["state"] = "declined"
        _event(rec, "declined", now)
        _save(rec)
        out("Not approved. Nothing will be sent.")
        return 1
    rec.update({
        "state": "approved", "approved_hosts": inside, "out_of_scope": outside,
        "scope": {"path": os.path.abspath(s.path), "sha256": s.sha256},
        "research": {"path": os.path.abspath(r.path), "sha256": r.sha256} if r else None,
        "max_per_host": TOOLS[rec["tool"]]["max_per_host"],
        "approved_at": _iso(now), "expires": _iso(now + APPROVAL_TTL),
    })
    _event(rec, "approved", now, hosts=len(inside))
    _save(rec)
    out(f"Approved {rid}: tell the agent to call active_run with this id (single use, until {rec['expires']}).")
    return 0


def claim(rid: str, now: datetime | None = None) -> dict:
    """Check everything again and mark the approval used, BEFORE anything
    is sent. Returns {"tool", "hosts", "scope", "research", "max_per_host"}."""
    now = now or _now()
    rec = _load(rid)
    if rec["state"] == "used" or os.path.exists(_used_path(rid)):
        raise _refuse(rec, f"approval {rid} was already used; each approval runs once", now)
    if rec["state"] != "approved":
        raise _refuse(rec, f"approval {rid} is {rec['state']}: the person running Monomi has to approve it "
                           f"first with `python monomi.py approve {rid} --scope FILE`", now)
    if _expired(rec, now):
        raise _refuse(rec, f"approval {rid} expired at {rec['expires']}; ask for a new one", now)
    s, problem = scope.check_pinned(rec["scope"]["path"], rec["scope"]["sha256"])
    if problem:
        raise _refuse(rec, f"scope file: {problem}", now)
    r = None
    if rec["research"]:
        r, problem = research.check_pinned(rec["research"]["path"], rec["research"]["sha256"])
        if problem:
            raise _refuse(rec, f"research file: {problem}", now)
    # One step only one process can win: two servers can't both use it.
    try:
        fd = os.open(_used_path(rid), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise _refuse(rec, f"approval {rid} was already used; each approval runs once", now)
    os.close(fd)
    rec["state"] = "used"
    _event(rec, "used", now)
    _save(rec)
    return {"tool": rec["tool"], "hosts": rec["approved_hosts"], "scope": s, "research": r,
            "max_per_host": rec["max_per_host"]}


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
