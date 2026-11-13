"""
The validation gate: one fixed checklist every attack path must pass
before Monomi calls it a finding.

The rules in paths.py don't decide whether what they built is an attack
path or only a lead. Each rule builds a candidate and says what it rests
on (its "gate input"). The gate runs every candidate through the same
checks, in the same order, and decides:

  finding    passes every check: an attack path (P1, P2...)
  lead       fails check 3, 4, 5 or 6: something to investigate (L1,
             L2...), with the first failed check's reason as its "missing" line
  set aside  fails check 1 or 2 (out of scope, or not the target's own):
             listed with the reason, never a path or a lead

Every path, lead and set-aside item carries its "gate": which checks it
passed and why any failed. Deterministic code only: the AI narrates the
result, it never decides a check.

The gate input a rule gives (every key optional except door/no_door):
  door / no_door  the facts that show an observed way in, or why there are none
  hosts           the hostnames the attack goes through
  ips             the IPs it rests on
  nxdomain        takeover records whose "doesn't exist" it rests on
  claim           {"cname", "claimable"} for a takeover
  program_note    a key of PROGRAM_NOTES, for kinds bug bounty programs often exclude

Program notes are not a check: they never change finding, lead or set
aside. Whether something is eligible depends on the program's own rules,
which Monomi can't know, so the note only says to check them.
"""

from internetdb import SHARED_EDGE, SHARED_FRONT_DOOR, THIRD_PARTY_HOSTING, edge_from_ip

# Kinds of path bug bounty programs often list as out of scope (gate "notes")
PROGRAM_NOTES = {
    "email": ("missing or weak DMARC / email spoofing is often out of scope for bug bounty "
              "programs: check the program's rules"),
    "version": ("a software version shown without a matched CVE is often out of scope for bug "
                "bounty programs: check the program's rules"),
}

# Failing one of these sets a candidate aside instead of making it a lead:
# a lead says "investigate this", and nobody should investigate hosts that
# are out of scope or belong to someone else
SET_ASIDE_CHECKS = (1, 2)


def edge_ips(results: dict) -> set[str]:
    """IPs that are shared CDN edge servers: what they show isn't the target's own."""
    edge = set()
    exp = results.get("exposure") or {}
    for group in ("ips", "nothing_seen"):
        for ip, d in exp.get(group, {}).items():
            if d.get("shared_edge"):
                edge.add(ip)
    enr = results.get("enrichment") or {}
    for h in enr.get("hosts", {}).values():
        if h.get("provider") in SHARED_EDGE:
            edge.update(h["ips"])
        edge.update(ip for ip in h["ips"] if edge_from_ip(ip))
    return edge


def not_own_ips(results: dict) -> dict[str, str]:
    """IPs that aren't the target's own server -> what they are, in words:
    a shared CDN edge, a third-party host (a store, a forum...) or a shared
    front door (AWS Global Accelerator). Check 2 and the path rules use this."""
    out = {ip: "a shared CDN edge IP" for ip in edge_ips(results)}
    enr = results.get("enrichment") or {}
    for h in enr.get("hosts", {}).values():
        provider = h.get("provider")
        if provider in THIRD_PARTY_HOSTING:
            kind = f"third-party hosting ({provider})"
        elif provider in SHARED_FRONT_DOOR:
            kind = f"a shared front door ({provider})"
        else:
            continue
        for ip in h.get("ips", []):
            out.setdefault(ip, kind)
    return out


class Context:
    """What every check may look at besides the candidate itself."""

    def __init__(self, results: dict, evidence=(), scope=None):
        self.results = results
        self.target = results.get("target", "")
        self.scanned = set(results.get("subdomains", [])) | {self.target}
        self.facts = {e["id"]: e for e in evidence}
        self.scope = scope  # the --scope file (a scope.Scope), or None
        self.not_own = not_own_ips(results)
        enr = results.get("enrichment") or {}
        self.private = {ip for h in enr.get("hosts", {}).values() for ip in h.get("private_ips", [])}


def _names(items, most=3):
    """"a", "a, b" or "a, b and 2 more", for a reason line."""
    items = list(items)
    shown = ", ".join(items[:most])
    return shown + (f" and {len(items) - most} more" if len(items) > most else "")


def _under(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)


def out_of_scope_hosts(results: dict, scope=None) -> set[str]:
    """Hosts this scan saw that are out of scope: not among the scan's hosts
    or under its domain, or not allowed by the --scope file when one was given.
    The path rules leave these out of their supporting evidence (v1.13.1), so an
    excluded host can never hold up a path or a lead about other hosts. A
    candidate that's about excluded hosts alone still reaches check 1, which
    sets it aside, so nothing disappears without a reason."""
    target = results.get("target", "")
    scanned = set(results.get("subdomains", [])) | {target}
    seen = set(results.get("subdomains", [])) | set((results.get("enrichment") or {}).get("hosts", {}))
    out = set()
    for h in seen:
        if target and h not in scanned and not _under(h, target):
            out.add(h)
        elif scope is not None and not scope.match(h).allowed:
            out.add(h)
    return out


# ---------- The checks: each returns why it fails, or None when it passes ----------

def in_scope(candidate: dict, ctx: Context) -> str | None:
    """Check 1, in scope: at least one host the attack goes through is one of
    this scan's hosts or under the scanned domain, and allowed by the --scope
    file when one was given. (The scan's hosts come from the domain's own
    sources, and --hosts files are already checked against the domain.)"""
    hosts = candidate["gate_input"].get("hosts", [])
    if not hosts or not ctx.target:
        return None
    under = [h for h in hosts if h in ctx.scanned or _under(h, ctx.target)]
    if not under:
        return (f"{_names(hosts)} {'is' if len(hosts) == 1 else 'are'} not under {ctx.target} "
                "and not among this scan's hosts")
    if ctx.scope is None:
        return None
    matches = [ctx.scope.match(h) for h in under]
    if any(m.allowed for m in matches):
        return None
    return "not in the scope file: " + "; ".join(f"{m.host} ({m.reason})" for m in matches[:3])


def target_own(candidate: dict, ctx: Context) -> str | None:
    """Check 2, the target's own: no IP the path rests on is someone else's
    server: a shared CDN edge (Cloudflare, Vercel...), third-party hosting (a
    store, a forum...) or a shared front door (AWS Global Accelerator). What
    such an IP shows belongs to that service, not to the target."""
    ips = [ip for ip in candidate["gate_input"].get("ips", []) if ip in ctx.not_own]
    if not ips:
        return None
    kinds = sorted({ctx.not_own[ip] for ip in ips})
    return (f"{_names(ips)} {'is' if len(ips) == 1 else 'are'} {' / '.join(kinds)}: what "
            f"{'it shows' if len(ips) == 1 else 'they show'} belongs to that service, not only "
            f"{ctx.target or 'the target'}")


def seen_this_run(candidate: dict, ctx: Context) -> str | None:
    """Check 3, seen this run: every fact the path cites was collected by this
    scan, not taken from a saved copy of a source or imported from another tool."""
    ids = [eid for s in candidate.get("steps", []) for eid in s["evidence"]]
    ids += [eid for a in candidate.get("actions", []) for eid in a["evidence"]]
    for eid in dict.fromkeys(ids):  # each fact once, in order
        for s in ctx.facts.get(eid, {}).get("sources", []):
            if s.get("from_saved"):
                return (f"{eid} comes from a saved copy ({s['name']}, collected {s.get('collected_at')}), "
                        "not this scan: re-run to confirm it")
            if s.get("imported_at"):
                return (f"{eid} was imported ({s['name']}) and its collection time is unknown: "
                        "re-run Monomi's own checks to confirm it")
    return None


def confirmed_twice(candidate: dict, ctx: Context) -> str | None:
    """Check 4, confirmed twice: every "doesn't exist" (NXDOMAIN) the path
    rests on was confirmed over DNS-over-HTTPS, not by system DNS alone.
    A local DNS cache (WSL's, the lab) can replay an old NXDOMAIN for a name
    that exists now."""
    for record in candidate["gate_input"].get("nxdomain", []):
        confirmed_by = record.get("nxdomain_confirmed_by")
        if confirmed_by is None:
            return (f"whether {record['cname']} not existing was double-checked over "
                    "DNS-over-HTTPS wasn't recorded (scan saved before v1.13)")
        if not confirmed_by:
            return (f"{record['cname']} not existing (NXDOMAIN) comes from system DNS alone: "
                    "DNS-over-HTTPS couldn't be reached to double-check it, so a stale DNS "
                    "cache can't be ruled out")
    return None


def way_in(candidate: dict, ctx: Context) -> str | None:
    """Check 5, observed way in: the path's door is an observed fact (a risky
    open service, a matched CVE, a claimable dangling CNAME, a DMARC record)."""
    gate_input = candidate["gate_input"]
    if gate_input["door"]:
        return None
    return gate_input["no_door"]


def claimable(candidate: dict, ctx: Context) -> str | None:
    """Check 6, claimable / reachable: a takeover target is on a service known
    to let deleted names be claimed again and isn't inside the scanned domain,
    and no IP the path rests on is a private one nobody outside can reach."""
    claim = candidate["gate_input"].get("claim")
    if claim:
        cname = claim["cname"]
        if ctx.target and _under(cname, ctx.target):
            return f"{cname} is inside {ctx.target}, so only its owner can create that name"
        if not claim["claimable"]:
            return (f"who can claim {cname} is unknown: it isn't on a service Monomi knows lets "
                    "deleted names be claimed again, and whether its domain can be registered "
                    "wasn't checked")
    private = [ip for ip in candidate["gate_input"].get("ips", []) if ip in ctx.private]
    if private:
        return f"{_names(private)} {'is a private IP' if len(private) == 1 else 'are private IPs'}: not reachable from the internet"
    return None


# (number, name, check), run in this order. Numbers match the design in
# issue #15, so a failed check reads the same in every output.
CHECKS = [
    (1, "in scope", in_scope),
    (2, "the target's own", target_own),
    (3, "seen this run", seen_this_run),
    (4, "confirmed twice", confirmed_twice),
    (5, "observed way in", way_in),
    (6, "claimable / reachable", claimable),
]


def failed_checks(candidate: dict, results: dict, evidence=(), scope=None, ctx=None) -> list[dict]:
    """Every check this candidate fails, in order, each with its reason."""
    ctx = ctx or Context(results, evidence, scope)
    failed = []
    for number, name, check in CHECKS:
        why = check(candidate, ctx)
        if why is not None:
            failed.append({"check": number, "name": name, "why": why})
    return failed


def review(candidates: list[dict], results: dict, evidence=(), scope=None
           ) -> tuple[list[dict], list[dict], list[dict]]:
    """Split candidates into (attack paths, leads, set aside), each in the order given.

    Each gets its "gate" block. A lead's "missing" line, and a set-aside
    item's "why", is the reason of the first check that decided it. The gate
    input is only for the gate, so it never leaves this function.
    """
    ctx = Context(results, evidence, scope)
    paths, leads, set_aside = [], [], []
    for candidate in candidates:
        failed = failed_checks(candidate, results, ctx=ctx)
        out = {k: v for k, v in candidate.items() if k != "gate_input"}
        aside = [f for f in failed if f["check"] in SET_ASIDE_CHECKS]
        result = "set_aside" if aside else "lead" if failed else "finding"
        note = candidate["gate_input"].get("program_note")
        out["gate"] = {"result": result, "passed": len(CHECKS) - len(failed),
                       "of": len(CHECKS), "failed": failed,
                       "notes": [PROGRAM_NOTES[note]] if note else []}
        if aside:
            set_aside.append({"title": out["title"], "severity": out["severity"],
                              "why": aside[0]["why"], "gate": out["gate"]})
        elif failed:
            out["missing"] = failed[0]["why"]
            leads.append(out)
        else:
            paths.append(out)
    return paths, leads, set_aside


# The checks that apply to one takeover record on its own, outside a scan
# (MCP check_takeover): its "doesn't exist" must be confirmed twice, and its
# target must be claimable. Scope, ownership and freshness need the whole scan.
TAKEOVER_CHECKS = (4, 6)


def takeover_gate(record: dict, domain: str | None = None) -> dict:
    """The gate block for one dangling-CNAME record from takeover.check_hosts().

    "finding" when its NXDOMAIN was confirmed over DNS-over-HTTPS and its
    target is on a service known to let deleted names be claimed again (and
    isn't inside the domain); otherwise "lead", with the failed checks.
    """
    candidate = {"gate_input": {"door": [record], "no_door": None, "nxdomain": [record],
                                "claim": {"cname": record["cname"], "claimable": record.get("claimable", False)}}}
    ctx = Context({"target": domain or ""})
    failed = []
    for number, name, check in CHECKS:
        if number in TAKEOVER_CHECKS:
            why = check(candidate, ctx)
            if why is not None:
                failed.append({"check": number, "name": name, "why": why})
    return {"result": "lead" if failed else "finding", "passed": len(TAKEOVER_CHECKS) - len(failed),
            "of": len(TAKEOVER_CHECKS), "failed": failed, "notes": []}


def describe(gate: dict | None) -> str:
    """The gate result in a few words, the same in every output.

    'gate 6/6' · 'gate 5/6, failed #5 observed way in' · 'gate not run (saved before v1.13)'
    """
    if not gate:
        return "gate not run (saved before v1.13)"
    text = f"gate {gate['passed']}/{gate['of']}"
    if gate["failed"]:
        text += ", failed " + ", ".join(f"#{f['check']} {f['name']}" for f in gate["failed"])
    return text
