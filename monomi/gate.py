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
  not_own         {ip: what it is, in words}: IPs the rule saw aren't the target's
                  own, beyond what not_own_ips() knows (check 2; v1.23, rule F)

Program notes are not a check: they never change finding, lead or set
aside. Whether something is eligible depends on the program's own rules,
which Monomi can't know, so the note only says to check them.
"""

from monomi.categorize import _find_match
from monomi.internetdb import (SHARED_EDGE, SHARED_FRONT_DOOR, THIRD_PARTY_HOSTING, edge_from_cname, edge_from_ip,
                               front_door_from_cname, third_party_from_cname, third_party_from_ip)

# Kinds of path bug bounty programs often list as out of scope (gate "notes")
PROGRAM_NOTES = {
    "email": ("missing or weak DMARC / email spoofing is often out of scope for bug bounty "
              "programs: check the program's rules"),
    "version": ("a software version shown without a matched CVE is often out of scope for bug "
                "bounty programs: check the program's rules"),
}

# Scope caution (v1.16): host-name words that mark hosts programs often close
# as Not Applicable or list as out of scope. Like program notes, never a check:
# the note only says to check the program's rules. Matched with the same rule
# as categorize.py ("dev" matches dev, dev2, api-dev, but not devices).
# Pre-release is checked first, so "beta-dev" gets the pre-release note.
SCOPE_CAUTION = [
    ("pre-release", ["alpha", "beta", "preview", "experimental", "canary", "nightly"],
     "pre-release hosts (beta, preview...) are often closed as Not Applicable by bug "
     "bounty programs: check the program's rules"),
    # "demo" and "poc" are left out: names like prod-...-demo are often real
    # production, the same false positive the roadmap lists for categorize.py
    ("non-production", ["dev", "staging", "stage", "stg", "test", "testing", "uat", "qa",
                        "sandbox", "nonprod", "preprod", "tst", "pre", "pp", "etst", "euat"],
     "non-production hosts (dev, staging, test...) are often out of scope for bug bounty "
     "programs: check the program's rules"),
]

# Failing one of these sets a candidate aside instead of making it a lead:
# a lead says "investigate this", and nobody should investigate hosts that
# are out of scope or belong to someone else
SET_ASIDE_CHECKS = (1, 2)


def _canonical(host: dict) -> list[str]:
    """The end of a host's CNAME chain, as a list (empty when it has none)."""
    return [host["canonical"]] if host.get("canonical") else []


def edge_vendor(host: dict) -> str | None:
    """Which CDN a host (an enrichment entry) is behind, if any: by the
    network owner, its CNAME, or its IP block, in that order."""
    if host.get("provider") in SHARED_EDGE:
        return host["provider"]
    found = edge_from_cname(_canonical(host))
    if found:
        return found[0]
    for ip in host.get("ips", []):
        found = edge_from_ip(ip)
        if found:
            return found[0]
    return None


def edge_ips(results: dict) -> set[str]:
    """IPs that are shared CDN edge servers: what they show isn't the target's own.

    Reads the host's CNAME too (v1.23), so a passive scan without --ports
    knows a host behind Azure Front Door is behind a CDN, the same as one with it."""
    edge = set()
    exp = results.get("exposure") or {}
    for group in ("ips", "nothing_seen"):
        for ip, d in exp.get(group, {}).items():
            if d.get("shared_edge"):
                edge.add(ip)
    enr = results.get("enrichment") or {}
    for h in enr.get("hosts", {}).values():
        if h.get("provider") in SHARED_EDGE or edge_from_cname(_canonical(h)):
            edge.update(h["ips"])
        edge.update(ip for ip in h["ips"] if edge_from_ip(ip))
    return edge


def not_own_ips(results: dict) -> dict[str, str]:
    """IPs that aren't the target's own server -> what they are, in words:
    a shared CDN edge, a third-party host (a store, a forum, Microsoft 365,
    Google's front end...) or a shared front door (AWS Global Accelerator). Check 2 and the path rules use this."""
    out = {ip: "a shared CDN edge IP" for ip in edge_ips(results)}
    enr = results.get("enrichment") or {}
    for h in enr.get("hosts", {}).values():
        for ip in h.get("ips", []):
            found = third_party_from_ip(ip)  # by address: the provider name can't tell (v1.22.1)
            if found:
                out.setdefault(ip, f"third-party hosting ({found[0]})")
        found = third_party_from_cname(_canonical(h))  # by CNAME: same reason (v1.23)
        if found:
            for ip in h.get("ips", []):
                out.setdefault(ip, f"third-party hosting ({found[0]})")
        found = front_door_from_cname(_canonical(h))  # API Gateway (v1.29.4)
        if found:
            for ip in h.get("ips", []):
                out.setdefault(ip, f"a shared front door ({found[0]})")
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


def _caution_kind(host: str, domain: str) -> int | None:
    """Index into SCOPE_CAUTION for this host, or None. Only the labels in
    front of the target domain count, so a target named "beta.test" doesn't
    put a note on every host. Without a domain, the last two labels are
    left out (the registrable name, roughly)."""
    host = host.lower().rstrip(".")
    domain = (domain or "").lower().rstrip(".")
    if domain and _under(host, domain):
        labels = host[: -len(domain)].rstrip(".").split(".") if host != domain else []
    else:
        labels = host.split(".")[:-2] if "." in host else [host]
    for i, (_, words, _) in enumerate(SCOPE_CAUTION):
        if any(_find_match(label, w) for label in labels if label for w in words):
            return i
    return None


def scope_notes(hosts, domain: str = "") -> list[str]:
    """One note per kind of scope caution the hosts hit, naming the hosts.
    Never a check: it never changes finding, lead or set aside."""
    hit = {}
    for h in hosts:
        kind = _caution_kind(h, domain)
        if kind is not None:
            hit.setdefault(kind, []).append(h)
    return [f"{SCOPE_CAUTION[k][2]} ({_names(sorted(set(hs)))})" for k, hs in sorted(hit.items())]


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
    not_own = {**candidate["gate_input"].get("not_own", {}), **ctx.not_own}
    ips = [ip for ip in candidate["gate_input"].get("ips", []) if ip in not_own]
    if not ips:
        return None
    kinds = sorted({not_own[ip] for ip in ips})
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
        notes = [PROGRAM_NOTES[note]] if note else []
        notes += scope_notes(candidate["gate_input"].get("hosts", []), ctx.target)
        out["gate"] = {"result": result, "passed": len(CHECKS) - len(failed),
                       "of": len(CHECKS), "failed": failed, "notes": notes}
        if aside:
            set_aside.append({"rule": out["rule"], "targets": out["targets"],
                              "title": out["title"], "severity": out["severity"],
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
            "of": len(TAKEOVER_CHECKS), "failed": failed,
            "notes": scope_notes([record["host"]] if record.get("host") else [], domain or "")}


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
