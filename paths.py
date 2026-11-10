"""
Attack paths: how an attacker would most likely try to get in, worked out
by code from the evidence list.

Each path is a chain of steps. Every step cites evidence IDs and gets its
label here, not from the AI: Observed (the evidence shows it), Inference
(follows from the evidence) or Lead (needs checking first). A path is only
as strong as its weakest step. The AI only writes the paths up in plain
English, so the same scan always gives the same paths, whatever the model.

No path is ever made up: if nothing chains, the answer is "no path found".

A side door (a risky-named host on the same server as production) is only
an attack path when something on that server gives a way in: a risky open
service or a known CVE. Without one it is a lead (L1, L2...): worth a look,
listed after the attack paths, with a "missing" line that names the gap.
Leads are never part of "fix this first".

Each path also lists its actions: the real fixes that close it. One action
is one job for one owner and holds the evidence IDs it deals with. A path is
only closed when every one of its actions is done.
"""

import re
from categorize import categorize
from internetdb import SHARED_EDGE, edge_from_ip

LABEL_RANK = {"Observed": 0, "Inference": 1, "Lead": 2}
SEVERITY_RANK = {"High": 0, "Medium": 1, "Low": 2}
MAX_PATHS = 10

# More hosts than this on the same IPs = a shared load balancer or ingress,
# not one server, so rule E builds no side door through it
SHARED_INGRESS = 10

# Rule E wording per hostname category: (one host, several hosts, why it's a soft target)
SIDE_DOOR_WORDS = {
    "non-production": ("a non-production host", "non-production hosts",
                       "Non-production sites are often less protected"),
    "legacy": ("an old or legacy host", "old or legacy hosts",
               "Old sites are often left unpatched"),
    "access": ("a login or remote-access host", "login or remote-access hosts",
               "Login and remote-access pages are where attackers try guessed or stolen passwords"),
    "internal-tools": ("an internal tool", "internal tools",
                       "Internal tools are often left with weak or default logins"),
    "iot-ot": ("a device or control system", "devices or control systems",
               "Devices and control systems are often left on default settings"),
    None: ("a non-production or internal host", "non-production or internal hosts",
           "Hosts like these are often less protected"),
}


def _by_kind(evidence):
    """{kind: [facts]} for every fact that has a kind."""
    found = {}
    for e in evidence:
        if e.get("kind"):
            found.setdefault(e["kind"], []).append(e)
    return found


def _step(text, facts, label):
    return {"text": text, "evidence": [f["id"] for f in facts], "label": label}


def _owners(facts):
    """Every owner of these facts, each named once, in the order first seen."""
    seen = []
    for f in facts:
        seen += [o for o in f.get("owners", []) if o not in seen]
    return seen


def _action(facts, what=None):
    """One real fix: what to do, the evidence it deals with, and who owns it."""
    return {"what": what or facts[0]["fact"], "evidence": [f["id"] for f in facts],
            "owners": _owners(facts)}


def _path(title, severity, steps, outcome, actions):
    return {
        "title": title,
        "severity": severity,
        "strength": max((s["label"] for s in steps), key=LABEL_RANK.get),
        "steps": steps,
        "outcome": outcome,
        "actions": actions,
    }


def _names(hosts, most=3):
    """"a", "a and b", "a, b and c", or "a, b, c and 2 more"."""
    if len(hosts) == 1:
        return hosts[0]
    if len(hosts) > most:
        return f"{', '.join(hosts[:most])} and {len(hosts) - most} more"
    return f"{', '.join(hosts[:-1])} and {hosts[-1]}"


def _edge_ips(results):
    """IPs that are shared CDN edge servers: sharing one proves nothing."""
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


def build_paths(results: dict, evidence: list[dict]) -> dict:
    """Chain evidence into attack paths and leads.

    Returns {"paths", "leads", "fix_first", "more", "more_leads"}.
    """
    # Each rule ends with the path's actions (see _action). Evidence that
    # only backs a step up, like the email facts in rule A, is in no action.
    kinds = _by_kind(evidence)
    target = results.get("target", "")
    spoof = kinds.get("email_spoofable", []) + kinds.get("email_partial", [])
    paths, leads = [], []

    # A. Subdomain takeover: claim the deleted name, then serve pages on it
    for lead in kinds.get("takeover_lead", []):
        host = lead["host"]
        steps = [
            _step(f"{host} points to a deleted cloud resource on a service that lets "
                  "deleted names be claimed again", [lead], "Observed"),
            _step(f"An attacker claims that name and controls what {host} serves", [lead], "Lead"),
        ]
        if spoof:
            steps.append(_step(f"They send email that appears to come from {target}, "
                               f"linking to {host}", spoof, "Inference"))
        paths.append(_path(f"Take over {host}", "High", steps,
                           f"Phishing pages or stolen cookies on a real {target} subdomain", [_action([lead])]))
    for lead in kinds.get("dangling_unknown", []):
        host = lead["host"]
        steps = [
            _step(f"{host} points to a name that no longer exists, on an unknown service", [lead], "Observed"),
            _step("If that name's domain is free to register, an attacker buys it "
                  f"and controls what {host} serves", [lead], "Lead"),
        ]
        paths.append(_path(f"Take over {host} through an expired name", "Medium", steps,
                           f"Phishing pages on a real {target} subdomain", [_action([lead])]))

    # B. Email impersonation
    for v in spoof:
        spoofable = v["kind"] == "email_spoofable"
        steps = [
            _step(f"Receiving mail servers have no enforced policy to reject mail that "
                  f"falsely claims to be from {target}", [v], "Observed" if spoofable else "Inference"),
            _step(f"An attacker sends phishing email from an @{target} address "
                  "to staff, customers or partners", [v], "Inference"),
        ]
        paths.append(_path(f"Send email as {target}", "High" if spoofable else "Medium", steps,
                           "Stolen passwords, payments or malware through trusted-looking email", [_action([v])]))

    exp = results.get("exposure") or {}
    exp_ips = exp.get("ips", {})

    # C. Services that usually shouldn't face the internet
    for r in kinds.get("risky_service", []):
        ip = r["host"]
        hosts = ", ".join(exp_ips.get(ip, {}).get("hosts", [])[:3]) or ip
        steps = [
            _step(f"{ip} ({hosts}) has services open to the internet that usually "
                  "shouldn't be", [r], "Observed"),
            _step("An attacker tries logins, password guessing or known exploits "
                  "against those services directly", [r], "Inference"),
        ]
        paths.append(_path(f"Attack the exposed services on {ip}", "High", steps,
                           "Direct access to the server or its data", [_action([r])]))

    # Which IPs each live host is on, for D and E
    enr = results.get("enrichment") or {}
    ips_of = {h: d.get("ips", []) for h, d in enr.get("hosts", {}).items()}
    edge = _edge_ips(results)

    # E. Side door: risky-named hosts on the same server as production.
    # Private IPs are skipped (nobody on the internet can reach them), hosts
    # are grouped by their set of IPs (one path per server, not one per IP),
    # and a host on several IPs, or an IP that carries many hosts, is behind a
    # load balancer or shared front door, not on one server.
    private = {h: d.get("private_ips", []) for h, d in enr.get("hosts", {}).items()}
    groups = {}  # set of IPs -> the risky-name facts of every host on exactly those IPs
    for r in kinds.get("risky_name", []):
        ips = frozenset(ip for ip in ips_of.get(r["host"], [])
                        if ip not in edge and ip not in private.get(r["host"], []))
        if ips:
            groups.setdefault(ips, []).append(r)
    side_door_ips = set()
    for ips, names in groups.items():
        names = sorted(names, key=lambda r: r["host"])
        hosts = [r["host"] for r in names]
        on_ips = [h for h, h_ips in ips_of.items() if ips & set(h_ips)]
        if len(ips) > 1 or len(on_ips) > SHARED_INGRESS:
            continue  # a load balancer or shared front door, so "same server" can't be claimed
        shared = [h for h in on_ips if h not in hosts
                  and categorize(h, target)["category"] in ("apex", "content", "app-api", "uncategorized")]
        if not shared:
            continue
        where = _names(sorted(ips))
        cats = {categorize(h, target)["category"] for h in hosts}
        cat = cats.pop() if len(cats) == 1 else None
        like_one, like_many, why = SIDE_DOOR_WORDS.get(cat, SIDE_DOOR_WORDS[None])
        who, one = _names(hosts), len(hosts) == 1
        resolves = [e for e in kinds.get("resolves", []) if e["host"] in hosts + shared]
        steps = [
            _step(f"{who} {'is' if one else 'are'} live and named like {like_one if one else like_many}",
                  names, "Observed"),
            _step(f"{'It is' if one else 'They are'} on the same IP ({where}) as {_names(shared)}", resolves, "Observed"),
            _step(f"{why}, so {who} {'is a likely first target' if one else 'are likely first targets'}, "
                  "and getting in there may mean getting into the same server", names, "Inference"),
        ]
        # What promotes a side door to an attack path: a way into the server
        # itself. Web ports alone don't count (every web server has them) and
        # neither does a version on its own (unverified).
        risky = [e for e in kinds.get("risky_service", []) if e["host"] in ips]
        cves = [e for e in kinds.get("cves", []) if e["host"] in ips]
        if risky:
            steps.append(_step(f"{where} also has services open to the internet that usually "
                               "shouldn't be", risky, "Observed"))
        leaks = [e for e in kinds.get("version_leak", []) if ips & set(ips_of.get(e["host"], []))]
        leaks += cves
        if leaks:
            steps.append(_step("The server shows software versions an attacker can match "
                               "to public exploits (versions must be verified)", leaks, "Lead"))
        side_door_ips.update(ips)
        if not risky and not cves:
            lead = _path(f"Check whether {who} {'is' if one else 'are'} a side door into {where}",
                         "Medium", steps, f"Access to the server that also runs {shared[0]}",
                         [_action([r], f"Take {r['host']} off the internet or restrict who can reach it")
                          for r in names])
            lead["missing"] = (f"nothing shows a way into {'this host' if one else 'these hosts'} yet "
                               f"(no risky open service or known CVE on {where})")
            leads.append(lead)
            continue
        # One action per risky host: each one is its own door, so all of them
        # must be dealt with. The version leaks only back the last step up.
        # The action says what to do; why the name is risky stays in the evidence.
        paths.append(_path(f"Use {who} as a side door into {where}", "Medium", steps,
                           f"Access to the server that also runs {shared[0]}",
                           [_action([r], f"Take {r['host']} off the internet or restrict who can reach it")
                            for r in names]))

    # D. Known-vulnerable versions (IPs already covered by a side door are skipped)
    for ip in sorted({e["host"] for e in kinds.get("cves", [])}
                     | {ip for e in kinds.get("version_leak", []) for ip in ips_of.get(e["host"], [])}):
        if ip in edge or ip in side_door_ips:
            continue
        cves = [e for e in kinds.get("cves", []) if e["host"] == ip]
        leaks = [e for e in kinds.get("version_leak", []) if ip in ips_of.get(e["host"], [])]
        steps = [_step(f"{ip} shows software versions or matching CVEs", cves + leaks, "Observed"),
                 _step("An attacker checks whether the running version really has those flaws "
                       "and tries public exploits", cves + leaks, "Lead")]
        paths.append(_path(f"Exploit known flaws on {ip}", "Medium" if cves else "Low", steps,
                           "Server compromise, if the version is really vulnerable",
                           [_action(cves + leaks, f"Upgrade or patch the server software on {ip}")]))

    paths.sort(key=lambda p: (SEVERITY_RANK[p["severity"]], LABEL_RANK[p["strength"]]))
    more = max(0, len(paths) - MAX_PATHS)
    paths = paths[:MAX_PATHS]
    for i, p in enumerate(paths, 1):
        p["id"] = f"P{i}"
    # Leads: never above Medium, surest first, and no part in fix_first
    leads.sort(key=lambda p: LABEL_RANK[p["strength"]])
    more_leads = max(0, len(leads) - MAX_PATHS)
    leads = leads[:MAX_PATHS]
    for i, p in enumerate(leads, 1):
        p["id"] = f"L{i}"
    return {"paths": paths, "leads": leads, "fix_first": _fix_first(paths),
            "more": more, "more_leads": more_leads}


def _fix_first(paths):
    """What to fix first, as a list of actions.

    An action closes a path on its own only when it is that path's only
    action. The single action that closes the most paths wins (ties go to
    the more severe path). When no single action closes any path, the answer
    is every action of the most severe path: together they close it.

    "closes" = paths closed by doing everything in "actions". "partial" =
    paths the chosen action is only one part of ({"path": "P1", "of": 3}),
    and "still_required_actions" = the other actions those paths need.
    """
    closes, partial, by_key = {}, {}, {}
    for p in paths:  # already sorted most severe first
        for a in p["actions"]:
            key = tuple(a["evidence"])
            by_key.setdefault(key, a)
            if len(p["actions"]) == 1:
                closes.setdefault(key, []).append(p["id"])
            else:
                partial.setdefault(key, []).append({"path": p["id"], "of": len(p["actions"])})
    if closes:
        best = max(closes, key=lambda key: len(closes[key]))  # first one wins a tie
        part_of = {x["path"] for x in partial.get(best, [])}
        others = [a for p in paths if p["id"] in part_of
                  for a in p["actions"] if tuple(a["evidence"]) != best]
        return {"actions": [by_key[best]], "closes": closes[best],
                "partial": partial.get(best, []), "still_required_actions": others}
    top = next((p for p in paths if p["actions"]), None)
    if not top:
        return None
    return {"actions": top["actions"], "closes": [top["id"]],
            "partial": [], "still_required_actions": []}


def fix_first_parts(fix: dict) -> dict:
    """The pieces of the "Fix this first" line, the same in every output.

    Several actions are never worded as if one of them closes the path:
    the label counts them and the text says they close it together.
    """
    actions = fix["actions"]
    one = len(actions) == 1
    return {
        "label": "Fix this first" if one else f"Fix these {len(actions)} first",
        "ids": [eid for a in actions for eid in a["evidence"]],
        "owners": ", ".join(_owners(actions)) or "unknown",
        "closes": ("closes " if one else "together they close ") + ", ".join(fix["closes"]),
        "what": "; ".join(a["what"] for a in actions),
    }


def upgrade_saved(built: dict, evidence: list[dict]) -> dict:
    """Give a scan saved before v1.10 its actions, keeping its paths and IDs.

    Old paths had "fix": a flat list of evidence IDs. Risky-name facts
    become one action each, version facts on a side door are dropped (they
    only back a step up), other version facts become one upgrade action.
    """
    built.setdefault("leads", [])       # saved before the Lead tier: its side
    built.setdefault("more_leads", 0)   # doors stay the paths they were saved as
    if all("actions" in p for p in built["paths"]):
        return built
    by_id = {e["id"]: e for e in evidence}
    for p in built["paths"]:
        facts = [by_id[eid] for eid in p.pop("fix", []) if eid in by_id]
        versions = [f for f in facts if f.get("kind") in ("cves", "version_leak")]
        rest = [f for f in facts if f not in versions]
        p["actions"] = [_action([f], f"Take {f['host']} off the internet or restrict who can reach it"
                                if f.get("kind") == "risky_name" else None) for f in rest]
        if versions and not rest:
            where = p["title"].rsplit(" ", 1)[-1]
            p["actions"] = [_action(versions, f"Upgrade or patch the server software on {where}")]
    built["fix_first"] = _fix_first(built["paths"])
    return built


def check_paths(report: str, built: dict) -> tuple[list[str], list[str]]:
    """Path and lead IDs the report left out, and IDs it made up (each sorted)."""
    ids = {p["id"] for p in built["paths"] + built.get("leads", [])}
    named = set(re.findall(r"\b[PL]\d+\b", report))
    order = lambda i: (i[0] != "P", int(i[1:]))  # paths first, then leads
    return sorted(ids - named, key=order), sorted(named - ids, key=order)


def paths_appendix(built: dict) -> str:
    """Markdown list of the paths exactly as code built them."""
    lines = [
        "## Attack paths (built by code)",
        "",
        "Worked out by monomi's code from the evidence above, not by the AI. "
        "A path shows how an attack would most likely go, not proof that it works.",
        "",
    ]
    if not built["paths"]:
        lines.append("*No attack path found in this scan's evidence.*")
    for p in built["paths"]:
        lines.append(f"- **{p['id']}: {p['title']}** ({p['severity']}, weakest step: {p['strength']})")
        for n, s in enumerate(p["steps"], 1):
            lines.append(f"  {n}. {s['label']}: {s['text']} [{', '.join(s['evidence'])}]")
        lines.append(f"  - Result: {p['outcome']}")
    if built.get("more"):
        lines.append(f"- {built['more']} lower-ranked path(s) left out")
    if built.get("leads"):
        lines += ["", "**Leads to investigate** (not attack paths: each is missing "
                      "something that would make it one)", ""]
    for p in built.get("leads", []):
        lines.append(f"- **{p['id']}: {p['title']}** ({p['severity']}, weakest step: {p['strength']})")
        for n, s in enumerate(p["steps"], 1):
            lines.append(f"  {n}. {s['label']}: {s['text']} [{', '.join(s['evidence'])}]")
        lines.append(f"  - Missing: {p['missing']}")
    if built.get("more_leads"):
        lines.append(f"- {built['more_leads']} more lead(s) left out")
    fix = built.get("fix_first")
    if fix:
        t = fix_first_parts(fix)
        lines += ["", f"**{t['label']}** ({', '.join(t['ids'])}, owner: {t['owners']}, "
                      f"{t['closes']}): {t['what']}"]
    return "\n".join(lines) + "\n"
