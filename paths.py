"""
Attack paths: how an attacker would most likely try to get in, worked out
by code from the evidence list.

Each path is a chain of steps. Every step cites evidence IDs and gets its
label here, not from the AI: Observed (the evidence shows it), Inference
(follows from the evidence) or Lead (needs checking first). A path is only
as strong as its weakest step. The AI only writes the paths up in plain
English, so the same scan always gives the same paths, whatever the model.

No path is ever made up: if nothing chains, the answer is "no path found".
"""

from categorize import categorize
from internetdb import SHARED_EDGE

LABEL_RANK = {"Observed": 0, "Inference": 1, "Lead": 2}
SEVERITY_RANK = {"High": 0, "Medium": 1, "Low": 2}
MAX_PATHS = 10


def _by_kind(evidence):
    """{kind: [facts]} for every fact that has a kind."""
    found = {}
    for e in evidence:
        if e.get("kind"):
            found.setdefault(e["kind"], []).append(e)
    return found


def _step(text, facts, label):
    return {"text": text, "evidence": [f["id"] for f in facts], "label": label}


def _path(title, severity, steps, outcome, fix):
    return {
        "title": title,
        "severity": severity,
        "strength": max((s["label"] for s in steps), key=LABEL_RANK.get),
        "steps": steps,
        "outcome": outcome,
        "fix": [f["id"] for f in fix],
    }


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
    return edge


def build_paths(results: dict, evidence: list[dict]) -> dict:
    """Chain evidence into attack paths. Returns {"paths", "fix_first", "more"}."""
    kinds = _by_kind(evidence)
    target = results.get("target", "")
    spoof = kinds.get("email_spoofable", []) + kinds.get("email_partial", [])
    paths = []

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
                           f"Phishing pages or stolen cookies on a real {target} subdomain", [lead]))
    for lead in kinds.get("dangling_unknown", []):
        host = lead["host"]
        steps = [
            _step(f"{host} points to a name that no longer exists, on an unknown service", [lead], "Observed"),
            _step("If that name's domain is free to register, an attacker buys it "
                  f"and controls what {host} serves", [lead], "Lead"),
        ]
        paths.append(_path(f"Take over {host} through an expired name", "Medium", steps,
                           f"Phishing pages on a real {target} subdomain", [lead]))

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
                           "Stolen passwords, payments or malware through trusted-looking email", [v]))

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
                           "Direct access to the server or its data", [r]))

    # Which IPs each live host is on, for D and E
    enr = results.get("enrichment") or {}
    ips_of = {h: d.get("ips", []) for h, d in enr.get("hosts", {}).items()}
    edge = _edge_ips(results)

    # E. Side door: a non-production host on the same server as production
    side_door_ips = set()
    for r in kinds.get("risky_name", []):
        host = r["host"]
        for ip in ips_of.get(host, []):
            if ip in edge or ip in side_door_ips:
                continue
            shared = [h for h, ips in ips_of.items()
                      if h != host and ip in ips
                      and categorize(h, target)["category"] in ("apex", "content", "app-api", "uncategorized")]
            if not shared:
                continue
            resolves = [e for e in kinds.get("resolves", []) if e["host"] in [host] + shared]
            steps = [
                _step(f"{host} is live and named like a non-production or internal host", [r], "Observed"),
                _step(f"It is on the same IP ({ip}) as {', '.join(shared[:3])}", resolves, "Observed"),
                _step(f"Non-production sites are often less protected, so {host} is a likely "
                      "first target, and getting in there may mean getting into the same server", [r], "Inference"),
            ]
            leaks = [e for e in kinds.get("version_leak", []) if ip in ips_of.get(e["host"], [])]
            leaks += [e for e in kinds.get("cves", []) if e["host"] == ip]
            if leaks:
                steps.append(_step("The server shows software versions an attacker can match "
                                   "to public exploits (versions must be verified)", leaks, "Lead"))
            side_door_ips.add(ip)
            paths.append(_path(f"Use {host} as a side door into {ip}", "Medium", steps,
                               f"Access to the server that also runs {shared[0]}", [r] + leaks))

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
                           "Server compromise, if the version is really vulnerable", cves + leaks))

    paths.sort(key=lambda p: (SEVERITY_RANK[p["severity"]], LABEL_RANK[p["strength"]]))
    more = max(0, len(paths) - MAX_PATHS)
    paths = paths[:MAX_PATHS]
    for i, p in enumerate(paths, 1):
        p["id"] = f"P{i}"
    return {"paths": paths, "fix_first": _fix_first(paths, evidence), "more": more}


def _fix_first(paths, evidence):
    """The one fix that closes the most paths (ties go to the more severe path)."""
    counts = {}
    for p in paths:  # already sorted most severe first
        for eid in p["fix"]:
            counts.setdefault(eid, []).append(p["id"])
    if not counts:
        return None
    best = max(counts, key=lambda eid: len(counts[eid]))  # first one wins a tie
    fact = next(e for e in evidence if e["id"] == best)
    return {"evidence": best, "fact": fact["fact"], "owners": fact["owners"], "closes": counts[best]}
