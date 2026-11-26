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
The same bar goes for software versions: a version a server shows is only
an attack path once a known CVE is matched to it; until then it is a lead.
Leads are never part of "fix this first".

The rules here don't decide path or lead themselves: each builds a
candidate that names its door (the observed way in, if any) and the hosts
and IPs it goes through, and gate.py runs every candidate through the same
checks. What fails "in scope" or "the target's own" is set aside: listed
with the reason, never a path or a lead (see gate.py).

One lead is only ever a lead: "go around the CDN". Some hosts sit behind a
CDN while others point straight at a web server of the target's own. If
that server is also the CDN's origin, the CDN can be skipped, but a CDN
hides its origin, so nothing seen from outside can show that.

Each path also lists its actions: the real fixes that close it. One action
is one job for one owner and holds the evidence IDs it deals with. A path is
only closed when every one of its actions is done.
"""

import ipaddress
import re

from monomi import gate
from monomi.categorize import RULES as CATEGORY_RULES, categorize
from monomi.content import SEVERITY_ORDER
from monomi.evidence import OWNERS
from monomi.internetdb import cloud_infra_from_cname
from monomi.takeover import delegation_view

LABEL_RANK = {"Observed": 0, "Inference": 1, "Lead": 2}
SEVERITY_RANK = {"High": 0, "Medium": 1, "Low": 2}
MAX_PATHS = 10

# More hosts than this on the same IPs = a shared load balancer or ingress,
# not one server, so rule E builds no side door through it
SHARED_INGRESS = 10

# Open ports that mean "this IP answers web requests" (rule F)
WEB_PORTS = {80, 443, 8080, 8443}

# Rule E wording per hostname category: (one host, several hosts, why it's a soft target)
SIDE_DOOR_WORDS = {
    "non-production": ("a non-production host", "non-production hosts",
                       "Non-production sites are often less protected"),
    "legacy": ("an old or legacy host", "old or legacy hosts",
               "Old sites are often left unpatched"),
    "access": ("a login or remote-access host", "login or remote-access hosts",
               "Login and remote-access pages are where attackers try guessed or stolen passwords"),
    "management": ("a device or infrastructure console", "device or infrastructure consoles",
                   "Management consoles control many machines at once and are often left with default logins"),
    "internal-tools": ("an internal tool", "internal tools",
                       "Internal tools are often left with weak or default logins"),
    "iot-ot": ("a device or control system", "devices or control systems",
               "Devices and control systems are often left on default settings"),
    None: ("a non-production or internal host", "non-production or internal hosts",
           "Hosts like these are often less protected"),
}


# Every "rule" a path, lead or set-aside item can have. Tools like Akashi pick
# their proof by this name, so a name never changes once released
# (tests/test_contract.py locks this set).
RULES = ("takeover", "takeover_unknown", "email_spoofing", "exposed_service",
         "known_cves", "version_check", "side_door", "around_cdn", "dangling_ns",
         "exposed_file")

# Rule C2 (exposed_file): what each of content.py's severities (secrets,
# source, info; content.SEVERITY_ORDER puts them worst first) means for the
# path's second step and its outcome
FILE_NEXT = {
    "secrets": "An attacker downloads them and uses the passwords or keys inside to log in "
               "to the services they open",
    "source": "An attacker downloads the code or its history and reads it for passwords, keys "
              "and flaws",
    "info": "An attacker reads what they reveal about the server and its setup to plan an attack",
}
FILE_OUTCOME = {
    "secrets": "Access to the databases, cloud accounts or services those credentials open",
    "source": "The site's code, and any secrets ever committed to it",
    "info": "A map of the server's internals that makes other attacks easier",
}


def _versions(results, hosts):
    """[{host, tech, version}] that --fingerprint saw on these hosts (versions only)."""
    fp = (results.get("fingerprint") or {}).get("hosts", {})
    return [{"host": h, "tech": t["tech"], "version": t["version"]}
            for h in hosts for t in fp.get(h, {}).get("techs", []) if t["version"]]


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


def _action(facts, what=None, owners=None):
    """One real fix: what to do, the evidence it deals with, and who owns it.

    The owners come from the facts, unless the facts have none of their own
    (a plain "resolves to" fact) and the rule names them.
    """
    return {"what": what or facts[0]["fact"], "evidence": [f["id"] for f in facts],
            "owners": owners or _owners(facts)}


def _targets(hosts=(), ips=(), **extra):
    """What a path or lead is about, for tools that act on it (Akashi).

    Always "hosts" and "ips" (maybe empty), so every item can be checked
    against a scope file the same way, plus rule-specific keys. Built from
    the scan's own data, never from the text of the path.
    """
    return {"hosts": list(hosts), "ips": list(ips), **extra}


def _path(title, severity, steps, outcome, actions, door=(), no_door=None, nxdomain=(),
          hosts=(), ips=(), claim=None, program_note=None, not_own=None, *, rule, targets):
    """A candidate attack path, with what the gate checks (see gate.py):
    door: the facts that show an observed way in (check 5); no_door: why it
    isn't a path when there are none; nxdomain: the takeover records whose
    "doesn't exist" it rests on (check 4); hosts / ips: what the attack goes
    through (checks 1, 2, 6); claim: a takeover's {"cname", "claimable"} (check 6);
    program_note: a gate.PROGRAM_NOTES key, for kinds programs often exclude (never a check);
    not_own: {ip: words} for IPs the rule saw aren't the target's own (check 2).
    rule: which rule built it, one of RULES; targets: see _targets(). Both are
    saved with the scan, unlike the gate input, which never leaves the gate."""
    assert rule in RULES, rule
    return {
        "rule": rule,
        "targets": targets,
        "title": title,
        "severity": severity,
        "strength": max((s["label"] for s in steps), key=LABEL_RANK.get),
        "steps": steps,
        "outcome": outcome,
        "actions": actions,
        "gate_input": {"door": list(door), "no_door": no_door, "nxdomain": list(nxdomain),
                       "hosts": list(hosts), "ips": list(ips), "claim": claim,
                       "program_note": program_note, "not_own": dict(not_own or {})},
    }


# Which leads survive the cut (v1.23). Before, leads that tied on severity and
# strength (most of them) kept the order their rule built them in, which for
# rule F was IPs sorted as text, so which 10 were shown was close to random.
# Now ties go to the hosts worth the most to an attacker: the lower the tier,
# the earlier the lead.
CATEGORY_TIER = {
    "apex": 0, "app-api": 0, "access": 0, "management": 0,
    "internal-tools": 1, "iot-ot": 1, "partner-portal": 1, "non-production": 1, "legacy": 1,
    "content": 2,
    "email": 3, "marketing": 3,
}
LAST_TIER = 4  # uncategorized, and anything without hosts


def _ip_order(ip):
    """An IP as numbers, so 198.51.100.9 comes before 198.51.100.10."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return (9, 0, ip)
    return (addr.version, int(addr), "")


# Words too common in hostnames to show an origin belongs to a fronted host
# (v1.28): sharing "api" or "www" says nothing.
COMMON_WORDS = {"www", "origin", "api", "app", "web", "cdn", "edge", "com", "net", "org"}
# Environment words don't show it either: in a CDN group of hundreds of hosts,
# some fronted host always has "stage" or "dev" (PlayStation: stage.haiku
# ranked up for sharing "stage"). Monomi's non-production words, plus the
# production ones. Two-letter ones (qa, pp, np, e1) are under the 3-letter minimum.
ENV_WORDS = {w for rule in CATEGORY_RULES if rule[0] == "non-production" for w in rule[1]} | {
    "prod", "production", "sit", "int", "integration", "live"}
_WORD = re.compile(r"[a-z0-9]+")


def _below(host, target):
    """The part of a hostname below the target domain:
    'origin-api.bridges.example.com' -> 'origin-api.bridges' (target example.com)."""
    host = host.lower().rstrip(".")
    if target and host.endswith("." + target):
        return host[:-len(target) - 1]
    return host


def _words(name):
    """The words of a name that can show what service it is: 3+ letters,
    no common or environment words. 'commerce-api.direct-stage' -> {commerce, direct}"""
    return {w for w in _WORD.findall(name) if len(w) >= 3 and w not in COMMON_WORDS | ENV_WORDS}


def _named_for(o, names):
    """True if the origin name o is a fronted name with "origin" added:
    origin-X, origin.X or X-origin (at the end or before a dot)."""
    return (o.startswith("origin.") and o[7:] in names
            or o.startswith("origin-") and o[7:] in names
            or "-origin." in o and o.replace("-origin.", ".", 1) in names
            or o.endswith("-origin") and o[:-7] in names)


def _name_match(origin_hosts, fronted, target):
    """How well an origin's hostnames match the hosts behind the CDN (v1.28,
    from PlayStation: origins came from unrelated hosts like stage.haiku while
    origin-api.bridges sat next to api.bridges). Lower ranks first:
      (0, 0)  an origin host named for a fronted host: origin-X, origin.X, X-origin
      (1, -n) a host the operator named "origin" (origin-us-west-1, bee-stg-origin)
      (2, -n) shares n service words with the fronted hosts (commerce-api.direct-stage
              next to commerce-api.direct: likely the same service)
      (3, 0)  nothing in common
    n breaks ties inside a tier: more shared service words first. Only
    reorders origins: none is dropped or added."""
    names = {_below(h, target) for h in fronted}
    words = set().union(*(_words(n) for n in names)) if names else set()
    best = (3, 0)
    for h in origin_hosts:
        o = _below(h, target)
        if _named_for(o, names):
            return (0, 0)
        shared = -len(_words(o) & words)
        score = (1, shared) if "origin" in _WORD.findall(o) else (2, shared) if shared else (3, 0)
        best = min(best, score)
    return best


def _lead_order(lead, results):
    """How a lead ranks among leads of the same severity and strength:
    a go-around-the-CDN lead through a rented load balancer or VM first (the
    classic origin), then by its best host's category, then its first IP as
    numbers, then its title, so the order is the same every run."""
    target = results.get("target", "")
    enr = (results.get("enrichment") or {}).get("hosts", {})
    hosts, ips = lead["targets"]["hosts"], lead["targets"]["ips"]
    rented = lead["rule"] == "around_cdn" and any(
        cloud_infra_from_cname([enr.get(h, {}).get("canonical") or ""]) for h in hosts)
    tier = min((CATEGORY_TIER.get(categorize(h, target)["category"], LAST_TIER) for h in hosts),
               default=LAST_TIER)
    return (0 if rented else 1, tier, _ip_order(ips[0]) if ips else (9, 0, ""), lead["title"])


def _names(hosts, most=3):
    """"a", "a and b", "a, b and c", or "a, b, c and 2 more"."""
    if len(hosts) == 1:
        return hosts[0]
    if len(hosts) > most:
        return f"{', '.join(hosts[:most])} and {len(hosts) - most} more"
    return f"{', '.join(hosts[:-1])} and {hosts[-1]}"


# IPs that are shared CDN edge servers, and IPs that aren't the target's own
# server for any reason (CDN, third-party hosting, shared front door). Both
# live in gate.py, which owns check 2.
_edge_ips = gate.edge_ips
_not_own_ips = gate.not_own_ips


def build_paths(results: dict, evidence: list[dict], scope=None) -> dict:
    """Chain evidence into attack paths and leads.

    scope: the --scope file (a scope.Scope), for gate check 1, or None.
    Returns {"paths", "leads", "set_aside", "fix_first", "more", "more_leads",
    "more_leads_hosts", "more_set_aside", "out_of_scope_hosts"}.

    Out-of-scope hosts (gate.out_of_scope_hosts) are left out of every rule's
    supporting evidence: they never count as a production neighbor, as "behind
    the CDN" or "pointing straight at" a server, or as the source of a version.
    A candidate about excluded hosts alone is still built, and check 1 sets it aside.
    """
    out_of_scope = gate.out_of_scope_hosts(results, scope)

    def inside(hosts):
        """The in-scope ones, or all of them when none are: then the candidate is
        about excluded hosts alone, and check 1 sets it aside with the reason."""
        kept = [h for h in hosts if h not in out_of_scope]
        return kept or list(hosts)

    # Each rule ends with the path's actions (see _action). Evidence that
    # only backs a step up, like the email facts in rule A, is in no action.
    kinds = _by_kind(evidence)
    target = results.get("target", "")
    spoof = kinds.get("email_spoofable", []) + kinds.get("email_partial", [])
    candidates = []  # every rule adds here; gate.review() splits paths from leads

    # A. Subdomain takeover: claim the deleted name, then serve pages on it.
    # The takeover records say whether DoH confirmed the NXDOMAIN (gate check 4).
    records = {r["host"]: r for r in (results.get("takeover") or {}).get("leads", [])}
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
        candidates.append(_path(f"Take over {host}", "High", steps,
                                f"Phishing pages or stolen cookies on a real {target} subdomain",
                                [_action([lead])], door=[lead], nxdomain=[records[host]], hosts=[host],
                                claim={"cname": records[host]["cname"], "claimable": True},
                                rule="takeover",
                                targets=_targets([host], cname=records[host]["cname"],
                                                 service=records[host].get("service"), claimable=True,
                                                 nxdomain_confirmed_by=records[host].get("nxdomain_confirmed_by"))))
    for lead in kinds.get("dangling_unknown", []):
        host = lead["host"]
        steps = [
            _step(f"{host} points to a name that no longer exists, on an unknown service", [lead], "Observed"),
            _step("If that name's domain is free to register, an attacker buys it "
                  f"and controls what {host} serves", [lead], "Lead"),
        ]
        candidates.append(_path(f"Take over {host} through an expired name", "Medium", steps,
                                f"Phishing pages on a real {target} subdomain", [_action([lead])],
                                door=[lead], nxdomain=[records[host]], hosts=[host],
                                claim={"cname": records[host]["cname"], "claimable": False},
                                rule="takeover_unknown",
                                targets=_targets([host], cname=records[host]["cname"],
                                                 service=records[host].get("service"), claimable=False,
                                                 nxdomain_confirmed_by=records[host].get("nxdomain_confirmed_by"))))

    # A2. Dangling NS delegation (v1.17): a subzone delegated to nameservers that
    # refuse it. Always a lead in v1: claiming it means getting those exact
    # nameservers, which Monomi never tries, and on a pooled service is impractical.
    delegations = {d["cut"]: d for d in (results.get("takeover") or {}).get("ns_delegations", [])}
    for fact in kinds.get("dangling_ns", []):
        d = delegations.get(fact["host"])
        if not d:
            continue
        cut, hosts = d["cut"], inside(d["hosts"])
        ns_ips, grade, provider = delegation_view(d)  # v1.28.1: older scans re-graded
        steps = [
            _step(f"{cut} is delegated to nameservers that refuse to answer for it", [fact], "Observed"),
            _step(f"If those nameservers can be claimed, an attacker controls DNS for every name "
                  f"under {cut}", [fact], "Lead"),
        ]
        if grade == "theoretical":
            no_door = (f"{cut}'s nameservers are on {provider}, which assigns nameservers from a "
                       "large pool: getting this exact set assigned again is impractical")
            severity = "Low"
        else:
            no_door = (f"whether {cut}'s nameservers can be registered again wasn't checked: find "
                       "the exact NS names with an authoritative query and check who runs them")
            severity = "Medium"
        candidates.append(_path(f"Take over DNS for {cut}", severity, steps,
                                f"Any page, cookie or email on a real {target} name under {cut}",
                                [_action([fact], what=f"Remove the NS records delegating {cut}, or "
                                         "recreate the zone where they point")],
                                no_door=no_door, hosts=hosts,
                                rule="dangling_ns",
                                targets=_targets(hosts, cut=cut, ns_ips=ns_ips,
                                                 provider=provider, grade=grade)))

    # B. Email impersonation
    for v in spoof:
        spoofable = v["kind"] == "email_spoofable"
        steps = [
            _step(f"Receiving mail servers have no enforced policy to reject mail that "
                  f"falsely claims to be from {target}", [v], "Observed" if spoofable else "Inference"),
            _step(f"An attacker sends phishing email from an @{target} address "
                  "to staff, customers or partners", [v], "Inference"),
        ]
        candidates.append(_path(f"Send email as {target}", "High" if spoofable else "Medium", steps,
                                "Stolen passwords, payments or malware through trusted-looking email",
                                [_action([v])], door=[v], hosts=[target], program_note="email",
                                rule="email_spoofing",
                                targets=_targets([target], verdict=(results.get("email") or {})
                                                 .get("verdict", {}).get("verdict"))))

    exp = results.get("exposure") or {}
    exp_ips = exp.get("ips", {})
    # A lead's "missing" line must not say "none found" when nobody looked
    looked = "exposure" in results

    # C. Services that usually shouldn't face the internet
    for r in kinds.get("risky_service", []):
        ip = r["host"]
        on_ip = inside(exp_ips.get(ip, {}).get("hosts", []))
        hosts = ", ".join(on_ip[:3]) or ip
        steps = [
            _step(f"{ip} ({hosts}) has services open to the internet that usually "
                  "shouldn't be", [r], "Observed"),
            _step("An attacker tries logins, password guessing or known exploits "
                  "against those services directly", [r], "Inference"),
        ]
        candidates.append(_path(f"Attack the exposed services on {ip}", "High", steps,
                                "Direct access to the server or its data", [_action([r])], door=[r],
                                hosts=on_ip, ips=[ip], rule="exposed_service",
                                targets=_targets(on_ip, [ip], services=exp_ips.get(ip, {}).get("risky", []))))

    # Which IPs each live host is on, for C2, D and E
    enr = results.get("enrichment") or {}
    ips_of = {h: d.get("ips", []) for h, d in enr.get("hosts", {}).items()}

    # C2. Files served by mistake (v1.27, from --content): one path per host,
    # listing every file found there, so one leaky host can't fill the list.
    # Each file's fact is the door: its content passed that kind's check.
    #
    # Which IPs the gate sees: a CDN or front door in front of the host only
    # passes the file on, so the file is still the target's own and its edge
    # IPs are left out of check 2. Third-party hosting (a store, a forum,
    # Microsoft 365) stays in: a file there belongs to that service, so check 2
    # sets the path aside.
    files_by_host = {}
    for fact in kinds.get("exposed_file", []):
        files_by_host.setdefault(fact["host"], []).append(fact)
    third_party = {ip: why for ip, why in gate.not_own_ips(results).items()
                   if why.startswith("third-party hosting")}
    content_hosts = (results.get("content") or {}).get("hosts", {})
    files_of = {}  # host -> [(found record, its fact)], for rule E's side doors (v1.27.1)
    for host, facts in files_by_host.items():
        r = content_hosts.get(host) or {}
        found = r.get("found", [])
        if len(found) != len(facts):
            continue  # facts and records come from the same list; never pair them by guess
        files_of[host] = list(zip(found, facts))
        worst = min((f["severity"] for f in found), key=SEVERITY_ORDER.get)
        names = ", ".join(f["path"] for f in found[:3]) + (
            f" and {len(found) - 3} more" if len(found) > 3 else "")
        steps = [
            _step(f"{host} serves {len(found)} file{'s' if len(found) != 1 else ''} to anyone "
                  f"that shouldn't be public: {names}", facts, "Observed"),
            _step(FILE_NEXT[worst], facts, "Inference"),
        ]
        actions = [_action([fact], what=f"Remove {f['path']} from {host} or block it in the web "
                           "server" + (", then change every secret it held" if f["severity"] == "secrets"
                                       else ""))
                   for f, fact in zip(found, facts)]
        ips = ips_of.get(host, [])
        candidates.append(_path(f"Read the files {host} serves by mistake",
                                "Medium" if worst == "info" else "High", steps, FILE_OUTCOME[worst],
                                actions, door=facts, hosts=[host],
                                ips=[ip for ip in ips if ip in third_party], not_own=third_party,
                                rule="exposed_file",
                                targets=_targets([host], ips, scheme=r.get("scheme"),
                                                 files=[{"path": f["path"], "url": f["url"], "kind": f["kind"],
                                                         "severity": f["severity"]} for f in found])))
    edge = _edge_ips(results)          # CDN edges only: what "behind a CDN" means (rule F)
    not_own = _not_own_ips(results)    # not the target's server: CDN, third-party host, front door

    # E. Side door: risky-named hosts on the same server as production.
    # Private IPs are skipped (nobody on the internet can reach them), hosts
    # are grouped by their set of IPs (one path per server, not one per IP),
    # and a host on several IPs, or an IP that carries many hosts, is behind a
    # load balancer or shared front door, not on one server.
    private = {h: d.get("private_ips", []) for h, d in enr.get("hosts", {}).items()}
    groups = {}  # set of IPs -> the risky-name facts of every host on exactly those IPs
    for r in kinds.get("risky_name", []):
        ips = frozenset(ip for ip in ips_of.get(r["host"], [])
                        if ip not in not_own and ip not in private.get(r["host"], []))
        if ips:
            groups.setdefault(ips, []).append(r)
    side_door_ips = set()
    offline = {}  # a "take this host off the internet" action (its evidence ids) -> the host (v1.27.2)
    for ips, names in groups.items():
        names = sorted(names, key=lambda r: r["host"])
        kept = inside([r["host"] for r in names])  # excluded risky hosts drop out of the side door
        names = [r for r in names if r["host"] in kept]
        hosts = [r["host"] for r in names]
        # Every host counts here, in scope or not: a crowded IP is a shared
        # front door whatever the scope file says
        on_ips = [h for h, h_ips in ips_of.items() if ips & set(h_ips)]
        if len(ips) > 1 or len(on_ips) > SHARED_INGRESS:
            continue  # a load balancer or shared front door, so "same server" can't be claimed
        shared = [h for h in on_ips if h not in hosts and h not in out_of_scope
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
        # Files the side-door hosts serve by mistake (v1.27.1, from rule C2). A
        # readable secrets file (.env, keys, credentials) is a way in: its
        # content was checked, and whoever reads it can log in with what it
        # holds. Source (a Git folder, a backup) is only a lead, like a
        # version: the code may hold passwords, but that isn't shown.
        files = [(f, fact) for h in hosts for f, fact in files_of.get(h, [])]
        secrets = [(f, fact) for f, fact in files if f["severity"] == "secrets"]
        source = [(f, fact) for f, fact in files if f["severity"] == "source"]
        if secrets:
            one_file = len(secrets) == 1
            steps.append(_step(f"{_file_names(secrets)} {'is' if one_file else 'are'} readable by anyone "
                               f"and {'holds' if one_file else 'hold'} passwords or keys an attacker can "
                               "log in with",
                               [fact for _, fact in secrets], "Observed"))
        if source:
            steps.append(_step(f"{_file_names(source)} {'lets' if len(source) == 1 else 'let'} anyone "
                               "download code or its history, "
                               "which an attacker reads for passwords and keys",
                               [fact for _, fact in source], "Lead"))
        leaks = [e for e in kinds.get("version_leak", [])
                 if ips & set(ips_of.get(e["host"], [])) and e["host"] not in out_of_scope]
        leaks += cves
        if leaks:
            steps.append(_step("The server shows software versions an attacker can match "
                               "to public exploits (versions must be verified)", leaks, "Lead"))
        side_door_ips.update(ips)
        door = risky + cves + [fact for _, fact in secrets]  # a way into the server itself (gate check 5)
        no_door = (f"nothing shows a way into {'this host' if one else 'these hosts'} yet "
                   + (f"(no risky open service or known CVE on {where})" if looked else
                      f"(open services and known CVEs on {where} weren't looked up: --ports wasn't run)"))
        if source:
            no_door += (f"; the code served at {_file_names(source)} may hold passwords, but that "
                        "isn't shown")
        # One action per risky host: each one is its own door, so all of them
        # must be dealt with. The version leaks only back the last step up.
        # The action says what to do; why the name is risky stays in the evidence.
        actions = [_action([r], f"Take {r['host']} off the internet or restrict who can reach it")
                   for r in names]
        offline.update({tuple(a["evidence"]): r["host"] for a, r in zip(actions, names)})
        if cves:
            # The CVE is on the server itself, so closing the doors isn't enough
            actions.append(_action(leaks, f"Upgrade or patch the server software on {where}"))
        title = (f"Use {who} as a side door into {where}" if door else
                 f"Check whether {who} {'is' if one else 'are'} a side door into {where}")
        candidates.append(_path(title, "Medium", steps, f"Access to the server that also runs {shared[0]}",
                                actions, door=door, no_door=no_door, hosts=hosts, ips=sorted(ips),
                                rule="side_door", targets=_targets(hosts, sorted(ips), shared_with=shared)))

    # D. Known-vulnerable versions (IPs already covered by a side door are skipped).
    # A matched CVE makes it an attack path; a version on its own is only a lead.
    # A shared CDN edge IP is set aside by the gate (check 2): its software isn't the target's.
    for ip in sorted({e["host"] for e in kinds.get("cves", [])}
                     | {ip for e in kinds.get("version_leak", []) for ip in ips_of.get(e["host"], [])}):
        if ip in side_door_ips:
            continue
        on_ip = inside(sorted(h for h, h_ips in ips_of.items() if ip in h_ips))
        cves = [e for e in kinds.get("cves", []) if e["host"] == ip]
        leaks = [e for e in kinds.get("version_leak", []) if ip in ips_of.get(e["host"], [])]
        leaks = [e for e in leaks if e["host"] in on_ip] or leaks  # an excluded host's version only if nothing else
        action = [_action(cves + leaks, f"Upgrade or patch the server software on {ip}")]
        if not cves:
            steps = [_step(f"{ip} shows which software versions it runs", leaks, "Observed"),
                     _step("An attacker looks those versions up for known flaws", leaks, "Lead")]
            no_door = (f"no known CVE is matched to {ip} in this scan" if looked else
                       f"known CVEs for {ip} weren't looked up (--ports wasn't run)"
                       ) + ", so the versions are unverified"
            candidates.append(_path(f"Check whether the software on {ip} has known flaws", "Low", steps,
                                    "Server compromise, if the version is really vulnerable", action,
                                    no_door=no_door, hosts=on_ip, ips=[ip], program_note="version",
                                    rule="version_check",
                                    targets=_targets(on_ip, [ip], versions=_versions(
                                        results, sorted({e["host"] for e in leaks})))))
            continue
        steps = [_step(f"{ip} shows software versions or matching CVEs", cves + leaks, "Observed"),
                 _step("An attacker checks whether the running version really has those flaws "
                       "and tries public exploits", cves + leaks, "Lead")]
        candidates.append(_path(f"Exploit known flaws on {ip}", "Medium", steps,
                                "Server compromise, if the version is really vulnerable", action,
                                door=cves, hosts=on_ip or exp_ips.get(ip, {}).get("hosts", []), ips=[ip],
                                rule="known_cves",
                                targets=_targets(on_ip or exp_ips.get(ip, {}).get("hosts", []), [ip],
                                                 cves=exp_ips.get(ip, {}).get("vulns", []),
                                                 versions=_versions(results, sorted({e["host"] for e in leaks})))))

    # F. Go around the CDN: always a lead (see the top of this file). Built
    # only when a server of the target's own is seen answering web requests.
    hosts_of = {}  # the target's own public IPs -> in-scope hosts pointing straight at them
    for h, h_ips in sorted(ips_of.items()):
        if h in out_of_scope:
            continue
        for ip in h_ips:
            if ip not in not_own and ip not in private.get(h, []):
                hosts_of.setdefault(ip, []).append(h)
    # Where each direct host's CNAME goes (v1.23). A CNAME outside the target's
    # domain names someone else's server, unless it's cloud infrastructure the
    # target rents (a load balancer, a VM). Hosts on known vendors never get
    # here (gate.not_own_ips); these are the ones no list knows yet.
    foreign = {}  # direct host -> its CNAME, when that leaves the target's domain
    for h, d in enr.get("hosts", {}).items():
        cname = d.get("canonical")
        if (cname and target and not gate._under(cname, target)
                and not cloud_infra_from_cname([cname])):
            foreign[h] = cname
    fronted = sorted(h for h, h_ips in ips_of.items()
                     if h_ips and all(ip in edge for ip in h_ips) and h not in out_of_scope)
    web = {}  # own IP -> facts showing it answers web requests
    for e in kinds.get("open_ports", []):
        if e["host"] in hosts_of and WEB_PORTS & set(exp_ips.get(e["host"], {}).get("ports", [])):
            web.setdefault(e["host"], []).append(e)
    for e in kinds.get("web_tech", []) + kinds.get("version_leak", []):
        if e["host"] in out_of_scope:
            continue
        for ip in ips_of.get(e["host"], []):
            if ip in hosts_of:
                web.setdefault(ip, []).append(e)
    if fronted and web:
        resolves = {e["host"]: e for e in kinds.get("resolves", [])}

        def rented(hosts):
            """A host pointing at a load balancer or VM the target rents (v1.23)."""
            return any(cloud_infra_from_cname([enr["hosts"].get(h, {}).get("canonical") or ""])
                       for h in hosts)

        # Every origin candidate, with the hosts pointing straight at it. Hosts
        # whose name points outside the target's domain don't show it's the
        # target's server (v1.23): an IP named only through them is set aside below
        own, outside = [], {}
        for ip in sorted(web):
            direct = [h for h in hosts_of[ip] if h not in foreign]
            if direct:
                own.append({"ip": ip, "hosts": direct})
            else:
                via = "; ".join(f"{h} -> {foreign[h]}" for h in hosts_of[ip][:3])
                outside[ip] = (f"a server named only through CNAMEs outside {target} ({via}), "
                               "likely a vendor's platform")
        # Ranked like leads (v1.23): a rented load balancer or VM first (the
        # classic origin), then by its hosts' category, then IP as numbers
        own.sort(key=lambda o: (0 if rented(o["hosts"]) else 1,
                                min(CATEGORY_TIER.get(categorize(h, target)["category"], LAST_TIER)
                                    for h in o["hosts"]),
                                _ip_order(o["ip"])))

        # One lead per CDN, listing every origin candidate (v1.24). The question
        # is "can these hosts be reached around the CDN?", and any one of the
        # origins could be the answer: one lead per origin (v1.10 to v1.23) made
        # one question into as many leads as the target has servers (11 on
        # Exoscale), crowding everything else out of the lead cap.
        by_cdn = {}
        for h in fronted:
            by_cdn.setdefault(gate.edge_vendor(enr["hosts"][h]), []).append(h)
        for cdn_name, group in sorted(by_cdn.items(), key=lambda kv: (kv[0] is None, kv[0] or "")):
            cdn = cdn_name or "the CDN"
            who, one = _names(group), len(group) == 1
            # Cite the hosts the text names (up to 3), not every host in a big scan
            front_facts = [resolves[h] for h in group[:3] if h in resolves]
            fronted_by = {"fronted": group, "cdn": cdn_name}
            if outside:
                # Vendor-named servers: listed set aside, with the CNAMEs (check 2)
                ips = sorted(outside, key=_ip_order)
                candidates.append(_path(
                    f"Check whether {who} can be reached around {cdn} through "
                    + (ips[0] if len(ips) == 1 else f"{len(ips)} vendor-named servers"), "Low",
                    [_step(f"{who} {'is' if one else 'are'} behind {cdn}", front_facts, "Observed")],
                    f"Attacks {cdn} would have blocked reach the server", [],
                    no_door="every server here is named only through another domain's CNAME",
                    ips=ips, not_own=outside, rule="around_cdn",
                    targets=_targets([], ips, origins=[{"ip": ip, "hosts": []} for ip in ips],
                                     **fronted_by)))
            if not own:
                continue
            # This CDN's origins, the ones named for its hosts first (v1.28);
            # sorted() is stable, so ties keep the order above
            ranked = sorted(own, key=lambda o: _name_match(o["hosts"], group, target))
            ips = [o["ip"] for o in ranked]
            direct = list(dict.fromkeys(h for o in ranked for h in o["hosts"]))
            direct_facts = [resolves[h] for h in direct[:3] if h in resolves]
            web_facts = [f for o in ranked[:3] for f in web[o["ip"]][:1]]
            if len(ranked) == 1:
                straight, where = _names(ranked[0]["hosts"]), ips[0]
                seen = (f"{straight} {'points' if len(ranked[0]['hosts']) == 1 else 'point'} straight "
                        f"at {where}, with no CDN in front, and a web server answers there")
                maybe = f"If {where} is also the server behind {who}"
                title_via = where
            else:
                where = _names(ips)
                seen = (f"{len(ips)} servers of the target's own answer web requests with no CDN in "
                        f"front ({where}), named by {_names(direct)}")
                maybe = f"If any of them is also the server behind {who}"
                title_via = f"any of {len(ips)} origin servers"
            steps = [
                _step(f"{who} {'is' if one else 'are'} behind {cdn}, which filters traffic before it "
                      "reaches the real server", front_facts, "Observed"),
                _step(seen, direct_facts + web_facts, "Observed"),
                _step(f"{maybe}, an attacker can send requests to it directly and skip {cdn}'s "
                      "protection", front_facts + direct_facts, "Inference"),
            ]
            # One action per origin: each one has to stop answering direct traffic
            actions = [_action([resolves[h] for h in o["hosts"][:3] if h in resolves] or web[o["ip"]][:1],
                               f"Only accept web traffic on {o['ip']} from {cdn}, or put its hosts "
                               f"behind {cdn} too", [OWNERS["server"], OWNERS["cdn"]])
                       for o in ranked]
            candidates.append(_path(
                f"Check whether {who} can be reached around {cdn} through {title_via}", "Low", steps,
                f"Attacks {cdn} would have blocked reach the server", actions,
                no_door=(f"nothing shows that {ips[0]} is the server behind {who}" if len(ranked) == 1 else
                         f"nothing shows that any of the {len(ranked)} servers is the one behind {who}")
                + " (a CDN hides its origin from outside)",
                hosts=direct, ips=ips, rule="around_cdn",
                targets=_targets(direct, ips, origins=ranked, **fronted_by)))

    paths, leads, set_aside = gate.review(candidates, results, evidence, scope)
    paths.sort(key=lambda p: (SEVERITY_RANK[p["severity"]], LABEL_RANK[p["strength"]]))
    more = max(0, len(paths) - MAX_PATHS)
    paths = paths[:MAX_PATHS]
    for i, p in enumerate(paths, 1):
        p["id"] = f"P{i}"
    # Leads: never above Medium, surest first, ties by what they're about
    # (_lead_order), and no part in fix_first
    leads.sort(key=lambda p: (SEVERITY_RANK[p["severity"]], LABEL_RANK[p["strength"]],
                              _lead_order(p, results)))
    more_leads = max(0, len(leads) - MAX_PATHS)
    # The hosts behind the leads that were cut, so nothing is left out unnamed (v1.23)
    shown = {h for p in leads[:MAX_PATHS] for h in p["targets"]["hosts"]}
    more_leads_hosts = sorted({h for p in leads[MAX_PATHS:] for h in p["targets"]["hosts"]} - shown)
    leads = leads[:MAX_PATHS]
    for i, p in enumerate(leads, 1):
        p["id"] = f"L{i}"
    # Set aside: out of scope or not the target's own. No IDs and no fixes.
    more_set_aside = max(0, len(set_aside) - MAX_PATHS)
    return {"paths": paths, "leads": leads, "set_aside": set_aside[:MAX_PATHS],
            "fix_first": _fix_first(paths, offline), "more": more, "more_leads": more_leads,
            "more_leads_hosts": more_leads_hosts, "more_set_aside": more_set_aside,
            "out_of_scope_hosts": sorted(out_of_scope)}


def _file_names(files, most=3):
    """"staging/.env, staging/.git/HEAD": each file as host + path (the first
    few), so a side door names exactly what it rests on."""
    names = [f"{fact['host']}{f['path']}" for f, fact in files]
    shown = ", ".join(names[:most]) + (f" and {len(names) - most} more" if len(names) > most else "")
    return shown


# Rules whose whole attack goes through one hostname: taking that host off
# the internet closes them too, whatever their own fixes say (v1.27.2). A
# file served by staging is gone once staging is. Rules that rest on an IP
# (a CVE, an open service) are left out: the server is still there.
OFFLINE_CLOSES = ("exposed_file",)


def _fix_first(paths, offline=None):
    """What to fix first, as a list of actions.

    offline: {action evidence ids: host} for the side doors' "take this host
    off the internet" actions. Such an action also closes every path in
    OFFLINE_CLOSES that rests on that host alone (v1.27.2): taking staging
    offline closes the files it serves, not only the side door.

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
    for key, host in (offline or {}).items():
        if key not in by_key:
            continue  # its side door is a lead, not a path: fix-first only looks at paths
        also = {p["id"] for p in paths if p["rule"] in OFFLINE_CLOSES and p["targets"]["hosts"] == [host]}
        if also - set(closes.get(key, [])):
            done = set(closes.get(key, [])) | also
            closes[key] = [p["id"] for p in paths if p["id"] in done]  # in path order
            # a path it now closes outright isn't also listed as one it's only part of
            partial[key] = [x for x in partial.get(key, []) if x["path"] not in done]
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
    become one action each. Version facts become one upgrade action, except
    on a side door with no matched CVE, where they only back a step up.
    """
    built.setdefault("leads", [])       # saved before the Lead tier: its side
    built.setdefault("more_leads", 0)   # doors stay the paths they were saved as
    built.setdefault("set_aside", [])   # saved before the gate (v1.13): its paths
    built.setdefault("more_set_aside", 0)  # keep their tier, marked "gate not run"
    built.setdefault("out_of_scope_hosts", [])  # saved before v1.13.1
    for p in built["paths"] + built["leads"]:
        p.setdefault("gate", None)
    if all("actions" in p for p in built["paths"]):
        return built
    by_id = {e["id"]: e for e in evidence}
    for p in built["paths"]:
        facts = [by_id[eid] for eid in p.pop("fix", []) if eid in by_id]
        versions = [f for f in facts if f.get("kind") in ("cves", "version_leak")]
        rest = [f for f in facts if f not in versions]
        p["actions"] = [_action([f], f"Take {f['host']} off the internet or restrict who can reach it"
                                if f.get("kind") == "risky_name" else None) for f in rest]
        if versions and (not rest or any(f.get("kind") == "cves" for f in versions)):
            where = p["title"].rsplit(" ", 1)[-1]
            p["actions"].append(_action(versions, f"Upgrade or patch the server software on {where}"))
    built["fix_first"] = _fix_first(built["paths"])
    return built


def out_of_scope_line(hosts: list[str]) -> str:
    """The one line every output uses for hosts left out of the attack paths."""
    shown = ", ".join(hosts[:5]) + (f" and {len(hosts) - 5} more" if len(hosts) > 5 else "")
    one = len(hosts) == 1
    return (f"{len(hosts)} out-of-scope host{'' if one else 's'} {'was' if one else 'were'} left "
            f"out of the evidence for attack paths and leads: {shown}")


def check_paths(report: str, built: dict) -> tuple[list[str], list[str]]:
    """Path and lead IDs the report left out, and IDs it made up (each sorted)."""
    ids = {p["id"] for p in built["paths"] + built.get("leads", [])}
    named = set(re.findall(r"\b[PL]\d+\b", report))

    def order(i):  # paths first, then leads
        return (i[0] != "P", int(i[1:]))
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
        lines.append(f"- **{p['id']}: {p['title']}** ({p['severity']}, weakest step: {p['strength']}, "
                     f"{gate.describe(p.get('gate'))})")
        for n, s in enumerate(p["steps"], 1):
            lines.append(f"  {n}. {s['label']}: {s['text']} [{', '.join(s['evidence'])}]")
        lines.append(f"  - Result: {p['outcome']}")
        lines += [f"  - Note: {n}" for n in (p.get("gate") or {}).get("notes", [])]
    if built.get("more"):
        lines.append(f"- {built['more']} lower-ranked path(s) left out")
    if built.get("leads"):
        lines += ["", "**Leads to investigate** (not attack paths: each is missing "
                      "something that would make it one)", ""]
    for p in built.get("leads", []):
        lines.append(f"- **{p['id']}: {p['title']}** ({p['severity']}, weakest step: {p['strength']}, "
                     f"{gate.describe(p.get('gate'))})")
        for n, s in enumerate(p["steps"], 1):
            lines.append(f"  {n}. {s['label']}: {s['text']} [{', '.join(s['evidence'])}]")
        lines.append(f"  - Missing: {p['missing']}")
        lines += [f"  - Note: {n}" for n in (p.get("gate") or {}).get("notes", [])]
    if built.get("more_leads"):
        lines.append(f"- {built['more_leads']} more lead(s) left out")
    if built.get("set_aside"):
        lines += ["", "**Set aside** (out of scope or not the target's own: neither "
                      "attack paths nor leads)", ""]
    for p in built.get("set_aside", []):
        lines.append(f"- {p['title']}: {p['why']}")
    if built.get("more_set_aside"):
        lines.append(f"- {built['more_set_aside']} more set aside")
    if built.get("out_of_scope_hosts"):
        lines += ["", out_of_scope_line(built["out_of_scope_hosts"])]
    fix = built.get("fix_first")
    if fix:
        t = fix_first_parts(fix)
        lines += ["", f"**{t['label']}** ({', '.join(t['ids'])}, owner: {t['owners']}, "
                      f"{t['closes']}): {t['what']}"]
    return "\n".join(lines) + "\n"
