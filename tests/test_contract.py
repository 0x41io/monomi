"""The contract with Akashi: what Akashi v0.1 reads from Monomi.

Akashi (0x41io/akashi) proves Monomi's leads. It reads a saved scan
(`--json`, run through build_evidence() and build_paths()) and imports a few
of Monomi's functions. Everything here is what it relies on. If a change
renames, moves or drops one of these, this test fails before Akashi breaks.

Changing something on purpose? Update this file in the same commit, say so in
the release notes, and bump the Monomi version Akashi pins.

Lead types Akashi v0.1 proves (design decision 2):
  takeover        "Take over <host>" paths and leads   (fixture: takeover-lead)
  around the CDN  rule F "can be reached around <CDN>" (fixtures: cves-edge-vs-own, 41xlab)
  email spoofing  "Send email as <domain>"             (fixture: 41xlab)

Each check names the exact key path Akashi reads (e.g. built["leads"][0]
["gate"]["failed"][0]["name"]), so a rename fails here, not just a missing key.
"""

import inspect
import json
from pathlib import Path

import pytest

from monomi import activelog, dnscheck, evidence, fingerprint, scope, takeover
from monomi.paths import build_paths

FIXTURES = Path(__file__).parent / "golden" / "fixtures"


def scan(name):
    """A saved scan plus what Monomi builds from it, the way Akashi will read it."""
    results = json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))
    ev = evidence.build_evidence(results)
    return results, ev, build_paths(results, ev)


def by_id(items):
    return {x["id"]: x for x in items}


# ---------- 1. The shape of every path, lead and evidence item ----------

PATH_KEYS = {"id", "rule", "targets", "title", "severity", "strength", "steps", "outcome", "actions", "gate"}
LEAD_KEYS = PATH_KEYS | {"missing"}
GATE_KEYS = {"result", "passed", "of", "failed", "notes"}
EVIDENCE_KEYS = {"id", "fact", "sources", "owners", "kind", "host"}
CONTRACT_SCANS = ["takeover-lead", "cves-edge-vs-own", "41xlab"]


@pytest.mark.parametrize("name", CONTRACT_SCANS)
def test_paths_and_leads_keep_their_shape(name):
    _, ev, built = scan(name)
    assert {"paths", "leads"} <= set(built)
    ids = {e["id"] for e in ev}
    groups = [("paths", built["paths"], PATH_KEYS, "P", "finding"),
              ("leads", built["leads"], LEAD_KEYS, "L", "lead")]
    for kind, items, keys, prefix, result in groups:
        for n, item in enumerate(items, start=1):
            assert set(item) == keys, (kind, item["id"])
            assert item["id"] == f"{prefix}{n}"
            assert set(item["gate"]) == GATE_KEYS
            assert item["gate"]["result"] == result
            assert isinstance(item["gate"]["passed"], int) and isinstance(item["gate"]["of"], int)
            for failed in item["gate"]["failed"]:
                assert set(failed) == {"check", "name", "why"}
            for step in item["steps"]:
                assert set(step) == {"text", "evidence", "label"}
                assert set(step["evidence"]) <= ids  # every cited evidence ID exists
            for action in item["actions"]:
                assert set(action) == {"what", "evidence", "owners"}
                assert set(action["evidence"]) <= ids
    for lead in built["leads"]:
        # A lead's "missing" line is its first failed gate check's reason
        assert lead["gate"]["failed"] and lead["missing"] == lead["gate"]["failed"][0]["why"]


@pytest.mark.parametrize("name", CONTRACT_SCANS)
def test_evidence_items_keep_their_shape(name):
    _, ev, _ = scan(name)
    for n, item in enumerate(ev, start=1):
        assert set(item) == EVIDENCE_KEYS
        assert item["id"] == f"E{n}"
        for source in item["sources"]:
            assert set(source) == {"name", "collected_at"}


# ---------- 2. Takeover ----------

def test_takeover_contract():
    results, ev, built = scan("takeover-lead")
    paths, leads, facts = by_id(built["paths"]), by_id(built["leads"]), by_id(ev)

    # The raw records Akashi re-checks (the CNAME, the service, who confirmed NXDOMAIN)
    assert set(results["takeover"]["leads"][0]) == {"host", "cname", "service", "claimable",
                                                    "nxdomain_confirmed_by", "collected_at"}
    claimable, unknown = results["takeover"]["leads"]
    assert claimable["service"] == "Azure App Service" and claimable["claimable"] is True
    assert claimable["nxdomain_confirmed_by"] == ["Cloudflare", "Google"]
    assert unknown["service"] is None and unknown["claimable"] is False
    assert set(results["takeover"]) >= {"leads", "stale", "results", "checked", "errors", "collected_at"}

    # Claimable and confirmed twice: a finding
    assert paths["P1"]["title"] == "Take over old-app.takeover.test"
    assert paths["P1"]["gate"]["failed"] == []
    cited = {e for step in paths["P1"]["steps"] for e in step["evidence"]}
    assert any(facts[e]["kind"] == "takeover_lead" and facts[e]["host"] == "old-app.takeover.test" for e in cited)

    # Unknown service: a lead that failed only "claimable / reachable", the case Akashi proves
    assert leads["L1"]["title"] == "Take over legacy-cdn.takeover.test through an expired name"
    assert [f["name"] for f in leads["L1"]["gate"]["failed"]] == ["claimable / reachable"]
    cited = {e for step in leads["L1"]["steps"] for e in step["evidence"]}
    assert any(facts[e]["kind"] == "dangling_unknown" and facts[e]["host"] == "legacy-cdn.takeover.test"
               for e in cited)


# ---------- 3. Go around the CDN (rule F) ----------

def test_around_the_cdn_contract():
    results, ev, built = scan("cves-edge-vs-own")
    lead, facts = by_id(built["leads"])["L1"], by_id(ev)
    assert lead["title"] == "Check whether www.cves.test can be reached around Cloudflare through 203.0.113.10"
    assert [f["name"] for f in lead["gate"]["failed"]] == ["observed way in"]
    cited = {e for step in lead["steps"] for e in step["evidence"]}
    seen = {(facts[e]["kind"], facts[e]["host"]) for e in cited}
    # The fronted host, the in-scope host that points at the origin, and the origin's open web ports
    assert {("resolves", "www.cves.test"), ("resolves", "cves.test"), ("open_ports", "203.0.113.10")} <= seen

    assert "hosts" in results["enrichment"] and "ips" in results["exposure"]


def test_around_the_cdn_on_the_lab_scan():
    # A real scan (41xlab) carries every section Akashi reads to plan its two GETs
    results, _, built = scan("41xlab")
    titles = [lead["title"] for lead in built["leads"]]
    assert any(t.startswith("Check whether www.41xlab.com can be reached around Cloudflare") for t in titles)
    assert set(results["enrichment"]) >= {"hosts", "ip_info", "providers", "resolved", "collected_at"}
    assert set(results["exposure"]) >= {"ips", "collected_at"}


# ---------- 4. Email spoofing ----------

def test_email_contract():
    results, ev, built = scan("41xlab")
    path, facts = by_id(built["paths"])["P1"], by_id(ev)
    assert path["title"] == "Send email as 41xlab.com"
    assert path["gate"]["failed"] == []

    email = results["email"]
    assert set(email) >= {"spf", "dmarc", "dkim", "verdict", "collected_at"}
    assert set(email["verdict"]) == {"verdict", "summary", "notes"}  # an object, not a bare word
    assert email["verdict"]["verdict"] == "spoofable"
    assert email["spf"]["record"] is None and email["dmarc"]["policy"] is None
    cited = {e for step in path["steps"] for e in step["evidence"]}
    assert any(facts[e]["kind"] == "email_spoofable" and facts[e]["host"] == "41xlab.com" for e in cited)


# ---------- 5. Status words Akashi branches on ----------

def test_dns_status_words(monkeypatch):
    def answer(a=None, aaaa=None, error=None, why="no_such_host"):
        def query(name, rtype):
            if error:
                raise error
            return a if rtype == "A" else aaaa
        monkeypatch.setattr(dnscheck, "_query", query)
        monkeypatch.setattr(dnscheck, "_why_nxdomain", lambda host: why)
        return dnscheck.host_status("h.test")[0]

    assert answer(a=("ok", ["203.0.113.1"])) == "live"
    assert answer(a=("ok", []), aaaa=("ok", ["2001:db8::1"])) == "ipv6_only"
    assert answer(a=("ok", []), aaaa=("ok", [])) == "no_address"
    assert answer(a=("nxdomain", [])) == "no_such_host"
    assert answer(a=("nxdomain", []), why="dangling_cname") == "dangling_cname"
    assert answer(error=dnscheck.ConflictingAnswers("x")) == "conflicting"
    assert answer(error=dnscheck.ServerFailure("x")) == "servfail"
    assert answer(error=dnscheck.DNSLookupError("x")) == "lookup_failed"


def test_gate_and_evidence_words():
    # Words Akashi matches on, found anywhere across the contract scans
    words = {"gate": set(), "kind": set(), "strength": set()}
    for name in CONTRACT_SCANS:
        _, ev, built = scan(name)
        for item in built["paths"] + built["leads"]:
            words["gate"].add(item["gate"]["result"])
            words["strength"].add(item["strength"])
        words["kind"] |= {e["kind"] for e in ev}
    assert words["gate"] == {"finding", "lead"}
    assert {"takeover_lead", "dangling_unknown", "resolves", "open_ports", "email_spoofable"} <= words["kind"]
    assert words["strength"] <= {"Observed", "Inference", "Lead"}


# ---------- 6. The functions Akashi imports ----------

API = {
    # scope file + hash pinning (Akashi uses the same scope format and rules)
    scope.load: "(path: str) -> monomi.scope.Scope",
    scope.from_bytes: "(data: bytes, path: str | None = None) -> monomi.scope.Scope",
    scope.check_pinned: "(path: str | None, sha256: str | None) -> tuple[monomi.scope.Scope | None, str | None]",
    scope.check_url: "(scope, url: str) -> str | None",
    # active log (same file format as Monomi's active.log)
    activelog.request: "(path, via, tool, host, url, scope_rule, scope) -> None",
    activelog.refused: "(path, via, tool, reason, host=None, scope=None) -> None",
    # DNS helper
    dnscheck.host_status: "(host: str) -> tuple[str, list[str]]",
    dnscheck.check_exists: "(name: str) -> tuple[bool, list[str]]",
    dnscheck.get_cname: "(name: str) -> str | None",
    dnscheck.doh_lookup: "(name: str, rtype: str) -> tuple[str, list[str]]",
    # HTTP fetch layer with the scope re-check (scope has no default on purpose)
    fingerprint.fetch_headers: "(host: str, timeout: int = 10, on_request=None, scheme: str = 'https', *, scope) -> dict",
    # takeover service lists
    takeover.match_service: "(target: str) -> str | None",
    takeover.match_not_claimable: "(target: str) -> str | None",
    # building what Akashi reads from a saved scan
    evidence.build_evidence: "(results: dict) -> list[dict]",
    build_paths: "(results: dict, evidence: list[dict], scope=None) -> dict",
}


@pytest.mark.parametrize("func", list(API), ids=[f"{f.__module__}.{f.__name__}" for f in API])
def test_imported_functions_keep_their_signature(func):
    assert str(inspect.signature(func)) == API[func]


def test_scope_objects_keep_their_fields():
    s = scope.from_bytes(b"example.test\n*.example.test\n!dev.example.test\n")
    assert {"path", "sha256", "rules", "rejected", "error"} <= set(vars(s))
    assert len(s.sha256) == 64
    m = s.match("www.example.test")
    assert (m.host, m.allowed) == ("www.example.test", True) and m.rule
    assert s.match("dev.example.test").allowed is False
    assert issubclass(scope.OutOfScope, Exception)
