# Hostnames without dots on purpose: the chat app turns dotted names into
# Markdown links when code is copied. The gate doesn't care.
import json
from pathlib import Path

import gate
import paths
from evidence import build_evidence
from test_paths import lab_results, run, with_cves

FIXTURES = sorted((Path(__file__).parent / "golden" / "fixtures").glob("*.json"))


def candidate(title, door=(), no_door=None):
    """The smallest candidate the gate accepts."""
    return {"title": title, "gate_input": {"door": list(door), "no_door": no_door}}


def test_a_candidate_with_a_door_is_an_attack_path():
    found, leads = gate.review([candidate("A", door=[{"id": "E1"}])], {})
    assert [p["title"] for p in found] == ["A"]
    assert leads == []


def test_a_candidate_without_a_door_is_a_lead_with_its_reason():
    found, leads = gate.review([candidate("A", no_door="nothing shows a way in")], {})
    assert found == []
    assert leads[0]["title"] == "A"
    assert leads[0]["missing"] == "nothing shows a way in"


def test_failed_checks_name_the_check_and_why():
    failed = gate.failed_checks(candidate("A", no_door="no CVE matched"), {})
    assert failed == [{"check": 5, "name": "observed way in", "why": "no CVE matched"}]


def test_review_keeps_the_order_within_paths_and_within_leads():
    given = [candidate("p1", door=[1]), candidate("l1", no_door="x"),
             candidate("p2", door=[1]), candidate("l2", no_door="y")]
    found, leads = gate.review(given, {})
    assert [p["title"] for p in found] == ["p1", "p2"]
    assert [p["title"] for p in leads] == ["l1", "l2"]


def test_gate_input_never_leaves_the_gate():
    """The golden files and every output compare paths as plain dicts:
    an internal key leaking out would change them all."""
    for fixture in FIXTURES:
        results = json.loads(fixture.read_text(encoding="utf-8"))
        built = paths.build_paths(results, build_evidence(results))
        for p in built["paths"] + built["leads"]:
            assert "gate_input" not in p, fixture.name


def test_the_gate_decides_path_or_lead(monkeypatch):
    """Break the rule: with no checks, the lab's side door (a lead, since no
    risky service or CVE shows a way in) becomes an attack path. So the
    decision is made by the gate, not by the side door rule."""
    built, _ = run(lab_results())
    assert any("side door" in p["title"] for p in built["leads"])
    assert not any("side door" in p["title"] for p in built["paths"])

    monkeypatch.setattr(gate, "CHECKS", [])
    built, _ = run(lab_results())
    assert any("side door" in p["title"] for p in built["paths"])
    assert built["leads"] == []


def test_a_matched_cve_is_the_door_that_makes_a_side_door_a_path():
    built, _ = run(with_cves(lab_results()))
    side = [p for p in built["paths"] if "side door" in p["title"]]
    assert side and side[0]["title"].startswith("Use ")
    assert not any("side door" in p["title"] for p in built["leads"])


# --- check 4, confirmed twice (v1.13 b1) ---

def takeover_results(confirmed_by="missing"):
    """The lab plus one claimable takeover lead; confirmed_by "missing" leaves
    the field out, like a scan saved before v1.13."""
    results = lab_results()
    lead = {"host": "oldapp", "cname": "gone-app", "service": "Azure App Service",
            "claimable": True, "collected_at": None}
    if confirmed_by != "missing":
        lead["nxdomain_confirmed_by"] = confirmed_by
    results["takeover"]["leads"] = [lead]
    return results


def titles(built):
    return [p["title"] for p in built["paths"]], [p["title"] for p in built["leads"]]


def test_takeover_confirmed_over_doh_is_an_attack_path():
    found, leads = titles(run(takeover_results(["Cloudflare", "Google"]))[0])
    assert "Take over oldapp" in found and "Take over oldapp" not in leads


def test_takeover_on_system_dns_alone_is_a_lead():
    built, _ = run(takeover_results([]))
    lead = next(p for p in built["leads"] if p["title"] == "Take over oldapp")
    assert "system DNS alone" in lead["missing"]
    assert "Take over oldapp" not in titles(built)[0]
    # A lead is never part of "fix this first"
    fix_ids = {eid for a in built["fix_first"]["actions"] for eid in a["evidence"]}
    assert not fix_ids & {eid for a in lead["actions"] for eid in a["evidence"]}


def test_takeover_without_a_record_says_it_was_not_recorded():
    built, _ = run(takeover_results())
    lead = next(p for p in built["leads"] if p["title"] == "Take over oldapp")
    assert "wasn't recorded" in lead["missing"]


def test_breaking_check_4_lets_an_unconfirmed_takeover_through(monkeypatch):
    """Break the rule: without check 4, the same unconfirmed lead is an attack path."""
    monkeypatch.setattr(gate, "CHECKS", [c for c in gate.CHECKS if c[0] != 4])
    found, _ = titles(run(takeover_results([]))[0])
    assert "Take over oldapp" in found


def test_the_first_failed_check_is_the_missing_line():
    c = candidate("A", no_door="no door")
    c["gate_input"]["nxdomain"] = [{"cname": "gone-app", "nxdomain_confirmed_by": []}]
    failed = gate.failed_checks(c, {})
    assert [f["check"] for f in failed] == [4, 5]
    _, leads = gate.review([c], {})
    assert "system DNS alone" in leads[0]["missing"]
