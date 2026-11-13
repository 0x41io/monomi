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
    found, leads, _ = gate.review([candidate("A", door=[{"id": "E1"}])], {})
    assert [p["title"] for p in found] == ["A"]
    assert leads == []


def test_a_candidate_without_a_door_is_a_lead_with_its_reason():
    found, leads, _ = gate.review([candidate("A", no_door="nothing shows a way in")], {})
    assert found == []
    assert leads[0]["title"] == "A"
    assert leads[0]["missing"] == "nothing shows a way in"


def test_failed_checks_name_the_check_and_why():
    failed = gate.failed_checks(candidate("A", no_door="no CVE matched"), {})
    assert failed == [{"check": 5, "name": "observed way in", "why": "no CVE matched"}]


def test_review_keeps_the_order_within_paths_and_within_leads():
    given = [candidate("p1", door=[1]), candidate("l1", no_door="x"),
             candidate("p2", door=[1]), candidate("l2", no_door="y")]
    found, leads, _ = gate.review(given, {})
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
    results["subdomains"].append("oldapp")  # a takeover check only runs on the scan's own hosts
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
    _, leads, _ = gate.review([c], {})
    assert "system DNS alone" in leads[0]["missing"]


# --- checks 1, 2, 3 and 6, and the set-aside outcome (v1.13 b2) ---

def without_check(monkeypatch, number):
    """Break the rule: run the gate without one of its checks."""
    monkeypatch.setattr(gate, "CHECKS", [c for c in gate.CHECKS if c[0] != number])


def dotted_results():
    """A lab with real-looking names, for scope files (which need dotted names).
    .test is reserved for testing, so it's never a real domain."""
    hosts = ["lab.test", "oldapp.lab.test"]
    return {
        "target": "lab.test", "subdomains": hosts,
        "sources": {"certlog": {"source": "certlog", "subdomains": hosts}},
        "takeover": {"leads": [{"host": "oldapp.lab.test", "cname": "gone.azurewebsites.net",
                                "service": "Azure App Service", "claimable": True,
                                "nxdomain_confirmed_by": ["Cloudflare"], "collected_at": None}],
                     "stale": [], "checked": 2, "errors": {}, "collected_at": None},
    }


def build(results, scope=None):
    return paths.build_paths(results, build_evidence(results), scope)


def test_every_path_and_lead_carries_its_gate():
    built, _ = run(lab_results())
    p1 = built["paths"][0]
    assert p1["title"] == "Send email as lab"
    assert p1["gate"] == {"result": "finding", "passed": 6, "of": 6, "failed": [],
                          "notes": [gate.PROGRAM_NOTES["email"]]}
    for lead in built["leads"]:
        assert lead["gate"]["result"] == "lead"
        assert lead["missing"] == lead["gate"]["failed"][0]["why"]


def test_check_1_sets_aside_a_host_the_scope_file_excludes(monkeypatch):
    import scope
    s = scope.from_bytes(b"lab.test\n*.lab.test\n!oldapp.lab.test\n")
    built = build(dotted_results(), s)
    assert "Take over oldapp.lab.test" not in [p["title"] for p in built["paths"] + built["leads"]]
    aside = built["set_aside"][0]
    assert aside["title"] == "Take over oldapp.lab.test"
    assert "excluded by !oldapp.lab.test" in aside["why"]
    assert aside["gate"]["result"] == "set_aside" and "id" not in aside
    assert built["fix_first"] is None  # a set-aside item is never something to fix first

    without_check(monkeypatch, 1)
    built = build(dotted_results(), s)
    assert [p["title"] for p in built["paths"]] == ["Take over oldapp.lab.test"]


def test_check_1_without_a_scope_file_allows_the_scans_own_hosts():
    built = build(dotted_results())
    assert [p["title"] for p in built["paths"]] == ["Take over oldapp.lab.test"]
    assert built["set_aside"] == []


def test_check_1_sets_aside_a_host_outside_the_scan():
    results = dotted_results()
    results["takeover"]["leads"][0]["host"] = "shop.other.test"  # never one of this scan's hosts
    results["takeover"]["leads"][0]["cname"] = "gone2.azurewebsites.net"
    built = build(results)
    assert "not under lab.test" in built["set_aside"][0]["why"]


def edge_version_results():
    """The lab, plus a software version shown by www, which sits on a Cloudflare edge IP."""
    results = lab_results()
    results["fingerprint"]["hosts"]["www"] = {
        "collected_at": None, "status": 200, "header_issues": [],
        "techs": [{"tech": "nginx", "version": "1.18.0", "evidence": "Server header"}]}
    return results


def test_check_2_sets_aside_a_version_seen_on_a_cdn_edge_ip(monkeypatch):
    built, _ = run(edge_version_results())
    title = "Check whether the software on 203.0.113.9 has known flaws"
    assert title not in [p["title"] for p in built["paths"] + built["leads"]]
    aside = next(p for p in built["set_aside"] if p["title"] == title)
    assert "shared CDN edge IP" in aside["why"]

    without_check(monkeypatch, 2)
    built, _ = run(edge_version_results())
    assert title in [p["title"] for p in built["leads"]]


def test_check_3_fails_a_fact_from_a_saved_copy():
    c = candidate("A", door=[1])
    c["steps"] = [{"text": "x", "evidence": ["E1"], "label": "Observed"}]
    saved = [{"id": "E1", "fact": "f", "sources": [
        {"name": "crt.sh (saved copy)", "collected_at": "2026-11-01", "from_saved": True}]}]
    failed = gate.failed_checks(c, {}, saved)
    assert failed[0]["check"] == 3 and "saved copy" in failed[0]["why"]
    imported = [{"id": "E1", "fact": "f", "sources": [
        {"name": "SpiderFoot export (x.csv)", "collected_at": None, "imported_at": "2026-11-13"}]}]
    assert "was imported" in gate.failed_checks(c, {}, imported)[0]["why"]
    fresh = [{"id": "E1", "fact": "f", "sources": [{"name": "DNS", "collected_at": "2026-11-13"}]}]
    assert gate.failed_checks(c, {}, fresh) == []


def test_saved_sources_are_flagged_in_the_evidence():
    results = dotted_results()
    results["sources"]["certlog"]["from_saved"] = True
    sources = build_evidence(results)[0]["sources"]
    assert sources[0]["from_saved"] is True and sources[0]["name"] == "certlog (saved copy)"


def unknown_takeover_results():
    results = dotted_results()
    results["takeover"]["leads"][0].update(cname="gone.unknownhost.test", service=None, claimable=False)
    return results


def test_check_6_makes_an_unknown_dangling_cname_a_lead(monkeypatch):
    built = build(unknown_takeover_results())
    title = "Take over oldapp.lab.test through an expired name"
    assert built["paths"] == []
    lead = next(p for p in built["leads"] if p["title"] == title)
    assert lead["gate"]["failed"][0]["check"] == 6
    assert "who can claim gone.unknownhost.test is unknown" in lead["missing"]

    without_check(monkeypatch, 6)
    built = build(unknown_takeover_results())
    assert title in [p["title"] for p in built["paths"]]


def test_check_6_fails_a_cname_inside_the_domain_and_a_private_ip():
    c = candidate("A", door=[1])
    c["gate_input"]["claim"] = {"cname": "old.lab.test", "claimable": True}
    why = gate.failed_checks(c, {"target": "lab.test"})[0]["why"]
    assert "inside lab.test" in why
    c = candidate("A", door=[1])
    c["gate_input"]["ips"] = ["10.0.0.5"]
    results = {"enrichment": {"hosts": {"db": {"ips": [], "private_ips": ["10.0.0.5"]}}}}
    assert "private IP" in gate.failed_checks(c, results)[0]["why"]


def test_describe_reads_the_same_everywhere():
    assert gate.describe({"passed": 6, "of": 6, "failed": []}) == "gate 6/6"
    assert gate.describe({"passed": 5, "of": 6, "failed": [{"check": 5, "name": "observed way in"}]}) \
        == "gate 5/6, failed #5 observed way in"
    assert gate.describe(None) == "gate not run (saved before v1.13)"


def test_every_output_shows_the_gate_and_the_set_aside_list(capsys):
    from datetime import datetime

    import report
    from monomi import show_paths
    results = edge_version_results()
    results["evidence"] = build_evidence(results)
    results["paths"] = paths.build_paths(results, results["evidence"])

    show_paths(results)
    terminal = capsys.readouterr().out
    md = report.to_markdown(results, datetime(2026, 11, 13))
    page = report.to_html(results, datetime(2026, 11, 13))
    for text in (terminal, md, page):
        assert "gate 6/6" in text
        assert "gate 5/6, failed #5 observed way in" in text
        assert "Set aside" in text and "shared CDN edge IP" in text


def test_scans_saved_before_the_gate_say_it_was_not_run():
    built, ev = run(lab_results())
    for p in built["paths"] + built["leads"]:
        del p["gate"]
    del built["set_aside"], built["more_set_aside"]
    paths.upgrade_saved(built, ev)
    assert built["set_aside"] == [] and built["paths"][0]["gate"] is None
    assert "gate not run (saved before v1.13)" in paths.paths_appendix(built)


# --- program notes (v1.13 b3): never a check ---

def test_a_program_note_never_changes_the_result():
    with_door = candidate("A", door=[1])
    with_door["gate_input"]["program_note"] = "email"
    no_door = candidate("B", no_door="no door")
    no_door["gate_input"]["program_note"] = "email"
    found, leads, aside = gate.review([with_door, no_door], {})
    assert [p["title"] for p in found] == ["A"] and [p["title"] for p in leads] == ["B"]
    for p in found + leads:
        assert p["gate"]["notes"] == [gate.PROGRAM_NOTES["email"]]
    assert found[0]["gate"]["passed"] == 6  # a note isn't a failed check


def test_a_version_without_a_cve_gets_the_version_note():
    built, _ = run(lab_results())
    side = next(p for p in built["leads"] if "side door" in p["title"])
    assert side["gate"]["notes"] == []  # only the kinds programs often exclude get a note
    results = lab_results()
    results["fingerprint"]["hosts"]["lab"]["techs"][0]["version"] = "1.18.0"
    results["subdomains"].remove("staging")  # no side door, so rule D builds the version lead
    built, _ = run(results)
    version = next(p for p in built["leads"] if "has known flaws" in p["title"])
    assert version["gate"]["notes"] == [gate.PROGRAM_NOTES["version"]]


def test_every_output_shows_the_program_note(capsys):
    from datetime import datetime

    import report
    from monomi import show_paths
    results = lab_results()
    results["evidence"] = build_evidence(results)
    results["paths"] = paths.build_paths(results, results["evidence"])
    show_paths(results)
    for text in (capsys.readouterr().out, report.to_markdown(results, datetime(2026, 11, 13)),
                 report.to_html(results, datetime(2026, 11, 13))):
        assert "Note:" in text and "often out of scope for bug bounty programs" in text
