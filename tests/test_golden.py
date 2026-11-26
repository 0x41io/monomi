"""
Golden-file tests: real scans, frozen.

Each file in tests/golden/fixtures/ is a saved Monomi scan (--json). The test
runs it through build_evidence() and build_paths() and compares the result
to the matching file in tests/golden/expected/. If a change moves a finding
or an attack path, this test fails and says what moved, in a few lines.

Private fixtures (v1.28): real scans of bug bounty targets go in
tests/golden/private/fixtures/ (expected files in tests/golden/private/expected/).
That folder is in .gitignore, so it never reaches the public repo: scan output
holds data about other organizations. The test picks those files up when they
exist, so the same check runs on real field scans on Roi's machine.

The differential check (before a release that changes big logic):
    1. on main, before the change:  pytest tests/test_golden.py --update-golden
       (freezes what the released version makes from every fixture)
    2. on the branch, after it:     pytest tests/test_golden.py
       Every line in a failure is something that moved. Each one is either
       intended (say so in the release notes) or a bug.
    3. once every move is intended: pytest tests/test_golden.py --update-golden
       and check git diff on the public expected files before committing.
To see the full JSON difference too, run pytest tests/test_golden.py -vv.
"""
import json
import subprocess
from pathlib import Path

import pytest

from monomi import evidence
from monomi.paths import build_paths

GOLDEN = Path(__file__).parent / "golden"
PRIVATE = GOLDEN / "private"
FROZEN_TIME = "2000-01-01T00:00:00Z"
SECTIONS = ("paths", "leads", "set_aside")
COUNTS = ("more", "more_leads", "more_set_aside")
HOST_LISTS = ("more_leads_hosts", "out_of_scope_hosts")
SHOW = 5  # at most this many examples per kind of move


def cases(folder):
    """(fixture, expected file) pairs for one golden folder."""
    return [(f, folder / "expected" / f.name) for f in sorted((folder / "fixtures").glob("*.json"))]


PUBLIC_CASES = cases(GOLDEN)
PRIVATE_CASES = cases(PRIVATE)
CASES = PUBLIC_CASES + PRIVATE_CASES
IDS = [f.stem for f, _ in PUBLIC_CASES] + ["private/" + f.stem for f, _ in PRIVATE_CASES]


def run(results):
    """What evidence + paths make from one scan."""
    ev = evidence.build_evidence(results)
    return {"evidence": ev, "paths": build_paths(results, ev)}


def _key(item):
    """What a path or lead is about: its rule, the hosts/IPs it targets and,
    for around-the-CDN leads, which CDN and which hosts behind it. Ids (P1, L3)
    and titles change when other items move, so they aren't the key. (Two
    around_cdn leads can share every origin and differ only in the CDN.)"""
    t = item.get("targets") or {}
    return (item.get("rule"), tuple(sorted(t.get("hosts") or [])), tuple(sorted(t.get("ips") or [])),
            t.get("cdn") or "", tuple(sorted(t.get("fronted") or [])))


def _name(key):
    rule, hosts, ips, cdn, fronted = key
    where = ", ".join(list(hosts) + list(ips)) or "no targets"
    if cdn or fronted:
        where = f"{cdn or 'the CDN'} ({len(fronted)} fronted hosts), origins " + where
    if len(where) > 90:
        where = where[:87] + "..."
    return f"{rule} on {where}"


def _listed(lines, label, items):
    if items:
        lines.append(f"{label} ({len(items)}):")
        lines += [f"    {i}" for i in items[:SHOW]]
        if len(items) > SHOW:
            lines.append(f"    ...and {len(items) - SHOW} more")


def summarize(expected, got):
    """What moved between two runs, as short lines (empty when nothing did).
    Covers what a person reads in a report: which paths/leads exist, their
    severity, strength and title, the lead cap, and which facts were collected."""
    lines = []
    want, have = expected["paths"], got["paths"]
    for section in SECTIONS:
        old = {_key(p): p for p in want.get(section, [])}
        new = {_key(p): p for p in have.get(section, [])}
        _listed(lines, f"{section} added", [f"{new[k]['id']} {_name(k)}" for k in new if k not in old])
        _listed(lines, f"{section} gone", [f"{old[k]['id']} {_name(k)}" for k in old if k not in new])
        changed = []
        for k in old.keys() & new.keys():
            for field in ("severity", "strength", "title"):
                if old[k].get(field) != new[k].get(field):
                    changed.append(f"{new[k]['id']} {_name(k)}: {field} "
                                   f"{old[k].get(field)!r} -> {new[k].get(field)!r}")
            # Order matters for origins: akashi tries the first 5 in scope (v1.28)
            was = [o["ip"] for o in (old[k].get("targets") or {}).get("origins") or []]
            now = [o["ip"] for o in (new[k].get("targets") or {}).get("origins") or []]
            if was != now:
                changed.append(f"{new[k]['id']} {_name(k)}: origin order, first 5 "
                               f"{', '.join(was[:5])} -> {', '.join(now[:5])}")
            if len(old[k].get("steps", [])) != len(new[k].get("steps", [])):
                changed.append(f"{new[k]['id']} {_name(k)}: steps "
                               f"{len(old[k].get('steps', []))} -> {len(new[k].get('steps', []))}")
        _listed(lines, f"{section} changed", sorted(changed))
    for field in COUNTS:
        if want.get(field) != have.get(field):
            lines.append(f"{field}: {want.get(field)} -> {have.get(field)}")
    for field in HOST_LISTS:
        old, new = set(want.get(field) or []), set(have.get(field) or [])
        _listed(lines, f"{field} added", sorted(new - old))
        _listed(lines, f"{field} gone", sorted(old - new))
    old_ff, new_ff = want.get("fix_first") or {}, have.get("fix_first") or {}
    if old_ff.get("closes") != new_ff.get("closes"):
        lines.append(f"fix_first closes: {old_ff.get('closes')} -> {new_ff.get('closes')}")
    old_facts = {e["fact"] for e in expected["evidence"]}
    new_facts = {e["fact"] for e in got["evidence"]}
    _listed(lines, "facts added", sorted(new_facts - old_facts))
    _listed(lines, "facts gone", sorted(old_facts - new_facts))
    return lines


@pytest.mark.parametrize("fixture,expected_file", CASES, ids=IDS)
def test_golden(fixture, expected_file, request, monkeypatch):
    # build_evidence stamps "now" on some facts; freeze it so every run matches
    monkeypatch.setattr(evidence, "now_utc", lambda: FROZEN_TIME)
    got = run(json.loads(fixture.read_text(encoding="utf-8")))

    if request.config.getoption("--update-golden"):
        expected_file.parent.mkdir(parents=True, exist_ok=True)
        expected_file.write_text(json.dumps(got, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        pytest.skip(f"rewrote {expected_file.name}")

    assert expected_file.exists(), f"no expected file yet: run pytest {__file__} --update-golden"
    expected = json.loads(expected_file.read_text(encoding="utf-8"))
    moved = summarize(expected, got)
    if moved:
        pytest.fail(f"{fixture.stem}: what moved\n  " + "\n  ".join(moved), pytrace=False)
    # Nothing a reader sees moved; anything deeper still counts (full diff with -vv)
    assert got["paths"] == expected["paths"]
    assert got["evidence"] == expected["evidence"]


def test_there_are_fixtures():
    """An empty fixtures folder would make the golden tests pass by doing nothing."""
    assert PUBLIC_CASES


def _sample(**over):
    lead = {"id": "L1", "rule": "around_cdn", "targets": {"hosts": ["a.example.test"], "ips": ["192.0.2.1"]},
            "title": "Check a", "severity": "Medium", "strength": "Lead", "steps": [{}]}
    lead.update(over)
    return {"paths": {"paths": [], "leads": [lead], "set_aside": [], "more_leads": 0,
                      "more_leads_hosts": [], "fix_first": {"closes": []}},
            "evidence": [{"fact": "a.example.test resolves to 192.0.2.1"}]}


def test_summary_is_empty_when_nothing_moved():
    assert summarize(_sample(), _sample()) == []


def test_summary_ignores_a_renumbered_id():
    # L1 becoming L2 because another lead moved ahead of it is not a move of its own
    assert summarize(_sample(), _sample(id="L2")) == []


def test_summary_names_each_kind_of_move():
    old = _sample()
    new = _sample(strength="Observed", title="Check a again")
    new["paths"]["leads"].append({"id": "L2", "rule": "takeover", "targets": {"hosts": ["b.example.test"]},
                                  "title": "b", "severity": "High", "strength": "Lead", "steps": []})
    new["paths"]["more_leads"] = 3
    new["paths"]["more_leads_hosts"] = ["c.example.test"]
    new["evidence"] = [{"fact": "b.example.test CNAME gone.example.test"}]
    text = "\n".join(summarize(old, new))
    assert "leads added (1):\n    L2 takeover on b.example.test" in text
    assert "strength 'Lead' -> 'Observed'" in text
    assert "title 'Check a' -> 'Check a again'" in text
    assert "more_leads: 0 -> 3" in text
    assert "more_leads_hosts added (1):\n    c.example.test" in text
    assert "facts added (1):\n    b.example.test CNAME gone.example.test" in text
    assert "facts gone (1):\n    a.example.test resolves to 192.0.2.1" in text


def test_summary_tells_apart_leads_that_share_origins():
    """PlayStation: one around_cdn lead per CDN, both listing the same 11 origins.
    A lead that comes out of the cut pile is "added", not a change to the other one."""
    def cdn_lead(lid, cdn, fronted):
        return {"id": lid, "rule": "around_cdn", "title": f"Check {fronted[0]} around {cdn}",
                "targets": {"hosts": [], "ips": ["192.0.2.1", "192.0.2.2"], "cdn": cdn, "fronted": fronted},
                "severity": "Medium", "strength": "Lead", "steps": [{}]}
    old, new = _sample(), _sample()
    akamai = cdn_lead("L2", "Akamai", ["accounts.example.test"])
    old["paths"]["leads"].append(akamai)
    new["paths"]["leads"] += [akamai, cdn_lead("L3", "AWS CloudFront", ["blog.example.test"])]
    lines = summarize(old, new)
    assert "leads added (1):" in lines
    assert not any("changed" in line for line in lines)


def test_summary_reports_a_new_origin_order():
    """Same origins, new order: akashi would try different servers first."""
    def lead(order):
        return {"id": "L1", "rule": "around_cdn", "title": "t", "severity": "Low", "strength": "Inference",
                "steps": [], "targets": {"hosts": ["a", "b"], "ips": sorted(order), "cdn": "Akamai",
                                         "fronted": ["www"], "origins": [{"ip": ip} for ip in order]}}
    old, new = _sample(), _sample()
    old["paths"]["leads"].append(lead(["192.0.2.1", "192.0.2.2"]))
    new["paths"]["leads"].append(lead(["192.0.2.2", "192.0.2.1"]))
    assert any("origin order, first 5 192.0.2.1, 192.0.2.2 -> 192.0.2.2, 192.0.2.1" in line
               for line in summarize(old, new))


def test_summary_caps_long_lists():
    old, new = _sample(), _sample()
    new["paths"]["more_leads_hosts"] = [f"h{i}.example.test" for i in range(SHOW + 3)]
    text = "\n".join(summarize(old, new))
    assert f"more_leads_hosts added ({SHOW + 3}):" in text
    assert "...and 3 more" in text


def test_private_fixtures_never_reach_git():
    """Real targets' scans stay on Roi's machine: git must ignore the private folder,
    even though .gitignore un-ignores the rest of tests/golden/."""
    root = Path(__file__).parent.parent
    for name in ("private/fixtures/target.json", "private/expected/target.json"):
        try:
            res = subprocess.run(["git", "check-ignore", "-q", str(GOLDEN / name)],
                                 cwd=root, capture_output=True, timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            pytest.skip("git isn't available here")
        if res.returncode == 128:
            pytest.skip("not a git checkout")
        assert res.returncode == 0, f"git would commit tests/golden/{name}"
