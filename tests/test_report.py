"""Tests for report.py: findings, Markdown and CSV exports, built from a
real saved scan (the 41xlab golden fixture) and small made-up ones."""

import csv
import io
import json
from datetime import datetime
from pathlib import Path

import pytest

import evidence
import paths
import report

FIXTURE = Path(__file__).parent / "golden" / "fixtures" / "41xlab.json"
WHEN = datetime(2026, 11, 8, 11, 20)
COM = ".com"
LAB = "41xlab" + COM


@pytest.fixture
def lab(monkeypatch):
    """The 41xlab scan with evidence and attack paths built, like a real run."""
    monkeypatch.setattr(evidence, "now_utc", lambda: "2000-01-01T00:00:00Z")
    results = json.loads(FIXTURE.read_text(encoding="utf-8"))
    results["evidence"] = evidence.build_evidence(results)
    results["paths"] = paths.build_paths(results, results["evidence"])
    return results


def made_up(facts, built=None):
    """A tiny scan: facts are (fact, owners, host) tuples."""
    ev = [{"id": f"E{i}", "fact": fact, "owners": owners, "kind": None, "host": host,
           "sources": [{"name": "test", "collected_at": "2026-11-08T00:00:00+00:00"}]}
          for i, (fact, owners, host) in enumerate(facts, 1)]
    return {"target": "example" + COM, "subdomains": ["a.example" + COM],
            "sources": {"test": {}}, "errors": {}, "evidence": ev,
            "paths": built or {"paths": [], "fix_first": None, "more": 0}}


# ---------- findings ----------

def test_findings_are_only_facts_with_an_owner(lab):
    ids = {f["id"] for f in report.findings(lab)}
    owned = {e["id"] for e in lab["evidence"] if e["owners"]}
    assert ids == owned
    assert "E1" not in ids  # "found by Cert Spotter" isn't something to fix


def test_findings_worst_path_first_and_fix_first_on_top(lab):
    found = report.findings(lab)
    assert found[0]["id"] == "E26"           # email spoofing: P1, High
    assert found[0]["fix_first"] is True
    assert [f["severity"] for f in found[:5]] == ["High"] + ["Medium"] * 4
    assert found[-1]["severity"] == ""       # stale CNAMEs are in no path


def test_finding_host_comes_from_the_fact_only_if_scanned(lab):
    by_id = {f["id"]: f for f in report.findings(lab)}
    assert by_id["E10"]["host"] == "legacy." + LAB  # starts the fact, was scanned
    assert by_id["E25"]["host"] == ""             # "No DKIM key..." isn't a host


def test_summary_counts(lab):
    s = report.summary(lab)
    assert s["hostnames"] == 7
    assert s["sources"] == ["Cert Spotter", "hosts file"]
    assert s["paths"] == {"High": 1, "Medium": 1, "Low": 0}
    assert report.path_counts(s) == "2 attack paths (1 High, 1 Medium)"


# ---------- Markdown ----------

def test_markdown_sections(lab):
    md = report.to_markdown(lab, WHEN)
    assert md.startswith(f"# mønømi report: {LAB}\n")
    assert "*Generated 2026-11-08 11:20 · sources: Cert Spotter, hosts file" in md
    for heading in ("## Summary", "## Findings", "## Attack paths (built by code)",
                    "## Evidence"):
        assert heading in md
    assert "## AI summary" not in md  # no --ai, no AI section
    assert "**Fix this first** (E26, closes P1)" in md


def test_markdown_evidence_covers_every_citation(lab):
    md = report.to_markdown(lab, WHEN)
    for f in report.findings(lab):
        assert f"- **{f['id']}**:" in md
    assert "- **E8**:" in md      # cited only by attack path P2
    assert "- **E1**:" not in md  # cited by nothing


def test_markdown_ai_section_is_labeled(lab):
    lab["ai_report"] = {"text": "Spoofing first [E26].", "model": "claude-test"}
    md = report.to_markdown(lab, WHEN)
    assert "AI summary: claude-test" in md
    assert "*Written by Claude (claude-test)." in md
    assert md.index("## AI summary") < md.index("## Findings")


def test_markdown_no_findings():
    found_by = "a.example" + COM + " was found by test"
    md = report.to_markdown(made_up([(found_by, [], None)]), WHEN)
    assert "*Nothing to fix was found in this scan.*" in md
    assert "no attack paths" in md


def test_md_cell_keeps_tables_and_html_safe():
    cell = report.md_cell("v=spf1 a|b\n<img src=x onerror=alert(1)>")
    assert "\n" not in cell and "<" not in cell
    assert "a\\|b" in cell


# ---------- CSV ----------

def rows(text):
    return list(csv.reader(io.StringIO(text)))


def test_csv_one_row_per_finding(lab):
    table = rows(report.to_csv(lab))
    assert table[0] == report.CSV_COLUMNS
    assert len(table) - 1 == len(report.findings(lab))
    first = dict(zip(table[0], table[1]))
    assert first["id"] == "E26"
    assert first["attack_paths"] == "P1"
    assert first["worst_path_severity"] == "High"
    assert first["fix_first"] == "yes"
    assert first["owners"] == "DNS admin; email admin"


@pytest.mark.parametrize("start", ["=", "+", "-", "@"])
def test_csv_cells_cant_run_as_formulas(start):
    evil = start + "HYPERLINK(\"x\",\"click\")"
    table = rows(report.to_csv(made_up([(evil, ["DNS admin"], None)])))
    assert table[1][2] == "'" + evil


def test_csv_with_no_findings_is_just_the_header():
    assert rows(report.to_csv(made_up([]))) == [report.CSV_COLUMNS]


# ---------- HTML ----------

EVIL = '<script>alert("x")</script>'


def test_html_is_one_safe_page(lab):
    page = report.to_html(lab, WHEN)
    assert page.startswith("<!DOCTYPE html>")
    assert f'content="{report.CSP}"' in page
    for outside in ("<script", "src=", "<link", "@import", "url("):
        assert outside not in page  # nothing runs, nothing loads from outside
    for heading in ("Summary", "Findings", "Attack paths (built by code)", "Evidence"):
        assert f"<h2>{heading}</h2>" in page


def test_html_links_citations_to_the_evidence(lab):
    page = report.to_html(lab, WHEN)
    assert '<a class="id" href="#E8">E8</a>' in page  # cited by path P2
    assert '<li id="E8">' in page
    assert '<li id="E1">' not in page                 # cited by nothing
    assert '<span class="sev High">High</span>' in page


def test_html_escapes_everything_from_the_target():
    page = report.to_html(made_up([(EVIL + " has no SPF record", ["DNS admin"], EVIL)]), WHEN)
    assert EVIL not in page
    assert "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;" in page


def test_html_escapes_the_ai_text(lab):
    lab["ai_report"] = {"text": EVIL + " [E26]", "model": "claude-test"}
    page = report.to_html(lab, WHEN)
    assert EVIL not in page
    assert "<h2>AI summary</h2>" in page
    assert '<li id="E26">' in page


def test_html_no_findings():
    page = report.to_html(made_up([]), WHEN)
    assert "Nothing to fix was found in this scan." in page
    assert "No attack path found" in page


# ---------- Saving and the report command ----------

def test_parse_formats():
    assert report.parse_formats("all") == ["md", "html", "csv"]
    assert report.parse_formats("HTML, csv,html") == ["html", "csv"]
    for bad in ("pdf", "html,pdf", ","):
        with pytest.raises(report.argparse.ArgumentTypeError):
            report.parse_formats(bad)


def test_save_writes_each_format(lab, tmp_path):
    written = report.save(lab, ["md", "html", "csv"], WHEN, folder=str(tmp_path))
    names = [Path(p).name for p in written]
    stem = LAB + "_2026-11-08_112000_export"
    assert names == [stem + ".md", stem + ".html", stem + ".csv"]
    raw = (tmp_path / names[2]).read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf")         # BOM, so Excel reads ø right
    assert b"\r\r\n" not in raw                    # no doubled line endings
    assert (tmp_path / names[1]).read_text(encoding="utf-8").startswith("<!DOCTYPE html>")


def test_save_file_name_is_only_safe_characters(tmp_path):
    scan = made_up([])
    scan["target"] = "../../evil name"
    [path] = report.save(scan, ["csv"], WHEN, folder=str(tmp_path))
    assert Path(path).parent == tmp_path
    assert Path(path).name.startswith(".._.._evil_name_")


def saved_scan(tmp_path, results):
    f = tmp_path / "scan.json"
    f.write_text(json.dumps(results), encoding="utf-8")
    return str(f)


def test_load_scan_builds_missing_evidence(tmp_path):
    raw = json.loads(FIXTURE.read_text(encoding="utf-8"))  # saved without evidence
    results = report.load_scan(saved_scan(tmp_path, raw))
    assert results["evidence"] and results["paths"]["paths"]


def test_load_scan_keeps_saved_evidence(lab, tmp_path):
    lab["evidence"][25]["fact"] = "fact as it was saved"  # E26
    results = report.load_scan(saved_scan(tmp_path, lab))
    assert results["evidence"][25]["fact"] == "fact as it was saved"


@pytest.mark.parametrize("scan", [{"mode": "investigate_ip", "ips": {}}, {"hello": 1}, []])
def test_load_scan_refuses_other_files(tmp_path, scan):
    with pytest.raises(ValueError):
        report.load_scan(saved_scan(tmp_path, scan))


def test_report_command(lab, tmp_path, monkeypatch):
    monkeypatch.setattr(report, "REPORTS_DIR", str(tmp_path / "reports"))
    assert report.main([saved_scan(tmp_path, lab), "--format", "csv", "--no-color"]) == 0
    assert len(list((tmp_path / "reports").glob("*_export.csv"))) == 1


def test_report_command_bad_files(tmp_path, capsys):
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    assert report.main([str(broken), "--no-color"]) == 1
    assert "isn't valid JSON" in capsys.readouterr().out
    assert report.main([str(tmp_path / "missing.json"), "--no-color"]) == 1
    assert "No such file" in capsys.readouterr().out


# ---------- fix groups (v1.10) ----------

GROUP = Path(__file__).parent / "golden" / "fixtures" / "side-door-three-hosts.json"


@pytest.fixture
def group(monkeypatch):
    """Three test hosts on one production server: no single fix closes P1."""
    monkeypatch.setattr(evidence, "now_utc", lambda: "2000-01-01T00:00:00Z")
    results = json.loads(GROUP.read_text(encoding="utf-8"))
    results["evidence"] = evidence.build_evidence(results)
    results["paths"] = paths.build_paths(results, results["evidence"])
    return results


def test_group_fix_flags_every_finding_in_it(group):
    found = report.findings(group)
    ids = [e for a in group["paths"]["fix_first"]["actions"] for e in a["evidence"]]
    assert len(ids) == 3
    assert [f["id"] for f in found if f["fix_first"]] == ids
    assert [f["id"] for f in found[:3]] == ids  # on top, in order


def test_group_fix_wording_in_every_format(group):
    md = report.to_markdown(group, WHEN)
    assert "- **Fix these 3 first** (E11, E12, E13, together they close P1)" in md
    page = report.to_html(group, WHEN)
    assert "<strong>Fix these 3 first</strong>" in page
    assert "together they close P1" in page
    assert "Fix this first" not in md and "Fix this first" not in page
    rows = list(csv.DictReader(io.StringIO(report.to_csv(group))))
    assert [r["id"] for r in rows if r["fix_first"] == "yes"] == ["E11", "E12", "E13"]


def test_load_scan_upgrades_paths_saved_before_actions(lab, tmp_path):
    for p in lab["paths"]["paths"]:
        steps = [e for s in p["steps"] for e in s["evidence"]]
        p["fix"] = [e for a in p.pop("actions") for e in a["evidence"]] + steps[-1:]
    lab["paths"]["fix_first"] = {"evidence": "E26", "fact": "x", "owners": [], "closes": ["P1"]}
    saved = tmp_path / "old.json"
    saved.write_text(json.dumps(lab), encoding="utf-8")
    loaded = report.load_scan(str(saved))
    assert [p["id"] for p in loaded["paths"]["paths"]] == ["P1", "P2"]
    assert all("actions" in p for p in loaded["paths"]["paths"])
    assert loaded["paths"]["fix_first"]["closes"] == ["P1"]
    report.to_html(loaded, WHEN)  # renders without the old keys
