"""Tests for how monomi.py wires up exports: the --export flag, the AI
summary kept with the results, and the report command."""

import json
import sys
import types
from pathlib import Path

import pytest

import evidence
import monomi
import paths
import report

FIXTURE = Path(__file__).parent / "golden" / "fixtures" / "41xlab.json"
DOMAIN = "example" + ".com"


def test_export_flag_takes_formats():
    args = monomi.build_parser().parse_args([DOMAIN, "--export", "html,csv"])
    assert args.export == ["html", "csv"]
    with pytest.raises(SystemExit):
        monomi.build_parser().parse_args([DOMAIN, "--export", "pdf"])


def test_export_refused_with_investigate_ip(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["monomi.py", "--investigate-ip", "192.0.2.1",
                                      "--export", "all", "--no-color"])
    with pytest.raises(SystemExit):
        monomi.main()


def test_ai_text_goes_into_the_export(monkeypatch, tmp_path):
    results = json.loads(FIXTURE.read_text(encoding="utf-8"))
    results["evidence"] = evidence.build_evidence(results)
    results["paths"] = paths.build_paths(results, results["evidence"])

    # A fake analysis module, so no real Claude API call is made
    fake = types.ModuleType("analysis")
    fake.summarize = lambda r: ("Spoofing first [E26]. Then P1, P2.", "claude-test")
    monkeypatch.setitem(sys.modules, "analysis", fake)
    monkeypatch.setattr(monomi, "REPORTS_DIR", str(tmp_path / "ai"))
    monkeypatch.setattr(report, "REPORTS_DIR", str(tmp_path / "export"))

    monomi.write_ai_report(results)
    assert results["ai_report"] == {"text": "Spoofing first [E26]. Then P1, P2.",
                                    "model": "claude-test"}
    monomi.export_reports(results, ["md"])
    [md] = (tmp_path / "export").glob("*_export.md")
    assert "## AI summary" in md.read_text(encoding="utf-8")


def test_report_command_is_routed(monkeypatch):
    seen = []

    def fake_main(argv):
        seen.append(argv)
        return 0
    monkeypatch.setattr(report, "main", fake_main)
    monkeypatch.setattr(sys, "argv", ["monomi.py", "report", "scan.json", "--format", "csv"])
    assert monomi.main() == 0
    assert seen == [["scan.json", "--format", "csv"]]
