"""subfinder import: reading its output, the CLI flag, history, evidence and MCP."""

import json
import os

import pytest

from monomi import cli, evidence, history, mcp_server
from monomi.importers import subfinder

D = "lab.test"


def write(tmp_path, text, name="out.txt"):
    f = tmp_path / name
    f.write_text(text)
    return str(f)


# --- reading the file ---

def test_plain_text(tmp_path):
    loaded = subfinder.load(write(tmp_path, "a.lab.test\nB.LAB.TEST.\n\n# a comment\na.lab.test\n"), D)
    assert loaded["hosts"] == {"a.lab.test": [], "b.lab.test": []}
    assert loaded["skipped"] == []


def test_json_lines_keep_which_source_found_each_host(tmp_path):
    lines = [
        {"host": "a.lab.test", "input": D, "source": "crtsh"},
        {"host": "a.lab.test", "input": D, "source": "alienvault"},
        {"host": "b.lab.test", "input": D, "sources": ["anubis", "rapiddns"]},  # -cs
    ]
    path = write(tmp_path, "\n".join(json.dumps(x) for x in lines), "out.json")
    assert subfinder.load(path, D)["hosts"] == {"a.lab.test": ["alienvault", "crtsh"],
                                                "b.lab.test": ["anubis", "rapiddns"]}


def test_host_and_ip_lines(tmp_path):
    assert subfinder.load(write(tmp_path, "a.lab.test,192.0.2.1\n"), D)["hosts"] == {"a.lab.test": []}


def test_only_the_targets_hostnames_are_kept(tmp_path):
    text = "a.lab.test\nother.test\nnotlab.test\nbad host.lab.test\n*.wild.lab.test\n{broken json\n"
    loaded = subfinder.load(write(tmp_path, text), D)
    assert loaded["hosts"] == {"a.lab.test": [], "wild.lab.test": []}
    assert loaded["skipped"] == ["2 hostnames not part of lab.test", "2 lines that aren't hostnames"]


def test_too_many_hosts_are_capped(tmp_path, monkeypatch):
    monkeypatch.setattr(subfinder, "MAX_HOSTS", 2)
    loaded = subfinder.load(write(tmp_path, "a.lab.test\nb.lab.test\nc.lab.test\n"), D)
    assert list(loaded["hosts"]) == ["a.lab.test", "b.lab.test"]
    assert loaded["skipped"] == ["1 more hostnames: over the 2 limit"]


def test_huge_file_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(subfinder, "MAX_BYTES", 5)
    with pytest.raises(ValueError, match="isn't read"):
        subfinder.load(write(tmp_path, "a.lab.test\n"), D)


def test_source_record_is_dated_when_subfinder_ran(tmp_path):
    path = write(tmp_path, "a.lab.test\n")
    os.utime(path, (1763035200, 1763035200))  # 2025-11-13 12:00 UTC
    r = subfinder.to_source(subfinder.load(path, D), path)
    assert r["source"] == "subfinder" and r["subdomains"] == ["a.lab.test"]
    assert r["collected_at"] == "2025-11-13T12:00:00+00:00"  # the file's time, not now
    assert r["imported_at"]  # another tool's list


# --- the CLI ---

def test_flag_adds_the_hosts_as_their_own_source(tmp_path, capsys):
    results = {"sources": {}, "errors": {}}
    assert cli.add_subfinder(results, write(tmp_path, "a.lab.test\nother.test\n"), D)
    assert results["sources"]["subfinder"]["subdomains"] == ["a.lab.test"]
    out = capsys.readouterr().out
    assert "subfinder: 1 hostnames from" in out and "Skipped 1 hostname not part of lab.test" in out


def test_unreadable_file_stops_the_scan(tmp_path, capsys):
    assert not cli.add_subfinder({"sources": {}, "errors": {}}, str(tmp_path / "missing.txt"), D)
    assert "Can't read the subfinder file" in capsys.readouterr().out


def test_subfinder_hosts_never_reach_history(tmp_path, monkeypatch, capsys):
    """Like --hosts: the import is only there on runs that pass the file."""
    monkeypatch.setattr(history, "SCANS_DIR", str(tmp_path / "history"))
    results = {"target": D, "errors": {}, "sources": {
        "certspotter": {"source": "certspotter", "subdomains": ["a.lab.test"], "certificates_seen": 1}}}
    cli.add_subfinder(results, write(tmp_path, "extra.lab.test\n"), D)
    cli.show_changes(results)
    assert history.load_last(D)["subdomains"] == ["a.lab.test"]


def test_evidence_marks_subfinder_hosts_as_imported(tmp_path):
    results = {"target": D, "subdomains": ["a.lab.test"], "sources": {}}
    cli.add_subfinder(results, write(tmp_path, "a.lab.test\n"), D)
    fact = evidence.build_evidence(results)[0]
    assert fact["fact"] == "a.lab.test was found by subfinder"
    assert fact["sources"][0]["imported_at"]


def test_main_with_the_flag(tmp_path, monkeypatch, capsys):
    """The whole CLI run: the flag's hosts are in the scan's list."""
    monkeypatch.setattr(history, "SCANS_DIR", str(tmp_path / "history"))
    for mod in (cli.crtsh, cli.crtsh_db, cli.certspotter):
        monkeypatch.setattr(mod, "collect", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("down")))
    path = write(tmp_path, "only-subfinder.lab.test\n")
    monkeypatch.setattr("sys.argv", ["monomi.py", D, "--subfinder", path, "--no-color"])
    cli.main()
    assert "only-subfinder.lab.test" in capsys.readouterr().out


# --- MCP ---

@pytest.fixture
def scans(tmp_path, monkeypatch):
    monkeypatch.setattr(mcp_server, "SCANS_DIR", str(tmp_path))
    for mod in (cli.crtsh, cli.crtsh_db, cli.certspotter):
        monkeypatch.setattr(mod, "collect", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("down")))
    return tmp_path


def test_mcp_adds_the_subfinder_source(scans):
    (scans / "subfinder").mkdir()
    (scans / "subfinder" / "lab.txt").write_text("a.lab.test\nother.test\n")
    full = mcp_server.find_subdomains(D, detail="full", subfinder_file="subfinder/lab.txt")
    assert full["hostnames"] == ["a.lab.test"]
    assert full["sources"]["subfinder"]["found"] == 1
    assert full["sources"]["subfinder"]["skipped"] == ["1 hostname not part of lab.test"]


@pytest.mark.parametrize("path, says", [
    ("../../etc/passwd.txt", "must be inside Monomi's scans folder"),
    ("lab.csv", "must be a .txt or .json or .jsonl file"),
    ("missing.txt", "not found"),
])
def test_mcp_refuses_files_it_shouldnt_read(scans, path, says):
    with pytest.raises(mcp_server.ToolError, match=says):
        mcp_server.find_subdomains(D, subfinder_file=path)
