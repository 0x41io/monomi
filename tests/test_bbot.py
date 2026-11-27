"""BBOT import (v1.29.0): reading output.json, the CLI flag, history, evidence
and MCP. The sample events copy the shapes of a real BBOT 3.1.0 run on the
41xlab lab (passive subdomain-enum), with lab.test names."""

import json
import os

import pytest

from monomi import cli, evidence, history, mcp_server
from monomi.importers import bbot

D = "lab.test"


def ev(type_, data, distance=0, module="certspotter", host=None, tags=()):
    return {"type": type_, "data": data, "host": host if host is not None else data,
            "resolved_hosts": ["192.0.2.7"], "scope_distance": distance, "module": module,
            "tags": list(tags)}


# A run like the lab's: the seed, two subdomains (one found twice), the
# provider's nameservers one hop out, and BBOT's other event types
REAL_RUN = [
    {"type": "SCAN", "data": None, "host": None, "scope_distance": 0, "module": "SEED", "tags": []},
    ev("DNS_NAME", "lab.test", module="SEED", tags=("in-scope", "target")),
    ev("DNS_NAME", "harley.ns.cloudflare.com", distance=1, module="NS", tags=("affiliate", "distance-1")),
    ev("DNS_NAME", "staging.lab.test", module="shodan_idb"),
    ev("DNS_NAME", "staging.lab.test", module="certspotter"),
    ev("DNS_NAME", "app.lab.test", module="hackertarget"),
    ev("OPEN_TCP_PORT", "lab.test:8080", module="shodan_idb", host="lab.test"),
    ev("OPEN_TCP_PORT", "lab.test:443", module="shodan_idb", host="lab.test"),
    {"type": "TECHNOLOGY", "data": None, "host": "lab.test", "scope_distance": 0, "module": "shodan_idb"},
    {"type": "ASN", "data": None, "host": None, "scope_distance": 1, "module": "asn"},
    {"type": "SCAN", "data": None, "host": None, "scope_distance": 0, "module": "SEED", "tags": []},
]


def write(tmp_path, events, name="output.json", extra=""):
    f = tmp_path / name
    f.write_text("\n".join(json.dumps(e) for e in events) + "\n" + extra)
    return str(f)


# --- reading the file ---

def test_a_real_run_keeps_only_the_in_scope_hosts(tmp_path):
    loaded = bbot.load(write(tmp_path, REAL_RUN), D)
    assert loaded["hosts"] == {"app.lab.test": ["hackertarget"], "lab.test": ["SEED"],
                               "staging.lab.test": ["certspotter", "shodan_idb"]}
    # the provider's nameserver (BBOT: affiliate, distance-1) never gets in
    assert loaded["skipped"] == ["1 DNS name BBOT itself marked out of scope (scope distance above 0)"]


def test_other_event_types_are_counted_never_used(tmp_path):
    loaded = bbot.load(write(tmp_path, REAL_RUN), D)
    assert loaded["not_used"] == {"ASN": 1, "OPEN_TCP_PORT": 2, "TECHNOLOGY": 1}  # SCAN records aren't data


def test_bbots_wildcard_placeholders_are_not_hosts(tmp_path):
    """PlayStation: BBOT records "_wildcard.<zone>" while testing a zone for
    wildcard DNS. It became a fake "Take over DNS for _wildcard.nonprod.pcs..."
    lead. Skipped and counted, never a host (v1.29.1)."""
    events = [ev("DNS_NAME", "_wildcard.nonprod.pcs.lab.test", module="dnsresolve"),
              ev("DNS_NAME", "_wildcard.ac.lab.test", module="dnsresolve"),
              ev("DNS_NAME", "real.nonprod.pcs.lab.test")]
    loaded = bbot.load(write(tmp_path, events), D)
    assert list(loaded["hosts"]) == ["real.nonprod.pcs.lab.test"]
    assert loaded["skipped"] == ["2 BBOT wildcard placeholders (_wildcard.<zone>, a name BBOT made up while "
                                 "testing for wildcard DNS)"]


def test_in_scope_names_of_other_domains_are_left_out(tmp_path):
    # a multi-target BBOT run: in scope for BBOT, not this scan's domain
    loaded = bbot.load(write(tmp_path, [ev("DNS_NAME", "www.other.test")]), D)
    assert loaded["hosts"] == {} and loaded["skipped"] == ["1 in-scope DNS name not part of lab.test"]


def test_null_data_falls_back_to_host(tmp_path):
    # some BBOT versions keep the value outside "data"
    loaded = bbot.load(write(tmp_path, [ev("DNS_NAME", None, host="API.Lab.Test.")]), D)
    assert list(loaded["hosts"]) == ["api.lab.test"]


def test_a_wildcard_name_stands_for_the_name_it_covers(tmp_path):
    assert list(bbot.load(write(tmp_path, [ev("DNS_NAME", "*.dev.lab.test")]), D)["hosts"]) == ["dev.lab.test"]


@pytest.mark.parametrize("distance", [None, "0", 2, -1])
def test_anything_but_scope_distance_0_is_out_of_scope(tmp_path, distance):
    loaded = bbot.load(write(tmp_path, [ev("DNS_NAME", "x.lab.test", distance=distance)]), D)
    assert loaded["hosts"] == {}


def test_broken_lines_are_counted_not_fatal(tmp_path):
    loaded = bbot.load(write(tmp_path, [ev("DNS_NAME", "a.lab.test")], extra="not json\n[1, 2]\n"), D)
    assert list(loaded["hosts"]) == ["a.lab.test"]
    assert "2 lines that aren't BBOT events" in loaded["skipped"]


def test_a_file_with_no_bbot_events_is_refused(tmp_path):
    f = tmp_path / "subs.txt"
    f.write_text("a.lab.test\nb.lab.test\n")  # BBOT's subdomains.txt, not output.json
    with pytest.raises(ValueError, match="expected BBOT's output.json"):
        bbot.load(str(f), D)


def test_too_many_hosts_are_capped(tmp_path, monkeypatch):
    monkeypatch.setattr(bbot, "MAX_HOSTS", 2)
    loaded = bbot.load(write(tmp_path, [ev("DNS_NAME", f"h{i}.lab.test") for i in range(4)]), D)
    assert len(loaded["hosts"]) == 2 and "2 more hostnames: over the 2 limit" in loaded["skipped"]


def test_huge_file_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(bbot, "MAX_BYTES", 10)
    with pytest.raises(ValueError, match="isn't read"):
        bbot.load(write(tmp_path, REAL_RUN), D)


def test_source_record_is_dated_when_bbot_ran(tmp_path):
    path = write(tmp_path, REAL_RUN)
    os.utime(path, (1700000000, 1700000000))
    r = bbot.to_source(bbot.load(path, D), path)
    assert r["source"] == "bbot" and r["collected_at"] == "2023-11-14T22:13:20+00:00"
    assert r["imported_at"] and r["subdomain_count"] == 3
    assert r["found_by"]["staging.lab.test"] == ["certspotter", "shodan_idb"]


# --- the CLI ---

def test_flag_adds_the_hosts_and_names_what_wasnt_used(tmp_path, capsys):
    results = {"sources": {}, "errors": {}}
    assert cli.add_bbot(results, write(tmp_path, REAL_RUN), D)
    assert results["sources"]["bbot"]["subdomains"] == ["app.lab.test", "lab.test", "staging.lab.test"]
    out = capsys.readouterr().out
    assert "BBOT: 3 in-scope hostnames from" in out
    assert "Skipped 1 DNS name BBOT itself marked out of scope" in out
    assert "Not used (other BBOT event types; Monomi checks these itself): ASN: 1, OPEN_TCP_PORT: 2" in out


def test_unreadable_file_stops_the_scan(tmp_path, capsys):
    assert not cli.add_bbot({"sources": {}, "errors": {}}, str(tmp_path / "missing.json"), D)
    assert "Can't read the BBOT file" in capsys.readouterr().out


def test_bbot_hosts_never_reach_history(tmp_path, monkeypatch, capsys):
    """Like --subfinder: the import is only there on runs that pass the file."""
    monkeypatch.setattr(history, "SCANS_DIR", str(tmp_path / "history"))
    results = {"target": D, "errors": {}, "sources": {
        "certspotter": {"source": "certspotter", "subdomains": ["a.lab.test"], "certificates_seen": 1}}}
    cli.add_bbot(results, write(tmp_path, [ev("DNS_NAME", "extra.lab.test")]), D)
    cli.show_changes(results)
    assert history.load_last(D)["subdomains"] == ["a.lab.test"]


def test_evidence_marks_bbot_hosts_as_imported(tmp_path):
    results = {"target": D, "subdomains": ["app.lab.test"], "sources": {}}
    cli.add_bbot(results, write(tmp_path, [ev("DNS_NAME", "app.lab.test")]), D)
    fact = evidence.build_evidence(results)[0]
    assert fact["fact"] == "app.lab.test was found by bbot"
    assert fact["sources"][0]["imported_at"]


def test_main_with_the_flag(tmp_path, monkeypatch, capsys):
    """The whole CLI run: the BBOT hosts are in the scan's list."""
    monkeypatch.setattr(history, "SCANS_DIR", str(tmp_path / "history"))
    for mod in (cli.crtsh, cli.crtsh_db, cli.certspotter):
        monkeypatch.setattr(mod, "collect", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("down")))
    path = write(tmp_path, [ev("DNS_NAME", "only-bbot.lab.test")])
    monkeypatch.setattr("sys.argv", ["monomi.py", D, "--bbot", path, "--no-color"])
    cli.main()
    assert "only-bbot.lab.test" in capsys.readouterr().out


# --- MCP ---

@pytest.fixture
def scans(tmp_path, monkeypatch):
    monkeypatch.setattr(mcp_server, "SCANS_DIR", str(tmp_path))
    for mod in (cli.crtsh, cli.crtsh_db, cli.certspotter):
        monkeypatch.setattr(mod, "collect", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("down")))
    return tmp_path


def test_mcp_adds_the_bbot_source(scans):
    (scans / "bbot").mkdir()
    write(scans / "bbot", REAL_RUN, name="lab.json")
    full = mcp_server.find_subdomains(D, detail="full", bbot_file="bbot/lab.json")
    assert full["hostnames"] == ["app.lab.test", "lab.test", "staging.lab.test"]
    assert full["sources"]["bbot"]["found"] == 3
    assert full["sources"]["bbot"]["not_used"] == {"ASN": 1, "OPEN_TCP_PORT": 2, "TECHNOLOGY": 1}


@pytest.mark.parametrize("path, says", [
    ("../../etc/passwd.json", "must be inside Monomi's scans folder"),
    ("lab.txt", "must be a .json or .ndjson or .jsonl file"),
    ("missing.json", "not found"),
])
def test_mcp_refuses_files_it_shouldnt_read(scans, path, says):
    with pytest.raises(mcp_server.ToolError, match=says):
        mcp_server.find_subdomains(D, bbot_file=path)
