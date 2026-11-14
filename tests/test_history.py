"""Per-source scan history (v1.14): failures, cut-short sources and new sources
never make hosts look new or gone."""

import json

import pytest

import history
import monomi
from history import CARRIED, FRESH, PARTIAL, build, source_lists
from monomi import history_input, show_changes

D = "lab.test"
T = "2026-11-13T12:00:00+00:00"


@pytest.fixture(autouse=True)
def history_dir(tmp_path, monkeypatch):
    """Every test gets its own empty history folder, never the real scans/."""
    monkeypatch.setattr(history, "SCANS_DIR", str(tmp_path / "history"))
    return tmp_path / "history"


def src(source, *hosts, partial=None, saved=False, certs=True):
    r = {"source": source, "collected_at": T, "subdomain_count": len(hosts), "subdomains": list(hosts)}
    r["certificates_seen" if certs else "records_seen"] = len(hosts)
    if partial:
        r["partial"] = partial
    if saved:
        r["from_saved"] = True
    return r


def scan(*sources, errors=None):
    return {"target": D, "sources": {r["source"]: r for r in sources}, "errors": errors or {}}


def run(results, capsys):
    show_changes(results)
    return results.get("changes"), capsys.readouterr().out


# --- the history module ---

def test_old_combined_list_counts_as_every_certificate_sources_list():
    old = {"scanned_at": T, "subdomains": ["a.lab.test"]}
    assert source_lists(old) == {"crt.sh": ["a.lab.test"], "certspotter": ["a.lab.test"]}
    assert source_lists(None) == {}


def test_build_marks_each_source():
    previous = {"scanned_at": T, "sources": {"crt.sh": {"subdomains": ["a.lab.test"]},
                                             "certspotter": {"subdomains": ["b.lab.test", "c.lab.test"]},
                                             "otx": {"subdomains": ["d.lab.test"]}}}
    entries = build(previous, fresh={"crt.sh": ["a.lab.test"]}, partial={"certspotter": ["b.lab.test", "e.lab.test"]})
    assert entries["crt.sh"] == {"subdomains": ["a.lab.test"], "status": FRESH}
    # cut short: last list plus what it found now
    assert entries["certspotter"] == {"subdomains": ["b.lab.test", "c.lab.test", "e.lab.test"], "status": PARTIAL}
    assert entries["otx"] == {"subdomains": ["d.lab.test"], "status": CARRIED}  # failed: kept


def test_saved_file_has_the_union_and_each_source(history_dir):
    path = history.save(D, build(None, {"crt.sh": ["a.lab.test"], "otx": ["b.lab.test"]}, {}))
    saved = json.loads(open(path).read())
    assert saved["subdomains"] == ["a.lab.test", "b.lab.test"]
    assert saved["sources"]["otx"] == {"subdomains": ["b.lab.test"], "status": FRESH}
    assert history.load_last(D)["sources"]["crt.sh"]["subdomains"] == ["a.lab.test"]


# --- the bug from the first v1.14 field run ---

def test_cert_spotter_cut_short_makes_nothing_gone(capsys):
    """The Deriv run: Cert Spotter stopped after 1 page of 3. Before v1.14 that
    saved a short baseline (6 fake [GONE]), and the next full run showed the
    same 6 as [NEW]."""
    full = ["a.lab.test", "b.lab.test", "c.lab.test"]
    run(scan(src("crt.sh database", "a.lab.test"), src("certspotter", *full)), capsys)
    changes, out = run(scan(src("crt.sh database", "a.lab.test"),
                            src("certspotter", "b.lab.test", partial="stopped after 1 page (rate limit)")),
                       capsys)
    assert changes["removed"] == [] and changes["added"] == []
    assert "Cert Spotter stopped after 1 page (rate limit)" in out
    # ...and the next complete run doesn't bring them back as [NEW]
    changes, _ = run(scan(src("crt.sh database", "a.lab.test"), src("certspotter", *full)), capsys)
    assert changes["added"] == [] and changes["removed"] == []


def test_breaking_the_partial_rule_brings_the_fake_gone_hosts_back(capsys, monkeypatch):
    """Break the rule: treat a cut-short source as complete, and the bug is back."""
    real = history_input

    def partial_counts_as_fresh(results):
        fresh, partial, notes = real(results)
        return {**fresh, **partial}, {}, {}
    monkeypatch.setattr(monomi, "history_input", partial_counts_as_fresh)
    run(scan(src("certspotter", "a.lab.test", "b.lab.test")), capsys)
    changes, _ = run(scan(src("certspotter", "a.lab.test", partial="stopped after 1 page (rate limit)")), capsys)
    assert changes["removed"] == ["b.lab.test"]


def test_cut_short_source_still_shows_hosts_it_really_found_new(capsys):
    run(scan(src("certspotter", "a.lab.test")), capsys)
    changes, _ = run(scan(src("certspotter", "z.lab.test", partial="stopped at the 5-page cap")), capsys)
    assert changes["added"] == ["z.lab.test"] and changes["removed"] == []


# --- failures, saved copies, new sources ---

def test_failed_source_keeps_its_hosts(capsys):
    run(scan(src("crt.sh database", "a.lab.test"), src("certspotter", "b.lab.test")), capsys)
    changes, out = run(scan(src("crt.sh database", "a.lab.test"), errors={"Cert Spotter": "rate limited"}), capsys)
    assert changes["removed"] == []
    assert "Cert Spotter failed" in out and "none is marked gone" in out


def test_saved_copy_is_not_fresh_data(capsys):
    """A saved copy stands in for a failure: it can't make hosts gone either."""
    run(scan(src("certspotter", "a.lab.test", "b.lab.test")), capsys)
    changes, _ = run(scan(src("certspotter", "a.lab.test", saved=True),
                          errors={"Cert Spotter": "rate limited; using the saved copy"}), capsys)
    assert changes["removed"] == []


def test_a_host_is_gone_when_every_source_that_had_it_worked(capsys):
    run(scan(src("crt.sh database", "a.lab.test", "old.lab.test"), src("certspotter", "old.lab.test")), capsys)
    changes, out = run(scan(src("crt.sh database", "a.lab.test"), src("certspotter", "a.lab.test")), capsys)
    assert changes["removed"] == ["old.lab.test"] and "Not complete" not in out


def test_one_crtsh_source_is_enough_for_crtsh(capsys):
    """The website and database hold the same data: one working is a fresh crt.sh."""
    run(scan(src("crt.sh database", "a.lab.test", "old.lab.test")), capsys)
    changes, out = run(scan(src("crt.sh database", "a.lab.test"), errors={"crt.sh": "HTTP 502"}), capsys)
    assert changes["removed"] == ["old.lab.test"] and "crt.sh failed" not in out


def test_otx_joining_history_marks_nothing_new(capsys):
    """First run with OTX on a domain with history: its extra hosts are its
    starting point, not [NEW]."""
    run(scan(src("crt.sh database", "a.lab.test")), capsys)
    changes, out = run(scan(src("crt.sh database", "a.lab.test"),
                            src("otx", "a.lab.test", "mail.lab.test", certs=False)), capsys)
    assert changes["added"] == [] and changes["joined"] == {"otx": ["mail.lab.test"]}
    assert "AlienVault OTX joins this domain's history: 1 hostname only it found is its starting point" in out
    # From then on OTX is a normal source: a host it finds later is new
    changes, _ = run(scan(src("crt.sh database", "a.lab.test"),
                          src("otx", "a.lab.test", "mail.lab.test", "vpn.lab.test", certs=False)), capsys)
    assert changes["added"] == ["vpn.lab.test"] and changes["joined"] == {}


def test_old_history_file_then_otx(capsys, history_dir):
    """A history file from before v1.14 (one combined list) works as the previous scan."""
    folder = history_dir / D
    folder.mkdir(parents=True)
    (folder / "2026-11-01_120000.json").write_text(json.dumps(
        {"target": D, "scanned_at": "2026-11-01T12:00:00", "subdomains": ["a.lab.test", "old.lab.test"]}))
    changes, _ = run(scan(src("crt.sh database", "a.lab.test"), src("certspotter", "a.lab.test"),
                          src("otx", "mail.lab.test", certs=False)), capsys)
    assert changes["removed"] == ["old.lab.test"] and changes["added"] == []
    assert changes["joined"] == {"otx": ["mail.lab.test"]}


def test_imports_never_reach_history(capsys):
    results = scan(src("certspotter", "a.lab.test"))
    results["sources"][monomi.HOSTS_FILE] = {"source": monomi.HOSTS_FILE, "subdomains": ["extra.lab.test"]}
    results["sources"]["spiderfoot"] = {"source": "spiderfoot", "subdomains": ["sf.lab.test"]}
    run(results, capsys)
    assert history.load_last(D)["subdomains"] == ["a.lab.test"]


def test_first_scan_with_a_failed_source_is_still_saved(capsys):
    """Every scan is saved now: the failed source joins once it works."""
    _, out = run(scan(src("crt.sh database", "a.lab.test"), errors={"AlienVault OTX": "rate limit hit"}), capsys)
    assert "saved as baseline" in out and "AlienVault OTX failed" in out
    assert history.load_last(D)["subdomains"] == ["a.lab.test"]


def test_nothing_worked_saves_nothing(capsys):
    _, out = run(scan(errors={"crt.sh": "HTTP 502", "crt.sh database": "timeout",
                              "Cert Spotter": "rate limited", "AlienVault OTX": "rate limit hit"}), capsys)
    assert history.load_last(D) is None and "nothing to save" in out


def test_crtsh_behind_reads_behind(capsys):
    run(scan(src("certspotter", "a.lab.test")), capsys)
    behind = monomi.CRTSH_BEHIND + ": the crt.sh database answered with 0"
    _, out = run(scan(src("certspotter", "a.lab.test"), errors={"crt.sh": behind, "crt.sh database": behind}),
                 capsys)
    assert "crt.sh, crt.sh database are behind on the CT logs" in out
