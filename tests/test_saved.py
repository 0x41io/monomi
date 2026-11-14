import json
from datetime import datetime, timezone

import pytest

from monomi import cli, evidence
from monomi.collectors import saved
from monomi.cli import baseline_gaps, collect_ct, history_input

NOW = datetime(2026, 11, 7, 18, 0, tzinfo=timezone.utc)


def _record(source, certs=3, hosts=("a.lab", "b.lab"), when="2026-11-05T12:00:00+00:00"):
    return {"source": source, "collected_at": when, "certificates_seen": certs,
            "subdomain_count": len(hosts), "subdomains": list(hosts), "wildcards": []}


# --- save() and load() ---

def test_save_then_load_marks_the_copy(saved_dir):
    path = saved.save("lab", _record("crt.sh database"))
    assert path == str(saved_dir / "lab" / "sources" / "crt.sh-database.json")
    copy = saved.load("lab", "crt.sh database", now=NOW)
    assert copy["from_saved"] is True
    assert copy["collected_at"] == "2026-11-05T12:00:00+00:00"  # the original time, not now
    assert copy["subdomains"] == ["a.lab", "b.lab"]


def test_saved_file_itself_has_no_from_saved_flag(saved_dir):
    saved.save("lab", _record("certspotter"))
    on_disk = json.loads((saved_dir / "lab" / "sources" / "certspotter.json").read_text())
    assert "from_saved" not in on_disk


def test_save_keeps_only_the_latest_copy():
    saved.save("lab", _record("certspotter", hosts=("old.lab",)))
    saved.save("lab", _record("certspotter", hosts=("new.lab",)))
    assert saved.load("lab", "certspotter", now=NOW)["subdomains"] == ["new.lab"]


def test_load_with_no_copy_is_none():
    assert saved.load("lab", "certspotter", now=NOW) is None


def test_load_ignores_a_broken_file(saved_dir):
    folder = saved_dir / "lab" / "sources"
    folder.mkdir(parents=True)
    (folder / "certspotter.json").write_text("{not json")
    assert saved.load("lab", "certspotter", now=NOW) is None


def test_load_ignores_a_copy_older_than_30_days():
    saved.save("lab", _record("certspotter", when="2026-10-07T17:00:00+00:00"))  # 31 days
    assert saved.load("lab", "certspotter", now=NOW) is None
    saved.save("lab", _record("certspotter", when="2026-10-09T18:00:00+00:00"))  # 29 days
    assert saved.load("lab", "certspotter", now=NOW) is not None


def test_unsafe_domain_names_are_refused():
    for bad in ("../etc", "a/b", "..", "", ".hidden"):
        with pytest.raises(ValueError):
            saved.save(bad, _record("certspotter"))
        assert saved.load(bad, "certspotter", now=NOW) is None


# --- collect_ct() saving and falling back ---

def _fake_sources(monkeypatch, crtsh=None, db=None, cs=None):
    """Each argument is a record to return, or None to make that source fail."""
    def job(record, error):
        def run(*args, **kwargs):
            if record is None:
                raise RuntimeError(error)
            return record
        return run
    monkeypatch.setattr(cli.crtsh, "collect", job(crtsh, "HTTP 502"))
    monkeypatch.setattr(cli.crtsh_db, "collect", job(db, "connection timeout"))
    monkeypatch.setattr(cli.certspotter, "collect", job(cs, "rate limited"))


def test_good_results_are_saved_empty_ones_are_not(monkeypatch):
    _fake_sources(monkeypatch, crtsh=_record("crt.sh", certs=0, hosts=()),
                  db=_record("crt.sh database", certs=0, hosts=()), cs=_record("certspotter", certs=0, hosts=()))
    collect_ct({"sources": {}, "errors": {}}, "lab")
    assert saved.load("lab", "certspotter", now=NOW) is None  # nothing found anywhere: nothing saved

    _fake_sources(monkeypatch, crtsh=None, db=_record("crt.sh database"), cs=_record("certspotter"))
    collect_ct({"sources": {}, "errors": {}}, "lab")
    assert saved.load("lab", "crt.sh database", now=NOW) is not None
    assert saved.load("lab", "certspotter", now=NOW) is not None
    assert saved.load("lab", "crt.sh", now=NOW) is None  # it failed, so there was nothing to save


def test_failed_cert_spotter_uses_its_saved_copy(monkeypatch):
    saved.save("lab", _record("certspotter", hosts=("old.lab",)))
    _fake_sources(monkeypatch, crtsh=_record("crt.sh"), db=_record("crt.sh database"), cs=None)
    results = {"sources": {}, "errors": {}}
    collect_ct(results, "lab")
    copy = results["sources"]["certspotter"]
    assert copy["from_saved"] is True and copy["subdomains"] == ["old.lab"]
    assert results["errors"]["Cert Spotter"] == "rate limited; using the saved copy from 2026-11-05T12:00:00+00:00"


def test_no_crtsh_copy_when_the_other_crtsh_source_worked(monkeypatch):
    saved.save("lab", _record("crt.sh"))
    _fake_sources(monkeypatch, crtsh=None, db=_record("crt.sh database"), cs=_record("certspotter"))
    results = {"sources": {}, "errors": {}}
    collect_ct(results, "lab")
    assert "crt.sh" not in results["sources"]  # the database has the same data
    assert results["errors"]["crt.sh"] == "HTTP 502"


def test_both_crtsh_failed_uses_only_the_newer_copy(monkeypatch):
    saved.save("lab", _record("crt.sh", hosts=("older.lab",), when="2026-11-01T00:00:00+00:00"))
    saved.save("lab", _record("crt.sh database", hosts=("newer.lab",), when="2026-11-04T00:00:00+00:00"))
    _fake_sources(monkeypatch, crtsh=None, db=None, cs=_record("certspotter"))
    results = {"sources": {}, "errors": {}}
    collect_ct(results, "lab")
    assert "crt.sh" not in results["sources"]
    assert results["sources"]["crt.sh database"]["subdomains"] == ["newer.lab"]
    assert results["errors"]["crt.sh"] == "HTTP 502"  # only the copy that was used is mentioned


def test_saved_copy_still_counts_as_a_gap(monkeypatch):
    # The baseline_gaps() trap: a saved crt.sh copy in "sources" must not look like crt.sh worked
    saved.save("lab", _record("crt.sh database"))
    _fake_sources(monkeypatch, crtsh=None, db=None, cs=_record("certspotter"))
    results = {"sources": {}, "errors": {}}
    collect_ct(results, "lab")
    assert results["sources"]["crt.sh database"]["from_saved"] is True
    assert {"crt.sh", "crt.sh database"} <= set(baseline_gaps(results))
    fresh, partial, notes = history_input(results)
    assert "crt.sh" not in fresh and "crt.sh" not in partial and "crt.sh" in notes


def test_evidence_says_saved_copy():
    results = {"sources": {"certspotter": {**_record("certspotter", hosts=("a.lab",)), "from_saved": True}},
               "subdomains": ["a.lab"]}
    first = evidence.build_evidence(results)[0]
    assert first["sources"][0]["name"] == "certspotter (saved copy)"
    assert first["sources"][0]["collected_at"] == "2026-11-05T12:00:00+00:00"
