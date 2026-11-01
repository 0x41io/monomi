import pytest

from monomi import clean_domain, flag_silent_crtsh_failure


def test_clean_domain_strips_url_parts():
    assert clean_domain("https://WWW.Example.com/login?x=1") == "example.com"
    assert clean_domain("example.com:8443") == "example.com"
    assert clean_domain("example.com.") == "example.com"


def test_clean_domain_keeps_real_subdomains():
    assert clean_domain("shop.example.co.uk") == "shop.example.co.uk"


def test_clean_domain_rejects_bad_input():
    with pytest.raises(ValueError):
        clean_domain("not a domain")
    with pytest.raises(ValueError):
        clean_domain("localhost")


def _ct(source, certs):
    return {"source": source, "certificates_seen": certs, "subdomains": []}


def test_silent_crtsh_failure_is_flagged():
    results = {"sources": {"crt.sh": _ct("crt.sh", 0), "certspotter": _ct("certspotter", 8)},
               "errors": {}}
    flag_silent_crtsh_failure(results)
    assert "crt.sh" not in results["sources"]
    assert "crt.sh" in results["errors"]


def test_real_empty_result_is_left_alone():
    # Both sources agree there's nothing: that's a genuine empty result
    results = {"sources": {"crt.sh": _ct("crt.sh", 0), "certspotter": _ct("certspotter", 0)},
               "errors": {}}
    flag_silent_crtsh_failure(results)
    assert "crt.sh" in results["sources"]
    assert results["errors"] == {}


def test_check_skipped_when_certspotter_failed():
    results = {"sources": {"crt.sh": _ct("crt.sh", 0)}, "errors": {"Cert Spotter": "HTTP 500"}}
    flag_silent_crtsh_failure(results)
    assert "crt.sh" in results["sources"]


def test_crtsh_flagged_when_database_found_certificates():
    results = {"sources": {"crt.sh": _ct("crt.sh", 0), "crt.sh database": _ct("crt.sh database", 703),
                           "certspotter": _ct("certspotter", 0)},
               "errors": {}}
    flag_silent_crtsh_failure(results)
    assert "crt.sh" not in results["sources"]
    assert "crt.sh database found 703" in results["errors"]["crt.sh"]


def test_both_crtsh_sources_flagged_when_only_certspotter_found_some():
    results = {"sources": {"crt.sh": _ct("crt.sh", 0), "crt.sh database": _ct("crt.sh database", 0),
                           "certspotter": _ct("certspotter", 8)},
               "errors": {}}
    flag_silent_crtsh_failure(results)
    assert list(results["sources"]) == ["certspotter"]
    assert set(results["errors"]) == {"crt.sh", "crt.sh database"}


def _source(source, certs):
    return {**_ct(source, certs), "subdomain_count": 0}


def test_collect_ct_runs_silent_check_when_every_source_succeeds(monkeypatch):
    # The bug fixed in v1.7: the check used to run only when some source errored
    import monomi
    monkeypatch.setattr(monomi.crtsh, "collect", lambda domain, budget, light: _source("crt.sh", 0))
    monkeypatch.setattr(monomi.crtsh_db, "collect", lambda domain, budget: _source("crt.sh database", 5))
    monkeypatch.setattr(monomi.certspotter, "collect", lambda domain: _source("certspotter", 2))
    results = {"sources": {}, "errors": {}}
    monomi.collect_ct(results, "example.com")
    assert "crt.sh" in results["errors"]
    assert set(results["sources"]) == {"crt.sh database", "certspotter"}
