import pytest

import monomi
from monomi import baseline_gaps, clean_domain, collect_ct, flag_silent_crtsh_failure, gap_reason


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


def test_one_crtsh_source_failing_leaves_no_gap():
    results = {"sources": {"crt.sh database": {}, "certspotter": {}},
               "errors": {"crt.sh": "HTTP 502"}}
    assert baseline_gaps(results) == []


def test_both_crtsh_sources_failing_is_a_gap():
    results = {"sources": {"certspotter": {}},
               "errors": {"crt.sh": "HTTP 502", "crt.sh database": "timeout"}}
    assert baseline_gaps(results) == ["crt.sh", "crt.sh database"]


def test_cert_spotter_failing_is_still_a_gap():
    results = {"sources": {"crt.sh": {}, "crt.sh database": {}},
               "errors": {"certspotter": "rate limited"}}
    assert baseline_gaps(results) == ["certspotter"]


def test_hosts_file_keeps_only_the_targets_hostnames(tmp_path):
    from monomi import read_hosts_file
    f = tmp_path / "hosts.txt"
    # "lab" stands in for the domain: dotless, so the chat app doesn't link it
    f.write_text("# known hosts\nOLDAPP.lab\n\nlab\nvpn.lab.   # trailing dot is fine\n"
                 "other\nevil.otherlab\nbad host.lab\nvpn.lab\n")
    hosts, skipped = read_hosts_file(str(f), "lab")
    assert hosts == ["lab", "oldapp.lab", "vpn.lab"]
    assert skipped == ["other: not part of lab", "evil.otherlab: not part of lab",
                       "bad host.lab: not a hostname"]


def test_hosts_file_is_capped(tmp_path):
    from monomi import MAX_HOSTS_FILE, read_hosts_file
    f = tmp_path / "hosts.txt"
    f.write_text("\n".join(f"h{i}.lab" for i in range(MAX_HOSTS_FILE + 5)))
    hosts, skipped = read_hosts_file(str(f), "lab")
    assert len(hosts) == MAX_HOSTS_FILE
    assert skipped == [f"5 more hostnames: over the {MAX_HOSTS_FILE} limit"]


def test_crtsh_database_answering_zero_means_behind():
    # The 41xlab case: crt.sh's own database has nothing, so crt.sh is behind, not broken
    results = {"sources": {"crt.sh": _ct("crt.sh", 0), "crt.sh database": _ct("crt.sh database", 0),
                           "certspotter": _ct("certspotter", 3)},
               "errors": {}}
    flag_silent_crtsh_failure(results)
    assert list(results["sources"]) == ["certspotter"]
    for name in ("crt.sh", "crt.sh database"):
        assert "may not have indexed them" in results["errors"][name]
        assert "Cert Spotter found 3" in results["errors"][name]  # display name, not the key
    assert baseline_gaps(results) == ["crt.sh", "crt.sh database"]  # still a gap: no baseline


def test_empty_website_with_failed_database_is_still_silent_failure():
    # The database didn't answer, so the website's empty reply can't be trusted
    results = {"sources": {"crt.sh": _ct("crt.sh", 0), "certspotter": _ct("certspotter", 3)},
               "errors": {"crt.sh database": "connection timeout"}}
    flag_silent_crtsh_failure(results)
    assert "likely failed silently" in results["errors"]["crt.sh"]


# --- gap_reason(): the history warning says "behind", not "failed", when crt.sh is behind ---

def test_gap_reason_all_behind():
    results = {"sources": {"crt.sh": _ct("crt.sh", 0), "crt.sh database": _ct("crt.sh database", 0),
                           "certspotter": _ct("certspotter", 3)},
               "errors": {}}
    flag_silent_crtsh_failure(results)
    gaps = baseline_gaps(results)
    assert gap_reason(results, gaps) == "crt.sh, crt.sh database are behind on the CT logs"


def test_gap_reason_failed():
    results = {"errors": {"certspotter": "429 rate limited"}}
    assert gap_reason(results, ["certspotter"]) == "certspotter failed"


def test_gap_reason_failed_and_behind():
    results = {"errors": {"certspotter": "429 rate limited",
                          "crt.sh": "no certificates for this domain yet: the crt.sh database answered with 0"}}
    assert gap_reason(results, ["certspotter", "crt.sh"]) == \
        "certspotter failed and crt.sh is behind on the CT logs"


# ---------- --exposed-files (ACTIVE) ----------

def test_exposed_files_flag_parses():
    args = monomi.build_parser().parse_args(["example.com", "--exposed-files"])
    assert args.exposed_files is True


def test_exposed_files_turns_on_enrich():
    # mirror main()'s dependency: --exposed-files needs resolved hosts
    args = monomi.build_parser().parse_args(["example.com", "--exposed-files"])
    assert args.enrich is False
    if args.exposed_files and not args.enrich:
        args.enrich = True
    assert args.enrich is True


def test_run_exposed_stores_results_and_summarizes(monkeypatch, capsys):
    spec = {"type": "OpenAPI", "version": "3.0.1",
            "url": "https://staging/openapi.json", "endpoint_count": 3,
            "method_count": 4, "servers": ["https://internal/"], "declares_auth": True}
    smap = {"map_url": "https://app/a.js.map", "source_count": 2,
            "sources": [], "has_source_content": True}
    hosts = {
        "staging": {"spec": spec, "source_maps": [], "collected_at": "t"},
        "app": {"spec": None, "source_maps": [smap], "collected_at": "t"},
    }
    finding = {"hosts": hosts, "requested": ["staging", "app"],
               "checked": 2, "requests": 10, "skipped": 0}
    monkeypatch.setattr(monomi.exposed, "check_all", lambda enrichment: finding)
    results = {}
    monomi.run_exposed(results, {"hosts": {}})
    assert results["exposed_files"] is finding
    out = capsys.readouterr().out
    assert "OpenAPI spec" in out and "source map" in out
    assert "source code" in out  # the embedded-code flag is shown
    assert "1 API spec(s) and 1 source map(s)" in out


def test_run_exposed_clean_says_nothing_found(monkeypatch, capsys):
    empty = {"hosts": {}, "requested": ["a"], "checked": 1, "requests": 7, "skipped": 0}
    monkeypatch.setattr(monomi.exposed, "check_all", lambda enrichment: empty)
    results = {}
    monomi.run_exposed(results, {"hosts": {}})
    assert "No exposed API specs or source maps" in capsys.readouterr().out
