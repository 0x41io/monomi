import json

import pytest

from monomi import cli
from monomi.cli import baseline_gaps, clean_domain, collect_ct, flag_silent_crtsh_failure, gap_reason


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
    from monomi import cli
    monkeypatch.setattr(cli.crtsh, "collect", lambda domain, budget, light: _source("crt.sh", 0))
    monkeypatch.setattr(cli.crtsh_db, "collect", lambda domain, budget: _source("crt.sh database", 5))
    monkeypatch.setattr(cli.certspotter, "collect", lambda domain: _source("certspotter", 2))
    results = {"sources": {}, "errors": {}}
    cli.collect_ct(results, "example.com")
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
    from monomi.cli import read_hosts_file
    f = tmp_path / "hosts.txt"
    # "lab" stands in for the domain: dotless, so the chat app doesn't link it
    f.write_text("# known hosts\nOLDAPP.lab\n\nlab\nvpn.lab.   # trailing dot is fine\n"
                 "other\nevil.otherlab\nbad host.lab\nvpn.lab\n")
    hosts, skipped = read_hosts_file(str(f), "lab")
    assert hosts == ["lab", "oldapp.lab", "vpn.lab"]
    assert skipped == ["other: not part of lab", "evil.otherlab: not part of lab",
                       "bad host.lab: not a hostname"]


def test_hosts_file_is_capped(tmp_path):
    from monomi.cli import MAX_HOSTS_FILE, read_hosts_file
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
    args = cli.build_parser().parse_args(["example.com", "--exposed-files"])
    assert args.exposed_files is True


def test_exposed_files_turns_on_enrich():
    # mirror main()'s dependency: --exposed-files needs resolved hosts
    args = cli.build_parser().parse_args(["example.com", "--exposed-files"])
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
    monkeypatch.setattr(cli.exposed, "check_all", lambda enrichment, **kwargs: finding)
    results = {}
    cli.run_exposed(results, {"hosts": {}}, cli.scope.UNSCOPED_CLI)
    assert results["exposed_files"] is finding
    out = capsys.readouterr().out
    assert "OpenAPI spec" in out and "source map" in out
    assert "source code" in out  # the embedded-code flag is shown
    assert "1 API spec(s) and 1 source map(s)" in out


def test_run_exposed_clean_says_nothing_found(monkeypatch, capsys):
    empty = {"hosts": {}, "requested": ["a"], "checked": 1, "requests": 7, "skipped": 0}
    monkeypatch.setattr(cli.exposed, "check_all", lambda enrichment, **kwargs: empty)
    results = {}
    cli.run_exposed(results, {"hosts": {}}, cli.scope.UNSCOPED_CLI)
    assert "No exposed API specs or source maps" in capsys.readouterr().out


# ---------- --scope on the CLI (v1.12) ----------


LAB_SCOPE = "example.test\n*.example.test\n!dev.example.test\n"


def lab_file(tmp_path, text=LAB_SCOPE):
    p = tmp_path / "scope.txt"
    p.write_text(text)
    return str(p)


def fake_fingerprint_web(monkeypatch):
    sent = []

    class R:
        status_code, headers = 200, {"Server": "nginx"}

        def close(self):
            pass

    def get(url, **kwargs):
        sent.append(url)
        return R()
    monkeypatch.setattr(cli.fingerprint.requests, "get", get)
    return sent


ENRICHED = {"hosts": {h: {"ips": ["8.8.8.8"]} for h in
                      ["www.example.test", "dev.example.test", "evil.test", "example.test"]}}


def test_cli_scope_only_lets_in_scope_hosts_through(monkeypatch, tmp_path, capsys, active_log):
    s = cli.load_cli_scope(lab_file(tmp_path))
    sent = fake_fingerprint_web(monkeypatch)
    results = {}
    cli.run_fingerprint(results, ENRICHED, s)
    assert sorted(sent) == ["https://example.test/", "https://www.example.test/"]
    assert [o["host"] for o in results["fingerprint"]["out_of_scope"]] == ["dev.example.test", "evil.test"]
    out = capsys.readouterr().out
    assert "2 host(s) out of scope, no active request sent: dev.example.test, evil.test" in out
    log = [json.loads(x) for x in active_log.read_text().splitlines()]
    assert {x["via"] for x in log} == {"cli"} and {x["tool"] for x in log} == {"--fingerprint"}
    assert sorted(x["host"] for x in log if x["event"] == "refused") == ["dev.example.test", "evil.test"]
    assert all(x["scope_sha256"] == s.sha256 for x in log)


def test_cli_without_scope_still_logs_every_request(monkeypatch, capsys, active_log):
    sent = fake_fingerprint_web(monkeypatch)
    cli.run_fingerprint({}, ENRICHED, cli.scope.UNSCOPED_CLI)
    assert len(sent) == 4
    log = [json.loads(x) for x in active_log.read_text().splitlines()]
    assert len(log) == 4 and all(x["event"] == "request" and x["scope_rule"] is None for x in log)


def test_cli_exposed_files_uses_the_scope_too(monkeypatch, tmp_path, capsys, active_log):
    s = cli.load_cli_scope(lab_file(tmp_path))
    seen = {}

    def check_all(enrichment, **kwargs):
        seen["hosts"], seen["scope"] = sorted(enrichment["hosts"]), kwargs["scope"]
        return {"hosts": {}, "requested": [], "checked": 0, "requests": 0, "skipped": 0}
    monkeypatch.setattr(cli.exposed, "check_all", check_all)
    results = {}
    cli.run_exposed(results, ENRICHED, s)
    assert seen == {"hosts": ["example.test", "www.example.test"], "scope": s}
    assert len(results["exposed_files"]["out_of_scope"]) == 2


@pytest.mark.parametrize("text", ["", "*\n", "!dev.example.test\n"])
def test_unusable_cli_scope_stops_before_scanning(monkeypatch, tmp_path, capsys, text):
    def boom(*a, **k):
        raise AssertionError("scanning started with an unusable --scope")
    monkeypatch.setattr(cli, "collect_ct", boom)
    monkeypatch.setattr(cli.sys, "argv", ["monomi.py", "example.test", "--fingerprint",
                                          "--scope", lab_file(tmp_path, text)])
    assert cli.main() == 1
    assert "Nothing was scanned" in capsys.readouterr().out


def test_missing_cli_scope_stops_before_scanning(monkeypatch, tmp_path, capsys):
    def boom(*a, **k):
        raise AssertionError("scanning started with a missing --scope file")
    monkeypatch.setattr(cli, "collect_ct", boom)
    monkeypatch.setattr(cli.sys, "argv", ["monomi.py", "example.test", "--fingerprint",
                                          "--scope", str(tmp_path / "nope.txt")])
    assert cli.main() == 1
    assert "missing" in capsys.readouterr().out


def test_cli_scope_shows_rejected_lines_and_summary(tmp_path, capsys):
    s = cli.load_cli_scope(lab_file(tmp_path, LAB_SCOPE + "*\n"))
    out = capsys.readouterr().out
    assert s.problem() is None
    assert "--scope line 4 ignored" in out and "2 in, 1 excluded" in out


def test_scope_without_active_checks_warns(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(cli, "collect_ct", lambda results, domain: None)  # no hosts: stops early
    monkeypatch.setattr(cli.sys, "argv", ["monomi.py", "example.test", "--scope", lab_file(tmp_path)])
    cli.main()
    assert "only sets aside attack paths" in capsys.readouterr().out


def test_show_investigation_prints_every_label(capsys):
    """--investigate-ip prints each label with its reason and source; an
    anonymizer is a warning. (Nothing tested this printout before v1.13.)"""
    r = {"ip": "198.51.100.9", "network": {"as_name": "ExampleNet", "asn": "AS64500", "country": "US"},
         "rdns": None, "shodan": None, "errors": {},
         "labels": [{"label": "tor_exit", "reason": "on the Tor exit list", "source": "Tor Project"},
                    {"label": "hosting", "reason": "a hosting network", "source": "Team Cymru"}]}
    cli.show_investigation(r)
    out = capsys.readouterr().out
    assert "TOR_EXIT" in out and "on the Tor exit list" in out and "[Tor Project]" in out
    assert "HOSTING" in out and "[Team Cymru]" in out
