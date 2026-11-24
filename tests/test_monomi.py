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


def test_run_exposed_clean_says_what_each_host_was_checked_for(monkeypatch, capsys):
    # v1.23
    cov = {"spec_paths": {"tried": 6, "answered": 6}, "homepage": 200, "scripts_and_maps": 2, "requests": 9}
    empty = {"hosts": {}, "requested": ["a"], "checked": 1, "requests": 9, "skipped": 0,
             "coverage": {"a": cov}}
    monkeypatch.setattr(cli.exposed, "check_all", lambda enrichment, **kwargs: empty)
    cli.run_exposed({}, {"hosts": {}}, cli.scope.UNSCOPED_CLI)
    out = capsys.readouterr().out
    assert "a  checked: 6/6 spec paths answered, homepage 200, 2 script(s) and map(s)" in out


def test_run_exposed_says_which_scheme_each_host_answered_on(monkeypatch, capsys):
    # v1.24: a host checked over plain HTTP, and one that answered neither
    cov = {"dev": {"spec_paths": {"tried": 6, "answered": 6}, "homepage": 200, "scheme": "http",
                   "https_error": "SSLError", "scripts_and_maps": 0, "requests": 8},
           "down": {"spec_paths": {"tried": 0, "answered": 0}, "homepage": "no answer", "scheme": None,
                    "https_error": "ConnectionError", "scripts_and_maps": 0, "requests": 2}}
    empty = {"hosts": {}, "requested": ["dev", "down"], "checked": 2, "requests": 10, "skipped": 0,
             "coverage": cov}
    monkeypatch.setattr(cli.exposed, "check_all", lambda enrichment, **kwargs: empty)
    cli.run_exposed({}, {"hosts": {}}, cli.scope.UNSCOPED_CLI)
    out = capsys.readouterr().out
    assert "dev  checked over plain HTTP (HTTPS failed: SSLError): 6/6 spec paths answered" in out
    assert "down  checked: homepage no answer over HTTPS or plain HTTP, so nothing else was sent" in out


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


def test_saved_scan_starts_with_the_monomi_version(tmp_path, capsys):
    import json
    from monomi.common import VERSION
    results = {"target": "lab", "subdomains": ["lab"], "monomi_version": "0.0.1"}
    path = tmp_path / "scan.json"
    cli.save_json(results, str(path))
    saved = json.loads(path.read_text())
    assert list(saved)[0] == "monomi_version" and saved["monomi_version"] == VERSION
    assert saved["target"] == "lab" and saved["subdomains"] == ["lab"]
    assert results["monomi_version"] == "0.0.1"  # the results in memory aren't changed


# --- v1.18: go-around-the-CDN leads grouped when printed ---

def _cdn_lead(lid, ip, direct, fronted=("a.example.test", "b.example.test"), notes=()):
    return {"id": lid, "rule": "around_cdn", "title": f"Check whether ... through {ip}",
            "steps": [], "missing": "m",
            "gate": {"passed": 5, "of": 6, "failed": [{"check": 5, "name": "observed way in"}],
                     "notes": list(notes)},
            "targets": {"hosts": list(direct), "ips": [ip], "fronted": list(fronted), "cdn": "AWS CloudFront"}}


def test_lead_groups_put_cdn_leads_together_where_the_first_was():
    side = {"id": "L1", "rule": "side_door", "targets": {"hosts": ["x"], "ips": ["9.9.9.9"]}}
    l2, l3, l4 = _cdn_lead("L2", "9.9.9.1", ["p1"]), _cdn_lead("L3", "9.9.9.2", ["p2"]), _cdn_lead("L4", "9.9.9.3", ["p3"])
    other_front = _cdn_lead("L5", "9.9.9.4", ["p4"], fronted=("c.example.test",))
    groups = cli.lead_groups([side, l2, l3, l4, other_front])
    assert [[p["id"] for p in g] for g in groups] == [["L1"], ["L2", "L3", "L4"], ["L5"]]


def test_id_span():
    assert cli.id_span(["L2", "L3", "L4"]) == "L2-L4"
    assert cli.id_span(["L1", "L3"]) == "L1, L3"


def test_cdn_group_prints_hosts_once_and_one_line_per_server(capsys):
    group = [_cdn_lead("L1", "9.9.9.1", ["andre.prd-pub.example.test"]),
             _cdn_lead("L2", "9.9.9.2", ["forms.example.test"], notes=["non-production note"])]
    cli.show_cdn_group(group)
    out = capsys.readouterr().out
    assert "L1-L2  LEADS  Check whether 2 hosts behind AWS CloudFront can be reached around it through one of 2 servers" in out
    assert out.count("a.example.test and b.example.test") == 2   # the Observed line and the Missing line
    assert "L1  9.9.9.1" in out and "<- andre.prd-pub.example.test" in out
    assert "L2  9.9.9.2" in out and "non-production note" in out


def test_show_paths_groups_cdn_leads_and_keeps_others(capsys):
    side = {"id": "L1", "rule": "side_door", "title": "Side door title", "steps": [],
            "missing": "m", "gate": {}, "targets": {"hosts": [], "ips": []}}
    built = {"paths": [], "leads": [side, _cdn_lead("L2", "9.9.9.1", ["p1"]), _cdn_lead("L3", "9.9.9.2", ["p2"])],
             "fix_first": None, "more": 0, "more_leads": 0, "set_aside": []}
    cli.show_paths({"enrichment": {}, "paths": built})
    out = capsys.readouterr().out
    assert "L1  LEAD  Side door title" in out
    assert "L2-L3  LEADS" in out
    assert "through 9.9.9.1" not in out          # the per-server titles are folded into the block


def _takeover_report():
    return {"leads": [], "stale": [], "errors": {}, "checked": 3, "ns_delegations": []}


def test_takeover_says_names_under_a_wildcard_cant_be_checked(monkeypatch, capsys):
    monkeypatch.setattr(cli.takeover, "check_hosts", lambda hosts, domain: _takeover_report())
    results = {"target": "example.test", "subdomains": ["a.example.test"],
               "enrichment": {"wildcard_only": {"x.wild.example.test": "wild.example.test",
                                                "y.wild.example.test": "wild.example.test"}}}
    cli.run_takeover(results)
    out = capsys.readouterr().out
    assert "2 name(s) resolve only through a wildcard (*.wild.example.test)" in out
    assert "can't be checked for takeover by DNS alone" in out
    assert results["takeover"]["under_wildcard"] == 2


def test_takeover_without_wildcards_adds_no_note(monkeypatch, capsys):
    monkeypatch.setattr(cli.takeover, "check_hosts", lambda hosts, domain: _takeover_report())
    results = {"target": "example.test", "subdomains": ["a.example.test"],
               "enrichment": {"wildcard_only": {}}}
    cli.run_takeover(results)
    assert "wildcard" not in capsys.readouterr().out
    assert "under_wildcard" not in results["takeover"]


# ---------- --rate and --research on the CLI (v1.19) ----------


def research_file(tmp_path, text="X-Intigriti: x41ok\n"):
    p = tmp_path / "research.txt"
    p.write_text(text)
    return str(p)


def args_for(*argv):
    return cli.build_parser().parse_args(["example.test", *argv])


def test_bad_rate_is_a_usage_error(capsys):
    with pytest.raises(SystemExit):
        args_for("--rate", "0")
    assert "--rate must be more than 0" in capsys.readouterr().err


def test_scoped_run_defaults_to_1_per_second(tmp_path, capsys):
    s = cli.load_cli_scope(lab_file(tmp_path))
    run = cli.load_active_run(args_for("--fingerprint", "--scope", "x"), s)
    assert run.limiter.rate == 1.0
    assert "1/s (the default with --scope" in capsys.readouterr().out


def test_unscoped_run_has_no_limit_unless_asked(capsys):
    assert cli.load_active_run(args_for("--fingerprint"), cli.scope.UNSCOPED_CLI).limiter.rate is None
    assert cli.load_active_run(args_for("--fingerprint", "--rate", "5"),
                               cli.scope.UNSCOPED_CLI).limiter.rate == 5.0


def test_given_rate_wins_over_the_scoped_default(tmp_path, capsys):
    s = cli.load_cli_scope(lab_file(tmp_path))
    run = cli.load_active_run(args_for("--fingerprint", "--scope", "x", "--rate", "0.5"), s)
    assert run.limiter.rate == 0.5


def test_bad_research_file_stops_before_scanning(monkeypatch, tmp_path, capsys):
    def boom(*a, **k):
        raise AssertionError("scanning started with an unusable --research file")
    monkeypatch.setattr(cli, "collect_ct", boom)
    monkeypatch.setattr(cli.sys, "argv", ["monomi.py", "example.test", "--fingerprint",
                                          "--research", research_file(tmp_path, "not a header\n")])
    assert cli.main() == 1
    assert "--research: line 1" in capsys.readouterr().out


def test_rate_and_research_without_active_checks_say_they_change_nothing(tmp_path, capsys):
    cli.load_active_run(args_for("--rate", "1", "--research", research_file(tmp_path)),
                        cli.scope.UNSCOPED_CLI)
    assert "they change nothing" in capsys.readouterr().out


def test_research_header_and_rate_reach_requests_and_the_log(monkeypatch, tmp_path, capsys, active_log):
    s = cli.load_cli_scope(lab_file(tmp_path))
    headers = []

    class R:
        status_code, headers = 200, {"Server": "nginx"}

        def close(self):
            pass

    def get(url, **kwargs):
        headers.append(kwargs["headers"])
        return R()
    monkeypatch.setattr(cli.fingerprint.requests, "get", get)
    args = args_for("--fingerprint", "--scope", "x", "--rate", "1000",
                    "--research", research_file(tmp_path))
    run = cli.load_active_run(args, s)
    results = {}
    cli.run_fingerprint(results, ENRICHED, s, run)
    assert len(headers) == 2 and all(h["X-Intigriti"] == "x41ok" for h in headers)
    log = [json.loads(x) for x in active_log.read_text().splitlines()]
    sent = [x for x in log if x["event"] == "request"]
    assert len(sent) == 2
    assert all(x["rate"] == 1000 and x["research_sha256"] == run.research.sha256 for x in sent)
    assert results["fingerprint"]["rate"] == 1000
    assert results["fingerprint"]["research_sha256"] == run.research.sha256


def test_one_limiter_is_shared_by_both_active_checks(monkeypatch, tmp_path, active_log):
    seen = []
    monkeypatch.setattr(cli.fingerprint, "fingerprint_all", lambda e, **k: seen.append(k["limiter"]) or
                        {"hosts": {}, "checked": 0, "requests": 0, "errors": {}, "skipped": 0})
    monkeypatch.setattr(cli.exposed, "check_all", lambda e, **k: seen.append(k["limiter"]) or
                        {"hosts": {}, "requested": [], "checked": 0, "requests": 0, "skipped": 0})
    run = cli.load_active_run(args_for("--fingerprint", "--exposed-files", "--rate", "2"),
                              cli.scope.UNSCOPED_CLI)
    cli.run_fingerprint({}, ENRICHED, cli.scope.UNSCOPED_CLI, run)
    cli.run_exposed({}, ENRICHED, cli.scope.UNSCOPED_CLI, run)
    assert seen[0] is seen[1] is run.limiter


# ---------- --extra-hosts (v1.19) ----------


def extra_file(tmp_path, text):
    p = tmp_path / "extra.txt"
    p.write_text(text)
    return str(p)


def test_extra_hosts_keep_other_domains_and_refuse_the_rest(tmp_path):
    path = extra_file(tmp_path, "app.other.test\nBrand.test.\n# note\nwww.example.test\n"
                                "not a host!\napp.other.test\n")
    hosts, refused = cli.read_extra_hosts(path, "example.test", cli.scope.UNSCOPED_CLI)
    assert hosts == ["app.other.test", "brand.test"]
    assert {r["host"]: r["reason"] for r in refused} == {
        "www.example.test": "part of example.test: use --hosts for it",
        "not a host!": "not a hostname"}


def test_extra_hosts_must_be_in_scope_when_there_is_one(tmp_path):
    s = cli.load_cli_scope(lab_file(tmp_path, "*.example.test\napp.other.test\n!old.other.test\n"))
    path = extra_file(tmp_path, "app.other.test\nold.other.test\nbrand.test\n")
    hosts, refused = cli.read_extra_hosts(path, "example.test", s)
    assert hosts == ["app.other.test"]
    reasons = {r["host"]: r["reason"] for r in refused}
    assert set(reasons) == {"old.other.test", "brand.test"}
    assert all(r.startswith("out of scope (") for r in reasons.values())


def test_extra_hosts_domains_are_never_searched(monkeypatch, tmp_path, capsys):
    searched = []

    def collect_ct(results, domain):
        searched.append(domain)
        results["sources"]["certspotter"] = {"source": "certspotter", "subdomains": ["www.example.test"]}
    monkeypatch.setattr(cli, "collect_ct", collect_ct)
    monkeypatch.setattr(cli, "show_changes", lambda results: None)
    saved = {}
    monkeypatch.setattr(cli, "save_json", lambda results, path: saved.update(results))
    monkeypatch.setattr(cli.sys, "argv", ["monomi.py", "example.test", "--json", "x.json",
                                          "--extra-hosts", extra_file(tmp_path, "app.other.test\n")])
    assert cli.main() == 0
    assert searched == ["example.test"]          # only the scanned domain, never other.test
    assert saved["subdomains"] == ["app.other.test", "www.example.test"]
    assert saved["extra_hosts"]["hosts"] == ["app.other.test"]
    assert "1 single host(s) on other domains" in capsys.readouterr().out


def test_extra_hosts_stay_out_of_change_history():
    results = {"sources": {"certspotter": {"source": "certspotter", "subdomains": ["www.example.test"]},
                           cli.EXTRA_HOSTS: {"source": cli.EXTRA_HOSTS, "subdomains": ["app.other.test"]}},
               "errors": {}}
    fresh, partial, notes = cli.history_input(results)
    assert "app.other.test" not in {h for hosts in fresh.values() for h in hosts}


def test_extra_hosts_are_labeled_in_the_enrichment_and_the_table(monkeypatch, capsys):
    monkeypatch.setattr(cli.enrich, "enrich", lambda hosts: {
        "hosts": {h: {"ips": ["8.8.8.8"], "provider": "Google", "country": "US"} for h in hosts},
        "asn_error": None, "resolved": len(hosts), "unique_ips": 1, "providers": {"Google": len(hosts)},
        "private_ip_hosts": []})
    results = {"target": "example.test", "subdomains": ["app.other.test", "www.example.test"],
               "sources": {}, "extra_hosts": {"hosts": ["app.other.test"]}}
    data = cli.run_enrich(results, ports_on=False)
    assert data["hosts"]["app.other.test"]["extra"] is True
    assert "extra" not in data["hosts"]["www.example.test"]
    out = capsys.readouterr().out
    assert "app.other.test [extra]" in out and "www.example.test [extra]" not in out


def test_takeover_judges_an_extra_host_by_its_own_name(monkeypatch, capsys):
    seen = {}

    def check_hosts(hosts, domain, domains=None):
        seen["domain"], seen["domains"] = domain, domains
        return _takeover_report()
    monkeypatch.setattr(cli.takeover, "check_hosts", check_hosts)
    cli.run_takeover({"target": "example.test", "subdomains": ["app.other.test", "www.example.test"],
                      "extra_hosts": {"hosts": ["app.other.test"]}})
    assert seen == {"domain": "example.test", "domains": {"app.other.test": "app.other.test"}}


def test_takeover_same_domain_rule_uses_the_per_host_domain(monkeypatch):
    # a CNAME from an extra host into the scanned domain is NOT "same domain" for it
    calls = []
    monkeypatch.setattr(cli.takeover, "_safe_check",
                        lambda h, d: calls.append((h, d)) or (h, {"status": "live", "cname": None,
                                                                  "lead": None, "stale": None},
                                                              None, None, None))
    cli.takeover.check_hosts(["app.other.test", "www.example.test"], workers=1, domain="example.test",
                             domains={"app.other.test": "app.other.test"})
    assert sorted(calls) == [("app.other.test", "app.other.test"), ("www.example.test", "example.test")]


# ---------- --probe (ACTIVE, v1.25) ----------

class ProbePage:
    """A fake streamed response for --probe."""
    def __init__(self, status=200, headers=None, body=b""):
        self.status_code = status
        self.headers = headers if headers is not None else {"Content-Type": "text/html"}
        self.encoding = "utf-8"
        self._body = body

    def iter_content(self, size):
        yield self._body

    def close(self):
        pass


def fake_probe_web(monkeypatch, pages):
    """pages: {url: ProbePage}. Returns the URLs requested, in order."""
    sent = []

    def get(url, **kwargs):
        sent.append(url)
        if url not in pages:
            raise AssertionError(f"unexpected request to {url}")
        return pages[url]
    monkeypatch.setattr(cli.probe.requests, "get", get)
    return sent


def test_probe_flag_parses_and_counts_as_active():
    args = args_for("--probe")
    assert args.probe is True
    assert cli.any_active(args) is True
    assert cli.any_active(args_for()) is False


def test_probe_turns_on_the_rate_limit(capsys):
    # --rate only takes effect when an active check runs: --probe is one
    run = cli.load_active_run(args_for("--probe", "--rate", "2"), cli.scope.UNSCOPED_CLI)
    assert run.limiter.rate == 2
    assert "change nothing" not in capsys.readouterr().out


def test_rate_without_an_active_check_names_probe(capsys):
    cli.load_active_run(args_for("--rate", "2"), cli.scope.UNSCOPED_CLI)
    assert "--fingerprint, --probe, --exposed-files or --content" in capsys.readouterr().out


def test_run_probe_uses_the_scope_and_logs_every_hop(monkeypatch, tmp_path, capsys, active_log):
    s = cli.load_cli_scope(lab_file(tmp_path))
    sent = fake_probe_web(monkeypatch, {
        "https://www.example.test/": ProbePage(301, {"Location": "/home"}),
        "https://www.example.test/home": ProbePage(body=b"<title>Home</title>"),
        "https://example.test/": ProbePage(body=b"<title>Root</title>"),
    })
    results = {}
    cli.run_probe(results, ENRICHED, s)
    assert sorted(sent) == ["https://example.test/", "https://www.example.test/",
                            "https://www.example.test/home"]
    pr = results["probe"]
    assert [o["host"] for o in pr["out_of_scope"]] == ["dev.example.test", "evil.test"]
    assert pr["requests"] == 3 and pr["hosts"]["www.example.test"]["title"] == "Home"
    log = [json.loads(x) for x in active_log.read_text().splitlines()]
    assert {x["tool"] for x in log} == {"--probe"}
    assert len([x for x in log if x["event"] == "request"]) == 3   # one line per hop
    out = capsys.readouterr().out
    assert "www.example.test  [200]  Home  -> https://www.example.test/home (1 redirect(s))" in out
    assert "2/2 hosts answered, 1 redirected elsewhere. 3 request(s) sent." in out


def test_run_probe_flags_blocked_redirects_and_mislabeled_json(monkeypatch, tmp_path, capsys, active_log):
    s = cli.load_cli_scope(lab_file(tmp_path))
    fake_probe_web(monkeypatch, {
        "https://www.example.test/": ProbePage(302, {"Location": "https://evil.test/"}),
        "https://example.test/": ProbePage(headers={"Content-Type": "text/html"}, body=b'{"ok": 1}'),
    })
    results = {}
    cli.run_probe(results, ENRICHED, s)
    out = capsys.readouterr().out
    assert "redirect leaves scope, not followed: https://evil.test/" in out
    assert "body is JSON but labeled text/html" in out
    assert "1 host(s) had a redirect Monomi refused to follow: www.example.test" in out


def test_run_probe_cleans_target_text_before_printing(monkeypatch, capsys, active_log):
    fake_probe_web(monkeypatch, {f"https://{h}/": ProbePage(body=b"<title>ok</title>")
                                 for h in ENRICHED["hosts"]})
    monkeypatch.setattr(cli.probe, "_title", lambda text: "evil\x1b[2Jtitle")
    cli.run_probe({}, ENRICHED, cli.scope.UNSCOPED_CLI)
    out = capsys.readouterr().out
    assert "\x1b[2J" not in out and "evil?[2Jtitle" in out


def test_probe_carries_research_and_rate_into_results_and_log(monkeypatch, tmp_path, capsys, active_log):
    s = cli.load_cli_scope(lab_file(tmp_path))
    headers = []

    def get(url, **kwargs):
        headers.append(kwargs["headers"])
        return ProbePage(body=b"<title>x</title>")
    monkeypatch.setattr(cli.probe.requests, "get", get)
    run = cli.load_active_run(args_for("--probe", "--scope", "x", "--rate", "1000",
                                       "--research", research_file(tmp_path)), s)
    results = {}
    cli.run_probe(results, ENRICHED, s, run)
    assert len(headers) == 2 and all(h["X-Intigriti"] == "x41ok" for h in headers)
    assert results["probe"]["rate"] == 1000
    assert results["probe"]["research_sha256"] == run.research.sha256
    sent = [json.loads(x) for x in active_log.read_text().splitlines() if '"request"' in x]
    assert all(x["rate"] == 1000 and x["research_sha256"] == run.research.sha256 for x in sent)


def test_one_limiter_is_shared_by_all_three_active_checks(monkeypatch, active_log):
    seen = []
    empty = {"hosts": {}, "checked": 0, "requests": 0, "errors": {}, "skipped": 0}
    monkeypatch.setattr(cli.fingerprint, "fingerprint_all", lambda e, **k: seen.append(k["limiter"]) or dict(empty))
    monkeypatch.setattr(cli.probe, "probe_all", lambda e, **k: seen.append(k["limiter"]) or dict(empty))
    monkeypatch.setattr(cli.exposed, "check_all", lambda e, **k: seen.append(k["limiter"]) or
                        {"hosts": {}, "requested": [], "checked": 0, "requests": 0, "skipped": 0})
    run = cli.load_active_run(args_for("--fingerprint", "--probe", "--exposed-files", "--rate", "2"),
                              cli.scope.UNSCOPED_CLI)
    cli.run_fingerprint({}, ENRICHED, cli.scope.UNSCOPED_CLI, run)
    cli.run_probe({}, ENRICHED, cli.scope.UNSCOPED_CLI, run)
    cli.run_exposed({}, ENRICHED, cli.scope.UNSCOPED_CLI, run)
    assert seen[0] is seen[1] is seen[2] is run.limiter


@pytest.mark.parametrize("page, reason", [
    (ProbePage(headers={"Content-Type": "application/json"}, body=b"{}"), "application/json, not read"),
    (ProbePage(headers={}, body=b""), "no content type, not read"),
    (ProbePage(body=b'{"ok": 1}'), "JSON"),
    (ProbePage(body=b""), "empty page"),
    (ProbePage(body=b"<html><body>hi</body></html>"), "none in the page"),
    (ProbePage(body=b"hello"), "not HTML"),
    (ProbePage(302, {"Location": "https://evil.test/"}), "redirect not followed"),
])
def test_no_title_always_says_why(monkeypatch, tmp_path, capsys, active_log, page, reason):
    # like the lab's notes app: "(no title)" alone left you guessing
    s = cli.load_cli_scope(lab_file(tmp_path, "example.test\n"))
    fake_probe_web(monkeypatch, {"https://example.test/": page})
    cli.run_probe({}, ENRICHED, s)
    assert f"example.test  [{page.status_code}]  (no title: {reason})" in capsys.readouterr().out


def test_probe_progress_line_quotes_the_true_worst_case(monkeypatch, capsys, active_log):
    # v1.25 field run: it said "at most 6 per host", but the HTTP retry can double that
    monkeypatch.setattr(cli.probe, "probe_all", lambda e, **k:
                        {"hosts": {}, "checked": 0, "requests": 0, "errors": {}, "skipped": 0})
    cli.run_probe({}, ENRICHED, cli.scope.UNSCOPED_CLI)
    assert f"at most {cli.probe.MAX_REQUESTS} per host" in capsys.readouterr().out
    from monomi import approvals
    assert cli.probe.MAX_REQUESTS == approvals.TOOLS["probe_hosts"]["max_per_host"] == 12


# --- --content (v1.26) --------------------------------------------------------

class ContentPage:
    def __init__(self, status=404, body=b"<html>nope</html>", headers=None):
        self.status_code, self._body = status, body
        self.headers = headers or {"Content-Type": "text/html"}

    def iter_content(self, size):
        yield self._body

    def close(self):
        pass


def fake_content_web(monkeypatch, pages):
    """pages: {url: ContentPage}; any other URL gets a 404. Returns the URLs sent."""
    from monomi import content
    sent = []

    def get(url, **kwargs):
        assert kwargs["allow_redirects"] is False
        sent.append(url)
        return pages.get(url, ContentPage())
    monkeypatch.setattr(content.requests, "get", get)
    return sent


def test_run_content_stays_in_scope_logs_every_request_and_prints_findings(
        monkeypatch, tmp_path, capsys, active_log):
    s = cli.load_cli_scope(lab_file(tmp_path))
    sent = fake_content_web(monkeypatch, {
        "https://www.example.test/.git/HEAD": ContentPage(200, b"ref: refs/heads/main\n"),
        "https://www.example.test/admin": ContentPage(401, b"", {"WWW-Authenticate": "Basic"}),
    })
    results = {}
    cli.run_content(results, ENRICHED, s)
    cd = results["content"]
    assert {u.split("/")[2] for u in sent} == {"www.example.test", "example.test"}
    assert [o["host"] for o in cd["out_of_scope"]] == ["dev.example.test", "evil.test"]
    log = [json.loads(x) for x in active_log.read_text().splitlines()]
    assert len([x for x in log if x["event"] == "request"]) == len(sent) == cd["requests"]
    assert {x["tool"] for x in log} == {"--content"}
    out = capsys.readouterr().out
    assert "/.git/HEAD: a Git HEAD file (branch main)" in out
    assert "/admin: 401 (Basic login)" in out
    assert "1 exposed file(s) and 1 lead(s) across 2 host(s)." in out


def test_content_turns_on_enrich_and_counts_as_active():
    args = args_for("--content")
    assert cli.any_active(args)


def test_a_bad_wordlist_stops_before_anything_is_scanned(monkeypatch, tmp_path, capsys):
    w = tmp_path / "w.txt"
    w.write_text("admin\n../../etc/passwd\n")
    monkeypatch.setattr(cli, "run_enrich", lambda *a, **k: (_ for _ in ()).throw(AssertionError("scanned")))
    monkeypatch.setattr(cli.sys, "argv", ["monomi.py", "example.test", "--content", "--wordlist", str(w)])
    assert cli.main() == 1
    assert "--wordlist:" in capsys.readouterr().out


def test_a_wordlist_without_content_changes_nothing(monkeypatch, tmp_path, capsys):
    w = tmp_path / "w.txt"
    w.write_text("admin\n")
    args = args_for("--wordlist", str(w))
    assert not cli.any_active(args)
