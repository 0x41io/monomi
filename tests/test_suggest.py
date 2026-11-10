"""Tests for suggest.py: which check to run next, from what a scan found.

Hostnames without dots on purpose (the chat app turns dotted names into links).
"""

import suggest


def scan(**extra):
    """Discovery only: three hostnames, nothing looked up yet."""
    return {"target": "lab", "subdomains": ["lab", "staging", "www"], **extra}


def enriched(**extra):
    """lab + staging on the target's own server, www behind a CDN, old a dangling CNAME."""
    hosts = {
        "lab": {"ips": ["198.51.100.7"], "canonical": None, "dns": "live", "provider": "DigitalOcean"},
        "staging": {"ips": ["198.51.100.7"], "canonical": None, "dns": "live", "provider": "DigitalOcean"},
        "www": {"ips": ["203.0.113.9"], "canonical": None, "dns": "live", "provider": "Cloudflare"},
        "old": {"ips": [], "canonical": None, "dns": "dangling_cname", "provider": None},
    }
    return scan(enrichment={"hosts": hosts}, **extra)


def flags(results, **kw):
    return [c["flag"] for c in suggest.next_checks(results, **kw)]


def test_discovery_only_suggests_looking_the_hosts_up():
    checks = suggest.next_checks(scan())
    assert [c["flag"] for c in checks] == ["--enrich", "--email"]
    assert checks[0]["why"].startswith("3 hostnames were found but not looked up")
    assert checks[0]["mcp_tool"] == "enrich_hosts" and checks[1]["mcp_tool"] == "check_email_auth"


def test_enriched_scan_suggests_from_what_it_found():
    checks = {c["flag"]: c for c in suggest.next_checks(enriched())}
    assert list(checks) == ["--ports", "--takeover", "--fingerprint", "--email"]
    # One own IP (the CDN edge isn't the target's server), one CNAME, two hosts on own servers
    assert checks["--ports"]["why"].startswith("1 IP is a server of the target's own")
    assert checks["--takeover"]["why"].startswith("1 hostname is a CNAME")
    assert checks["--fingerprint"]["why"].startswith("2 hosts sit on the target's own servers")


def test_only_fingerprint_is_marked_active():
    active = [c["flag"] for c in suggest.next_checks(enriched()) if c["active"]]
    assert active == ["--fingerprint"]


def test_a_check_that_ran_is_never_suggested_again():
    done = enriched(exposure={"ips": {}}, takeover={}, fingerprint={"hosts": {}}, email={})
    assert suggest.next_checks(done) == []


def test_no_ports_or_fingerprint_when_everything_is_behind_a_cdn():
    results = enriched()
    for h in ("lab", "staging"):
        results["enrichment"]["hosts"][h] = {"ips": ["203.0.113.9"], "dns": "live", "provider": "Cloudflare"}
    assert flags(results) == ["--takeover", "--email"]


def test_private_ips_are_not_the_targets_public_servers():
    results = enriched()
    for h in ("lab", "staging"):
        results["enrichment"]["hosts"][h] = {"ips": ["10.0.0.5"], "private_ips": ["10.0.0.5"], "dns": "live"}
    assert "--ports" not in flags(results) and "--fingerprint" not in flags(results)


def test_no_takeover_suggestion_without_a_cname():
    results = enriched()
    results["enrichment"]["hosts"].pop("old")
    assert "--takeover" not in flags(results)
    results["enrichment"]["hosts"]["www"]["canonical"] = "site.cdn"  # a live CNAME counts too
    assert "--takeover" in flags(results)


def test_cves_found_suggests_saving_them_once():
    exposure = {"ips": {
        "198.51.100.7": {"shared_edge": False, "vulns": ["CVE-2099-0001", "CVE-2099-0002"]},
        "203.0.113.9": {"shared_edge": True, "vulns": ["CVE-2099-0003"]},  # the CDN's, not the target's
    }}
    results = enriched(exposure=exposure, takeover={}, fingerprint={"hosts": {}}, email={})
    (check,) = suggest.next_checks(results)
    assert check["flag"] == "--cves FILE" and check["why"].startswith("2 known CVEs were found")
    assert suggest.next_checks(results, cves_saved=True) == []


def test_terminal_lists_suggestions_and_saves_them(capsys):
    from monomi import show_next_checks
    results = enriched()
    show_next_checks(results)
    text = capsys.readouterr().out
    assert "Next checks worth running (suggestions only" in text
    assert "--ports        1 IP is a server" in text
    assert "--fingerprint  ACTIVE, sends requests to the target: 2 hosts sit" in text
    assert [c["flag"] for c in results["next_checks"]] == ["--ports", "--takeover", "--fingerprint", "--email"]


def test_terminal_says_nothing_when_there_is_nothing_to_add(capsys):
    from monomi import show_next_checks
    results = enriched(exposure={"ips": {}}, takeover={}, fingerprint={"hosts": {}}, email={})
    show_next_checks(results)
    assert capsys.readouterr().out == ""
    assert results["next_checks"] == []
