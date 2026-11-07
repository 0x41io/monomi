"""Tests for the MCP server's tool wrappers. No network: the checks
the tools call are swapped for fakes with monkeypatch."""
import json

import pytest

import mcp_server


@pytest.fixture(autouse=True)
def results_dir(tmp_path, monkeypatch):
    """Every test saves its full results in a temp folder, not the real scans/."""
    monkeypatch.setattr(mcp_server, "RESULTS_DIR", str(tmp_path))
    return tmp_path


def test_clean_hosts_normalizes_and_dedupes():
    hosts, skipped, _ = mcp_server.clean_hosts(
        [" WWW.Example.com ", "www.example.com.", "", "api.example.com"]
    )
    assert hosts == ["api.example.com", "www.example.com"]
    assert skipped == 0


def test_clean_hosts_keeps_www():
    hosts, _, _ = mcp_server.clean_hosts(["example.com", "www.example.com"])
    assert hosts == ["example.com", "www.example.com"]


def test_clean_hosts_caps_and_counts_skipped():
    names = [f"h{i}.example.com" for i in range(150)]
    hosts, skipped, _ = mcp_server.clean_hosts(names, limit=100)
    assert len(hosts) == 100
    assert skipped == 50


def test_check_takeover_uses_cleaned_hosts(monkeypatch):
    seen = {}

    def fake_check_hosts(hosts, domain=None):
        seen["hosts"] = hosts
        seen["domain"] = domain
        return {"leads": [], "checked": len(hosts), "errors": {}}

    monkeypatch.setattr(mcp_server, "check_hosts", fake_check_hosts)
    result = mcp_server.check_takeover(["WWW.example.com", "www.example.com"], domain="Example.com.")
    assert seen["hosts"] == ["www.example.com"]
    assert seen["domain"] == "example.com"
    assert result["hosts_checked"] == 1
    assert result["hosts_skipped"] == 0
    assert "checked" not in result  # the duplicate of hosts_checked is gone


def test_check_ports_uses_smaller_cap(monkeypatch):
    monkeypatch.setattr(mcp_server, "enrich", lambda hosts: {"hosts": hosts})
    monkeypatch.setattr(mcp_server.internetdb, "lookup", lambda enrichment: {
        "ips": {}, "checked": 0, "errors": 0, "skipped": 0})
    names = [f"h{i}.example.com" for i in range(150)]
    result = mcp_server.check_ports(names)
    assert result["hosts_checked"] == mcp_server.MAX_PORT_HOSTS
    assert result["hosts_skipped"] == 150 - mcp_server.MAX_PORT_HOSTS

def test_check_ports_renames_ip_counts(monkeypatch):
    monkeypatch.setattr(mcp_server, "enrich", lambda hosts: {"hosts": hosts})
    monkeypatch.setattr(mcp_server.internetdb, "lookup", lambda enrichment: {
        "ips": {}, "checked": 2, "errors": 1, "skipped": 0})
    result = mcp_server.check_ports(["a.example.com"])
    assert result["ips_checked"] == 2
    assert result["ip_errors"] == 1
    assert result["ips_skipped"] == 0
    for old in ("checked", "errors", "skipped"):
        assert old not in result

def test_check_ports_summary_counts(monkeypatch):
    monkeypatch.setattr(mcp_server, "enrich", lambda hosts: {
        "hosts": hosts, "resolved": 3,
        "not_resolving": {"no_such_host": ["x.example.com"],
                          "no_address": ["y.example.com", "z.example.com"]}})
    monkeypatch.setattr(mcp_server.internetdb, "lookup", lambda enrichment: {
        "ips": {"1.1.1.1": {"shared_edge": True}, "2.2.2.2": {"shared_edge": False}},
        "nothing_seen": {"3.3.3.3": {"shared_edge": False}},
        "checked": 4, "errors": 1, "skipped": 0,
        "unique_cves": ["CVE-2024-0001"], "risky": [("2.2.2.2", ["22/ssh"])]})
    result = mcp_server.check_ports(["a.example.com"], detail="full")
    assert list(result)[0] == "summary"  # agents read it first
    assert result["summary"] == {
        "hosts_resolved": 3, "hosts_not_resolving": 3,
        "edge_ips": 1, "origin_ips": 2, "ips_nothing_seen": 1,
        "origin_cves": 1, "origin_ips_with_risky_ports": 1,
    }
    assert result["not_resolving"]["no_address"] == ["y.example.com", "z.example.com"]


def fake_investigate(ip):
    """A boring investigate() result, so no test touches the network."""
    return {"ip": ip, "collected_at": "2026-10-31T16:00:00+00:00", "tor_exit": False,
            "network": None, "rdns": None, "shodan": None, "errors": {}, "labels": []}


def test_investigate_ip_cleans_rejects_and_dedupes(monkeypatch):
    monkeypatch.setattr(mcp_server.threatintel, "investigate", fake_investigate)
    result = mcp_server.investigate_ip([" 8.8.8.8 ", "8.8.8.8", "192.168.1.1", "junk"])
    assert list(result["ips"]) == ["8.8.8.8"]
    assert result["rejected"] == [
        {"ip": "192.168.1.1", "reason": "private (internal network)"},
        {"ip": "junk", "reason": "not an IP address"},
    ]
    assert result["ips_checked"] == 1
    assert result["evidence"][0]["id"] == "E1"


def test_investigate_ip_caps_and_counts_skipped(monkeypatch):
    monkeypatch.setattr(mcp_server.threatintel, "investigate", fake_investigate)
    ips = [f"8.8.8.{i}" for i in range(1, 16)]
    result = mcp_server.investigate_ip(ips)
    assert result["ips_checked"] == mcp_server.MAX_IPS
    assert result["ips_skipped"] == 15 - mcp_server.MAX_IPS

def test_clean_hosts_rejects_junk_with_reasons():
    import mcp_server
    link = "[dev.lab.test](https:" + "//dev.lab.test)"
    url = "https:" + "//app.lab.test/login"
    hosts, skipped, rejected = mcp_server.clean_hosts(
        ["Dev.Lab.test.", "dev.lab.test", link, url, "*.lab.test",
         "bad..lab.test", "-x.lab.test", "_dmarc.lab.test", "   "])

    assert hosts == ["_dmarc.lab.test", "dev.lab.test"]   # cleaned, deduped, sorted
    assert skipped == 0
    reasons = {r["host"]: r["reason"] for r in rejected}
    assert "Markdown link" in reasons[link]
    assert "URL" in reasons[url]
    assert "wildcard" in reasons["*.lab.test"]
    assert "not a valid hostname" in reasons["bad..lab.test"]
    assert "not a valid hostname" in reasons["-x.lab.test"]
    assert len(rejected) == 5


def test_clean_hosts_caps_rejected_list():
    import mcp_server
    _, _, rejected = mcp_server.clean_hosts([f"bad{i}..test" for i in range(50)])
    assert len(rejected) == 20

def test_check_takeover_adds_owners(monkeypatch):
    monkeypatch.setattr(mcp_server, "check_hosts", lambda hosts, domain=None: {
        "leads": [{"host": "a", "claimable": True}, {"host": "b", "claimable": False}],
        "stale": [{"host": "c"}], "results": {}, "checked": 3, "errors": {}})
    result = mcp_server.check_takeover(["a", "b", "c"])
    assert result["leads"][0]["owners"] == ["DNS admin", "cloud / service account owner"]
    assert result["leads"][1]["owners"] == ["DNS admin"]
    assert result["stale"][0]["owners"] == ["DNS admin"]


def test_enrich_hosts_owners_only_on_problems(monkeypatch):
    monkeypatch.setattr(mcp_server, "enrich", lambda hosts: {"hosts": {
        "dangle": {"ips": [], "dns": "dangling_cname"},
        "inside": {"ips": ["10.0.0.5"], "dns": "live", "private_ips": ["10.0.0.5"]},
        "fine": {"ips": ["8.8.8.8"], "dns": "live", "private_ips": []}}})
    hosts = mcp_server.enrich_hosts(["dangle", "inside", "fine"], detail="full")["hosts"]
    assert hosts["dangle"]["owners"] == ["DNS admin"]
    assert hosts["inside"]["owners"] == ["DNS admin"]
    assert "owners" not in hosts["fine"]


def test_check_ports_owners_skip_edge_ips(monkeypatch):
    monkeypatch.setattr(mcp_server, "enrich", lambda hosts: {"hosts": {}})
    monkeypatch.setattr(mcp_server.internetdb, "lookup", lambda enrichment: {
        "ips": {"1.1.1.1": {"shared_edge": True}, "8.8.8.8": {"shared_edge": False}},
        "checked": 2, "errors": 0, "skipped": 0})
    ips = mcp_server.check_ports(["a"], detail="full")["ips"]
    assert ips["8.8.8.8"]["owners"] == ["server / infrastructure admin"]
    assert "owners" not in ips["1.1.1.1"]


def test_check_email_auth_adds_owners(monkeypatch):
    monkeypatch.setattr(mcp_server, "clean_domain", lambda d: d)
    monkeypatch.setattr(mcp_server, "check_email", lambda domain: {"verdict": {}})
    result = mcp_server.check_email_auth("examplecom")
    assert result["owners"] == ["DNS admin", "email admin"]


# --- Summary mode (v1.9) ---

def test_takeover_summary_counts_and_keeps_leads(monkeypatch):
    monkeypatch.setattr(mcp_server, "check_hosts", lambda hosts, domain=None: {
        "leads": [{"host": "a", "claimable": True}],
        "stale": [{"host": "b"}],
        "results": {"a": {"status": "lead"}, "b": {"status": "stale"},
                    "c": {"status": "no_such_host"}, "d": {"status": "no_such_host"},
                    "e": {"status": "error"}},
        "checked": 5, "errors": {"e": "timeout"}})
    result = mcp_server.check_takeover(["a"])
    assert result["detail"] == "summary"
    assert "results" not in result          # the per-host list stays in the file
    assert result["status_counts"]["no_such_host"] == 2
    assert result["leads"][0]["owners"] == ["DNS admin", "cloud / service account owner"]
    assert result["stale"][0]["owners"] == ["DNS admin"]
    assert result["unknown_hosts"] == ["e"]
    with open(result["full_results_file"]) as f:   # the file has everything
        assert len(json.load(f)["results"]) == 5


def test_full_detail_still_returns_everything(monkeypatch):
    monkeypatch.setattr(mcp_server, "check_hosts", lambda hosts, domain=None: {
        "leads": [], "stale": [], "results": {"a": {"status": "no_cname"}},
        "checked": 1, "errors": {}})
    result = mcp_server.check_takeover(["a"], detail="full")
    assert "detail" not in result
    assert result["results"]["a"]["status"] == "no_cname"
    assert result["full_results_file"].endswith("_check_takeover.json")


def test_enrich_summary_caps_private_hosts(monkeypatch):
    hosts = {f"h{i:03}": {"ips": ["10.0.0.1"], "dns": "live", "private_ips": ["10.0.0.1"]}
             for i in range(50)}
    hosts["dangle"] = {"ips": [], "dns": "dangling_cname", "cname": "gone"}
    monkeypatch.setattr(mcp_server, "enrich", lambda h: {
        "hosts": hosts, "private_ip_hosts": [h for h in hosts if h != "dangle"],
        "resolved": 50, "unique_ips": 1, "providers": {"PRIVATE IP": 50},
        "not_resolving": {"dangling_cname": ["dangle"]}})
    result = mcp_server.enrich_hosts(["a"])
    assert "hosts" not in result and "ip_info" not in result
    assert result["private_ip_host_count"] == 50
    assert len(result["private_ip_hosts"]) == mcp_server.LIST_CAP
    assert result["dangling_cnames"] == {"dangle": {"cname": "gone", "owners": ["DNS admin"]}}
    assert result["not_resolving_counts"] == {"dangling_cname": 1}


def test_ports_summary_counts_edge_and_keeps_origin(monkeypatch):
    monkeypatch.setattr(mcp_server, "enrich", lambda h: {"hosts": {}, "resolved": 30,
                                                         "not_resolving": {}})
    edge = {f"104.16.0.{i}": {"shared_edge": True, "provider": "Cloudflare", "hosts": ["w"]}
            for i in range(5)}
    origin = {"shared_edge": False, "provider": "DigitalOcean",
              "hosts": [f"h{i}" for i in range(30)], "ports": [22]}
    monkeypatch.setattr(mcp_server.internetdb, "lookup", lambda e: {
        "ips": {**edge, "64.227.89.72": origin},
        "nothing_seen": {"5.5.5.5": {"shared_edge": False, "provider": "OVH", "hosts": ["x"]}},
        "checked": 7, "errors": 0, "skipped": 0})
    result = mcp_server.check_ports(["a"])
    assert "ips" not in result
    assert result["edge_ips_by_provider"] == {"Cloudflare": 5}
    ip = result["origin_ips"]["64.227.89.72"]
    assert ip["owners"] == ["server / infrastructure admin"]
    assert ip["host_count"] == 30 and len(ip["hosts"]) == mcp_server.LIST_CAP
    assert list(result["origin_ips_nothing_seen"]) == ["5.5.5.5"]


def test_subdomains_summary_counts_categories():
    full = {"domain": "lab", "hostname_count": 3, "wildcards": [], "sources": {},
            "errors": {}, "hostnames": ["dev", "www", "lab"],
            "categories": {"dev": {"category": "non-production"},
                           "www": {"category": "content"},
                           "lab": {"category": "apex"}}}
    s = mcp_server.subdomains_summary(full)
    assert "hostnames" not in s and "categories" not in s
    assert s["category_counts"] == {"non-production": 1, "content": 1, "apex": 1}
    assert s["risky_categories"] == {"non-production": {"count": 1, "hosts": ["dev"]}}
