"""Tests for the MCP server's tool wrappers. No network: the checks
the tools call are swapped for fakes with monkeypatch."""
import asyncio
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
    assert list(result)[:2] == ["detail", "summary"]  # agents read these first
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
    assert result["detail"] == "full"
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
    assert list(result["nothing_seen"]) == ["5.5.5.5"]


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


# --- hosts_file + batches (v1.9) ---

def scans_dir(monkeypatch, tmp_path):
    """Point SCANS_DIR at a temp folder and return it."""
    folder = tmp_path / "scans"
    folder.mkdir()
    monkeypatch.setattr(mcp_server, "SCANS_DIR", str(folder))
    return folder


def test_hosts_file_reads_find_subdomains_json(monkeypatch, tmp_path):
    folder = scans_dir(monkeypatch, tmp_path)
    (folder / "subs.json").write_text(json.dumps({"hostnames": ["b", "a"]}))
    assert mcp_server.load_hosts_file(str(folder / "subs.json")) == ["b", "a"]


def test_hosts_file_reads_txt_and_drops_comments(monkeypatch, tmp_path):
    folder = scans_dir(monkeypatch, tmp_path)
    (folder / "hosts.txt").write_text("a\n# a comment\nb  # old box\n")
    hosts, _, _, _ = mcp_server.pick_hosts(None, "hosts.txt", 0, 200)  # relative = inside scans/
    assert hosts == ["a", "b"]


def test_hosts_file_outside_scans_is_refused(monkeypatch, tmp_path):
    folder = scans_dir(monkeypatch, tmp_path)
    secret = tmp_path / "bashrc.txt"
    secret.write_text("export ANTHROPIC_API_KEY=sk-ant-secret\n")
    for path in (str(secret), "../bashrc.txt"):
        with pytest.raises(mcp_server.ToolError, match="scans folder"):
            mcp_server.load_hosts_file(path)


def test_hosts_file_symlink_out_of_scans_is_refused(monkeypatch, tmp_path):
    folder = scans_dir(monkeypatch, tmp_path)
    secret = tmp_path / "secret.txt"
    secret.write_text("sk-ant-secret\n")
    try:
        (folder / "link.txt").symlink_to(secret)
    except OSError:  # Windows only allows symlinks with admin rights or Developer Mode
        pytest.skip("this system doesn't allow creating symlinks")
    with pytest.raises(mcp_server.ToolError, match="scans folder"):
        mcp_server.load_hosts_file("link.txt")


def test_hosts_file_wrong_type_or_shape_is_refused(monkeypatch, tmp_path):
    folder = scans_dir(monkeypatch, tmp_path)
    (folder / "notes.md").write_text("a\n")
    (folder / "other.json").write_text(json.dumps({"leads": []}))
    with pytest.raises(mcp_server.ToolError, match=".json or .txt"):
        mcp_server.load_hosts_file("notes.md")
    with pytest.raises(mcp_server.ToolError, match="hostnames"):
        mcp_server.load_hosts_file("other.json")
    with pytest.raises(mcp_server.ToolError, match="not found"):
        mcp_server.load_hosts_file("missing.txt")


def test_pick_hosts_needs_exactly_one_input():
    with pytest.raises(mcp_server.ToolError, match="either hostnames or hosts_file"):
        mcp_server.pick_hosts(None, None, 0, 200)
    with pytest.raises(mcp_server.ToolError, match="either hostnames or hosts_file"):
        mcp_server.pick_hosts(["a"], "hosts.txt", 0, 200)


def test_refused_hosts_file_reason_reaches_the_client():
    # Only a ToolError's message gets through MCP; any other error shows
    # just "Error executing tool", so the agent can't tell what went wrong.
    with pytest.raises(mcp_server.ToolError, match="scans folder"):
        asyncio.run(mcp_server.mcp.call_tool(
            "check_takeover", {"hosts_file": "../../hosts.txt"}))


def test_pick_hosts_batches_with_next_start():
    names = [f"h{i:03d}" for i in range(250)]
    first_batch, left, _, info = mcp_server.pick_hosts(names, None, 0, 200)
    assert len(first_batch) == 200 and left == 50
    assert info == {"start": 0, "size": 200, "total": 250, "next_start": 200}
    last_batch, left, _, info = mcp_server.pick_hosts(names, None, 200, 200)
    assert last_batch[0] == "h200" and len(last_batch) == 50 and left == 0
    assert info["next_start"] is None


def test_check_takeover_from_hosts_file(monkeypatch, tmp_path):
    folder = scans_dir(monkeypatch, tmp_path)
    (folder / "subs.json").write_text(json.dumps({"hostnames": ["a", "bad host"]}))
    seen = {}

    def fake_check(hosts, domain=None):
        seen["hosts"] = hosts
        return {"leads": [], "stale": [], "results": {}, "checked": len(hosts), "errors": {}}
    monkeypatch.setattr(mcp_server, "check_hosts", fake_check)
    result = mcp_server.check_takeover(hosts_file="subs.json")
    assert seen["hosts"] == ["a"]
    assert result["rejected"][0]["host"] == "bad host"
    assert result["batch"]["next_start"] is None

def test_find_subdomains_includes_next_checks(monkeypatch):
    """find_subdomains attaches next_checks; enrich is suggested when hosts exist."""
    def fake_collect(results, domain, **kwargs):
        results["sources"] = {"crtsh": {"subdomains": ["app", "www"], "subdomain_count": 2,
                                         "collected_at": "2026-01-01T00:00:00Z"}}
        results["errors"] = {}
    monkeypatch.setattr(mcp_server, "collect_ct", fake_collect)
    monkeypatch.setattr(mcp_server, "categorize_all", lambda hosts, domain: {})
    result = mcp_server.find_subdomains("lab.invalid", detail="summary")
    assert "next_checks" in result
    flags = [c["flag"] for c in result["next_checks"]]
    assert "--enrich" in flags
    assert "--email" in flags
    full = mcp_server.find_subdomains("lab.invalid", detail="full")
    assert full["next_checks"] == result["next_checks"]


def test_enrich_hosts_suppresses_enrich_suggests_ports(monkeypatch):
    """After enrich, --enrich is gone and --ports appears when own IPs exist."""
    def fake_enrich(hosts):
        return {
            "hosts": {"app": {"ips": ["192.0.2.10"], "provider": "Example", "private_ips": []}},
            "providers": {"Example": 1},
            "resolved": 1,
            "unique_ips": 1,
            "not_resolving": {},
            "private_ip_hosts": [],
        }
    monkeypatch.setattr(mcp_server, "enrich", fake_enrich)
    monkeypatch.setattr(mcp_server, "owners", lambda *a: ["dns"])
    result = mcp_server.enrich_hosts(["app.lab"], detail="summary")
    flags = [c["flag"] for c in result["next_checks"]]
    assert "--enrich" not in flags
    assert "--ports" in flags


def test_check_ports_suppresses_ports(monkeypatch):
    """After check_ports, --ports is not re-suggested."""
    def fake_enrich(hosts):
        return {"hosts": {"app": {"ips": ["192.0.2.10"], "provider": "Example", "private_ips": []}},
                "not_resolving": {}}
    def fake_lookup(enr):
        return {"ips": {"192.0.2.10": {"shared_edge": False, "vulns": [], "hosts": ["app.lab"],
                                       "ports": [443], "risky": [], "provider": "Example"}},
                "nothing_seen": {}, "checked": 1, "errors": 0, "skipped": 0,
                "unique_cves": [], "risky": []}
    monkeypatch.setattr(mcp_server, "enrich", fake_enrich)
    monkeypatch.setattr(mcp_server.internetdb, "lookup", fake_lookup)
    monkeypatch.setattr(mcp_server, "owners", lambda *a: ["server"])
    result = mcp_server.check_ports(["app.lab"], detail="summary")
    flags = [c["flag"] for c in result["next_checks"]]
    assert "--ports" not in flags


def test_check_email_auth_includes_next_checks(monkeypatch):
    def fake_check(domain):
        return {"verdict": "ok", "spf": {}, "dmarc": {}, "dkim": {}}
    monkeypatch.setattr(mcp_server, "check_email", fake_check)
    monkeypatch.setattr(mcp_server, "owners", lambda *a: ["dns", "email"])
    result = mcp_server.check_email_auth("lab.invalid")
    assert "next_checks" in result
    flags = [c["flag"] for c in result["next_checks"]]
    assert "--email" not in flags
