"""Tests for the MCP server's tool wrappers. No network: the checks
the tools call are swapped for fakes with monkeypatch."""
import asyncio
import json
import os

import pytest

from monomi import mcp_server, scope


class AllowAll(scope.Scope):
    """A stand-in approved scope that allows every host, so the older tests
    (which use short dotless names like "app") reach the tool. The scope
    tests at the end of this file use a real scope file instead."""
    def __init__(self):
        super().__init__(path="test-scope.txt", sha256="ab" * 32,
                         rules=[scope.Rule("*.example.test", "example.test", True, False)])

    def match(self, host):
        h = scope.normalize_host(host)
        if h is None:
            return scope.Match(host, False, None, "not a valid hostname")
        return scope.Match(h, True, "(test: allow all)", "allowed by (test: allow all)")


@pytest.fixture(autouse=True)
def results_dir(tmp_path, monkeypatch):
    """Every test saves its full results, the active log and its approvals
    in a temp folder, never the real scans/."""
    monkeypatch.setattr(mcp_server, "RESULTS_DIR", str(tmp_path))
    monkeypatch.setattr(mcp_server, "ACTIVE_LOG", str(tmp_path / "active.log"))
    monkeypatch.setattr(mcp_server.approvals, "approvals_dir", lambda: str(tmp_path / "approvals"))
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
        "hosts_wildcard_only": 0,
        "hosts_resolved": 3, "hosts_not_resolving": 3,
        "edge_ips": 1, "third_party_ips": 0, "origin_ips": 2, "ips_nothing_seen": 1,
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
    from monomi import mcp_server
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
    from monomi import mcp_server
    _, _, rejected = mcp_server.clean_hosts([f"bad{i}..test" for i in range(50)])
    assert len(rejected) == 20


def test_check_takeover_adds_owners(monkeypatch):
    monkeypatch.setattr(mcp_server, "check_hosts", lambda hosts, domain=None: {
        "leads": [{"host": "a", "cname": "gone-a", "claimable": True, "nxdomain_confirmed_by": ["Google"]},
                  {"host": "b", "cname": "gone-b", "claimable": False, "nxdomain_confirmed_by": ["Google"]}],
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
        "leads": [{"host": "a", "cname": "gone-a", "claimable": True, "nxdomain_confirmed_by": ["Google"]}],
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
    assert result["leads_passing_gate"] == 1 and result["leads"][0]["gate"]["result"] == "finding"
    with open(result["full_results_file"]) as f:   # the file has everything
        assert len(json.load(f)["results"]) == 5


def test_takeover_summary_keeps_lame_delegations(monkeypatch):
    # v1.17: a lame NS delegation reaches Claude in the default summary
    monkeypatch.setattr(mcp_server, "check_hosts", lambda hosts, domain=None: {
        "leads": [], "stale": [],
        "results": {"a.dev.x": {"status": "servfail"}, "b.dev.x": {"status": "servfail"}},
        "checked": 2, "errors": {"a.dev.x": "SERVFAIL", "b.dev.x": "SERVFAIL"},
        "ns_delegations": [{"cut": "dev.x", "hosts": ["a.dev.x", "b.dev.x"],
                            "ns_ips": ["205.251.192.127"], "detail": "lame", "collected_at": None,
                            "grade": "theoretical", "provider": "AWS Route 53"}]})
    result = mcp_server.check_takeover(["a.dev.x", "b.dev.x"])
    assert result["detail"] == "summary"
    d = result["ns_delegations"][0]
    assert (d["cut"], d["grade"], d["provider"]) == ("dev.x", "theoretical", "AWS Route 53")
    assert d["owners"] == ["DNS admin"]


def test_takeover_summary_doesnt_count_lame_hosts_as_unknown(monkeypatch):
    # v1.17.1: a lame host's servfail is explained by ns_delegations; only
    # the plain servfail is still unknown
    monkeypatch.setattr(mcp_server, "check_hosts", lambda hosts, domain=None: {
        "leads": [], "stale": [],
        "results": {"a.dev.x": {"status": "servfail"}, "busy.x": {"status": "servfail"}},
        "checked": 2, "errors": {"a.dev.x": "SERVFAIL", "busy.x": "SERVFAIL"},
        "ns_delegations": [{"cut": "dev.x", "hosts": ["a.dev.x"], "ns_ips": ["205.251.192.127"],
                            "detail": "lame", "collected_at": None,
                            "grade": "theoretical", "provider": "AWS Route 53"}]})
    result = mcp_server.check_takeover(["a.dev.x", "busy.x"])
    assert result["unknown_count"] == 1
    assert result["unknown_hosts"] == ["busy.x"]
    assert result["status_counts"] == {"servfail": 2}     # results keep the status word


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


def test_subdomains_summary_lists_management_right_after_access():
    full = {"domain": "lab", "hostname_count": 3, "wildcards": [], "sources": {},
            "errors": {}, "hostnames": ["cp-unifi", "extranet", "www"],
            "categories": {"cp-unifi": {"category": "management"},
                           "extranet": {"category": "access"},
                           "www": {"category": "content"}}}
    s = mcp_server.subdomains_summary(full)
    assert list(s["risky_categories"]) == ["access", "management"]
    assert s["risky_categories"]["management"] == {"count": 1, "hosts": ["cp-unifi"]}


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
    scans_dir(monkeypatch, tmp_path)  # point scans/ at tmp_path; the file below is outside it
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


# --- next_checks ----------------------------------------------------------
# The lab scan's saved results, so the suggestions are tested on real shapes.
GOLDEN = os.path.join(os.path.dirname(__file__), "golden", "fixtures")


def golden(name: str) -> dict:
    """A fresh copy of a golden fixture (each test may change it)."""
    with open(os.path.join(GOLDEN, name)) as f:
        return json.load(f)


def flags(result: dict) -> list[str]:
    return [c["flag"] for c in result["next_checks"]]


def fake_ct(monkeypatch, hosts=("app", "www")):
    def fake_collect(results, domain, **kwargs):
        results["sources"] = {"crtsh": {"subdomains": list(hosts), "subdomain_count": len(hosts),
                                        "collected_at": "2026-01-01T00:00:00Z"}}
        results["errors"] = {}
    monkeypatch.setattr(mcp_server, "collect_ct", fake_collect)
    monkeypatch.setattr(mcp_server, "categorize_all", lambda hosts, domain: {})


def fake_lab(monkeypatch, fixture="41xlab.json"):
    """enrich and Shodan answer with a golden fixture's saved results."""
    scan = golden(fixture)
    monkeypatch.setattr(mcp_server, "enrich", lambda hosts: golden(fixture)["enrichment"])

    def lookup(enr):
        exposure = golden(fixture)["exposure"]
        for key in ("checked", "errors", "skipped"):  # trimmed fixtures may leave the counts out
            exposure.setdefault(key, 0)
        exposure.setdefault("nothing_seen", {})
        return exposure
    monkeypatch.setattr(mcp_server.internetdb, "lookup", lookup)
    monkeypatch.setattr(mcp_server, "check_hosts",
                        lambda hosts, domain=None: golden(fixture)["takeover"])
    monkeypatch.setattr(mcp_server, "check_email",
                        lambda domain: {"verdict": "ok", "spf": {}, "dmarc": {}, "dkim": {}})
    return scan["subdomains"]


def test_tool_names_match_the_real_tools():
    # already_ran is checked against TOOL_NAMES, so it must list every tool.
    real = [t.name for t in asyncio.run(mcp_server.mcp.list_tools())]
    assert sorted(real) == sorted(mcp_server.TOOL_NAMES)


def test_find_subdomains_suggests_enrich_and_email(monkeypatch):
    fake_ct(monkeypatch)
    result = mcp_server.find_subdomains("lab.invalid")
    assert flags(result) == ["--enrich", "--email"]
    assert all(c["cli_only"] is False for c in result["next_checks"])
    assert "already_ran" in result["next_checks_note"]
    full = mcp_server.find_subdomains("lab.invalid", detail="full")
    assert full["next_checks"] == result["next_checks"]


def test_find_subdomains_leaves_out_already_ran(monkeypatch):
    fake_ct(monkeypatch)
    result = mcp_server.find_subdomains("lab.invalid", already_ran=["check_email_auth"])
    assert flags(result) == ["--enrich"]


def test_check_email_auth_suggests_nothing(monkeypatch):
    fake_lab(monkeypatch)
    result = mcp_server.check_email_auth("lab.invalid")
    assert result["next_checks"] == []
    assert "next_checks_note" in result and "next_checks_error" not in result


def test_check_takeover_suggests_nothing_and_passes_the_target(monkeypatch):
    hosts = fake_lab(monkeypatch)
    seen = {}
    real = mcp_server.suggest.next_checks

    def spy(results, *args):
        seen.update(results)
        return real(results, *args)
    monkeypatch.setattr(mcp_server.suggest, "next_checks", spy)
    result = mcp_server.check_takeover(hosts, domain="Lab.Invalid.")
    assert result["next_checks"] == []
    assert seen["target"] == "lab.invalid"


def test_enrich_hosts_suggests_what_its_results_back_up(monkeypatch):
    hosts = fake_lab(monkeypatch)
    result = mcp_server.enrich_hosts(hosts)
    assert flags(result) == ["--ports", "--takeover", "--fingerprint"]  # never --email
    fp = result["next_checks"][2]
    assert fp["mcp_tool"] == "fingerprint_hosts"
    assert fp["cli_only"] is False and fp["active"] is True
    result = mcp_server.enrich_hosts(hosts, already_ran=["check_takeover"])
    assert flags(result) == ["--ports", "--fingerprint"]


def test_check_ports_marks_cves_cli_only(monkeypatch):
    hosts = fake_lab(monkeypatch, "cves-edge-vs-own.json")
    result = mcp_server.check_ports(hosts, already_ran=["enrich_hosts"])
    assert flags(result) == ["--fingerprint", "--cves FILE"]  # never --ports again
    cli_only = {c["flag"]: c["cli_only"] for c in result["next_checks"]}
    assert cli_only == {"--fingerprint": False, "--cves FILE": True}


def test_full_chain_never_repeats_a_check(monkeypatch):
    """find_subdomains -> check_takeover -> enrich_hosts -> check_ports, each
    passing the tools already called: no tool is ever suggested again."""
    fake_ct(monkeypatch, hosts=fake_lab(monkeypatch))
    ran = []
    calls = [("find_subdomains", lambda r: mcp_server.find_subdomains("lab.invalid", already_ran=r)),
             ("check_email_auth", lambda r: mcp_server.check_email_auth("lab.invalid", already_ran=r)),
             ("check_takeover", lambda r: mcp_server.check_takeover(["a"], domain="lab.invalid", already_ran=r)),
             ("enrich_hosts", lambda r: mcp_server.enrich_hosts(["a"], already_ran=r)),
             ("check_ports", lambda r: mcp_server.check_ports(["a"], already_ran=r))]
    for tool, call in calls:
        result = call(list(ran))
        for c in result["next_checks"]:
            assert c["mcp_tool"] not in ran + [tool], (tool, c["flag"])
        ran.append(tool)
    assert flags(result) == ["--fingerprint"]  # only the active check is left


def test_unknown_already_ran_refused_before_any_lookup(monkeypatch):
    def boom(hosts):
        raise AssertionError("lookup ran before already_ran was checked")
    monkeypatch.setattr(mcp_server, "enrich", boom)
    with pytest.raises(mcp_server.ToolError, match="check_takover"):
        mcp_server.enrich_hosts(["a"], already_ran=["check_takover"])


def test_suggest_failure_is_reported_not_hidden(monkeypatch, capsys):
    hosts = fake_lab(monkeypatch)

    def broken(results, *args):
        raise KeyError("hosts")
    monkeypatch.setattr(mcp_server.suggest, "next_checks", broken)
    result = mcp_server.enrich_hosts(hosts)
    assert result["next_checks"] == []
    assert "KeyError" in result["next_checks_error"]
    assert "KeyError" in capsys.readouterr().err  # stderr, since stdout carries MCP


# --- fingerprint_hosts (ACTIVE) ---------------------------------------------
# requests.get is faked, so the real fetch_headers() and fingerprint_all()
# run (including the audit-log hook) without touching the network.

class FakeResponse:
    def __init__(self, status, headers):
        self.status_code = status
        self.headers = headers

    def close(self):
        pass


FAKE_SITES = {  # dotless test hostnames, so the chat app doesn't turn them into links
    "https://app/": FakeResponse(200, {"Server": "nginx/1.24.0", "X-Frame-Options": "DENY",
                                       "X-Content-Type-Options": "nosniff"}),
    "https://www/": FakeResponse(301, {"Location": "https://app/", "Server": "nginx"}),
}


def fake_web(monkeypatch):
    """Fake DNS and web: app and www are public, intranet is private, gone doesn't resolve,
    down is public but never answers. Returns the list of URLs requested."""
    monkeypatch.setattr(mcp_server, "enrich", lambda hosts: {"hosts": {
        "app": {"ips": ["8.8.8.8"]}, "www": {"ips": ["8.8.8.8"]},
        "intranet": {"ips": ["10.0.0.5"], "private_ips": ["10.0.0.5"]},
        "gone": {"ips": []}, "down": {"ips": ["8.8.4.4"]}}})
    sent = []

    def get(url, **kwargs):
        sent.append(url)
        if url not in FAKE_SITES:  # never answers = a timeout, so no HTTP retry
            raise mcp_server.fingerprint.requests.ConnectTimeout("no answer")
        return FAKE_SITES[url]
    monkeypatch.setattr(mcp_server.fingerprint.requests, "get", get)
    return sent


HOSTS = ["app", "www", "intranet", "gone", "down"]


def read_log(results_dir):
    path = results_dir / "active.log"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def run(monkeypatch, tool, hosts, detail="summary", already_ran=None, scope_file=None, research_file=None):
    """The v1.20 flow without a terminal: the tool only asks (nothing sent),
    the person's typed yes is stood in for (approvals.py has its own tests),
    and active_run runs it once with the approved scope and research file."""
    asked = getattr(mcp_server, tool)(hosts)
    assert asked["nothing_sent"] and asked["approval_needed"]
    grant = {"tool": tool, "hosts": asked["hosts"], "scope": scope_file or AllowAll(),
             "research": research_file, "max_per_host": 2}
    monkeypatch.setattr(mcp_server.approvals, "claim", lambda rid: dict(grant))
    return mcp_server.active_run(asked["approval_id"], detail=detail, already_ran=already_ran)


@pytest.mark.parametrize("tool", ["fingerprint_hosts", "check_exposed_files", "probe_hosts"])
def test_an_active_tool_only_asks_sends_nothing_and_looks_nothing_up(monkeypatch, results_dir, tool):
    def boom(*args, **kwargs):
        raise AssertionError("DNS lookup ran before a person approved")
    monkeypatch.setattr(mcp_server, "enrich", boom)
    sent = fake_web(monkeypatch)
    asked = getattr(mcp_server, tool)(["app", "WWW."])
    assert asked["nothing_sent"] is True and asked["approval_needed"] is True
    assert asked["hosts"] == ["app", "www"]
    assert f"python monomi.py approve {asked['approval_id']} --scope" in asked["next_step"]
    assert sent == [] and read_log(results_dir) == []   # nothing sent, so nothing logged
    rec = json.loads((results_dir / "approvals" / f"{asked['approval_id']}.json").read_text())
    assert rec["state"] == "pending" and rec["tool"] == tool


def test_no_valid_hosts_means_nothing_to_approve(monkeypatch):
    asked = mcp_server.fingerprint_hosts(["not a host!"])
    assert asked["approval_needed"] is False and asked["nothing_sent"] is True
    assert asked["rejected"] and "approval_id" not in asked


def test_active_run_without_an_approval_refuses_logs_and_reaches_the_client(monkeypatch, results_dir):
    sent = fake_web(monkeypatch)
    rid = mcp_server.fingerprint_hosts(["app"])["approval_id"]
    with pytest.raises(mcp_server.ToolError, match="approve it first.*Nothing was sent"):
        mcp_server.active_run(rid)
    with pytest.raises(Exception, match="approve it first"):
        asyncio.run(mcp_server.mcp.call_tool("active_run", {"approval_id": rid}))
    assert sent == []
    [line, _] = read_log(results_dir)
    assert line["event"] == "refused" and line["tool"] == "active_run" and "approve it first" in line["reason"]


@pytest.mark.parametrize("rid", ["nope", "../../etc/passwd", "abcd-efgh"])
def test_active_run_refuses_ids_that_are_not_approvals(monkeypatch, rid):
    sent = fake_web(monkeypatch)
    with pytest.raises(mcp_server.ToolError, match="Nothing was sent"):
        mcp_server.active_run(rid)
    assert sent == []


def test_fingerprint_only_requests_public_hosts_and_logs_each(monkeypatch, results_dir):
    sent = fake_web(monkeypatch)
    result = run(monkeypatch, "fingerprint_hosts", HOSTS)
    assert sorted(sent) == ["https://app/", "https://down/", "https://www/"]
    assert result["requests_sent"] == 3
    assert result["not_requested"] == ["gone", "intranet"]
    log = [json.loads(line) for line in (results_dir / "active.log").read_text().splitlines()]
    assert sorted(entry["url"] for entry in log) == sorted(sent)
    assert {entry["tool"] for entry in log} == {"fingerprint_hosts"}
    assert all(entry["time"] for entry in log)


def test_fingerprint_summary_leaks_headers_redirects_errors(monkeypatch):
    fake_web(monkeypatch)
    result = run(monkeypatch, "fingerprint_hosts", HOSTS)
    assert result["version_leaks"] == [{
        "host": "app", "tech": "nginx/1.24.0", "version": "1.24.0",
        "evidence": "server: nginx/1.24.0", "owners": ["server / infrastructure admin"]}]
    # app has X-Frame-Options and nosniff; www is a redirect, so it isn't judged
    assert sorted(result["header_issues"]) == [
        "Content-Security-Policy", "Referrer-Policy", "Strict-Transport-Security"]
    hsts = result["header_issues"]["Strict-Transport-Security"]
    assert hsts == {"problems": {"missing": 1}, "host_count": 1, "hosts": ["app"],
                    "owners": ["web app team", "CDN / proxy admin"]}
    assert result["not_judged"] == {"www": 301}
    assert result["errors"] == {"down": "ConnectTimeout"} and result["error_count"] == 1
    assert result["status_counts"] == {200: 1, 301: 1}


def test_fingerprint_full_detail_has_owners_on_each_issue(monkeypatch):
    fake_web(monkeypatch)
    result = run(monkeypatch, "fingerprint_hosts", HOSTS, detail="full")
    app = result["hosts"]["app"]
    assert all(i["owners"] == ["web app team", "CDN / proxy admin"] for i in app["header_issues"])
    assert app["techs"][0]["owners"] == ["server / infrastructure admin"]


def test_fingerprint_caps_hosts_per_call(monkeypatch):
    fake_web(monkeypatch)
    many = [f"h{i:02d}" for i in range(45)]
    asked = mcp_server.fingerprint_hosts(many)
    assert asked["hosts_checked"] == 30 and asked["batch"]["next_start"] == 30
    assert run(monkeypatch, "fingerprint_hosts", many)["hosts_checked"] == 30


def test_fingerprint_never_suggests_itself(monkeypatch):
    fake_web(monkeypatch)
    result = run(monkeypatch, "fingerprint_hosts", HOSTS)
    assert "--fingerprint" not in flags(result)
    # app/www/down sit on the target's own IPs; having fingerprinted, the next
    # active step it points to is checking those live pages for exposed files
    assert flags(result) == ["--ports", "--exposed-files"]
    result = run(monkeypatch, "fingerprint_hosts", HOSTS, already_ran=["check_ports", "check_exposed_files"])
    assert flags(result) == []


def test_active_tools_are_labeled_and_only_active_run_reaches_out():
    tools = {t.name: t for t in asyncio.run(mcp_server.mcp.list_tools())}
    for name in ("fingerprint_hosts", "check_exposed_files", "probe_hosts"):
        a = tools[name].annotations
        assert a.title.startswith("ACTIVE (needs approval)")
        assert a.read_only_hint is True and a.open_world_hint is False   # this call sends nothing
        assert tools[name].description.lstrip().startswith("ACTIVE, needs a person's approval")
    run_ = tools["active_run"].annotations
    assert run_.read_only_hint is False and run_.destructive_hint is False and run_.open_world_hint is True
    assert set(tools["active_run"].input_schema["properties"]) == {"approval_id", "detail", "already_ran"}


def test_main_ignores_old_config_flags_with_a_note(monkeypatch, capsys, tmp_path):
    # A v1.19 config still passes these: the server must start, use none of
    # them, and say how to clean them up
    monkeypatch.setattr(mcp_server.mcp, "run", lambda: None)
    f = tmp_path / "scope.txt"
    f.write_text("*.example.test\n")
    mcp_server.main(["--allow-active", "--scope", str(f), "--scope-sha256", "ab" * 32,
                     "--research", str(f), "--research-sha256", "cd" * 32])
    err = capsys.readouterr().err
    assert "ignoring --allow-active, --scope, --scope-sha256, --research, --research-sha256" in err
    assert "mcp setup" in err and "need a terminal approval" in err
    assert not hasattr(mcp_server, "ALLOW_ACTIVE") and not hasattr(mcp_server, "SCOPE")


def fake_plain_http_host(monkeypatch):
    """Like dev on the lab: HTTPS fails with a TLS error, plain HTTP works."""
    monkeypatch.setattr(mcp_server, "enrich", lambda hosts: {"hosts": {"dev": {"ips": ["8.8.8.8"]}}})
    sent = []

    def get(url, **kwargs):
        sent.append(url)
        if url == "https://dev/":
            raise mcp_server.fingerprint.requests.exceptions.SSLError("wrong certificate")
        return FakeResponse(200, {"Server": "nginx/1.28.3 (Ubuntu)"})
    monkeypatch.setattr(mcp_server.fingerprint.requests, "get", get)
    return sent


def test_fingerprint_falls_back_to_http_and_logs_both(monkeypatch, results_dir):
    sent = fake_plain_http_host(monkeypatch)
    result = run(monkeypatch, "fingerprint_hosts", ["dev"], detail="full")
    assert sent == ["https://dev/", "http://dev/"]
    assert result["requests_sent"] == 2  # requests, not hosts: matches the log
    log = [json.loads(line) for line in (results_dir / "active.log").read_text().splitlines()]
    assert [entry["url"] for entry in log] == sent
    dev = result["hosts"]["dev"]
    assert dev["url"] == "http://dev/" and dev["https_error"] == "SSLError"
    assert result["errors"] == {}


def test_broken_https_is_owned_by_server_and_cdn(monkeypatch):
    fake_plain_http_host(monkeypatch)
    result = run(monkeypatch, "fingerprint_hosts", ["dev"])
    issues = result["header_issues"]
    assert "Strict-Transport-Security" not in issues
    assert issues["HTTPS"] == {"problems": {"broken": 1}, "host_count": 1, "hosts": ["dev"],
                               "owners": ["server / infrastructure admin", "CDN / proxy admin"]}
    assert issues["Content-Security-Policy"]["owners"] == ["web app team", "CDN / proxy admin"]


# --- check_exposed_files (ACTIVE) -------------------------------------------

class MapResp:
    """A fake response exposed.py can read a body from (it uses iter_content)."""
    def __init__(self, status=200, headers=None, body=b""):
        self.status_code = status
        self.headers = headers or {}
        self._body = body

    def iter_content(self, n):
        for i in range(0, len(self._body), n):
            yield self._body[i:i + n]

    def close(self):
        pass


EXPOSED_OPENAPI = json.dumps({
    "openapi": "3.0.1", "info": {"title": "Lab API"},
    "paths": {"/users": {"get": {}}, "/admin": {"get": {}, "post": {}}},
    "components": {"securitySchemes": {"bearer": {}}}}).encode()

EXPOSED_MAP = json.dumps({
    "version": 3, "sources": ["src/app.ts"], "sourcesContent": ["secret code"]}).encode()


def fake_exposed_web(monkeypatch, pages):
    """pages: {url: MapResp}. app and intranet resolve; intranet is private.
    Returns the list of URLs requested."""
    monkeypatch.setattr(mcp_server, "enrich", lambda hosts: {"hosts": {
        "app": {"ips": ["8.8.8.8"]},
        "intranet": {"ips": ["10.0.0.5"], "private_ips": ["10.0.0.5"]}}})
    sent = []

    def get(url, **kwargs):
        sent.append(url)
        return pages.get(url, MapResp(404, body=b"nope"))
    monkeypatch.setattr(mcp_server.exposed.requests, "get", get)
    return sent


EXP_HOSTS = ["app", "intranet"]


def test_exposed_finds_spec_and_map_with_owners(monkeypatch):
    fake_exposed_web(monkeypatch, {
        "https://app/openapi.json": MapResp(body=EXPOSED_OPENAPI),
        "https://app/": MapResp(body=b'<script src="/app.js"></script>'),
        "https://app/app.js": MapResp(headers={"sourcemap": "app.js.map"}, body=b"x=1"),
        "https://app/app.js.map": MapResp(body=EXPOSED_MAP)})
    result = run(monkeypatch, "check_exposed_files", EXP_HOSTS, detail="full")
    assert result["hosts_checked"] == 2 and result["not_requested"] == ["intranet"]
    app = result["hosts"]["app"]
    assert app["spec"]["type"] == "OpenAPI" and app["spec"]["declares_auth"] is True
    assert app["spec"]["owners"] == ["web app team", "CDN / proxy admin"]
    [m] = app["source_maps"]
    assert m["has_source_content"] is True and m["owners"] == ["web app team"]
    # the embedded source code never appears in what the tool returns
    assert "secret code" not in json.dumps(result)


def test_exposed_summary_counts_and_flags_source_code(monkeypatch):
    fake_exposed_web(monkeypatch, {
        "https://app/openapi.json": MapResp(body=EXPOSED_OPENAPI),
        "https://app/": MapResp(body=b'<script src="/app.js"></script>'),
        "https://app/app.js": MapResp(headers={"sourcemap": "app.js.map"}, body=b"x=1"),
        "https://app/app.js.map": MapResp(body=EXPOSED_MAP)})
    result = run(monkeypatch, "check_exposed_files", EXP_HOSTS)  # summary mode
    assert result["specs_found"] == 1 and result["source_maps_found"] == 1
    assert result["maps_with_source_code"] == ["app"]
    assert result["specs"][0]["endpoints"] == 2
    assert result["hosts_with_findings"] == 1


def test_exposed_logs_each_request_and_counts_them(monkeypatch, results_dir):
    sent = fake_exposed_web(monkeypatch, {
        "https://app/openapi.json": MapResp(body=EXPOSED_OPENAPI),
        "https://app/": MapResp(body=b"<html></html>")})
    result = run(monkeypatch, "check_exposed_files", EXP_HOSTS)
    log = [json.loads(line) for line in (results_dir / "active.log").read_text().splitlines()]
    assert result["requests_sent"] == len(log) == len(sent)
    assert {entry["tool"] for entry in log} == {"check_exposed_files"}
    assert all(entry["host"] == "app" for entry in log)  # intranet was never contacted


def test_exposed_clean_host_is_no_finding(monkeypatch):
    fake_exposed_web(monkeypatch, {"https://app/": MapResp(body=b"<html></html>")})
    result = run(monkeypatch, "check_exposed_files", EXP_HOSTS)
    assert result["hosts_with_findings"] == 0 and result["specs_found"] == 0
    # v1.23: a clean result says what was checked on each host
    [clean] = result["checked_clean"]
    assert clean["host"] == "app" and clean["homepage"] == 200
    assert clean["spec_paths"] == {"tried": 6, "answered": 6}


def test_exposed_suggests_next_active_and_passive_checks(monkeypatch):
    fake_exposed_web(monkeypatch, {"https://app/openapi.json": MapResp(body=EXPOSED_OPENAPI),
                                   "https://app/": MapResp(body=b"<html></html>")})
    result = run(monkeypatch, "check_exposed_files", EXP_HOSTS)
    # app sits on a public IP of its own, so --ports follows; it never suggests
    # itself, and it doesn't point back at its active sibling --fingerprint
    assert flags(result) == ["--ports"]


# --- scope (v1.12) -----------------------------------------------------------

def test_no_tool_takes_a_scope_research_file_or_a_yes():
    # The agent can never supply the scope, the research header or the yes:
    # they only come with a person's approval in a terminal
    for tool in asyncio.run(mcp_server.mcp.list_tools()):
        params = [name.lower() for name in tool.input_schema.get("properties", {})]
        assert not any(w in name for name in params for w in ("scope", "research", "yes", "approve")), tool.name


# --- per-host scope filter + audit log (v1.12) -------------------------------

LAB_SCOPE = b"example.test\n*.example.test\n!dev.example.test\n"


@pytest.fixture
def lab_scope():
    """A real scope (not AllowAll), as a person's approval would carry it."""
    return scope.from_bytes(LAB_SCOPE, "scope.txt")


def lab_web(monkeypatch, module):
    """DNS that records what it was asked, and a web that answers 200 to anything."""
    looked_up, sent = [], []

    def enrich(hosts):
        looked_up.extend(hosts)
        return {"hosts": {h: {"ips": ["8.8.8.8"]} for h in hosts}}
    monkeypatch.setattr(mcp_server, "enrich", enrich)

    def get(url, **kwargs):
        sent.append(url)
        if module is mcp_server.exposed:
            return MapResp(404, body=b"nope")
        return FakeResponse(200, {"Server": "nginx"})
    monkeypatch.setattr(module.requests, "get", get)
    return looked_up, sent


ASKED = ["www.example.test", "dev.example.test", "evil.test", "example.test"]


@pytest.mark.parametrize("tool,module", [
    ("fingerprint_hosts", mcp_server.fingerprint), ("check_exposed_files", mcp_server.exposed)])
def test_out_of_scope_hosts_get_no_dns_lookup_and_no_request(
        monkeypatch, results_dir, lab_scope, tool, module):
    looked_up, sent = lab_web(monkeypatch, module)
    result = run(monkeypatch, tool, ASKED, detail="full", scope_file=lab_scope)
    assert looked_up == ["example.test", "www.example.test"]   # filtered BEFORE the lookup
    assert sent and all("dev.example.test" not in u and "evil.test" not in u for u in sent)
    assert result["out_of_scope"] == [
        {"host": "dev.example.test", "reason": "excluded by !dev.example.test"},
        {"host": "evil.test", "reason": "no rule matches"}]
    assert result["hosts_checked"] == 2


@pytest.mark.parametrize("tool,module", [
    ("fingerprint_hosts", mcp_server.fingerprint), ("check_exposed_files", mcp_server.exposed)])
def test_audit_log_has_rules_hashes_and_refusals(monkeypatch, results_dir, lab_scope, tool, module):
    _, sent = lab_web(monkeypatch, module)
    result = run(monkeypatch, tool, ASKED, scope_file=lab_scope)
    log = read_log(results_dir)
    refused = [x for x in log if x["event"] == "refused"]
    requests_ = [x for x in log if x["event"] == "request"]
    assert [(x["host"], x["reason"]) for x in refused] == [
        ("dev.example.test", "excluded by !dev.example.test"), ("evil.test", "no rule matches")]
    assert len(requests_) == len(sent) == result["requests_sent"]
    assert {x["scope_rule"] for x in requests_ if x["host"] == "www.example.test"} == {"*.example.test"}
    assert {x["scope_rule"] for x in requests_ if x["host"] == "example.test"} == {"example.test"}
    assert all(x["scope_sha256"] == lab_scope.sha256 and x["via"] == "mcp" and x["tool"] == tool
               for x in log)


def test_summary_shows_out_of_scope(monkeypatch, results_dir, lab_scope):
    lab_web(monkeypatch, mcp_server.fingerprint)
    result = run(monkeypatch, "fingerprint_hosts", ASKED, scope_file=lab_scope)
    assert result["out_of_scope_count"] == 2 and len(result["out_of_scope"]) == 2


def test_all_hosts_out_of_scope_sends_nothing(monkeypatch, results_dir, lab_scope):
    looked_up, sent = lab_web(monkeypatch, mcp_server.fingerprint)
    result = run(monkeypatch, "fingerprint_hosts", ["evil.test", "dev.example.test"], scope_file=lab_scope)
    assert looked_up == [] and sent == [] and result["requests_sent"] == 0
    assert result["out_of_scope_count"] == 2


# --- The validation gate on takeover leads (v1.13): checks 4 and 6 ---

def gated_leads(monkeypatch, *leads, domain=None):
    monkeypatch.setattr(mcp_server, "check_hosts", lambda hosts, domain=None: {
        "leads": [dict(lead) for lead in leads], "stale": [],
        "results": {lead["host"]: {"status": "lead"} for lead in leads}, "checked": len(leads), "errors": {}})
    return mcp_server.check_takeover([lead["host"] for lead in leads], domain=domain)


CONFIRMED = {"host": "a", "cname": "gone.azurewebsites.net", "claimable": True,
             "nxdomain_confirmed_by": ["Cloudflare", "Google"]}


def test_confirmed_claimable_takeover_passes_the_gate(monkeypatch):
    result = gated_leads(monkeypatch, CONFIRMED)
    assert result["leads"][0]["gate"] == {"result": "finding", "passed": 2, "of": 2,
                                          "failed": [], "notes": []}
    assert result["leads_passing_gate"] == 1


def test_takeover_on_system_dns_alone_fails_check_4(monkeypatch):
    lead = gated_leads(monkeypatch, dict(CONFIRMED, nxdomain_confirmed_by=[]))["leads"][0]
    assert lead["gate"]["result"] == "lead"
    assert [f["check"] for f in lead["gate"]["failed"]] == [4]
    assert "system DNS alone" in lead["gate"]["failed"][0]["why"]


def test_unknown_service_and_same_domain_fail_check_6(monkeypatch):
    unknown = dict(CONFIRMED, host="b", cname="gone.unknownhost.test", claimable=False)
    inside = dict(CONFIRMED, host="c", cname="old.lab.test")
    result = gated_leads(monkeypatch, unknown, inside, domain="lab.test")
    unknown_gate, inside_gate = (lead["gate"] for lead in result["leads"])
    assert unknown_gate["failed"][0]["check"] == 6 and "who can claim" in unknown_gate["failed"][0]["why"]
    assert inside_gate["failed"][0]["check"] == 6 and "inside lab.test" in inside_gate["failed"][0]["why"]
    assert result["leads_passing_gate"] == 0


def test_breaking_the_takeover_gate_lets_an_unconfirmed_lead_through(monkeypatch):
    """Break the rule: with no checks, an unconfirmed lead reads as a finding."""
    monkeypatch.setattr(mcp_server.gate, "TAKEOVER_CHECKS", ())
    lead = gated_leads(monkeypatch, dict(CONFIRMED, nxdomain_confirmed_by=[]))["leads"][0]
    assert lead["gate"]["result"] == "finding"


# --- --rate and --research on the server (v1.19) ------------------------------

def test_default_rate_is_1_per_second(monkeypatch, capsys):
    monkeypatch.setattr(mcp_server.mcp, "run", lambda: None)
    mcp_server.main([])
    assert mcp_server.LIMITER.rate == 1.0 and mcp_server.RATE_PROBLEM is None
    assert "rate 1 request(s)/second" in capsys.readouterr().err


def test_a_bad_rate_refuses_active_tools_before_asking(monkeypatch, results_dir):
    monkeypatch.setattr(mcp_server.mcp, "run", lambda: None)
    mcp_server.main(["--rate", "fast"])
    assert "--rate needs a number" in mcp_server.RATE_PROBLEM
    with pytest.raises(mcp_server.ToolError, match="nothing was sent"):
        mcp_server.fingerprint_hosts(["app"])
    assert not (results_dir / "approvals").exists()


def test_research_header_and_rate_go_on_every_request_and_log_line(monkeypatch, results_dir):
    r = mcp_server.research.Research({"X-Intigriti": "x41ok"}, "ab" * 32, "research.txt")
    monkeypatch.setattr(mcp_server, "LIMITER", mcp_server.rate.Limiter(1000))
    monkeypatch.setattr(mcp_server, "enrich", lambda hosts: {"hosts": {"app": {"ips": ["8.8.8.8"]}}})
    headers = []

    def get(url, **kwargs):
        headers.append(kwargs["headers"])
        return FAKE_SITES["https://app/"]
    monkeypatch.setattr(mcp_server.fingerprint.requests, "get", get)
    result = run(monkeypatch, "fingerprint_hosts", ["app"], research_file=r)
    assert headers and all(h["X-Intigriti"] == "x41ok" for h in headers)
    assert result["sent_as"] == {"rate_per_second": 1000, "research_sha256": "ab" * 32,
                                 "research_headers": ["X-Intigriti"]}
    [line] = [x for x in read_log(results_dir) if x["event"] == "request"]
    assert line["rate"] == 1000 and line["research_sha256"] == "ab" * 32


# exposed files at 1/s: 2 hosts per call since v1.24 (14 requests a host, was 13)
@pytest.mark.parametrize("speed, fp_hosts, exp_hosts", [(None, 30, 10), (1, 20, 2), (10, 30, 10)])
def test_hosts_per_call_fits_the_rate(monkeypatch, speed, fp_hosts, exp_hosts):
    monkeypatch.setattr(mcp_server, "LIMITER", mcp_server.rate.Limiter(speed))
    assert mcp_server.hosts_per_call("t", mcp_server.MAX_FP_HOSTS, mcp_server.FP_REQUESTS_PER_HOST) == fp_hosts
    assert mcp_server.hosts_per_call("t", mcp_server.MAX_EXP_HOSTS, mcp_server.exposed.MAX_REQUESTS) == exp_hosts


def test_at_1_per_second_exposed_files_goes_in_batches_of_2(monkeypatch):
    # 2 since v1.24: up to 14 requests a host (the plain-HTTP homepage), was 13
    monkeypatch.setattr(mcp_server, "LIMITER", mcp_server.rate.Limiter(1))
    seen = {}

    def check_all(enrichment, **kwargs):
        seen["max_hosts"] = kwargs["max_hosts"]
        return {"hosts": {}, "requested": [], "checked": 0, "requests": 0, "skipped": 0}
    monkeypatch.setattr(mcp_server.exposed, "check_all", check_all)
    monkeypatch.setattr(mcp_server, "enrich", lambda hosts: {"hosts": {}})
    asked = mcp_server.check_exposed_files([f"h{i}" for i in range(7)])
    assert asked["hosts_checked"] == 2 and asked["max_requests"] == 2 * mcp_server.exposed.MAX_REQUESTS
    assert asked["batch"]["size"] == 2 and asked["batch"]["next_start"] == 2
    run(monkeypatch, "check_exposed_files", [f"h{i}" for i in range(7)])
    assert seen["max_hosts"] == 2


def test_a_rate_too_slow_for_one_host_refuses_before_any_lookup(monkeypatch, results_dir):
    monkeypatch.setattr(mcp_server, "LIMITER", mcp_server.rate.Limiter(0.1))

    def boom(hosts):
        raise AssertionError("DNS lookup ran for a call that can't fit")
    monkeypatch.setattr(mcp_server, "enrich", boom)
    with pytest.raises(mcp_server.ToolError, match="Use the CLI instead"):
        mcp_server.check_exposed_files(["app"])
    assert read_log(results_dir)[-1]["event"] == "refused"


def test_check_ports_keeps_someone_elses_server_out_of_the_targets_ips(monkeypatch):
    # v1.23.1, the Superdrug run: CVEs on Google's shared front end
    monkeypatch.setattr(mcp_server, "enrich", lambda hosts: {"hosts": {}, "resolved": 2})
    monkeypatch.setattr(mcp_server.internetdb, "lookup", lambda enrichment: {
        "ips": {"216.239.32.21": {"shared_edge": False, "not_own": "third-party hosting (Google front end)",
                                  "hosts": ["ecom.shop.test"], "vulns": ["CVE-2021-41184"], "ports": [443]},
                "198.51.100.7": {"shared_edge": False, "hosts": ["shop.test"], "vulns": [], "ports": [443]}},
        "nothing_seen": {}, "checked": 2, "errors": 0, "skipped": 0, "unique_cves": [], "risky": []})
    result = mcp_server.check_ports(["shop.test"])
    assert result["summary"]["third_party_ips"] == 1 and result["summary"]["origin_ips"] == 1
    assert list(result["origin_ips"]) == ["198.51.100.7"]
    assert result["third_party_ips"]["216.239.32.21"] == {
        "not_own": "third-party hosting (Google front end)", "hosts": ["ecom.shop.test"], "cve_count": 1}


# --- probe_hosts (ACTIVE, v1.25) --------------------------------------------
# requests.get is faked (the same fake_web as fingerprint), so the real
# probe_all() runs, including the audit-log hook and the approved-hosts rule.

def test_probe_follows_redirects_between_approved_hosts_and_logs_each_hop(monkeypatch, results_dir):
    sent = fake_web(monkeypatch)
    result = run(monkeypatch, "probe_hosts", HOSTS)
    # www redirects to app, which is in this approval: followed (app is also probed itself)
    assert sorted(sent) == ["https://app/", "https://app/", "https://down/", "https://www/"]
    assert result["requests_sent"] == 4
    assert result["not_requested"] == ["gone", "intranet"]
    www = next(p for p in result["pages"] if p["host"] == "www")
    assert www == {"host": "www", "status": 200, "title": None, "final_url": "https://app/",
                   "redirects": 1, "content_type": None, "body_kind": None}
    assert result["redirected"] == ["www"] and result["redirects_blocked"] == []
    assert result["errors"] == {"down": "ConnectTimeout"}
    log = read_log(results_dir)
    assert sorted(entry["url"] for entry in log) == sorted(sent)
    assert {entry["tool"] for entry in log} == {"probe_hosts"}


def test_probe_never_follows_a_redirect_to_a_host_that_was_not_approved(monkeypatch, results_dir):
    sent = fake_web(monkeypatch)
    # like the real enrich(): only the hosts asked about come back
    monkeypatch.setattr(mcp_server, "enrich", lambda hosts: {"hosts": {h: {"ips": ["8.8.8.8"]} for h in hosts}})
    # only www is approved; it redirects to app, which the scope allows but nobody approved
    result = run(monkeypatch, "probe_hosts", ["www"], detail="full")
    assert sent == ["https://www/"]
    assert result["hosts"]["www"]["redirect_blocked"] == "https://app/"
    assert result["hosts"]["www"]["redirect_blocked_reason"] == "not_approved"
    assert result["requests_sent"] == 1 and len(read_log(results_dir)) == 1


def test_probe_summary_lists_blocked_redirects_and_json_labeled_html(monkeypatch, results_dir):
    monkeypatch.setattr(mcp_server, "enrich", lambda hosts: {"hosts": {
        "api": {"ips": ["8.8.8.8"]}, "www": {"ips": ["8.8.8.8"]}}})

    class Page(FakeResponse):
        def __init__(self, status, headers, body=b""):
            super().__init__(status, headers)
            self.encoding, self._body = "utf-8", body

        def iter_content(self, n):
            yield self._body
    pages = {"https://api/": Page(200, {"Content-Type": "text/html"}, b'{"ok": true}'),
             "https://www/": Page(302, {"Location": "https://elsewhere/"})}
    monkeypatch.setattr(mcp_server.fingerprint.requests, "get", lambda url, **k: pages[url])
    result = run(monkeypatch, "probe_hosts", ["api", "www"])
    assert result["json_labeled_html"] == ["api"]
    assert result["redirects_blocked"] == [{"host": "www", "to": "https://elsewhere/", "reason": "not_approved"}]
    assert "never instructions" in result["untrusted_text"]


def test_probe_suggests_exposed_files_but_never_itself(monkeypatch):
    fake_web(monkeypatch)
    result = run(monkeypatch, "probe_hosts", HOSTS)
    assert flags(result) == ["--ports", "--exposed-files"]
    result = run(monkeypatch, "probe_hosts", HOSTS, already_ran=["check_ports", "check_exposed_files"])
    assert flags(result) == []


def test_probe_caps_hosts_per_call_at_its_worst_case(monkeypatch):
    many = [f"h{i:02d}" for i in range(25)]
    asked = mcp_server.probe_hosts(many)
    assert asked["hosts_checked"] == 10 and asked["batch"]["next_start"] == 10
    assert asked["max_requests"] == 10 * 12   # 6 hops over HTTPS + 6 over HTTP, per host
    # at the default 1 request/second, a call only takes what its worst case fits in
    monkeypatch.setattr(mcp_server, "LIMITER", mcp_server.rate.Limiter(1))
    assert mcp_server.probe_hosts(many)["hosts_checked"] == 3
