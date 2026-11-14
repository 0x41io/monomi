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
    """Every test saves its full results in a temp folder, not the real scans/,
    and starts with active tools off (as the real server does). An approved
    scope is in place, so tests that turn active tools on reach the tool;
    the scope tests below take it away again."""
    monkeypatch.setattr(mcp_server, "RESULTS_DIR", str(tmp_path))
    monkeypatch.setattr(mcp_server, "ACTIVE_LOG", str(tmp_path / "active.log"))
    monkeypatch.setattr(mcp_server, "ALLOW_ACTIVE", False)
    monkeypatch.setattr(mcp_server, "SCOPE", AllowAll())
    monkeypatch.setattr(mcp_server, "SCOPE_PROBLEM", None)
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


def assert_only_a_refusal(results_dir):
    [line] = read_log(results_dir)
    assert line["event"] == "refused" and line["reason"] == "active checks are off"
    assert line["via"] == "mcp" and line["host"] is None


def test_fingerprint_refused_when_active_is_off(monkeypatch, results_dir):
    sent = fake_web(monkeypatch)
    with pytest.raises(mcp_server.ToolError, match="nothing was sent"):
        mcp_server.fingerprint_hosts(HOSTS)
    assert sent == []
    assert_only_a_refusal(results_dir)  # v1.12: refusals are logged, requests none


def test_fingerprint_refusal_reason_reaches_the_client(monkeypatch):
    fake_web(monkeypatch)
    with pytest.raises(mcp_server.ToolError, match="--allow-active"):
        asyncio.run(mcp_server.mcp.call_tool("fingerprint_hosts", {"hostnames": ["app"]}))


def test_fingerprint_refused_before_any_lookup(monkeypatch):
    def boom(hosts):
        raise AssertionError("DNS lookup ran while active tools were off")
    monkeypatch.setattr(mcp_server, "enrich", boom)
    with pytest.raises(mcp_server.ToolError):
        mcp_server.fingerprint_hosts(["app"])


def test_fingerprint_only_requests_public_hosts_and_logs_each(monkeypatch, results_dir):
    monkeypatch.setattr(mcp_server, "ALLOW_ACTIVE", True)
    sent = fake_web(monkeypatch)
    result = mcp_server.fingerprint_hosts(HOSTS)
    assert sorted(sent) == ["https://app/", "https://down/", "https://www/"]
    assert result["requests_sent"] == 3
    assert result["not_requested"] == ["gone", "intranet"]
    log = [json.loads(line) for line in (results_dir / "active.log").read_text().splitlines()]
    assert sorted(entry["url"] for entry in log) == sorted(sent)
    assert {entry["tool"] for entry in log} == {"fingerprint_hosts"}
    assert all(entry["time"] for entry in log)


def test_fingerprint_summary_leaks_headers_redirects_errors(monkeypatch):
    monkeypatch.setattr(mcp_server, "ALLOW_ACTIVE", True)
    fake_web(monkeypatch)
    result = mcp_server.fingerprint_hosts(HOSTS)
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
    monkeypatch.setattr(mcp_server, "ALLOW_ACTIVE", True)
    fake_web(monkeypatch)
    result = mcp_server.fingerprint_hosts(HOSTS, detail="full")
    app = result["hosts"]["app"]
    assert all(i["owners"] == ["web app team", "CDN / proxy admin"] for i in app["header_issues"])
    assert app["techs"][0]["owners"] == ["server / infrastructure admin"]


def test_fingerprint_caps_hosts_per_call(monkeypatch):
    monkeypatch.setattr(mcp_server, "ALLOW_ACTIVE", True)
    fake_web(monkeypatch)
    many = [f"h{i:02d}" for i in range(45)]
    result = mcp_server.fingerprint_hosts(many)
    assert result["hosts_checked"] == 30 and result["batch"]["next_start"] == 30


def test_fingerprint_never_suggests_itself(monkeypatch):
    monkeypatch.setattr(mcp_server, "ALLOW_ACTIVE", True)
    fake_web(monkeypatch)
    result = mcp_server.fingerprint_hosts(HOSTS)
    assert "--fingerprint" not in flags(result)
    # app/www/down sit on the target's own IPs; having fingerprinted, the next
    # active step it points to is checking those live pages for exposed files
    assert flags(result) == ["--ports", "--exposed-files"]
    result = mcp_server.fingerprint_hosts(
        HOSTS, already_ran=["check_ports", "check_exposed_files"])
    assert flags(result) == []


def test_fingerprint_tool_is_labeled_active():
    tools = {t.name: t for t in asyncio.run(mcp_server.mcp.list_tools())}
    fp = tools["fingerprint_hosts"].annotations
    assert fp.read_only_hint is False and fp.destructive_hint is False and fp.open_world_hint is True
    assert fp.title.startswith("ACTIVE")
    assert tools["fingerprint_hosts"].description.lstrip().startswith("ACTIVE")


def test_main_reads_allow_active(monkeypatch, capsys):
    monkeypatch.setattr(mcp_server.mcp, "run", lambda: None)
    mcp_server.main([])
    assert mcp_server.ALLOW_ACTIVE is False
    mcp_server.main(["--allow-active"])
    assert mcp_server.ALLOW_ACTIVE is True
    err = capsys.readouterr().err
    assert "active tools off" in err and "active tools ON" in err


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
    monkeypatch.setattr(mcp_server, "ALLOW_ACTIVE", True)
    sent = fake_plain_http_host(monkeypatch)
    result = mcp_server.fingerprint_hosts(["dev"], detail="full")
    assert sent == ["https://dev/", "http://dev/"]
    assert result["requests_sent"] == 2  # requests, not hosts: matches the log
    log = [json.loads(line) for line in (results_dir / "active.log").read_text().splitlines()]
    assert [entry["url"] for entry in log] == sent
    dev = result["hosts"]["dev"]
    assert dev["url"] == "http://dev/" and dev["https_error"] == "SSLError"
    assert result["errors"] == {}


def test_broken_https_is_owned_by_server_and_cdn(monkeypatch):
    monkeypatch.setattr(mcp_server, "ALLOW_ACTIVE", True)
    fake_plain_http_host(monkeypatch)
    result = mcp_server.fingerprint_hosts(["dev"])
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


def test_exposed_refused_when_active_is_off(monkeypatch, results_dir):
    sent = fake_exposed_web(monkeypatch, {})
    with pytest.raises(mcp_server.ToolError, match="nothing was sent"):
        mcp_server.check_exposed_files(EXP_HOSTS)
    assert sent == []
    assert_only_a_refusal(results_dir)  # v1.12: refusals are logged, requests none


def test_exposed_refusal_reason_reaches_the_client(monkeypatch):
    fake_exposed_web(monkeypatch, {})
    with pytest.raises(mcp_server.ToolError, match="--allow-active"):
        asyncio.run(mcp_server.mcp.call_tool("check_exposed_files", {"hostnames": ["app"]}))


def test_exposed_refused_before_any_lookup(monkeypatch):
    def boom(hosts):
        raise AssertionError("DNS lookup ran while active tools were off")
    monkeypatch.setattr(mcp_server, "enrich", boom)
    with pytest.raises(mcp_server.ToolError):
        mcp_server.check_exposed_files(["app"])


def test_exposed_finds_spec_and_map_with_owners(monkeypatch):
    monkeypatch.setattr(mcp_server, "ALLOW_ACTIVE", True)
    fake_exposed_web(monkeypatch, {
        "https://app/openapi.json": MapResp(body=EXPOSED_OPENAPI),
        "https://app/": MapResp(body=b'<script src="/app.js"></script>'),
        "https://app/app.js": MapResp(headers={"sourcemap": "app.js.map"}, body=b"x=1"),
        "https://app/app.js.map": MapResp(body=EXPOSED_MAP)})
    result = mcp_server.check_exposed_files(EXP_HOSTS, detail="full")
    assert result["hosts_checked"] == 2 and result["not_requested"] == ["intranet"]
    app = result["hosts"]["app"]
    assert app["spec"]["type"] == "OpenAPI" and app["spec"]["declares_auth"] is True
    assert app["spec"]["owners"] == ["web app team", "CDN / proxy admin"]
    [m] = app["source_maps"]
    assert m["has_source_content"] is True and m["owners"] == ["web app team"]
    # the embedded source code never appears in what the tool returns
    assert "secret code" not in json.dumps(result)


def test_exposed_summary_counts_and_flags_source_code(monkeypatch):
    monkeypatch.setattr(mcp_server, "ALLOW_ACTIVE", True)
    fake_exposed_web(monkeypatch, {
        "https://app/openapi.json": MapResp(body=EXPOSED_OPENAPI),
        "https://app/": MapResp(body=b'<script src="/app.js"></script>'),
        "https://app/app.js": MapResp(headers={"sourcemap": "app.js.map"}, body=b"x=1"),
        "https://app/app.js.map": MapResp(body=EXPOSED_MAP)})
    result = mcp_server.check_exposed_files(EXP_HOSTS)  # summary mode
    assert result["specs_found"] == 1 and result["source_maps_found"] == 1
    assert result["maps_with_source_code"] == ["app"]
    assert result["specs"][0]["endpoints"] == 2
    assert result["hosts_with_findings"] == 1


def test_exposed_logs_each_request_and_counts_them(monkeypatch, results_dir):
    monkeypatch.setattr(mcp_server, "ALLOW_ACTIVE", True)
    sent = fake_exposed_web(monkeypatch, {
        "https://app/openapi.json": MapResp(body=EXPOSED_OPENAPI),
        "https://app/": MapResp(body=b"<html></html>")})
    result = mcp_server.check_exposed_files(EXP_HOSTS)
    log = [json.loads(line) for line in (results_dir / "active.log").read_text().splitlines()]
    assert result["requests_sent"] == len(log) == len(sent)
    assert {entry["tool"] for entry in log} == {"check_exposed_files"}
    assert all(entry["host"] == "app" for entry in log)  # intranet was never contacted


def test_exposed_clean_host_is_no_finding(monkeypatch):
    monkeypatch.setattr(mcp_server, "ALLOW_ACTIVE", True)
    fake_exposed_web(monkeypatch, {"https://app/": MapResp(body=b"<html></html>")})
    result = mcp_server.check_exposed_files(EXP_HOSTS)
    assert result["hosts_with_findings"] == 0 and result["specs_found"] == 0


def test_exposed_suggests_next_active_and_passive_checks(monkeypatch):
    monkeypatch.setattr(mcp_server, "ALLOW_ACTIVE", True)
    fake_exposed_web(monkeypatch, {"https://app/openapi.json": MapResp(body=EXPOSED_OPENAPI),
                                   "https://app/": MapResp(body=b"<html></html>")})
    result = mcp_server.check_exposed_files(EXP_HOSTS)
    # app sits on a public IP of its own, so --ports follows; it never suggests
    # itself, and it doesn't point back at its active sibling --fingerprint
    assert flags(result) == ["--ports"]


# --- scope (v1.12) -----------------------------------------------------------

def test_active_tools_refuse_without_a_usable_scope_even_when_on(monkeypatch):
    monkeypatch.setattr(mcp_server, "ALLOW_ACTIVE", True)
    monkeypatch.setattr(mcp_server, "SCOPE", None)
    monkeypatch.setattr(mcp_server, "SCOPE_PROBLEM", scope.NO_SCOPE)

    def boom(*args, **kwargs):
        raise AssertionError("DNS lookup ran without an approved scope")
    monkeypatch.setattr(mcp_server, "enrich", boom)
    for tool in (mcp_server.fingerprint_hosts, mcp_server.check_exposed_files):
        with pytest.raises(mcp_server.ToolError, match="no scope file is approved"):
            tool(["www.example.test"])


def test_scope_refusal_reason_reaches_the_client(monkeypatch):
    monkeypatch.setattr(mcp_server, "ALLOW_ACTIVE", True)
    monkeypatch.setattr(mcp_server, "SCOPE_PROBLEM", "the scope file changed since it was approved")
    with pytest.raises(Exception, match="changed since it was approved"):
        asyncio.run(mcp_server.mcp.call_tool("fingerprint_hosts",
                                             {"hostnames": ["www.example.test"]}))


def test_no_tool_takes_a_scope_argument():
    # Invariant 4: the agent can never supply or change the scope
    for tool in asyncio.run(mcp_server.mcp.list_tools()):
        params = tool.input_schema.get("properties", {})
        assert not any("scope" in name.lower() for name in params), tool.name


def test_server_starts_fail_closed():
    # The module's own defaults, before main() runs, checked in a fresh Python
    import subprocess
    import sys
    code = "from monomi import mcp_server, scope; print(mcp_server.SCOPE is None, mcp_server.SCOPE_PROBLEM == scope.NO_SCOPE)"
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                         cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    assert out.stdout.split() == ["True", "True"], out.stderr


def test_main_reads_and_pins_the_scope(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(mcp_server.mcp, "run", lambda: None)
    f = tmp_path / "scope.txt"
    f.write_bytes(b"example.test\n*.example.test\n!dev.example.test\n")
    digest = scope.load(str(f)).sha256
    mcp_server.main(["--allow-active", "--scope", str(f), "--scope-sha256", digest])
    assert mcp_server.SCOPE_PROBLEM is None
    assert mcp_server.SCOPE.match("www.example.test").allowed
    err = capsys.readouterr().err
    assert f"scope {f} sha256 {digest} (2 in, 1 excluded)" in err  # full hash at startup


def test_main_refuses_a_scope_edited_after_approval(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(mcp_server.mcp, "run", lambda: None)
    f = tmp_path / "scope.txt"
    f.write_bytes(b"*.example.test\n")
    digest = scope.load(str(f)).sha256
    f.write_bytes(b"*.example.test\n*.other.test\n")
    mcp_server.main(["--allow-active", "--scope", str(f), "--scope-sha256", digest])
    assert "changed since it was approved" in mcp_server.SCOPE_PROBLEM
    assert "scope REFUSED: the scope file changed" in capsys.readouterr().err
    with pytest.raises(mcp_server.ToolError, match="changed since it was approved"):
        mcp_server.require_active("fingerprint_hosts")


def test_main_without_a_scope_says_so(monkeypatch, capsys):
    monkeypatch.setattr(mcp_server.mcp, "run", lambda: None)
    mcp_server.main(["--allow-active"])
    assert mcp_server.SCOPE_PROBLEM == scope.NO_SCOPE
    assert "active tools ON; scope REFUSED: no scope file is approved" in capsys.readouterr().err


# --- per-host scope filter + audit log (v1.12) -------------------------------

LAB_SCOPE = b"example.test\n*.example.test\n!dev.example.test\n"


@pytest.fixture
def lab_scope(monkeypatch):
    """A real approved scope (not AllowAll) with active tools on."""
    s = scope.from_bytes(LAB_SCOPE, "scope.txt")
    monkeypatch.setattr(mcp_server, "SCOPE", s)
    monkeypatch.setattr(mcp_server, "SCOPE_PROBLEM", None)
    monkeypatch.setattr(mcp_server, "ALLOW_ACTIVE", True)
    return s


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
    result = getattr(mcp_server, tool)(ASKED, detail="full")
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
    result = getattr(mcp_server, tool)(ASKED)
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
    result = mcp_server.fingerprint_hosts(ASKED)
    assert result["out_of_scope_count"] == 2 and len(result["out_of_scope"]) == 2


def test_all_hosts_out_of_scope_sends_nothing(monkeypatch, results_dir, lab_scope):
    looked_up, sent = lab_web(monkeypatch, mcp_server.fingerprint)
    result = mcp_server.fingerprint_hosts(["evil.test", "dev.example.test"])
    assert looked_up == [] and sent == [] and result["requests_sent"] == 0
    assert result["out_of_scope_count"] == 2


def test_scope_problem_refusal_is_logged_with_its_reason(monkeypatch, results_dir):
    monkeypatch.setattr(mcp_server, "ALLOW_ACTIVE", True)
    monkeypatch.setattr(mcp_server, "SCOPE", None)
    monkeypatch.setattr(mcp_server, "SCOPE_PROBLEM", scope.NO_SCOPE)
    with pytest.raises(mcp_server.ToolError):
        mcp_server.check_exposed_files(["www.example.test"])
    [line] = read_log(results_dir)
    assert line["event"] == "refused" and line["reason"] == scope.NO_SCOPE
    assert line["tool"] == "check_exposed_files" and line["scope_sha256"] is None


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
