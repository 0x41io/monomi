import pytest

from monomi import dnscheck, takeover
from monomi.evidence import build_evidence
from monomi.takeover import check_host, check_hosts, in_domain, inspect_host, match_not_claimable, match_provider, match_service

# Both DNS-over-HTTPS providers confirmed the NXDOMAIN (see dnscheck.check_exists)
DOH_BOTH = ["Cloudflare", "Google"]


def fake_dns(monkeypatch, cnames, dead):
    """Replace the real DNS lookups with made-up answers.

    cnames: {host: where its CNAME points}. Hosts not listed have no CNAME.
    dead:   names that don't exist (NXDOMAIN).
    """
    monkeypatch.setattr(takeover, "get_cname", lambda name: cnames.get(name))
    monkeypatch.setattr(takeover, "check_exists", lambda name: (name not in dead, DOH_BOTH if name in dead else []))


# --- matching services ---

def test_known_service_matches():
    assert match_service("myapp.azurewebsites.net") == "Azure App Service"


def test_unknown_target_does_not_match():
    assert match_service("www.example.com") is None


def test_lookalike_domain_does_not_match():
    assert match_service("evilazurewebsites.net") is None


# --- checking one host ---

def test_no_cname_is_not_a_lead(monkeypatch):
    fake_dns(monkeypatch, cnames={}, dead=set())
    assert check_host("www.example.com") is None


def test_missing_host_is_no_such_host_not_no_cname(monkeypatch):
    def gone(name):
        raise takeover.NoSuchHost(name)
    monkeypatch.setattr(takeover, "get_cname", gone)
    result = inspect_host("old.example.com")
    assert result["status"] == "no_such_host"
    assert result["lead"] is None


def test_cname_to_live_target_is_not_a_lead(monkeypatch):
    fake_dns(monkeypatch, cnames={"app.example.com": "myapp.azurewebsites.net"}, dead=set())
    assert check_host("app.example.com") is None


def test_dangling_cname_to_known_service_is_claimable(monkeypatch):
    fake_dns(monkeypatch, cnames={"app.example.com": "gone.azurewebsites.net"},
             dead={"gone.azurewebsites.net"})
    lead = check_host("app.example.com")
    assert lead["cname"] == "gone.azurewebsites.net"
    assert lead["service"] == "Azure App Service"
    assert lead["claimable"] is True


def test_dangling_cname_to_unknown_target_is_still_a_lead(monkeypatch):
    fake_dns(monkeypatch, cnames={"promo.example.com": "old-campaign.com"},
             dead={"old-campaign.com"})
    lead = check_host("promo.example.com")
    assert lead["service"] is None
    assert lead["claimable"] is False


def test_dangling_cname_to_load_balancer_is_stale_not_a_lead(monkeypatch):
    target = "internal-lb-sorter-prd-1879541874.sa-east-1.elb.amazonaws.com"
    fake_dns(monkeypatch, cnames={"amr.example.com": target}, dead={target})
    info = inspect_host("amr.example.com")
    assert info["status"] == "stale"
    assert info["lead"] is None
    assert info["stale"]["service"] == "AWS Elastic Load Balancing"


def test_dangling_cname_inside_own_domain_is_stale_not_a_lead(monkeypatch):
    fake_dns(monkeypatch, cnames={"www.designdelivered.wolt.com": "designdelivered.wolt.com"},
             dead={"designdelivered.wolt.com"})
    result = inspect_host("www.designdelivered.wolt.com", domain="wolt.com")
    assert result["status"] == "stale"
    assert result["lead"] is None
    assert "wolt.com" in result["stale"]["reason"]


def test_lookalike_domain_is_not_same_domain():
    assert in_domain("designdelivered.wolt.com", "wolt.com")
    assert in_domain("wolt.com", "wolt.com")
    assert not in_domain("evilwolt.com", "wolt.com")


def test_live_load_balancer_is_just_cname_ok(monkeypatch):
    target = "internal-lb-1553539328.sa-east-1.elb.amazonaws.com"
    fake_dns(monkeypatch, cnames={"amr.example.com": target}, dead=set())
    assert inspect_host("amr.example.com")["status"] == "cname_ok"


def test_lookalike_load_balancer_domain_does_not_match():
    assert match_not_claimable("evil-elb.amazonaws.com.attacker.net") is None
# --- checking many hosts ---


def test_one_broken_host_does_not_stop_the_scan(monkeypatch):
    def flaky_cname(name):
        if name == "broken.example.com":
            raise takeover.DNSLookupError("no DNS server answered")
        return {"app.example.com": "gone.azurewebsites.net"}.get(name)

    monkeypatch.setattr(takeover, "get_cname", flaky_cname)
    monkeypatch.setattr(takeover, "check_exists", lambda name: (False, DOH_BOTH))

    report = check_hosts(["app.example.com", "broken.example.com", "www.example.com"])
    assert report["checked"] == 3
    assert [lead["host"] for lead in report["leads"]] == ["app.example.com"]
    assert list(report["errors"]) == ["broken.example.com"]


# --- evidence items ---

def base_results(takeover_report):
    return {"target": "example.com", "sources": {}, "subdomains": [], "takeover": takeover_report}


def test_lead_becomes_evidence():
    lead = {"host": "app.example.com", "cname": "gone.azurewebsites.net", "service": "Azure App Service",
            "claimable": True, "collected_at": "2026-10-25T16:00:00+00:00"}
    report = {"leads": [lead], "checked": 1, "errors": {}, "collected_at": "2026-10-25T16:00:00+00:00"}
    facts = [e["fact"] for e in build_evidence(base_results(report))]
    assert any("gone.azurewebsites.net" in f and "claimed again" in f for f in facts)


def test_stale_record_becomes_evidence_not_a_lead():
    record = {"host": "amr.example.com", "cname": "internal-lb-1.sa-east-1.elb.amazonaws.com",
              "service": "AWS Elastic Load Balancing", "collected_at": "2026-11-01T03:11:30+00:00"}
    report = {"leads": [], "stale": [record], "checked": 1, "errors": {},
              "collected_at": "2026-11-01T03:11:30+00:00"}
    facts = [e["fact"] for e in build_evidence(base_results(report))]
    assert any("stale DNS record, not a takeover risk" in f for f in facts)
    assert not any(f.startswith("Takeover check: none of") for f in facts)


def test_clean_result_still_becomes_evidence():
    report = {"leads": [], "checked": 5, "errors": {"x.example.com": "timeout"},
              "collected_at": "2026-10-25T16:00:00+00:00"}
    facts = [e["fact"] for e in build_evidence(base_results(report))]
    assert any(f.startswith("Takeover check: none of 4 hostnames") for f in facts)


def test_get_cname_returns_the_target(monkeypatch):
    class FakeAnswer:
        target = "MyApp.AzureWebsites.net."

    class FakeResolver:
        def resolve(self, name, rtype, lifetime):
            return [FakeAnswer()]

    monkeypatch.setattr(dnscheck, "_resolvers", lambda: (FakeResolver(),))
    assert takeover.get_cname("app.example.com") == "myapp.azurewebsites.net"


def test_nlb_dangling_cname_is_stale(monkeypatch):
    target = "app-nlb-1a2b3c.elb.us-east-1.amazonaws.com"
    fake_dns(monkeypatch, cnames={"api.example.com": target}, dead={target})
    result = inspect_host("api.example.com")
    assert result["status"] == "stale"
    assert result["stale"]["service"] == "AWS Elastic Load Balancing"


def test_nlb_govcloud_and_china_match():
    assert match_not_claimable("x-1.elb.us-gov-west-1.amazonaws.com") == "AWS Elastic Load Balancing"
    assert match_not_claimable("x-1.elb.cn-north-1.amazonaws.com.cn") == "AWS Elastic Load Balancing"
    assert match_not_claimable("x.cn-north-1.elb.amazonaws.com.cn") == "AWS Elastic Load Balancing"


def test_s3_and_lookalike_nlb_do_not_match():
    assert match_not_claimable("bucket.s3.amazonaws.com") is None
    assert match_not_claimable("evil.elb.us-east-1.amazonaws.com.attacker.net") is None


def test_provider_domain_matches():
    assert match_provider("web-1.svc.us-east-1.amazonaws.com") == "AWS"
    assert match_provider("x.blob.core.windows.net") == "Microsoft Azure"
    assert match_provider("gone.blog-example.com") is None
    assert match_provider("evil.amazonaws.com.attacker.net") is None


# --- AWS API Gateway (v1.13.1): random-ID names, so stale, not a lead ---

@pytest.mark.parametrize("target", [
    "d-ab12cd34ef.execute-api.us-east-1.amazonaws.com",   # a custom domain's target
    "a1b2c3d4e5.execute-api.eu-west-2.amazonaws.com",     # an API's own name
])
def test_api_gateway_names_are_not_claimable(target):
    assert match_not_claimable(target) == "AWS API Gateway"


def test_lookalike_api_gateway_name_does_not_match():
    assert match_not_claimable("x.execute-api.us-east-1.amazonaws.com.attacker.net") is None


def test_dangling_api_gateway_cname_is_stale_not_a_lead(monkeypatch):
    fake_dns(monkeypatch, {"api.example.com": "d-ab12cd34ef.execute-api.us-east-1.amazonaws.com"},
             dead={"d-ab12cd34ef.execute-api.us-east-1.amazonaws.com"})
    result = inspect_host("api.example.com")
    assert result["status"] == "stale" and result["lead"] is None
    assert result["stale"]["service"] == "AWS API Gateway"


# --- v1.17: lame NS delegations grouped by zone cut (dangling_ns candidate) ---

def _lame(ns_ips, detail="Name servers refused query (lame delegation?)"):
    e = takeover.ServerFailure("SERVFAIL")
    e.detail = detail
    e.ns_ips = ns_ips
    e.lame = True
    return e


def test_lame_delegation_grouped_under_its_zone_cut(monkeypatch):
    def cname(name):
        raise _lame(["205.251.192.127"])
    monkeypatch.setattr(takeover, "get_cname", cname)
    monkeypatch.setattr(takeover, "find_zone_cut",
                        lambda h, **kw: ("local-dev.example.com", {"detail": "d", "ns_ips": ["205.251.192.127"]}))
    report = check_hosts(["alice.local-dev.example.com", "bob.local-dev.example.com"])
    assert len(report["ns_delegations"]) == 1
    d = report["ns_delegations"][0]
    assert d["cut"] == "local-dev.example.com"
    assert d["hosts"] == ["alice.local-dev.example.com", "bob.local-dev.example.com"]
    assert d["ns_ips"] == ["205.251.192.127"]
    # the hosts still show as servfail errors, as before
    assert report["results"]["alice.local-dev.example.com"]["status"] == "servfail"


def test_zone_cut_found_once_for_many_hosts(monkeypatch):
    calls = []
    monkeypatch.setattr(takeover, "get_cname", lambda name: (_ for _ in ()).throw(_lame(["203.0.113.9"])))

    def counting_cut(h, **kw):
        calls.append(h)
        return ("dev.example.com", {"detail": "d", "ns_ips": ["203.0.113.9"]})
    monkeypatch.setattr(takeover, "find_zone_cut", counting_cut)
    check_hosts(["a.dev.example.com", "b.dev.example.com", "c.dev.example.com"])
    assert len(calls) == 1          # walked the delegation once, not once per host


def test_walk_gets_known_lame_info_and_one_shared_cache(monkeypatch):
    # v1.17.1: the host's own lame answer is handed to the walk (not asked
    # again), and every walk in the run shares one cache
    seen = []

    def spy_cut(h, known=None, cache=None):
        seen.append((h, known, cache))
        return (h.split(".", 1)[1], known)
    monkeypatch.setattr(takeover, "get_cname", lambda name: (_ for _ in ()).throw(_lame(["203.0.113.9"])))
    monkeypatch.setattr(takeover, "find_zone_cut", spy_cut)
    check_hosts(["a.one.example.com", "b.two.example.com"])
    assert len(seen) == 2
    assert all(known and known["ns_ips"] == ["203.0.113.9"] for _, known, _ in seen)
    assert seen[0][2] is seen[1][2]     # the same dict, not a fresh one per walk


def test_plain_servfail_is_not_a_delegation(monkeypatch):
    plain = takeover.ServerFailure("SERVFAIL")   # lame defaults to False
    monkeypatch.setattr(takeover, "get_cname", lambda name: (_ for _ in ()).throw(plain))
    report = check_hosts(["busy.example.com"])
    assert report["ns_delegations"] == []
    assert report["results"]["busy.example.com"]["status"] == "servfail"


def test_grade_route53_nameservers_theoretical():
    assert takeover.grade_delegation(["205.251.192.127", "205.251.198.35"]) == ("theoretical", "AWS Route 53")


def test_grade_unrecognized_nameserver_investigate():
    assert takeover.grade_delegation(["205.251.192.127", "198.51.100.9"]) == ("investigate", None)
    assert takeover.grade_delegation(["198.51.100.9"]) == ("investigate", None)


def test_grade_no_ips_investigate():
    assert takeover.grade_delegation([]) == ("investigate", None)
    assert takeover.grade_delegation(["not-an-ip"]) == ("investigate", None)


def test_delegation_record_carries_its_grade(monkeypatch):
    monkeypatch.setattr(takeover, "get_cname", lambda name: (_ for _ in ()).throw(_lame(["205.251.196.249"])))
    monkeypatch.setattr(takeover, "find_zone_cut",
                        lambda h, **kw: ("local-dev.example.com", {"detail": "d", "ns_ips": ["205.251.196.249"]}))
    d = check_hosts(["a.local-dev.example.com"])["ns_delegations"][0]
    assert (d["grade"], d["provider"]) == ("theoretical", "AWS Route 53")


def test_delegation_becomes_one_evidence_fact():
    report = {"leads": [], "stale": [], "checked": 2, "errors": {}, "collected_at": None,
              "ns_delegations": [{"cut": "local-dev.example.com", "hosts": ["a.local-dev.example.com"],
                                  "ns_ips": ["205.251.192.127"], "detail": "d", "collected_at": None,
                                  "grade": "theoretical", "provider": "AWS Route 53"}]}
    facts = [e for e in build_evidence(base_results(report)) if e["kind"] == "dangling_ns"]
    assert len(facts) == 1
    assert facts[0]["host"] == "local-dev.example.com"
    assert "lame delegation" in facts[0]["fact"] and "AWS Route 53" in facts[0]["fact"]
    assert facts[0]["owners"] == ["DNS admin"]


# --- v1.17.1: the CLI counts lame hosts as checked ---

def test_cli_counts_lame_hosts_as_checked(monkeypatch, capsys):
    from monomi import cli
    monkeypatch.setattr(cli.takeover, "check_hosts", lambda hosts, domain=None: {
        "leads": [], "stale": [], "checked": 4,
        "results": {}, "errors": {"a.dev.example.test": "SERVFAIL", "b.dev.example.test": "SERVFAIL",
                                  "busy.example.test": "SERVFAIL"},
        "ns_delegations": [{"cut": "dev.example.test",
                            "hosts": ["a.dev.example.test", "b.dev.example.test"],
                            "ns_ips": ["205.251.192.127"], "detail": "d", "collected_at": None,
                            "grade": "theoretical", "provider": "AWS Route 53"}]})
    cli.run_takeover({"subdomains": ["x"] * 4, "target": "example.test"})
    out = capsys.readouterr().out
    assert "1 host(s) couldn't be checked" in out
    assert "No takeover leads among 3 hosts checked" in out     # 4 minus the 1 plain SERVFAIL


def test_cli_all_lame_hosts_means_none_unchecked(monkeypatch, capsys):
    from monomi import cli
    monkeypatch.setattr(cli.takeover, "check_hosts", lambda hosts, domain=None: {
        "leads": [], "stale": [], "checked": 1, "results": {},
        "errors": {"a.dev.example.test": "SERVFAIL"},
        "ns_delegations": [{"cut": "dev.example.test", "hosts": ["a.dev.example.test"],
                            "ns_ips": ["198.51.100.9"], "detail": "d", "collected_at": None,
                            "grade": "investigate", "provider": None}]})
    cli.run_takeover({"subdomains": ["x"], "target": "example.test"})
    out = capsys.readouterr().out
    assert "couldn't be checked" not in out
    assert "No takeover leads among 1 hosts checked" in out
