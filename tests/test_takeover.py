import takeover
from evidence import build_evidence
from takeover import check_host, check_hosts, inspect_host, match_not_claimable, match_service


def fake_dns(monkeypatch, cnames, dead):
    """Replace the real DNS lookups with made-up answers.

    cnames: {host: where its CNAME points}. Hosts not listed have no CNAME.
    dead:   names that don't exist (NXDOMAIN).
    """
    monkeypatch.setattr(takeover, "get_cname", lambda name: cnames.get(name))
    monkeypatch.setattr(takeover, "name_exists", lambda name: name not in dead)


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
    monkeypatch.setattr(takeover, "name_exists", lambda name: False)

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
