"""Tests for internetdb.py: shared edge detection."""

import internetdb
from internetdb import edge_from_cpes, edge_reason


def test_cdn_network_owner_is_edge():
    assert edge_reason("Cloudflare", []) == "network owner is Cloudflare"


def test_cloudflare_cpe_on_own_network_is_edge():
    # The 1win case: Cloudflare serving from the company's own IP range
    reason = edge_reason("MFI-AS", ["cpe:/a:cloudflare:cloudflare"])
    assert reason == "Shodan identifies the service as Cloudflare (cpe:/a:cloudflare:cloudflare)"


def test_okta_cpe_is_edge():
    # The MercadoLibre case: Okta's login servers run on AWS
    assert edge_from_cpes(["cpe:/a:f5:nginx", "cpe:/a:okta::7.50.0"]) == ("Okta", "cpe:/a:okta::7.50.0")


def test_plain_server_is_not_edge():
    assert edge_reason("AWS", ["cpe:/a:apache:http_server"]) is None


def test_lookalike_cpe_part_does_not_match():
    assert edge_from_cpes(["cpe:/a:cloudflarex:thing"]) is None


def test_cpe_edge_ports_are_not_blamed_on_target(monkeypatch):
    shodan = {"ports": [80, 443, 2052, 8443], "vulns": [], "tags": [],
              "cpes": ["cpe:/a:cloudflare:cloudflare"]}
    monkeypatch.setattr(internetdb, "lookup_one", lambda ip: dict(shodan))
    enrichment = {"hosts": {"token.example.com": {"ips": ["194.67.193.73"], "provider": "MFI-AS"}},
                  "ip_info": {"194.67.193.73": {"provider": "MFI-AS"}}}
    result = internetdb.lookup(enrichment)
    ip = result["ips"]["194.67.193.73"]
    assert ip["shared_edge"] is True
    assert ip["edge_reason"].startswith("Shodan identifies the service as Cloudflare")

