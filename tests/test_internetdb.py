"""Tests for internetdb.py: shared edge detection."""

import internetdb
from internetdb import edge_from_cname, edge_from_cpes, edge_from_ip, edge_reason

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




def test_okta_cname_is_edge():
    assert edge_from_cname({"meli.customdomains.okta.com"}) == ("Okta", "meli.customdomains.okta.com")


def test_lookalike_cname_does_not_match():
    # No dot before "cloudfront.net", so it's someone else's domain
    assert edge_from_cname({"evilcloudfront.net"}) is None


def test_cname_is_used_when_owner_and_cpes_say_nothing():
    reason = edge_reason("AWS", [], {"d3rx.cloudfront.net"})
    assert reason == "hostname's CNAME points to AWS CloudFront (d3rx.cloudfront.net)"


def test_network_owner_wins_over_cname():
    assert edge_reason("Cloudflare", [], {"x.cloudfront.net"}) == "network owner is Cloudflare"


def test_cname_edge_ports_are_not_blamed_on_target(monkeypatch):
    # The adminml.com case: Okta on plain AWS IPs, Shodan has no Okta CPE
    shodan = {"ports": [80, 443], "vulns": ["CVE-2023-0001"], "tags": [], "cpes": []}
    monkeypatch.setattr(internetdb, "lookup_one", lambda ip: dict(shodan))
    enrichment = {"hosts": {"auth.example.com": {"ips": ["3.3.3.3"], "provider": "AWS",
                                                 "canonical": "example.customdomains.okta.com"}},
                  "ip_info": {"3.3.3.3": {"provider": "AWS"}}}
    result = internetdb.lookup(enrichment)
    ip = result["ips"]["3.3.3.3"]
    assert ip["shared_edge"] is True
    assert ip["edge_reason"] == "hostname's CNAME points to Okta (example.customdomains.okta.com)"
    assert result["unique_cves"] == []  # Okta's CVE isn't blamed on the target

def test_ips_shodan_has_nothing_on_are_still_listed(monkeypatch):
    # The lab Droplet: an origin server Shodan hasn't crawled yet. It must
    # show up as "nothing seen", not vanish from the result.
    monkeypatch.setattr(internetdb, "lookup_one", lambda ip: None)
    enrichment = {"hosts": {"dev.example.com": {"ips": ["64.227.89.72"], "provider": "DigitalOcean"}},
                  "ip_info": {"64.227.89.72": {"provider": "DigitalOcean"}}}
    result = internetdb.lookup(enrichment)
    assert result["ips"] == {}
    assert result["nothing_seen"] == {"64.227.89.72": {
        "hosts": ["dev.example.com"], "provider": "DigitalOcean", "shared_edge": False}}


# --- Vercel: its IP blocks are announced through AWS, so the owner says "AWS" ---
# Names are built from pieces so the chat app can't turn them into links

COM = ".com"


def test_vercel_ip_is_edge_even_when_owner_says_aws():
    # The Yuga Labs case: 216.150.1.x labeled AWS (AS16509)
    reason = edge_reason("AWS", [], (), "216.150.1.1")
    assert reason == "IP is in Vercel's edge range (216.150.1.0/24)"


def test_ip_outside_the_ranges_is_not_edge():
    assert edge_from_ip("216.150.2.1") is None
    assert edge_from_ip("2001:db8::1") is None
    assert edge_from_ip("not-an-ip") is None


def test_numbered_vercel_cname_is_edge():
    name = "4f5c61a345ea02e1.vercel-dns-017" + COM
    assert edge_from_cname({name}) == ("Vercel", name)


def test_lookalike_vercel_cname_does_not_match():
    assert edge_from_cname({"evilvercel-dns" + COM}) is None
    assert edge_from_cname({"x.vercel-dns-017" + COM + ".evil"}) is None


def test_vercel_ports_are_not_blamed_on_target(monkeypatch):
    shodan = {"ports": [80, 443], "vulns": ["CVE-2023-0001"], "tags": [], "cpes": []}
    monkeypatch.setattr(internetdb, "lookup_one", lambda ip: dict(shodan))
    enrichment = {"hosts": {"app": {"ips": ["216.150.1.1"], "provider": "AWS"}},
                  "ip_info": {"216.150.1.1": {"provider": "AWS"}}}
    result = internetdb.lookup(enrichment)
    ip = result["ips"]["216.150.1.1"]
    assert ip["shared_edge"] is True
    assert ip["edge_reason"] == "IP is in Vercel's edge range (216.150.1.0/24)"
    assert result["unique_cves"] == []


def test_quiet_vercel_ip_is_still_edge(monkeypatch):
    # Shodan has nothing on it, but it's still Vercel's server, not the target's
    monkeypatch.setattr(internetdb, "lookup_one", lambda ip: None)
    enrichment = {"hosts": {"app": {"ips": ["216.198.79.1"], "provider": "AWS"}},
                  "ip_info": {"216.198.79.1": {"provider": "AWS"}}}
    result = internetdb.lookup(enrichment)
    assert result["nothing_seen"]["216.198.79.1"]["shared_edge"] is True
