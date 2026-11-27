"""Tests for internetdb.py: shared edge detection."""

from monomi import internetdb
from monomi.internetdb import edge_from_cname, edge_from_cpes, edge_from_ip, edge_reason, third_party_from_ip


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


# --- shared services found by address (v1.22.1, Marionnaud field run) ---

def test_google_front_end_is_the_four_exact_ips_only():
    for ip in ("216.239.32.21", "216.239.34.21", "216.239.36.21", "216.239.38.21"):
        assert third_party_from_ip(ip) == ("Google front end", f"{ip}/32")
    # the rest of Google's 216.239.32.0/19 is other services, never matched
    assert third_party_from_ip("216.239.32.22") is None
    assert third_party_from_ip("216.239.35.21") is None


def test_exchange_online_blocks():
    assert third_party_from_ip("52.96.79.8") == ("Microsoft 365", "52.96.0.0/14")
    assert third_party_from_ip("52.99.255.255") == ("Microsoft 365", "52.96.0.0/14")
    assert third_party_from_ip("40.96.1.1") == ("Microsoft 365", "40.96.0.0/13")
    assert third_party_from_ip("132.245.10.20") == ("Microsoft 365", "132.245.0.0/16")
    # next to the blocks, and other Microsoft space: a customer's Azure server could be there
    assert third_party_from_ip("52.100.0.1") is None
    assert third_party_from_ip("20.1.2.3") is None


def test_third_party_from_ip_ignores_what_isnt_an_ipv4_in_a_block():
    assert third_party_from_ip("not-an-ip") is None
    assert third_party_from_ip("2001:db8::1") is None


def test_front_doors_chain_end_counts_as_its_edge():
    # The Superdrug dev portal (v1.23): its CNAME chain ends on tm-azurefd.net,
    # which the ".azurefd.net" ending can't match (the label is "tm-azurefd")
    assert edge_from_cname({"mr-a02.tm-azurefd.net"}) == ("Azure Front Door", "mr-a02.tm-azurefd.net")
    name = "shed.dual-low.s-part-0017.t-0009.t-msedge.net"
    assert edge_from_cname({name}) == ("Azure Front Door", name)
    assert edge_from_cname({"evil-tm-azurefd.net"}) is None


def test_shared_hosting_is_known_by_cname():
    tp = internetdb.third_party_from_cname
    assert tp(["polite-sea-0a1b2c.azurestaticapps.net"]) == (
        "Azure Static Web Apps", "polite-sea-0a1b2c.azurestaticapps.net")
    assert tp(["shops.myshopify.com."]) == ("Shopify", "shops.myshopify.com")
    assert tp(["shop.azurewebsites.net"]) == ("Azure App Service", "shop.azurewebsites.net")
    # Endings start with a dot: a look-alike domain doesn't count
    assert tp(["evilazurestaticapps.net"]) is None
    assert tp([]) is None


def test_only_app_services_shared_front_end_is_third_party_on_cloudapp():
    # waws-prod names are App Service's shared front ends; any other
    # cloudapp.azure.com name is a customer's own VM or load balancer
    tp = internetdb.third_party_from_cname
    name = "waws-prod-ln1-175-3cf9.uksouth.cloudapp.azure.com"
    assert tp([name]) == ("Azure App Service", name)
    assert tp(["myvm.uksouth.cloudapp.azure.com"]) is None
    assert tp(["waws-prod-ln1-175.uksouth.cloudapp.azure.com.evil"]) is None


def test_shopify_storefront_block_is_third_party():
    assert third_party_from_ip("23.227.38.65") == ("Shopify", "23.227.38.0/24")
    assert third_party_from_ip("23.227.38.32") == ("Shopify", "23.227.38.0/24")
    assert third_party_from_ip("23.227.39.1") is None


def test_cves_on_someone_elses_server_arent_the_targets(monkeypatch):
    # v1.23.1, the Superdrug run: jQuery UI CVEs on Google's shared front end
    # were counted as the target's, and 0x41's report listed them as such
    shodan = {"216.239.32.21": {"ports": [80, 443], "vulns": ["CVE-2021-41184"], "tags": [], "cpes": []},
              "9.9.9.9": {"ports": [443, 3389], "vulns": ["CVE-2024-0001"], "tags": [], "cpes": []}}
    monkeypatch.setattr(internetdb, "lookup_one", lambda ip: dict(shodan[ip]))
    enrichment = {"hosts": {"ecom.shop.test": {"ips": ["216.239.32.21"], "provider": "Google"},
                            "app.shop.test": {"ips": ["9.9.9.9"], "provider": "DigitalOcean"}},
                  "ip_info": {}}
    result = internetdb.lookup(enrichment)
    google = result["ips"]["216.239.32.21"]
    assert google["not_own"] == "third-party hosting (Google front end)" and google["shared_edge"] is False
    assert "not_own" not in result["ips"]["9.9.9.9"]
    assert result["unique_cves"] == ["CVE-2024-0001"]          # Google's CVE left out
    assert result["risky"] == [("9.9.9.9", ["3389/RDP"])]
    assert internetdb.is_own(result["ips"]["9.9.9.9"]) and not internetdb.is_own(google)


def test_without_the_label_googles_cve_was_counted(monkeypatch):
    # The removal test: no third-party address list, and the CVE counts again
    monkeypatch.setattr(internetdb, "THIRD_PARTY_RANGES", [])
    monkeypatch.setattr(internetdb, "lookup_one",
                        lambda ip: {"ports": [443], "vulns": ["CVE-2021-41184"], "tags": [], "cpes": []})
    result = internetdb.lookup({"hosts": {"ecom.shop.test": {"ips": ["216.239.32.21"], "provider": "Google"}},
                                "ip_info": {}})
    assert result["unique_cves"] == ["CVE-2021-41184"]


def test_a_cdn_edge_gets_no_not_own_label(monkeypatch):
    # shared_edge already says it; not_own is for servers that aren't a CDN
    monkeypatch.setattr(internetdb, "lookup_one",
                        lambda ip: {"ports": [443], "vulns": [], "tags": [], "cpes": []})
    result = internetdb.lookup({"hosts": {"www.shop.test": {"ips": ["1.1.1.1"], "provider": "Cloudflare"}},
                                "ip_info": {}})
    assert result["ips"]["1.1.1.1"]["shared_edge"] is True
    assert "not_own" not in result["ips"]["1.1.1.1"]


# --- v1.29.2: over the cap, the target's own servers are looked up first ---

def _mixed(own=3, edges=4):
    """own servers on AWS (public addresses), edges on Akamai; the edges sort
    FIRST as text (23.x before 54.x), like PlayStation's Akamai addresses."""
    hosts, info = {}, {}
    for i in range(edges):
        ip = f"23.2.157.{10 + i}"
        hosts[f"edge{i}.example.com"] = {"ips": [ip], "provider": "Akamai"}
        info[ip] = {"provider": "Akamai"}
    for i in range(own):
        ip = f"54.189.166.{130 + i}"
        hosts[f"own{i}.example.com"] = {"ips": [ip], "provider": "AWS"}
        info[ip] = {"provider": "AWS"}
    return {"hosts": hosts, "ip_info": info}


def test_over_the_cap_own_servers_are_checked_before_cdn_edges(monkeypatch):
    """PlayStation: 655 IPs cut at 200 in text order skipped zitadel.sit.pcs
    (54.189.166.133) while Akamai edges (23.x) were checked."""
    asked = []
    monkeypatch.setattr(internetdb, "MAX_IPS", 4)
    monkeypatch.setattr(internetdb, "lookup_one", lambda ip: asked.append(ip) or None)
    result = internetdb.lookup(_mixed(own=3, edges=4), workers=1)
    assert asked[:3] == ["54.189.166.130", "54.189.166.131", "54.189.166.132"]
    assert result["checked"] == 4 and result["skipped"] == 3 and result["skipped_edges"] == 3


def test_under_the_cap_everything_is_checked(monkeypatch):
    asked = []
    monkeypatch.setattr(internetdb, "lookup_one", lambda ip: asked.append(ip) or None)
    result = internetdb.lookup(_mixed(own=2, edges=2), workers=1)
    assert len(asked) == 4 and result["skipped"] == 0 and result["skipped_edges"] == 0


def test_when_own_servers_alone_pass_the_cap_the_skip_says_so(monkeypatch):
    monkeypatch.setattr(internetdb, "MAX_IPS", 2)
    monkeypatch.setattr(internetdb, "lookup_one", lambda ip: None)
    result = internetdb.lookup(_mixed(own=4, edges=1), workers=1)
    assert result["skipped"] == 3 and result["skipped_edges"] == 1  # 2 own servers + the edge left out


def test_cli_says_what_kind_of_ips_were_skipped(monkeypatch, capsys):
    from monomi import cli
    monkeypatch.setattr(internetdb, "MAX_IPS", 4)
    monkeypatch.setattr(internetdb, "lookup_one", lambda ip: None)
    results = {"target": "example.com", "errors": {}}
    cli.run_ports(results, _mixed(own=3, edges=4), None)
    out = capsys.readouterr().out
    assert "Only 4 IPs were checked, the target's own servers first (3 skipped: all of them CDN edges" in out
