import enrich


def fake_resolve(hosts):
    """The fast first lookup (socket) failing for every host."""
    return {h: {"ips": [], "canonical": None} for h in hosts}


def test_enrich_groups_hosts_that_dont_resolve(monkeypatch):
    monkeypatch.setattr(enrich, "resolve", fake_resolve)
    statuses = {"old.example.com": ("no_such_host", []),
                "legacy.example.com": ("dangling_cname", []),
                "v6.example.com": ("ipv6_only", [])}
    monkeypatch.setattr(enrich, "host_status", lambda h: statuses[h])
    monkeypatch.setattr(enrich, "get_cname", lambda h: "gone.example.com")

    data = enrich.enrich(list(statuses))

    assert data["hosts"]["old.example.com"]["dns"] == "no_such_host"
    assert data["hosts"]["legacy.example.com"]["cname"] == "gone.example.com"
    assert "cname" not in data["hosts"]["old.example.com"]
    assert data["not_resolving"] == {"no_such_host": ["old.example.com"],
                                     "dangling_cname": ["legacy.example.com"],
                                     "ipv6_only": ["v6.example.com"]}
    assert data["providers"] == {"no DNS record": 1, "CNAME to a deleted name": 1, "IPv6 only": 1}
    assert data["resolved"] == 0


def test_enrich_keeps_ips_found_on_second_look(monkeypatch):
    # The lab's dev/www bug: the fast lookup failed (WSL's DNS cache), but the
    # shared helper got real IPs over HTTPS, so the host is live, not "gone"
    monkeypatch.setattr(enrich, "resolve", fake_resolve)
    monkeypatch.setattr(enrich, "host_status", lambda h: ("live", ["203.0.113.7"]))
    monkeypatch.setattr(enrich, "asn_lookup", lambda ips: {})

    data = enrich.enrich(["dev.example.com"])

    assert data["hosts"]["dev.example.com"]["ips"] == ["203.0.113.7"]
    assert data["hosts"]["dev.example.com"]["dns"] == "live"
    assert data["not_resolving"] == {}
    assert data["resolved"] == 1


def test_resolve_one_keeps_where_the_cname_ends(monkeypatch):
    monkeypatch.setattr(enrich.socket, "gethostbyname_ex",
                        lambda h: ("D3RX.cloudfront.net.", [h], ["18.154.101.92", "18.154.101.35"]))
    assert enrich._resolve_one("gslink.example.com") == {
        "ips": ["18.154.101.35", "18.154.101.92"], "canonical": "d3rx.cloudfront.net"}


def test_resolve_one_without_cname_has_no_canonical(monkeypatch):
    monkeypatch.setattr(enrich.socket, "gethostbyname_ex", lambda h: (h, [], ["1.2.3.4"]))
    assert enrich._resolve_one("www.example.com")["canonical"] is None


# --- Amazon's own range list labels AWS IPs (v1.13.1: Global Accelerator) ---

def test_aws_ips_are_labeled_from_amazons_range_list(monkeypatch):
    import ipaddress
    ips = {"cdn.example.com": "13.224.0.5", "front.example.com": "15.197.34.10",
           "server.example.com": "3.5.0.1"}
    monkeypatch.setattr(enrich, "resolve", lambda hosts: {h: {"ips": [ips[h]], "canonical": None} for h in hosts})
    monkeypatch.setattr(enrich, "asn_lookup", lambda public: {ip: {"as_name": "AWS"} for ip in public})
    # Amazon's list, faked: never downloaded in a test
    monkeypatch.setattr(enrich.aws_ranges, "cloudfront_networks", lambda: [ipaddress.ip_network("13.224.0.0/14")])
    monkeypatch.setattr(enrich.aws_ranges, "accelerator_networks", lambda: [ipaddress.ip_network("15.197.34.0/23")])

    hosts = enrich.enrich(list(ips))["hosts"]

    assert hosts["cdn.example.com"]["provider"] == "AWS CloudFront"
    assert hosts["front.example.com"]["provider"] == "AWS Global Accelerator"
    assert hosts["server.example.com"]["provider"] == "AWS"  # a plain AWS server stays the target's own


def test_cdck_is_named_as_discourse_hosting():
    assert enrich.friendly_name("CDCK, US") == "Discourse (CDCK)"
