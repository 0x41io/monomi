from monomi import enrich

# The real wildcard check, kept before conftest's no_wildcard_probes fixture
# swaps it out in every test (that fixture runs after this module is imported)
REAL_WILDCARD_ANSWERS = enrich.wildcard_answers


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


# --- v1.18: wildcard DNS ---

CDN_WILD = {"ips": ["1.1.1.1", "1.0.0.1"], "canonicals": []}


def test_zone_of_never_a_tld_or_shared_suffix():
    assert enrich._zone_of("a.example.test") == "example.test"
    assert enrich._zone_of("x.acc.example.test") == "acc.example.test"
    assert enrich._zone_of("example.test") is None          # zone would be the TLD
    assert enrich._zone_of("shop.co.uk") is None            # zone would be a shared suffix


def test_through_wildcard_cname_wildcard_matches_by_chain_end():
    w = {"ips": ["1.1.1.1"], "canonicals": ["d1.cdn.test"]}
    assert enrich.through_wildcard({"ips": ["1.0.0.9"], "canonical": "d1.cdn.test"}, w)
    assert not enrich.through_wildcard({"ips": ["1.1.1.1"], "canonical": "d2.cdn.test"}, w)


def test_through_wildcard_a_record_wildcard_matches_by_shared_ip():
    # a CDN rotates IPs: sharing one with the wildcard's pool is enough
    assert enrich.through_wildcard({"ips": ["1.0.0.1", "1.0.0.7"], "canonical": None}, CDN_WILD)
    assert not enrich.through_wildcard({"ips": ["9.9.9.9"], "canonical": None}, CDN_WILD)
    # a host with a CNAME of its own was set up on purpose
    assert not enrich.through_wildcard({"ips": ["1.1.1.1"], "canonical": "own.cdn.test"}, CDN_WILD)
    assert not enrich.through_wildcard({"ips": [], "canonical": None}, CDN_WILD)


def _fake_dns(monkeypatch, answers, wildcards, asn=None):
    """answers: host -> ips; wildcards: zone -> wildcard answer."""
    monkeypatch.setattr(enrich, "resolve",
                        lambda hosts: {h: {"ips": answers.get(h, []), "canonical": None} for h in hosts})
    monkeypatch.setattr(enrich, "host_status", lambda h: ("no_such_host", []))
    monkeypatch.setattr(enrich, "asn_lookup", lambda ips: asn or {})
    asked = []

    def fake_wildcards(zones):
        asked.append(list(zones))
        return {z: w for z, w in wildcards.items() if z in zones}, None
    monkeypatch.setattr(enrich, "wildcard_answers", fake_wildcards)
    return asked


def test_hosts_through_a_wildcard_are_set_aside(monkeypatch):
    answers = {"junk1.example.test": ["1.1.1.1"], "junk2.example.test": ["1.0.0.1"],
               "app.example.test": ["9.9.9.9"]}
    asn = {ip: {"as_name": "Fastly"} for ip in ["1.1.1.1", "1.0.0.1", "9.9.9.9"]}
    asked = _fake_dns(monkeypatch, answers, {"example.test": CDN_WILD}, asn)

    data = enrich.enrich(list(answers))

    assert asked == [["example.test"]]
    assert list(data["hosts"]) == ["app.example.test"]       # only the real host is counted
    assert data["wildcard_only"] == {"junk1.example.test": "example.test",
                                     "junk2.example.test": "example.test"}
    assert data["resolved"] == 1 and data["unique_ips"] == 1
    assert data["providers"] == {"Fastly": 1}
    w = data["wildcards"]["example.test"]
    assert (w["hosts"], w["provider"], w["private"]) == (2, "Fastly", False)
    assert w["examples"] == ["junk1.example.test", "junk2.example.test"]


def test_private_wildcard_leaves_the_private_ip_list(monkeypatch):
    # an ingress wildcard (*.acc -> internal IPs): its names leave the leak list,
    # the wildcard itself says it points at private IPs
    wild = {"ips": ["10.54.0.1"], "canonicals": []}
    answers = {"fakta.acc.example.test": ["10.54.0.1"], "db.acc.example.test": ["10.54.9.9"]}
    _fake_dns(monkeypatch, answers, {"acc.example.test": wild})

    data = enrich.enrich(list(answers))

    assert data["private_ip_hosts"] == ["db.acc.example.test"]   # own record: still reported
    assert data["wildcards"]["acc.example.test"]["private"] is True


def test_no_wildcard_changes_nothing(monkeypatch):
    answers = {"a.example.test": ["9.9.9.9"], "b.example.test": ["9.9.9.10"]}
    _fake_dns(monkeypatch, answers, {})
    data = enrich.enrich(list(answers))
    assert sorted(data["hosts"]) == sorted(answers)
    assert data["wildcard_only"] == {} and data["wildcards"] == {}


def test_wildcard_answers_finds_zones_that_answer_made_up_names(monkeypatch):
    def fake_one(name):
        if name.endswith(".wild.example.test"):
            return {"ips": ["1.1.1.1"], "canonical": None}
        return {"ips": [], "canonical": None}       # everything else: no such name
    monkeypatch.setattr(enrich, "_resolve_one", fake_one)
    found, error = REAL_WILDCARD_ANSWERS(["wild.example.test", "plain.example.test"])
    assert error is None
    assert found == {"wild.example.test": {"ips": ["1.1.1.1"], "canonicals": []}}


def test_wildcard_answers_unions_a_rotating_pool(monkeypatch):
    pool = iter(["1.1.1.1", "1.0.0.1", "1.0.0.2"])

    def fake_one(name):
        if name.endswith(".example.test"):
            return {"ips": [next(pool)], "canonical": None}
        return {"ips": [], "canonical": None}
    monkeypatch.setattr(enrich, "_resolve_one", fake_one)
    found, _ = REAL_WILDCARD_ANSWERS(["example.test"])
    assert found["example.test"]["ips"] == ["1.0.0.1", "1.0.0.2", "1.1.1.1"]   # sorted


def test_wildcard_check_skipped_when_resolver_answers_everything(monkeypatch):
    # an ISP/VPN resolver that answers for names that don't exist
    monkeypatch.setattr(enrich, "_resolve_one", lambda name: {"ips": ["192.0.2.80"], "canonical": None})
    found, error = REAL_WILDCARD_ANSWERS(["example.test"])
    assert found == {} and "answers for names that don't exist" in error


def test_wildcard_probes_use_made_up_labels(monkeypatch):
    asked = []

    def fake_one(name):
        asked.append(name)
        return {"ips": [], "canonical": None}
    monkeypatch.setattr(enrich, "_resolve_one", fake_one)
    REAL_WILDCARD_ANSWERS(["example.test"])
    probes = [n for n in asked if n.endswith(".example.test")]
    assert len(probes) == enrich.WILDCARD_PROBES and len(set(probes)) == enrich.WILDCARD_PROBES
    assert all(n.startswith("monomi-wc-") for n in probes)


def test_ips_cymru_doesnt_know_are_checked_against_amazons_list(monkeypatch):
    # v1.23: CloudFront IPs Team Cymru had no answer for came back "unknown"
    import ipaddress
    ips = {"cdn.example.com": "13.224.0.5", "other.example.com": "9.9.9.9"}
    monkeypatch.setattr(enrich, "resolve", lambda hosts: {h: {"ips": [ips[h]], "canonical": None} for h in hosts})
    monkeypatch.setattr(enrich, "asn_lookup", lambda public: {})  # Cymru answered nothing
    monkeypatch.setattr(enrich.aws_ranges, "cloudfront_networks", lambda: [ipaddress.ip_network("13.224.0.0/14")])
    monkeypatch.setattr(enrich.aws_ranges, "accelerator_networks", lambda: [])

    hosts = enrich.enrich(list(ips))["hosts"]

    assert hosts["cdn.example.com"]["provider"] == "AWS CloudFront"
    assert hosts["other.example.com"]["provider"] == "unknown"  # honest: not on Amazon's list either


def test_zoho_is_named():
    assert enrich.friendly_name("ZOHO-AS - ZOHO Corporation, US") == "Zoho"
