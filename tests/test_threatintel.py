import requests

import enrich
import internetdb
import threatintel
from threatintel import clean_ip, label


def facts(**changes):
    """A clean, boring IP's facts. Pass keyword args to change any part."""
    base = {"ip": "203.0.113.7", "tor_exit": False, "network": None,
            "rdns": None, "shodan": None, "errors": {}}
    base.update(changes)
    return base


def names(labels):
    """Just the label names, in order: ['tor_exit', 'tor_exit', ...]"""
    return [l["label"] for l in labels]


# --- cleaning the input ---

def test_clean_ip_strips_spaces():
    assert clean_ip("  8.8.8.8 \n") == "8.8.8.8"


def test_clean_ip_rejects_private_ips():
    assert clean_ip("192.168.1.1") is None
    assert clean_ip("10.0.0.5") is None


def test_clean_ip_rejects_junk():
    assert clean_ip("not-an-ip") is None
    assert clean_ip("8.8.8.8; rm -rf /") is None


def test_clean_ip_writes_ipv6_one_way():
    # Same address written two ways must come out identical, or the
    # "is it in the Tor list?" check would miss it.
    assert clean_ip("2001:4860:4860:0000:0000:0000:0000:8888") == clean_ip("2001:4860:4860::8888")


# --- labels ---

def test_tor_exit_from_three_sources():
    labels = label(facts(tor_exit=True, rdns="tor-exit-read-me.dfri.se",
                         shodan={"tags": ["tor", "self-signed"]}))
    assert names(labels) == ["tor_exit", "tor_exit", "tor_exit"]
    assert {l["source"] for l in labels} == {"Tor exit list", "Shodan InternetDB", "reverse DNS"}


def test_rdns_matches_whole_words_only():
    labels = label(facts(rdns="monitor.storage.example.com"))
    assert "tor_exit" not in names(labels)


def test_vpn_hint_in_rdns():
    labels = label(facts(rdns="nl-ams-vpn-12.example.net"))
    assert "vpn" in names(labels)
    assert "no_anonymizer_found" not in names(labels)


def test_clean_ip_gets_no_anonymizer_found():
    assert names(label(facts())) == ["no_anonymizer_found"]


def test_unknown_tor_status_never_claims_no_anonymizer():
    # Tor list failed to download (None): we never checked, so don't say "none found"
    assert label(facts(tor_exit=None)) == []


def test_cdn_edge_from_network_owner():
    labels = label(facts(network={"as_name": "Cloudflare"}))
    assert names(labels) == ["cdn_edge", "no_anonymizer_found"]


def test_hosting_provider():
    assert "hosting" in names(label(facts(network={"as_name": "DigitalOcean"})))


def test_known_bad_shodan_tag():
    assert "known_bad" in names(label(facts(shodan={"tags": ["c2"]})))


def test_unimportant_shodan_tags_are_ignored():
    assert names(label(facts(shodan={"tags": ["pqc", "self-signed"]}))) == ["no_anonymizer_found"]


# --- investigate(): one source failing doesn't stop the others ---

def test_every_source_failing_is_reported_not_crashed(monkeypatch):
    def tor_down():
        raise requests.ConnectionError("tor list down")

    def asn_down(ips):
        raise RuntimeError("cymru down")

    def shodan_down(ip):
        raise requests.Timeout("shodan slow")

    monkeypatch.setattr(threatintel, "tor_exit_ips", tor_down)
    monkeypatch.setattr(enrich, "asn_lookup", asn_down)
    monkeypatch.setattr(internetdb, "lookup_one", shodan_down)
    monkeypatch.setattr(threatintel, "reverse_dns", lambda ip: None)

    result = threatintel.investigate("203.0.113.7")
    assert set(result["errors"]) == {"tor", "asn", "shodan"}
    assert result["tor_exit"] is None
    assert result["labels"] == []


def test_investigate_puts_facts_together(monkeypatch):
    monkeypatch.setattr(threatintel, "tor_exit_ips", lambda: {"203.0.113.7"})
    monkeypatch.setattr(enrich, "asn_lookup",
                        lambda ips: {"203.0.113.7": {"asn": "AS64500", "as_name": "Hetzner", "country": "DE"}})
    monkeypatch.setattr(internetdb, "lookup_one", lambda ip: None)
    monkeypatch.setattr(threatintel, "reverse_dns", lambda ip: None)

    result = threatintel.investigate("203.0.113.7")
    assert result["errors"] == {}
    assert result["tor_exit"] is True
    assert names(result["labels"]) == ["tor_exit", "hosting"]