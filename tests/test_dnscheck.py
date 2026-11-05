"""Tests for the DNS-over-HTTPS double-check in dnscheck.py (v1.8)."""

import dns.exception
import dns.resolver
import pytest
import requests

import dnscheck
import takeover


class FakeResponse:
    """Stands in for a requests response with a JSON body."""
    def __init__(self, data):
        self.data = data

    def raise_for_status(self):
        pass

    def json(self):
        return self.data


class FakeResolver:
    """Stands in for a dnspython resolver that always raises one error."""
    def __init__(self, error):
        self.error = error

    def resolve(self, name, rtype, lifetime=None):
        raise self.error


def use_resolvers(monkeypatch, *errors):
    """Make _resolvers() return fake resolvers that raise these errors."""
    fakes = [FakeResolver(e) for e in errors]
    monkeypatch.setattr(dnscheck, "_resolvers", lambda: fakes)


def use_doh(monkeypatch, answer):
    """Make doh_lookup() return a fixed answer, or raise if given an exception."""
    def fake(name, rtype):
        if isinstance(answer, Exception):
            raise answer
        return answer
    monkeypatch.setattr(dnscheck, "doh_lookup", fake)


# --- doh_lookup(): reading Cloudflare's JSON reply (the real function) ---

def test_doh_lookup_returns_cname(monkeypatch):
    data = {"Status": 0, "Answer": [{"type": 5, "data": "App.Cloud.test."}]}
    monkeypatch.setattr(dnscheck.requests, "get", lambda *a, **k: FakeResponse(data))
    assert dnscheck.doh_lookup("www.lab.test", "CNAME") == ("ok", ["app.cloud.test"])


def test_doh_lookup_keeps_only_the_asked_type(monkeypatch):
    # An A lookup on a CNAME'd host returns the CNAME AND the A record
    data = {"Status": 0, "Answer": [{"type": 5, "data": "app.cloud.test."},
                                    {"type": 1, "data": "203.0.113.7"}]}
    monkeypatch.setattr(dnscheck.requests, "get", lambda *a, **k: FakeResponse(data))
    assert dnscheck.doh_lookup("www.lab.test", "A") == ("ok", ["203.0.113.7"])


def test_doh_lookup_nxdomain(monkeypatch):
    monkeypatch.setattr(dnscheck.requests, "get", lambda *a, **k: FakeResponse({"Status": 3}))
    assert dnscheck.doh_lookup("gone.lab.test", "A") == ("nxdomain", [])


def test_doh_lookup_server_failure_raises(monkeypatch):
    monkeypatch.setattr(dnscheck.requests, "get", lambda *a, **k: FakeResponse({"Status": 2}))
    with pytest.raises(dnscheck.DNSLookupError):
        dnscheck.doh_lookup("www.lab.test", "A")


def test_doh_lookup_network_error_raises(monkeypatch):
    def boom(*a, **k):
        raise requests.ConnectionError("no route")
    monkeypatch.setattr(dnscheck.requests, "get", boom)
    with pytest.raises(dnscheck.DNSLookupError):
        dnscheck.doh_lookup("www.lab.test", "A")


# --- get_cname(): the NXDOMAIN double-check and the HTTPS fallback ---

def test_nxdomain_confirmed_by_doh_is_no_such_host(monkeypatch):
    use_resolvers(monkeypatch, dns.resolver.NXDOMAIN())
    use_doh(monkeypatch, ("nxdomain", []))
    with pytest.raises(dnscheck.NoSuchHost):
        dnscheck.get_cname("gone.lab.test")


def test_nxdomain_contradicted_by_doh_is_conflict(monkeypatch):
    # The 41xlab lab bug: WSL's cache said "gone", the host was live
    use_resolvers(monkeypatch, dns.resolver.NXDOMAIN())
    use_doh(monkeypatch, ("ok", []))
    with pytest.raises(dnscheck.ConflictingAnswers):
        dnscheck.get_cname("dev.lab.test")


def test_nxdomain_kept_when_doh_unreachable(monkeypatch):
    use_resolvers(monkeypatch, dns.resolver.NXDOMAIN())
    use_doh(monkeypatch, dnscheck.DNSLookupError("blocked"))
    with pytest.raises(dnscheck.NoSuchHost):
        dnscheck.get_cname("gone.lab.test")


def test_timeouts_fall_back_to_doh(monkeypatch):
    use_resolvers(monkeypatch, dns.exception.Timeout(), dns.exception.Timeout())
    use_doh(monkeypatch, ("ok", ["app.cloud.test"]))
    assert dnscheck.get_cname("www.lab.test") == "app.cloud.test"


# --- name_exists(): same rules for CNAME targets ---

def test_name_exists_timeouts_then_doh_nxdomain(monkeypatch):
    use_resolvers(monkeypatch, dns.exception.Timeout(), dns.exception.Timeout())
    use_doh(monkeypatch, ("nxdomain", []))
    assert dnscheck.name_exists("gone.cloud.test") is False


# --- check_hosts(): a conflict is reported as an error, never a verdict ---

def test_conflict_lands_in_errors(monkeypatch):
    use_resolvers(monkeypatch, dns.resolver.NXDOMAIN())
    use_doh(monkeypatch, ("ok", []))
    report = takeover.check_hosts(["dev.lab.test"])
    assert report["results"]["dev.lab.test"]["status"] == "error"
    assert "conflicting answers" in report["errors"]["dev.lab.test"]
    assert report["leads"] == []

# --- host_status(): one answer per host (the shared helper) ---

class Rec:
    """A fake DNS record: to_text() for _query(), target for get_cname()."""
    def __init__(self, text):
        self.text = text
        self.target = text

    def to_text(self):
        return self.text


class MapResolver:
    """Fake resolver answering from a dict: {(name, rtype): [records] or an error}.
    Anything not in the dict gets NoAnswer (name exists, no such record)."""
    def __init__(self, answers):
        self.answers = answers

    def resolve(self, name, rtype, lifetime=None):
        a = self.answers.get((name, rtype), dns.resolver.NoAnswer())
        if isinstance(a, Exception):
            raise a
        return [Rec(t) for t in a]


def use_map(monkeypatch, answers):
    monkeypatch.setattr(dnscheck, "_resolvers", lambda: (MapResolver(answers),))


def test_host_status_live(monkeypatch):
    use_map(monkeypatch, {("www.lab.test", "A"): ["203.0.113.7"]})
    assert dnscheck.host_status("www.lab.test") == ("live", ["203.0.113.7"])


def test_host_status_ipv6_only(monkeypatch):
    use_map(monkeypatch, {("v6.lab.test", "AAAA"): ["2001:db8::1"]})
    assert dnscheck.host_status("v6.lab.test") == ("ipv6_only", [])


def test_host_status_no_address(monkeypatch):
    use_map(monkeypatch, {})   # NoAnswer for A and AAAA
    assert dnscheck.host_status("mx.lab.test") == ("no_address", [])


def test_host_status_no_such_host(monkeypatch):
    use_map(monkeypatch, {("nope.lab.test", "A"): dns.resolver.NXDOMAIN(),
                          ("nope.lab.test", "CNAME"): dns.resolver.NXDOMAIN()})
    use_doh(monkeypatch, ("nxdomain", []))
    assert dnscheck.host_status("nope.lab.test") == ("no_such_host", [])


def test_host_status_dangling_cname(monkeypatch):
    # The lab's "legacy" host: it exists, but its CNAME target was deleted
    use_map(monkeypatch, {("legacy.lab.test", "A"): dns.resolver.NXDOMAIN(),
                          ("legacy.lab.test", "CNAME"): ["gone.lab.test."]})
    use_doh(monkeypatch, ("nxdomain", []))
    assert dnscheck.host_status("legacy.lab.test") == ("dangling_cname", [])


def test_host_status_conflicting(monkeypatch):
    use_map(monkeypatch, {("dev.lab.test", "A"): dns.resolver.NXDOMAIN()})
    use_doh(monkeypatch, ("ok", ["203.0.113.7"]))
    assert dnscheck.host_status("dev.lab.test") == ("conflicting", [])


def test_host_status_timeouts_then_doh_finds_ips(monkeypatch):
    # The lab's dev/www in WSL: port 53 dead, HTTPS gets the real answer
    use_resolvers(monkeypatch, dns.exception.Timeout(), dns.exception.Timeout())
    use_doh(monkeypatch, ("ok", ["203.0.113.7"]))
    assert dnscheck.host_status("dev.lab.test") == ("live", ["203.0.113.7"])


def test_host_status_nobody_answers(monkeypatch):
    use_resolvers(monkeypatch, dns.exception.Timeout(), dns.exception.Timeout())
    use_doh(monkeypatch, dnscheck.DNSLookupError("blocked"))
    assert dnscheck.host_status("x.lab.test") == ("lookup_failed", [])
