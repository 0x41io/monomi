"""Tests for the DNS-over-HTTPS double-check in takeover.py (v1.8)."""

import dns.exception
import dns.resolver
import pytest
import requests

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
    monkeypatch.setattr(takeover, "_resolvers", lambda: fakes)


def use_doh(monkeypatch, answer):
    """Make doh_lookup() return a fixed answer, or raise if given an exception."""
    def fake(name, rtype):
        if isinstance(answer, Exception):
            raise answer
        return answer
    monkeypatch.setattr(takeover, "doh_lookup", fake)


# --- doh_lookup(): reading Cloudflare's JSON reply (the real function) ---

def test_doh_lookup_returns_cname(monkeypatch):
    data = {"Status": 0, "Answer": [{"type": 5, "data": "App.Cloud.test."}]}
    monkeypatch.setattr(takeover.requests, "get", lambda *a, **k: FakeResponse(data))
    assert takeover.doh_lookup("www.lab.test", "CNAME") == ("ok", ["app.cloud.test"])


def test_doh_lookup_keeps_only_the_asked_type(monkeypatch):
    # An A lookup on a CNAME'd host returns the CNAME AND the A record
    data = {"Status": 0, "Answer": [{"type": 5, "data": "app.cloud.test."},
                                    {"type": 1, "data": "203.0.113.7"}]}
    monkeypatch.setattr(takeover.requests, "get", lambda *a, **k: FakeResponse(data))
    assert takeover.doh_lookup("www.lab.test", "A") == ("ok", ["203.0.113.7"])


def test_doh_lookup_nxdomain(monkeypatch):
    monkeypatch.setattr(takeover.requests, "get", lambda *a, **k: FakeResponse({"Status": 3}))
    assert takeover.doh_lookup("gone.lab.test", "A") == ("nxdomain", [])


def test_doh_lookup_server_failure_raises(monkeypatch):
    monkeypatch.setattr(takeover.requests, "get", lambda *a, **k: FakeResponse({"Status": 2}))
    with pytest.raises(takeover.DNSLookupError):
        takeover.doh_lookup("www.lab.test", "A")


def test_doh_lookup_network_error_raises(monkeypatch):
    def boom(*a, **k):
        raise requests.ConnectionError("no route")
    monkeypatch.setattr(takeover.requests, "get", boom)
    with pytest.raises(takeover.DNSLookupError):
        takeover.doh_lookup("www.lab.test", "A")


# --- get_cname(): the NXDOMAIN double-check and the HTTPS fallback ---

def test_nxdomain_confirmed_by_doh_is_no_such_host(monkeypatch):
    use_resolvers(monkeypatch, dns.resolver.NXDOMAIN())
    use_doh(monkeypatch, ("nxdomain", []))
    with pytest.raises(takeover.NoSuchHost):
        takeover.get_cname("gone.lab.test")


def test_nxdomain_contradicted_by_doh_is_conflict(monkeypatch):
    # The 41xlab lab bug: WSL's cache said "gone", the host was live
    use_resolvers(monkeypatch, dns.resolver.NXDOMAIN())
    use_doh(monkeypatch, ("ok", []))
    with pytest.raises(takeover.ConflictingAnswers):
        takeover.get_cname("dev.lab.test")


def test_nxdomain_kept_when_doh_unreachable(monkeypatch):
    use_resolvers(monkeypatch, dns.resolver.NXDOMAIN())
    use_doh(monkeypatch, takeover.DNSLookupError("blocked"))
    with pytest.raises(takeover.NoSuchHost):
        takeover.get_cname("gone.lab.test")


def test_timeouts_fall_back_to_doh(monkeypatch):
    use_resolvers(monkeypatch, dns.exception.Timeout(), dns.exception.Timeout())
    use_doh(monkeypatch, ("ok", ["app.cloud.test"]))
    assert takeover.get_cname("www.lab.test") == "app.cloud.test"


# --- name_exists(): same rules for CNAME targets ---

def test_name_exists_timeouts_then_doh_nxdomain(monkeypatch):
    use_resolvers(monkeypatch, dns.exception.Timeout(), dns.exception.Timeout())
    use_doh(monkeypatch, ("nxdomain", []))
    assert takeover.name_exists("gone.cloud.test") is False


# --- check_hosts(): a conflict is reported as an error, never a verdict ---

def test_conflict_lands_in_errors(monkeypatch):
    use_resolvers(monkeypatch, dns.resolver.NXDOMAIN())
    use_doh(monkeypatch, ("ok", []))
    report = takeover.check_hosts(["dev.lab.test"])
    assert report["results"]["dev.lab.test"]["status"] == "error"
    assert "conflicting answers" in report["errors"]["dev.lab.test"]
    assert report["leads"] == []
