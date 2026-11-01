import dns.exception
import dns.resolver

import enrich


class FakeResolver:
    """Answers from a dict: {(host, rtype): "ok" | exception class}."""

    def __init__(self, answers):
        self.answers = answers

    def resolve(self, host, rtype, lifetime=None):
        result = self.answers.get((host, rtype), dns.resolver.NoAnswer)
        if result == "ok":
            return ["fake answer"]
        raise result()


def use_resolvers(monkeypatch, *resolvers):
    monkeypatch.setattr(enrich, "_resolvers", lambda: resolvers)


def test_nxdomain_is_gone(monkeypatch):
    use_resolvers(monkeypatch, FakeResolver({("old.example.com", "A"): dns.resolver.NXDOMAIN}))
    assert enrich.dns_status("old.example.com") == "gone"


def test_aaaa_only_is_ipv6_only(monkeypatch):
    use_resolvers(monkeypatch, FakeResolver({("v6.example.com", "AAAA"): "ok"}))
    assert enrich.dns_status("v6.example.com") == "ipv6_only"


def test_no_a_or_aaaa_is_no_address(monkeypatch):
    use_resolvers(monkeypatch, FakeResolver({}))  # NoAnswer for everything
    assert enrich.dns_status("mx.example.com") == "no_address"


def test_falls_back_to_next_resolver(monkeypatch):
    down = FakeResolver({("old.example.com", "A"): dns.exception.Timeout})
    up = FakeResolver({("old.example.com", "A"): dns.resolver.NXDOMAIN})
    use_resolvers(monkeypatch, down, up)
    assert enrich.dns_status("old.example.com") == "gone"


def test_all_resolvers_down_is_lookup_failed(monkeypatch):
    down = FakeResolver({("x.example.com", "A"): dns.exception.Timeout})
    use_resolvers(monkeypatch, down, down)
    assert enrich.dns_status("x.example.com") == "lookup_failed"


def test_enrich_groups_hosts_that_dont_resolve(monkeypatch):
    monkeypatch.setattr(enrich, "resolve", lambda hosts: {h: [] for h in hosts})
    statuses = {"old.example.com": "gone", "v6.example.com": "ipv6_only"}
    monkeypatch.setattr(enrich, "dns_status", lambda h: statuses[h])

    data = enrich.enrich(["old.example.com", "v6.example.com"])

    assert data["hosts"]["old.example.com"]["dns"] == "gone"
    assert data["not_resolving"] == {"gone": ["old.example.com"], "ipv6_only": ["v6.example.com"]}
    assert data["providers"] == {"no DNS record": 1, "IPv6 only": 1}
    assert data["resolved"] == 0
