"""Tests for the DNS-over-HTTPS double-check in dnscheck.py (v1.8)."""

import dns.exception
import dns.resolver
import pytest
import requests

from monomi import dnscheck, takeover


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
    """Make every DoH server return a fixed answer, or raise if given an exception."""
    def fake(url, name, rtype):
        if isinstance(answer, Exception):
            raise answer
        return answer
    monkeypatch.setattr(dnscheck, "_ask_doh", fake)


def use_doh_servers(monkeypatch, *answers):
    """Make DoH answer differently per call, in order: Cloudflare, Google, retry.
    Each answer is a (result, records) tuple or an exception to raise."""
    calls = []

    def fake(url, name, rtype):
        answer = answers[len(calls)]
        calls.append(url)
        if isinstance(answer, Exception):
            raise answer
        return answer
    monkeypatch.setattr(dnscheck, "_ask_doh", fake)
    return calls


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


def test_doh_txt_keeps_case_and_drops_quotes(monkeypatch):
    # Cloudflare style: quoted, and DKIM keys are case-sensitive
    data = {"Status": 0, "Answer": [{"type": 16, "data": '"v=DKIM1; k=rsa; p=MIGfMA0GCSq"'}]}
    monkeypatch.setattr(dnscheck.requests, "get", lambda *a, **k: FakeResponse(data))
    assert dnscheck.doh_lookup("sel-lab", "TXT") == ("ok", ["v=DKIM1; k=rsa; p=MIGfMA0GCSq"])


def test_txt_text_joins_chunks_and_unescapes():
    assert dnscheck.txt_text('"v=spf1 include:a" " ~all"') == "v=spf1 include:a ~all"
    assert dnscheck.txt_text('"say \\"hi\\""') == 'say "hi"'
    assert dnscheck.txt_text('"a\\032b"') == "a b"
    assert dnscheck.txt_text("v=spf1 -all") == "v=spf1 -all"  # Google style: bare text


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
    assert report["results"]["dev.lab.test"]["status"] == "conflicting"
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


# --- v1.9: two DoH servers, one retry, and the "servfail" status ---

def test_doh_lookup_asks_google_when_cloudflare_servfails(monkeypatch):
    calls = use_doh_servers(monkeypatch, dnscheck.ServerFailure("cf"), ("ok", ["203.0.113.7"]))
    assert dnscheck.doh_lookup("web.lab.test", "A") == ("ok", ["203.0.113.7"])
    assert calls == list(dnscheck.DOH_SERVERS.values())


def test_doh_lookup_retries_once_after_both_fail(monkeypatch):
    calls = use_doh_servers(monkeypatch, dnscheck.ServerFailure("cf"),
                            dnscheck.ServerFailure("google"), ("ok", ["203.0.113.7"]))
    assert dnscheck.doh_lookup("web.lab.test", "A") == ("ok", ["203.0.113.7"])
    assert len(calls) == 3


def test_doh_lookup_servfail_after_retry(monkeypatch):
    use_doh_servers(monkeypatch, *[dnscheck.ServerFailure("x")] * 3)
    with pytest.raises(dnscheck.ServerFailure):
        dnscheck.doh_lookup("broken.lab.test", "A")


def test_doh_lookup_unreachable_is_not_servfail(monkeypatch):
    use_doh_servers(monkeypatch, *[dnscheck.DNSLookupError("blocked")] * 3)
    with pytest.raises(dnscheck.DNSLookupError) as e:
        dnscheck.doh_lookup("x.lab.test", "A")
    assert not isinstance(e.value, dnscheck.ServerFailure)


def test_nxdomain_contradicted_by_google_is_conflict(monkeypatch):
    # The 41xlab lab: Cloudflare had cached the old NXDOMAIN too, Google hadn't
    use_resolvers(monkeypatch, dns.resolver.NXDOMAIN())
    use_doh_servers(monkeypatch, ("nxdomain", []), ("ok", []))
    with pytest.raises(dnscheck.ConflictingAnswers, match="Google"):
        dnscheck.get_cname("dev.lab.test")


def test_nxdomain_confirmed_when_one_server_unreachable(monkeypatch):
    use_resolvers(monkeypatch, dns.resolver.NXDOMAIN())
    use_doh_servers(monkeypatch, dnscheck.DNSLookupError("blocked"), ("nxdomain", []))
    with pytest.raises(dnscheck.NoSuchHost):
        dnscheck.get_cname("gone.lab.test")


def test_host_status_servfail(monkeypatch):
    use_resolvers(monkeypatch, dns.exception.Timeout(), dns.exception.Timeout())
    use_doh(monkeypatch, dnscheck.ServerFailure("SERVFAIL"))
    assert dnscheck.host_status("broken.lab.test") == ("servfail", [])


def test_servfail_lands_in_takeover_errors(monkeypatch):
    # The Anduril sweep: ~90 hosts came back as a generic "error"
    use_resolvers(monkeypatch, dns.exception.Timeout(), dns.exception.Timeout())
    use_doh(monkeypatch, dnscheck.ServerFailure("SERVFAIL"))
    report = takeover.check_hosts(["broken.lab.test"])
    assert report["results"]["broken.lab.test"]["status"] == "servfail"
    assert report["leads"] == []


# --- check_exists(): who confirmed "doesn't exist" (v1.13, gate check 4) ---

def test_check_exists_lists_every_doh_server_that_confirmed(monkeypatch):
    use_resolvers(monkeypatch, dns.resolver.NXDOMAIN())
    use_doh(monkeypatch, ("nxdomain", []))
    assert dnscheck.check_exists("gone.cloud.test") == (False, ["Cloudflare", "Google"])


def test_check_exists_unconfirmed_when_doh_unreachable(monkeypatch):
    # The case gate check 4 catches: system DNS alone said NXDOMAIN
    use_resolvers(monkeypatch, dns.resolver.NXDOMAIN())
    use_doh(monkeypatch, dnscheck.DNSLookupError("blocked"))
    assert dnscheck.check_exists("gone.cloud.test") == (False, [])


def test_check_exists_names_only_the_servers_that_answered(monkeypatch):
    use_resolvers(monkeypatch, dns.resolver.NXDOMAIN())
    use_doh_servers(monkeypatch, dnscheck.DNSLookupError("blocked"), ("nxdomain", []))
    assert dnscheck.check_exists("gone.cloud.test") == (False, ["Google"])


def test_check_exists_doh_only_asks_every_server(monkeypatch):
    # No port 53 at all (WSL): the first DoH answer is double-checked too
    use_resolvers(monkeypatch, dns.exception.Timeout(), dns.exception.Timeout())
    use_doh(monkeypatch, ("nxdomain", []))
    assert dnscheck.check_exists("gone.cloud.test") == (False, ["Cloudflare", "Google"])


def test_check_exists_live_name_has_no_confirmations(monkeypatch):
    use_resolvers(monkeypatch, dns.resolver.NoAnswer())
    assert dnscheck.check_exists("app.cloud.test") == (True, [])


def test_takeover_lead_carries_who_confirmed_it(monkeypatch):
    monkeypatch.setattr(takeover, "get_cname", lambda name: "gone.azurewebsites.net")
    use_resolvers(monkeypatch, dns.resolver.NXDOMAIN())
    use_doh_servers(monkeypatch, ("nxdomain", []), dnscheck.DNSLookupError("blocked"))
    lead = takeover.inspect_host("app.lab.test")["lead"]
    assert lead["nxdomain_confirmed_by"] == ["Cloudflare"]


# --- v1.17: lame-delegation capture and the zone cut (dangling NS) ---

def _servfail_body(comment):
    return {"Status": 2, "Comment": comment}


def test_doh_lookup_tags_google_lame_delegation(monkeypatch):
    # Google's wording: a string Comment naming the refusing nameservers
    body = _servfail_body("Name servers refused query (lame delegation?) "
                          "[205.251.198.35, 205.251.194.214].")
    monkeypatch.setattr(dnscheck.requests, "get", lambda *a, **k: FakeResponse(body))
    with pytest.raises(dnscheck.ServerFailure) as e:
        dnscheck.doh_lookup("local-dev.example.test", "A")
    assert e.value.lame is True
    assert "205.251.198.35" in e.value.ns_ips


def test_doh_lookup_tags_cloudflare_ede_delegation(monkeypatch):
    # Cloudflare's wording: a list of EDE lines
    body = _servfail_body(["EDE(22): No Reachable Authority at delegation local-dev.example.test.",
                           "EDE(23): Network Error 205.251.192.127:53 returned REFUSED"])
    monkeypatch.setattr(dnscheck.requests, "get", lambda *a, **k: FakeResponse(body))
    with pytest.raises(dnscheck.ServerFailure) as e:
        dnscheck.doh_lookup("local-dev.example.test", "A")
    assert e.value.lame is True
    assert 22 in e.value.ede and 23 in e.value.ede
    assert "205.251.192.127" in e.value.ns_ips


def test_doh_lookup_plain_servfail_is_not_lame(monkeypatch):
    # A bare SERVFAIL under load: no delegation wording, so never lame
    monkeypatch.setattr(dnscheck.requests, "get", lambda *a, **k: FakeResponse({"Status": 2}))
    with pytest.raises(dnscheck.ServerFailure) as e:
        dnscheck.doh_lookup("busy.example.test", "A")
    assert e.value.lame is False
    assert e.value.ns_ips == []


def test_merge_keeps_lame_detail_when_only_one_server_gives_it(monkeypatch):
    plain = dnscheck.ServerFailure("cf")           # Cloudflare: bare SERVFAIL
    lame = dnscheck._servfail("x", _servfail_body(
        "Name servers refused query (lame delegation?) [203.0.113.9]."))
    use_doh_servers(monkeypatch, plain, lame, plain)
    with pytest.raises(dnscheck.ServerFailure) as e:
        dnscheck.doh_lookup("local-dev.example.test", "A")
    assert e.value.lame is True
    assert "203.0.113.9" in e.value.ns_ips


def test_lame_delegation_returns_detail(monkeypatch):
    use_doh(monkeypatch, dnscheck._servfail("x", _servfail_body(
        "Name servers refused query (lame delegation?) [205.251.192.127].")))
    info = dnscheck.lame_delegation("local-dev.example.test")
    assert info and info["ns_ips"] == ["205.251.192.127"]


def test_lame_delegation_none_for_plain_servfail(monkeypatch):
    use_doh(monkeypatch, dnscheck.ServerFailure("busy"))
    assert dnscheck.lame_delegation("busy.example.test") is None


def test_lame_delegation_none_when_name_resolves(monkeypatch):
    use_doh(monkeypatch, ("ok", ["203.0.113.7"]))
    assert dnscheck.lame_delegation("example.test") is None


def test_find_zone_cut_returns_shallowest_lame_ancestor(monkeypatch):
    lame = dnscheck._servfail("x", _servfail_body(
        "Name servers refused query (lame delegation?) [205.251.192.127]."))

    def fake_lame(name):
        # local-dev.example.test and everything under it are lame; example.test resolves
        if name.endswith("local-dev.example.test"):
            return {"detail": lame.detail, "ede": [], "ns_ips": lame.ns_ips}
        return None
    monkeypatch.setattr(dnscheck, "lame_delegation", fake_lame)
    cut, info = dnscheck.find_zone_cut("alice.local-dev.example.test")
    assert cut == "local-dev.example.test"
    assert info["ns_ips"] == ["205.251.192.127"]


def test_find_zone_cut_none_when_no_ancestor_is_lame(monkeypatch):
    monkeypatch.setattr(dnscheck, "lame_delegation", lambda name: None)
    assert dnscheck.find_zone_cut("busy.example.test") is None
