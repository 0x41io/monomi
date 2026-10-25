import dns.exception
import dns.resolver
import pytest

import emailauth
from emailauth import check_dkim, check_dmarc, check_spf, email_verdict


def spf_problems(records):
    """Run check_spf() on fake TXT records and return the set of problem names."""
    return {i["problem"] for i in check_spf(records)["issues"]}


def dmarc_problems(records):
    """Run check_dmarc() on fake records and return the set of problem names."""
    return {i["problem"] for i in check_dmarc(records)["issues"]}


# --- SPF ---

def test_spf_hard_fail_is_strong():
    assert spf_problems(["v=spf1 include:_spf.google.com -all"]) == set()


def test_spf_softfail_is_flagged():
    assert spf_problems(["v=spf1 include:_spf.google.com ~all"]) == {"softfail"}


def test_spf_plus_all_is_too_open():
    assert spf_problems(["v=spf1 +all"]) == {"too-open"}


def test_spf_missing():
    assert spf_problems(["google-site-verification=abc"]) == {"missing"}


def test_two_spf_records_break_spf():
    assert spf_problems(["v=spf1 a -all", "v=spf1 mx -all"]) == {"multiple"}


def test_spf_redirect_needs_no_all():
    assert spf_problems(["v=spf1 redirect=_spf.example.com"]) == set()


def test_spf10_is_not_spf():
    assert spf_problems(["v=spf10 -all"]) == {"missing"}


# --- DMARC ---

def test_dmarc_reject_is_strong():
    assert dmarc_problems(["v=DMARC1; p=reject; rua=mailto:x@example.com"]) == set()


def test_dmarc_none_is_monitor_only():
    assert dmarc_problems(["v=DMARC1; p=none"]) == {"monitor-only"}


def test_dmarc_partial_pct():
    assert dmarc_problems(["v=DMARC1; p=quarantine; pct=25"]) == {"partial"}


def test_dmarc_missing():
    assert dmarc_problems([]) == {"missing"}


def test_dmarc_sloppy_formatting_still_parses():
    assert check_dmarc(["V = DMARC1;p=Reject;"])["policy"] == "reject"


# --- Overall verdict ---

NO_DKIM = {"selectors": []}


def verdict(spf_records, dmarc_records, dkim=NO_DKIM):
    """Run the full verdict on fake SPF and DMARC records."""
    return email_verdict(check_spf(spf_records), check_dmarc(dmarc_records), dkim)


def test_softfail_plus_reject_is_protected():
    v = verdict(["v=spf1 include:x ~all"], ["v=DMARC1; p=reject"])
    assert v["verdict"] == "protected"
    assert any("softfail" in n for n in v["notes"])


def test_no_dmarc_is_spoofable_even_with_hard_fail():
    assert verdict(["v=spf1 -all"], [])["verdict"] == "spoofable"


def test_partial_pct_is_partial():
    assert verdict(["v=spf1 -all"], ["v=DMARC1; p=reject; pct=50"])["verdict"] == "partial"


# --- DKIM (fake DNS) ---

def test_dkim_found_and_revoked_keys(monkeypatch):
    fake_dns = {
        "google._domainkey.example.com": ["v=DKIM1; k=rsa; p=MIIBIjAN"],
        "k1._domainkey.example.com": ["v=DKIM1; p="],  # revoked key: empty p=
    }
    monkeypatch.setattr(emailauth, "get_txt", lambda name: fake_dns.get(name, []))
    result = check_dkim("example.com")
    assert result["selectors"] == ["google"]
    assert result["issues"] == []


def test_dkim_not_found_is_not_confirmed(monkeypatch):
    monkeypatch.setattr(emailauth, "get_txt", lambda name: [])
    assert [i["problem"] for i in check_dkim("example.com")["issues"]] == ["not-confirmed"]


# --- DNS fallback ---

def test_falls_back_to_public_dns_on_timeout(monkeypatch):
    calls = []

    def fake_query(resolver, name):
        calls.append(resolver)
        if len(calls) == 1:
            raise dns.exception.Timeout()  # the system resolver (like WSL's relay) times out
        return ["v=spf1 -all"]

    monkeypatch.setattr(emailauth, "_query_txt", fake_query)
    assert emailauth.get_txt("example.com") == ["v=spf1 -all"]
    assert len(calls) == 2


def test_no_record_does_not_retry(monkeypatch):
    calls = []

    def fake_query(resolver, name):
        calls.append(resolver)
        raise dns.resolver.NXDOMAIN()

    monkeypatch.setattr(emailauth, "_query_txt", fake_query)
    assert emailauth.get_txt("nope.example") == []
    assert len(calls) == 1


def test_all_resolvers_down_raises(monkeypatch):
    def fake_query(resolver, name):
        raise dns.exception.Timeout()

    monkeypatch.setattr(emailauth, "_query_txt", fake_query)
    with pytest.raises(emailauth.DNSLookupError):
        emailauth.get_txt("example.com")
