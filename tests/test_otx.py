"""AlienVault OTX passive DNS source: the collector, how scans use it, doctor and MCP."""

import pytest

import doctor
import mcp_server
import monomi
from collectors import otx, saved
from doctor import OK, WARN
from monomi import collect_ct, flag_silent_crtsh_failure

REAL_FETCH = otx.fetch_raw  # conftest turns OTX off for every test; these tests use the real one
D = "lab.test"


class Resp:
    def __init__(self, status, body=None, headers=None, bad_json=False):
        self.status_code = status
        self._body = body
        self.headers = headers or {}
        self._bad = bad_json

    def json(self):
        if self._bad:
            raise ValueError("not JSON")
        return self._body


def answer(monkeypatch, resp, calls=None):
    """otx's requests.get returns resp; each call's url and headers go into calls."""
    def get(url, headers=None, timeout=None):
        if calls is not None:
            calls.append({"url": url, "headers": dict(headers or {})})
        return resp
    monkeypatch.setattr(otx.requests, "get", get)


def records(*names):
    return {"passive_dns": [{"hostname": n, "address": "192.0.2.1", "record_type": "A"} for n in names],
            "count": len(names)}


# --- the collector ---

def test_keyless_request_sends_no_key(monkeypatch):
    monkeypatch.delenv(otx.KEY_VAR, raising=False)
    calls = []
    answer(monkeypatch, Resp(200, records("a.lab.test")), calls)
    assert REAL_FETCH(D) == records("a.lab.test")["passive_dns"]
    assert calls[0]["url"].endswith("/indicators/domain/lab.test/passive_dns")
    assert "X-OTX-API-KEY" not in calls[0]["headers"]


def test_key_from_the_environment_is_sent(monkeypatch):
    monkeypatch.setenv(otx.KEY_VAR, "  abc123  ")  # spaces around a pasted key are dropped
    calls = []
    answer(monkeypatch, Resp(200, records()), calls)
    REAL_FETCH(D)
    assert calls[0]["headers"]["X-OTX-API-KEY"] == "abc123"


def test_only_the_targets_own_hostnames_are_kept():
    recs = records("a.lab.test", "B.LAB.TEST.", "lab.test", "other.test", "notlab.test", "x.lab.test.evil.test")
    recs["passive_dns"].append({"address": "192.0.2.9"})  # a record with no hostname
    assert otx.parse_subdomains(recs["passive_dns"], D) == ["a.lab.test", "b.lab.test", "lab.test"]


def test_collect_counts_records_not_certificates(monkeypatch):
    monkeypatch.setattr(otx, "fetch_raw", lambda domain: records("a.lab.test", "a.lab.test", "b.lab.test")["passive_dns"])
    r = otx.collect(D)
    assert r["source"] == "otx" and r["records_seen"] == 3 and r["subdomain_count"] == 2
    assert "certificates_seen" not in r  # OTX never claims to have seen certificates


def test_429_starts_a_cooldown_and_the_next_domain_skips_otx(monkeypatch):
    monkeypatch.delenv(otx.KEY_VAR, raising=False)
    calls = []
    answer(monkeypatch, Resp(429, headers={"Retry-After": "120"}), calls)
    with pytest.raises(RuntimeError, match=f"rate limit hit .*{otx.KEY_VAR}"):
        REAL_FETCH(D)
    with pytest.raises(RuntimeError, match="AlienVault OTX skipped"):
        REAL_FETCH("other.test")
    assert len(calls) == 1  # the second domain sent nothing


def test_cooldown_length():
    assert otx.cooldown_seconds(Resp(429, headers={"Retry-After": "120"})) == 120
    assert otx.cooldown_seconds(Resp(429, headers={"Retry-After": "99999"})) == otx.MAX_COOLDOWN
    assert otx.cooldown_seconds(Resp(429)) == otx.DEFAULT_COOLDOWN


@pytest.mark.parametrize("keyed, says", [(False, "wants an API key"), (True, "refused the key")])
def test_401_says_what_to_do(monkeypatch, keyed, says):
    if keyed:
        monkeypatch.setenv(otx.KEY_VAR, "abc")
    else:
        monkeypatch.delenv(otx.KEY_VAR, raising=False)
    answer(monkeypatch, Resp(401))
    with pytest.raises(RuntimeError, match=says):
        REAL_FETCH(D)


@pytest.mark.parametrize("resp, says", [
    (Resp(500), "HTTP 500"),
    (Resp(200, bad_json=True), "invalid JSON"),
    (Resp(200, {"detail": "something else"}), "without a passive DNS list"),
    (Resp(200, ["not", "a", "dict"]), "without a passive DNS list"),
])
def test_bad_answers_fail_loudly(monkeypatch, resp, says):
    answer(monkeypatch, resp)
    with pytest.raises(RuntimeError, match=says):
        REAL_FETCH(D)


def test_network_error_is_a_runtime_error(monkeypatch):
    def get(*args, **kwargs):
        raise otx.requests.ConnectionError("no route")
    monkeypatch.setattr(otx.requests, "get", get)
    with pytest.raises(RuntimeError, match="request failed"):
        REAL_FETCH(D)


# --- how a scan uses it ---

def _otx_record(*hosts, when="2026-11-13T12:00:00+00:00"):
    return {"source": "otx", "collected_at": when, "domain": D, "records_seen": len(hosts),
            "subdomain_count": len(hosts), "subdomains": list(hosts), "keyed": False}


def _ct_record(source, *hosts, certs=None):
    return {"source": source, "collected_at": "2026-11-13T12:00:00+00:00", "domain": D,
            "certificates_seen": len(hosts) if certs is None else certs,
            "subdomain_count": len(hosts), "subdomains": list(hosts), "wildcards": []}


def _sources(monkeypatch, cs=None, otx_record=None):
    """crt.sh and its database fail; Cert Spotter and OTX return these records (None = fail)."""
    def job(record, error):
        def run(*args, **kwargs):
            if record is None:
                raise RuntimeError(error)
            return record
        return run
    monkeypatch.setattr(monomi.crtsh, "collect", job(None, "HTTP 502"))
    monkeypatch.setattr(monomi.crtsh_db, "collect", job(None, "connection timeout"))
    monkeypatch.setattr(monomi.certspotter, "collect", job(cs, "rate limited"))
    monkeypatch.setattr(monomi.otx, "collect", job(otx_record, "rate limit hit"))


def test_scan_adds_otx_hosts_and_says_records(monkeypatch, capsys):
    _sources(monkeypatch, cs=_ct_record("certspotter", "www.lab.test"), otx_record=_otx_record("mail.lab.test"))
    results = {"sources": {}, "errors": {}}
    collect_ct(results, D)
    assert results["sources"]["otx"]["subdomains"] == ["mail.lab.test"]
    out = capsys.readouterr().out
    assert "AlienVault OTX: 1 passive DNS records -> 1 hostnames" in out
    assert "Cert Spotter: 1 certificates -> 1 hostnames" in out


def test_failed_otx_uses_its_saved_copy(monkeypatch):
    saved.save(D, _otx_record("old.lab.test", when="2026-11-10T00:00:00+00:00"))
    _sources(monkeypatch, cs=_ct_record("certspotter", "www.lab.test"), otx_record=None)
    results = {"sources": {}, "errors": {}}
    collect_ct(results, D)
    assert results["sources"]["otx"]["from_saved"] is True
    assert results["errors"]["AlienVault OTX"] == "rate limit hit; using the saved copy from 2026-11-10T00:00:00+00:00"


def test_empty_otx_result_is_not_saved(monkeypatch):
    _sources(monkeypatch, cs=_ct_record("certspotter", "www.lab.test"), otx_record=_otx_record())
    collect_ct({"sources": {}, "errors": {}}, D)
    assert saved.load(D, "otx") is None


def test_otx_finds_never_make_crtsh_look_broken():
    """crt.sh is compared with other CT logs only: OTX's hosts aren't certificates."""
    results = {"sources": {"crt.sh": _ct_record("crt.sh", certs=0), "otx": _otx_record("a.lab.test")},
               "errors": {}}
    flag_silent_crtsh_failure(results)
    assert "crt.sh" in results["sources"] and results["errors"] == {}


# --- doctor ---

def doctor_answer(monkeypatch, resp, calls=None):
    def get(url, headers=None, timeout=None, **kwargs):
        if calls is not None:
            calls.append({"url": url, "headers": dict(headers or {})})
        if isinstance(resp, Exception):
            raise resp
        return resp
    monkeypatch.setattr(doctor.requests, "get", get)


def test_doctor_otx_ok_without_a_key(monkeypatch):
    monkeypatch.delenv(otx.KEY_VAR, raising=False)
    doctor_answer(monkeypatch, Resp(200, records()))
    r = doctor.check_otx()
    assert r["status"] == OK and "no key (works, with lower limits)" in r["detail"]


def test_doctor_otx_sends_the_key_and_says_so_without_showing_it(monkeypatch):
    monkeypatch.setenv(otx.KEY_VAR, "secret-key-value")
    calls = []
    doctor_answer(monkeypatch, Resp(200, records()), calls)
    r = doctor.check_otx()
    assert calls[0]["headers"]["X-OTX-API-KEY"] == "secret-key-value"
    assert r["status"] == OK and "key set" in r["detail"] and "secret" not in r["detail"]


def test_doctor_otx_401_without_a_key_points_to_the_free_key(monkeypatch):
    monkeypatch.delenv(otx.KEY_VAR, raising=False)
    doctor_answer(monkeypatch, Resp(401))
    r = doctor.check_otx()
    assert r["status"] == WARN and "wants an API key" in r["detail"] and otx.KEY_VAR in r["fix"]


def test_doctor_otx_429_starts_a_cooldown_then_sends_nothing(monkeypatch):
    doctor_answer(monkeypatch, Resp(429, headers={"Retry-After": "300"}))
    assert doctor.check_otx()["status"] == WARN
    calls = []
    doctor_answer(monkeypatch, Resp(200, records()), calls)
    r = doctor.check_otx()
    assert r["status"] == WARN and "cooling down until" in r["detail"] and calls == []


def test_doctor_otx_network_error(monkeypatch):
    doctor_answer(monkeypatch, doctor.requests.ConnectionError("no route"))
    assert doctor.check_otx()["status"] == WARN


# --- MCP ---

def test_find_subdomains_reports_otx_records(monkeypatch):
    _sources(monkeypatch, cs=_ct_record("certspotter", "www.lab.test"), otx_record=_otx_record("mail.lab.test"))
    full = mcp_server.find_subdomains(D, detail="full")
    assert full["hostnames"] == ["mail.lab.test", "www.lab.test"]
    assert full["sources"]["otx"]["records_seen"] == 1
    assert full["sources"]["otx"]["certificates_seen"] is None
    assert full["sources"]["certspotter"]["certificates_seen"] == 1
    assert full["sources"]["certspotter"]["partial"] is None


def test_find_subdomains_says_when_a_list_was_cut_short(monkeypatch):
    cut = {**_ct_record("certspotter", "www.lab.test"), "partial": "stopped after 1 page (rate limit)"}
    _sources(monkeypatch, cs=cut, otx_record=None)
    full = mcp_server.find_subdomains(D, detail="full")
    assert full["sources"]["certspotter"]["partial"] == "stopped after 1 page (rate limit)"
