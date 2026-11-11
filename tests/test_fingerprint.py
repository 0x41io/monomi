import pytest
import requests

import fingerprint
from fingerprint import detect


def techs(headers):
    """Run detect() on fake headers and return just the tech names."""
    return [t["tech"] for t in detect({"headers": headers})]


def test_detect_reads_naming_headers_and_versions():
    found = detect({"headers": {"server": "Apache/2.4.41 (Ubuntu)"}})
    assert found[0]["tech"] == "Apache/2.4.41 (Ubuntu)"
    assert found[0]["version"] == "2.4.41"
    assert found[0]["evidence"] == "server: Apache/2.4.41 (Ubuntu)"


def test_detect_no_version_when_none_leaked():
    found = detect({"headers": {"x-powered-by": "Next.js"}})
    assert found[0]["version"] is None


def test_detect_skips_repeats():
    # server + cf-ray both say Cloudflare; PHP/7.4.3 + PHPSESSID both say PHP
    headers = {"server": "cloudflare", "cf-ray": "abc", "x-powered-by": "PHP/7.4.3", "set-cookie": "PHPSESSID=1"}
    assert techs(headers) == ["cloudflare", "PHP/7.4.3"]


def test_detect_spots_cookies():
    assert techs({"set-cookie": "wordpress_test_cookie=1; path=/"}) == ["WordPress"]


def test_detect_nothing_to_find():
    assert techs({"content-type": "text/html", "date": "Thu, 22 Oct 2026"}) == []


# ---------- HTTP fallback when HTTPS fails ----------

class Answer:
    """A fake response: just a status and headers."""
    def __init__(self, status=200, headers=None):
        self.status_code = status
        self.headers = headers or {"Server": "nginx/1.28.3"}

    def close(self):
        pass


def fake_get(monkeypatch, https, http=None):
    """https/http: an Answer, or an exception class to raise for that URL.
    Returns the list of URLs requested, in order."""
    sent = []

    def get(url, **kwargs):
        sent.append(url)
        outcome = https if url.startswith("https://") else http
        if isinstance(outcome, type) and issubclass(outcome, Exception):
            raise outcome("fake")
        if outcome is None:
            raise AssertionError(f"unexpected request to {url}")
        return outcome
    monkeypatch.setattr(fingerprint.requests, "get", get)
    return sent


def test_https_works_so_no_http_request(monkeypatch):
    sent = fake_get(monkeypatch, https=Answer())
    host, result, err, n = fingerprint._safe_fetch("dev")
    assert sent == ["https://dev/"] and n == 1 and err is None
    assert "https_error" not in result


@pytest.mark.parametrize("failure", [requests.exceptions.SSLError, requests.ConnectionError])
def test_tls_error_or_refused_retries_on_http(monkeypatch, failure):
    # like dev on the lab: 443 answers with another name's certificate
    sent = fake_get(monkeypatch, https=failure, http=Answer())
    host, result, err, n = fingerprint._safe_fetch("dev")
    assert sent == ["https://dev/", "http://dev/"] and n == 2 and err is None
    assert result["url"] == "http://dev/" and result["status"] == 200
    assert result["https_error"] == failure.__name__  # the HTTPS failure is never lost


@pytest.mark.parametrize("failure", [requests.Timeout, requests.ConnectTimeout,
                                     requests.ReadTimeout])
def test_timeouts_are_not_retried(monkeypatch, failure):
    # ConnectTimeout is also a ConnectionError: it must still not be retried
    sent = fake_get(monkeypatch, https=failure)
    host, result, err, n = fingerprint._safe_fetch("slow")
    assert sent == ["https://slow/"] and n == 1
    assert result is None and err == failure.__name__


def test_both_failing_keeps_both_errors(monkeypatch):
    sent = fake_get(monkeypatch, https=requests.exceptions.SSLError,
                    http=requests.ConnectionError)
    host, result, err, n = fingerprint._safe_fetch("dead")
    assert n == 2 and result is None
    assert err == "SSLError; http: ConnectionError"


def test_every_request_goes_through_on_request(monkeypatch):
    # the MCP server writes the audit log from this hook: the retry must be logged too
    fake_get(monkeypatch, https=requests.exceptions.SSLError, http=Answer())
    logged = []
    fingerprint._safe_fetch("dev", on_request=lambda host, url: logged.append(url))
    assert logged == ["https://dev/", "http://dev/"]


def test_fingerprint_all_counts_requests_not_hosts(monkeypatch):
    fake_get(monkeypatch, https=requests.exceptions.SSLError, http=Answer())
    enrichment = {"hosts": {"dev": {"ips": ["8.8.8.8"]}}}
    fp = fingerprint.fingerprint_all(enrichment)
    assert fp["checked"] == 1 and fp["requests"] == 2
    issues = {i["header"]: i["problem"] for i in fp["hosts"]["dev"]["header_issues"]}
    assert issues["HTTPS"] == "broken" and "Strict-Transport-Security" not in issues


def test_fingerprint_sends_the_active_user_agent(monkeypatch):
    seen = {}

    def get(url, **kwargs):
        seen["ua"] = kwargs["headers"]["User-Agent"]
        return Answer()
    monkeypatch.setattr(fingerprint.requests, "get", get)
    fingerprint.fetch_headers("host")
    assert "active security check" in seen["ua"]  # not the passive string
