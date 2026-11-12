import pytest
import requests

import fingerprint
import scope
from scope import UNSCOPED_CLI
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
    host, result, err, n = fingerprint._safe_fetch("dev", scope=UNSCOPED_CLI)
    assert sent == ["https://dev/"] and n == 1 and err is None
    assert "https_error" not in result


@pytest.mark.parametrize("failure", [requests.exceptions.SSLError, requests.ConnectionError])
def test_tls_error_or_refused_retries_on_http(monkeypatch, failure):
    # like dev on the lab: 443 answers with another name's certificate
    sent = fake_get(monkeypatch, https=failure, http=Answer())
    host, result, err, n = fingerprint._safe_fetch("dev", scope=UNSCOPED_CLI)
    assert sent == ["https://dev/", "http://dev/"] and n == 2 and err is None
    assert result["url"] == "http://dev/" and result["status"] == 200
    assert result["https_error"] == failure.__name__  # the HTTPS failure is never lost


@pytest.mark.parametrize("failure", [requests.Timeout, requests.ConnectTimeout,
                                     requests.ReadTimeout])
def test_timeouts_are_not_retried(monkeypatch, failure):
    # ConnectTimeout is also a ConnectionError: it must still not be retried
    sent = fake_get(monkeypatch, https=failure)
    host, result, err, n = fingerprint._safe_fetch("slow", scope=UNSCOPED_CLI)
    assert sent == ["https://slow/"] and n == 1
    assert result is None and err == failure.__name__


def test_both_failing_keeps_both_errors(monkeypatch):
    sent = fake_get(monkeypatch, https=requests.exceptions.SSLError,
                    http=requests.ConnectionError)
    host, result, err, n = fingerprint._safe_fetch("dead", scope=UNSCOPED_CLI)
    assert n == 2 and result is None
    assert err == "SSLError; http: ConnectionError"


def test_every_request_goes_through_on_request(monkeypatch):
    # the MCP server writes the audit log from this hook: the retry must be logged too
    fake_get(monkeypatch, https=requests.exceptions.SSLError, http=Answer())
    logged = []
    fingerprint._safe_fetch("dev", scope=UNSCOPED_CLI,
                            on_request=lambda host, url, rule: logged.append(url))
    assert logged == ["https://dev/", "http://dev/"]


def test_fingerprint_all_counts_requests_not_hosts(monkeypatch):
    fake_get(monkeypatch, https=requests.exceptions.SSLError, http=Answer())
    enrichment = {"hosts": {"dev": {"ips": ["8.8.8.8"]}}}
    fp = fingerprint.fingerprint_all(enrichment, scope=UNSCOPED_CLI)
    assert fp["checked"] == 1 and fp["requests"] == 2
    issues = {i["header"]: i["problem"] for i in fp["hosts"]["dev"]["header_issues"]}
    assert issues["HTTPS"] == "broken" and "Strict-Transport-Security" not in issues


def test_fingerprint_sends_the_active_user_agent(monkeypatch):
    seen = {}

    def get(url, **kwargs):
        seen["ua"] = kwargs["headers"]["User-Agent"]
        return Answer()
    monkeypatch.setattr(fingerprint.requests, "get", get)
    fingerprint.fetch_headers("host", scope=UNSCOPED_CLI)
    assert "active security check" in seen["ua"]  # not the passive string


# ---------- scope in the fetch layer (v1.12) ----------


LAB = scope.from_bytes(b"*.example.test\n!dev.example.test\n")


def no_network(monkeypatch):
    sent = []

    def get(url, **kwargs):
        sent.append(url)
        raise AssertionError(f"a request was sent to {url}")
    monkeypatch.setattr(fingerprint.requests, "get", get)
    return sent


def test_fetch_headers_has_no_default_scope():
    # forgetting the scope is a crash in the tests, never a silent skip
    with pytest.raises(TypeError, match="scope"):
        fingerprint.fetch_headers("www.example.test")
    with pytest.raises(TypeError, match="scope"):
        fingerprint.fingerprint_all({"hosts": {}})


def test_out_of_scope_host_gets_no_request_and_no_log_line(monkeypatch):
    sent, logged = no_network(monkeypatch), []
    with pytest.raises(scope.OutOfScope):
        fingerprint.fetch_headers("dev.example.test", scope=LAB,
                                  on_request=lambda *a: logged.append(a))
    assert sent == [] and logged == []


def test_out_of_scope_isnt_retried_over_http_or_counted(monkeypatch):
    sent = no_network(monkeypatch)
    host, result, err, n = fingerprint._safe_fetch("evil.test", scope=LAB)
    assert (result, err, n, sent) == (None, "OutOfScope", 0, [])


def test_in_scope_request_logs_the_rule(monkeypatch):
    class R:
        status_code, headers = 200, {"Server": "nginx"}

        def close(self):
            pass
    monkeypatch.setattr(fingerprint.requests, "get", lambda url, **kw: R())
    logged = []
    fingerprint.fetch_headers("www.example.test", scope=LAB,
                              on_request=lambda host, url, rule: logged.append((host, url, rule)))
    assert logged == [("www.example.test", "https://www.example.test/", "*.example.test")]


def test_fingerprint_all_rechecks_every_host(monkeypatch):
    # even if an out-of-scope host slips into the list, the fetch layer stops it
    sent = no_network(monkeypatch)
    fp = fingerprint.fingerprint_all({"hosts": {"evil.test": {"ips": ["8.8.8.8"]}}}, scope=LAB)
    assert sent == [] and fp["requests"] == 0 and fp["errors"] == {"evil.test": "OutOfScope"}
