import pytest
import requests

from monomi import probe, research, scope
from monomi.scope import UNSCOPED_CLI

LAB = scope.from_bytes(b"*.example.test\n!dev.example.test\n")
HTML = {"Content-Type": "text/html; charset=utf-8"}


class Page:
    """A fake streamed response: status, headers, and a body probe may read."""
    def __init__(self, status=200, headers=None, body=b"", encoding="utf-8"):
        self.status_code = status
        self.headers = headers if headers is not None else dict(HTML)
        self.encoding = encoding
        self._body = body
        self.read_bytes = 0
        self.closed = False

    def iter_content(self, size):
        for i in range(0, len(self._body), size):
            chunk = self._body[i:i + size]
            self.read_bytes += len(chunk)
            yield chunk

    def close(self):
        self.closed = True


def redirect(status, location):
    return Page(status, {"Location": location})


def fake_web(monkeypatch, pages):
    """pages: {url: Page, or an exception class to raise for it}. Returns
    the list of (url, request headers) sent, in order. Any URL not listed
    fails the test."""
    sent = []

    def get(url, **kwargs):
        assert kwargs["allow_redirects"] is False  # probe follows by hand, never requests
        sent.append((url, kwargs["headers"]))
        outcome = pages.get(url)
        if isinstance(outcome, type) and issubclass(outcome, Exception):
            raise outcome("fake")
        if outcome is None:
            raise AssertionError(f"unexpected request to {url}")
        return outcome
    monkeypatch.setattr(probe.requests, "get", get)
    return sent


def urls(sent):
    return [url for url, _ in sent]


class CountingLimiter:
    """Stands in for rate.Limiter: counts the slots taken."""
    def __init__(self):
        self.slots = 0

    def wait(self):
        self.slots += 1


# ---------- the live-page record ----------

def test_plain_page_gets_its_title(monkeypatch):
    fake_web(monkeypatch, {"https://www.example.test/":
                           Page(body=b"<html><TITLE>\n  Tom &amp;\n Jerry </TITLE></html>")})
    r = probe.fetch_live("www.example.test", scope=LAB)
    assert r["status"] == 200 and r["chain"] == []
    assert r["final_url"] == r["start_url"] == "https://www.example.test/"
    assert r["title"] == "Tom & Jerry"  # entities decoded, whitespace squeezed
    assert r["redirect_blocked"] is None and r["hit_redirect_limit"] is False


def test_title_control_characters_are_dropped(monkeypatch):
    # the title is written by the target: an escape code must never reach a terminal
    fake_web(monkeypatch, {"https://www.example.test/":
                           Page(body=b"<title>Admin\x1b[2J\x07 panel</title>")})
    r = probe.fetch_live("www.example.test", scope=LAB)
    assert r["title"] == "Admin [2J panel"
    assert all(ch.isprintable() for ch in r["title"])


def test_follows_redirects_to_the_final_page(monkeypatch):
    first = redirect(301, "/login")  # a relative Location
    sent = fake_web(monkeypatch, {
        "https://app.example.test/": first,
        "https://app.example.test/login": redirect(302, "https://sso.example.test/start"),
        "https://sso.example.test/start": Page(body=b"<title>Sign in</title>"),
    })
    r = probe.fetch_live("app.example.test", scope=LAB)
    assert r["final_url"] == "https://sso.example.test/start" and r["status"] == 200
    assert r["chain"] == [
        {"status": 301, "from": "https://app.example.test/", "to": "https://app.example.test/login"},
        {"status": 302, "from": "https://app.example.test/login", "to": "https://sso.example.test/start"},
    ]
    assert r["title"] == "Sign in"
    assert urls(sent) == ["https://app.example.test/", "https://app.example.test/login",
                          "https://sso.example.test/start"]
    assert first.closed and first.read_bytes == 0  # a redirect's body is never read


def test_non_html_page_body_is_not_read(monkeypatch):
    pdf = Page(headers={"Content-Type": "application/pdf"}, body=b"%PDF-1.7 ...")
    fake_web(monkeypatch, {"https://docs.example.test/": pdf})
    r = probe.fetch_live("docs.example.test", scope=LAB)
    assert r["title"] is None and pdf.read_bytes == 0


def test_big_page_is_read_only_up_to_the_cap(monkeypatch):
    big = Page(body=b"<title>Top</title>" + b"x" * 500_000)
    fake_web(monkeypatch, {"https://big.example.test/": big})
    r = probe.fetch_live("big.example.test", scope=LAB, max_body_bytes=16384)
    assert r["title"] == "Top"
    assert big.read_bytes <= 16384


def test_redirect_loop_stops_at_the_limit(monkeypatch):
    sent = fake_web(monkeypatch, {"https://loop.example.test/":
                                  redirect(301, "https://loop.example.test/")})
    r = probe.fetch_live("loop.example.test", scope=LAB, max_redirects=3)
    assert r["hit_redirect_limit"] is True
    assert len(r["chain"]) == 3 and len(sent) == 4  # 3 hops followed, 4 requests


# ---------- scope at every hop ----------

def test_probe_has_no_default_scope():
    # forgetting the scope is a crash in the tests, never a silent skip
    with pytest.raises(TypeError, match="scope"):
        probe.fetch_live("www.example.test")
    with pytest.raises(TypeError, match="scope"):
        probe.probe_host("www.example.test")


def test_out_of_scope_host_gets_no_request_no_slot_and_no_log_line(monkeypatch):
    sent, logged, limiter = fake_web(monkeypatch, {}), [], CountingLimiter()
    with pytest.raises(scope.OutOfScope):
        probe.fetch_live("dev.example.test", scope=LAB, limiter=limiter,  # excluded by !dev
                         on_request=lambda *a: logged.append(a))
    assert sent == [] and logged == [] and limiter.slots == 0


@pytest.mark.parametrize("target", [
    "https://evil.test/login",         # another site entirely
    "https://dev.example.test/admin",  # inside the wildcard, but excluded
])
def test_redirect_out_of_scope_is_recorded_not_followed(monkeypatch, target):
    sent, limiter = fake_web(monkeypatch, {"https://www.example.test/": redirect(302, target)}), CountingLimiter()
    r = probe.fetch_live("www.example.test", scope=LAB, limiter=limiter)
    assert r["redirect_blocked"] == target
    assert r["status"] == 302 and r["final_url"] == "https://www.example.test/"
    assert r["title"] is None
    assert urls(sent) == ["https://www.example.test/"]  # the target was never requested
    assert limiter.slots == 1                             # and never took a --rate slot


def test_every_hop_is_logged_with_its_rule(monkeypatch):
    fake_web(monkeypatch, {
        "https://www.example.test/": redirect(301, "https://shop.example.test/"),
        "https://shop.example.test/": Page(body=b"<title>Shop</title>"),
    })
    logged = []
    probe.fetch_live("www.example.test", scope=LAB,
                     on_request=lambda host, url, rule: logged.append((host, url, rule)))
    assert logged == [("www.example.test", "https://www.example.test/", "*.example.test"),
                      ("www.example.test", "https://shop.example.test/", "*.example.test")]


# ---------- research headers and --rate on every hop ----------

def test_every_hop_sends_the_active_user_agent(monkeypatch):
    sent = fake_web(monkeypatch, {
        "https://www.example.test/": redirect(301, "https://www.example.test/home"),
        "https://www.example.test/home": Page(),
    })
    probe.fetch_live("www.example.test", scope=LAB)
    assert len(sent) == 2
    assert all("active security check" in headers["User-Agent"] for _, headers in sent)


def test_every_hop_carries_the_research_header(monkeypatch):
    # a program that requires the header must get it on redirects too
    sent = fake_web(monkeypatch, {
        "https://www.example.test/": redirect(301, "https://www.example.test/home"),
        "https://www.example.test/home": Page(),
    })
    res = research.Research({"X-HackerOne-Researcher": "someone"}, "0" * 64, "research.txt")
    probe.fetch_live("www.example.test", scope=LAB, research=res)
    assert len(sent) == 2
    for _, headers in sent:
        assert headers["X-HackerOne-Researcher"] == "someone"
        assert "active security check" in headers["User-Agent"]


def test_every_hop_takes_its_own_rate_slot(monkeypatch):
    fake_web(monkeypatch, {
        "https://www.example.test/": redirect(301, "https://www.example.test/a"),
        "https://www.example.test/a": redirect(302, "https://www.example.test/b"),
        "https://www.example.test/b": Page(),
    })
    limiter = CountingLimiter()
    probe.fetch_live("www.example.test", scope=LAB, limiter=limiter)
    assert limiter.slots == 3


# ---------- probe_host: HTTPS first, HTTP fallback, request counting ----------

def test_out_of_scope_isnt_retried_over_http_or_counted(monkeypatch):
    sent = fake_web(monkeypatch, {})
    host, rec, err, n = probe.probe_host("evil.test", scope=LAB)
    assert (rec, err, n, sent) == (None, "OutOfScope", 0, [])


@pytest.mark.parametrize("failure", [requests.exceptions.SSLError, requests.ConnectionError])
def test_tls_error_or_refused_retries_on_http(monkeypatch, failure):
    sent = fake_web(monkeypatch, {"https://dev2.example.test/": failure,
                                  "http://dev2.example.test/": Page(body=b"<title>Plain</title>")})
    host, rec, err, n = probe.probe_host("dev2.example.test", scope=LAB)
    assert err is None and n == 2 and rec["title"] == "Plain"
    assert rec["start_url"] == "http://dev2.example.test/"
    assert rec["https_error"] == failure.__name__  # the HTTPS failure is never lost
    assert urls(sent) == ["https://dev2.example.test/", "http://dev2.example.test/"]


@pytest.mark.parametrize("failure", [requests.Timeout, requests.ConnectTimeout,
                                     requests.ReadTimeout])
def test_timeouts_are_not_retried(monkeypatch, failure):
    sent = fake_web(monkeypatch, {"https://slow.example.test/": failure})
    host, rec, err, n = probe.probe_host("slow.example.test", scope=LAB)
    assert rec is None and err == failure.__name__ and n == 1
    assert urls(sent) == ["https://slow.example.test/"]


def test_both_failing_keeps_both_errors(monkeypatch):
    fake_web(monkeypatch, {"https://dead.example.test/": requests.exceptions.SSLError,
                           "http://dead.example.test/": requests.ConnectionError})
    host, rec, err, n = probe.probe_host("dead.example.test", scope=LAB)
    assert rec is None and n == 2 and err == "SSLError; http: ConnectionError"


def test_request_count_includes_hops_and_matches_the_log(monkeypatch):
    fake_web(monkeypatch, {
        "https://www.example.test/": redirect(301, "https://www.example.test/a"),
        "https://www.example.test/a": redirect(302, "https://www.example.test/b"),
        "https://www.example.test/b": Page(),
    })
    logged = []
    host, rec, err, n = probe.probe_host("www.example.test", scope=UNSCOPED_CLI,
                                         on_request=lambda h, url, rule: logged.append(url))
    assert err is None and n == 3 == len(logged)


def test_probe_host_passes_rate_and_research_to_the_http_retry(monkeypatch):
    sent = fake_web(monkeypatch, {"https://dev2.example.test/": requests.exceptions.SSLError,
                                  "http://dev2.example.test/": Page()})
    res = research.Research({"X-Intigriti": "someone"}, "0" * 64, "research.txt")
    limiter = CountingLimiter()
    probe.probe_host("dev2.example.test", scope=LAB, limiter=limiter, research=res)
    assert limiter.slots == 2
    assert all(headers["X-Intigriti"] == "someone" for _, headers in sent)
