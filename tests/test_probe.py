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
    assert r["title"] is None and r["body_kind"] is None and pdf.read_bytes == 0
    assert r["content_type"] == "application/pdf"


def test_big_page_is_read_only_up_to_the_cap(monkeypatch):
    # v1.25 review: 16384 hid the overshoot (a multiple of the chunk size). The
    # real guarantee: reading stops within one chunk of the cap.
    big = Page(body=b"<title>Top</title>" + b"x" * 500_000)
    fake_web(monkeypatch, {"https://big.example.test/": big})
    r = probe.fetch_live("big.example.test", scope=LAB, max_body_bytes=10000)
    assert r["title"] == "Top"
    assert 10000 <= big.read_bytes < 10000 + probe.CHUNK


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
    assert r["redirect_blocked"] == target and r["redirect_blocked_reason"] == "out_of_scope"
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


# ---------- what the body really is (content_type vs body_kind) ----------

def test_json_labeled_html_is_seen_as_json(monkeypatch):
    # like the lab's notes app: JSON sent with Content-Type text/html
    fake_web(monkeypatch, {"https://api.example.test/":
                           Page(headers={"Content-Type": "text/html;charset=utf-8"},
                                body=b'{"app": "notes", "mode": "vulnerable"}')})
    r = probe.fetch_live("api.example.test", scope=LAB)
    assert r["content_type"] == "text/html;charset=utf-8"
    assert r["body_kind"] == "json" and r["title"] is None


@pytest.mark.parametrize("body, kind", [
    (b"<!doctype html><title>x</title>", "html"),
    (b"\xef\xbb\xbf\n  <html></html>", "html"),  # a BOM and blank lines first
    (b"[1, 2]", "json"),
    (b"", "empty"),
    (b"   \n", "empty"),
    (b"plain words", "other"),
])
def test_body_kind_is_judged_from_the_first_character(monkeypatch, body, kind):
    fake_web(monkeypatch, {"https://www.example.test/": Page(body=body)})
    assert probe.fetch_live("www.example.test", scope=LAB)["body_kind"] == kind


def test_unread_body_has_no_kind(monkeypatch):
    fake_web(monkeypatch, {"https://docs.example.test/":
                           Page(headers={"Content-Type": "application/json"}, body=b"{}")})
    r = probe.fetch_live("docs.example.test", scope=LAB)
    assert r["content_type"] == "application/json" and r["body_kind"] is None


def test_missing_content_type_is_none_and_body_not_read(monkeypatch):
    page = Page(headers={}, body=b"<title>x</title>")
    fake_web(monkeypatch, {"https://www.example.test/": page})
    r = probe.fetch_live("www.example.test", scope=LAB)
    assert r["content_type"] is None and r["body_kind"] is None and page.read_bytes == 0


# ---------- probe_all ----------

ENRICHED = {"hosts": {
    "www.example.test": {"ips": ["8.8.8.8"]},
    "app.example.test": {"ips": ["8.8.4.4"]},
    "dev.example.test": {"ips": ["8.8.8.8"]},   # excluded by the scope
    "internal.example.test": {"ips": ["10.0.0.5"]},  # private IP: never probed
    "gone.example.test": {"ips": []},           # doesn't resolve: never probed
}}


def test_probe_all_has_no_default_scope():
    with pytest.raises(TypeError, match="scope"):
        probe.probe_all({"hosts": {}})


def test_probe_all_probes_public_hosts_and_counts_every_request(monkeypatch):
    sent = fake_web(monkeypatch, {
        "https://www.example.test/": redirect(301, "https://www.example.test/home"),
        "https://www.example.test/home": Page(body=b"<title>Home</title>"),
        "https://app.example.test/": Page(body=b"<title>App</title>"),
    })
    logged = []
    out = probe.probe_all(ENRICHED, scope=LAB, on_request=lambda h, url, rule: logged.append(url))
    assert sorted(out["hosts"]) == ["app.example.test", "www.example.test"]
    assert out["hosts"]["www.example.test"]["title"] == "Home"
    assert out["checked"] == 3                        # the three public hosts
    assert out["errors"] == {"dev.example.test": "OutOfScope"}  # rechecked: no request
    assert out["requests"] == 3 == len(logged) == len(sent)   # 2 hops + 1, matches the log
    assert "https://dev.example.test/" not in urls(sent)


def test_probe_all_caps_the_hosts(monkeypatch):
    fake_web(monkeypatch, {"https://app.example.test/": Page()})
    out = probe.probe_all(ENRICHED, scope=UNSCOPED_CLI, max_hosts=1)
    assert out["checked"] == 1 and out["skipped"] == 2


def test_probe_all_shares_one_limiter_across_hosts_and_hops(monkeypatch):
    fake_web(monkeypatch, {
        "https://www.example.test/": redirect(301, "https://www.example.test/home"),
        "https://www.example.test/home": Page(),
        "https://app.example.test/": Page(),
    })
    limiter = CountingLimiter()
    probe.probe_all(ENRICHED, scope=LAB, limiter=limiter)
    assert limiter.slots == 3   # every hop of every host, dev never takes one


# ---------- allowed_hosts: redirects stay on the hosts a person approved (MCP) ----------

def test_redirect_to_an_unapproved_host_is_recorded_not_followed(monkeypatch):
    sent = fake_web(monkeypatch, {"https://www.example.test/": redirect(302, "https://shop.example.test/")})
    r = probe.fetch_live("www.example.test", scope=LAB, allowed_hosts=["www.example.test"])
    assert r["redirect_blocked"] == "https://shop.example.test/"   # in scope, but not approved
    assert r["redirect_blocked_reason"] == "not_approved"
    assert urls(sent) == ["https://www.example.test/"]


def test_redirect_to_another_approved_host_is_followed(monkeypatch):
    fake_web(monkeypatch, {"https://www.example.test/": redirect(302, "https://SHOP.example.test./"),
                           "https://SHOP.example.test./": Page(body=b"<title>Shop</title>")})
    r = probe.fetch_live("www.example.test", scope=LAB,
                         allowed_hosts=["WWW.example.test", "shop.example.test"])  # any spelling
    assert r["title"] == "Shop" and r["redirect_blocked"] is None


def test_scope_refusal_wins_over_approval(monkeypatch):
    # dev is excluded by the scope: that's the reason given, even if it's "approved"
    fake_web(monkeypatch, {"https://www.example.test/": redirect(302, "https://dev.example.test/")})
    r = probe.fetch_live("www.example.test", scope=LAB,
                         allowed_hosts=["www.example.test", "dev.example.test"])
    assert r["redirect_blocked_reason"] == "out_of_scope"


def test_without_allowed_hosts_any_in_scope_host_is_followed(monkeypatch):
    # the CLI: the scope file is the only limit
    fake_web(monkeypatch, {"https://www.example.test/": redirect(302, "https://shop.example.test/"),
                           "https://shop.example.test/": Page()})
    r = probe.fetch_live("www.example.test", scope=LAB)
    assert r["final_url"] == "https://shop.example.test/" and r["redirect_blocked"] is None


def test_probe_all_passes_allowed_hosts_to_every_host(monkeypatch):
    sent = fake_web(monkeypatch, {"https://www.example.test/": redirect(302, "https://shop.example.test/"),
                                  "https://app.example.test/": Page()})
    enrichment = {"hosts": {"www.example.test": {"ips": ["8.8.8.8"]},
                            "app.example.test": {"ips": ["8.8.8.8"]}}}
    out = probe.probe_all(enrichment, scope=LAB, allowed_hosts=["www.example.test", "app.example.test"])
    assert out["hosts"]["www.example.test"]["redirect_blocked_reason"] == "not_approved"
    assert "https://shop.example.test/" not in urls(sent)


# ---------- v1.25 review: every redirect goes through _refuse_hop ----------
# The scope check and the hop checks run for real here (real requests/urllib3
# URL parsing); only requests.get is faked. connects_to() is where requests
# would really connect: every URL actually sent must be in scope.

def connects_to(url):
    from urllib3.util import parse_url
    return parse_url(requests.Request("GET", url).prepare().url).host


def assert_only_in_scope_hosts_contacted(sent):
    for url, _ in sent:
        assert LAB.match(connects_to(url)).allowed, f"{url} reached {connects_to(url)}"


def test_backslash_redirect_never_leaves_scope_or_the_approval(monkeypatch):
    # the critical finding: urlparse says www.example.test, requests connects to evil.test
    target = "http://evil.test\\@www.example.test/"
    assert connects_to(target) == "evil.test"
    for allowed in (None, ["www.example.test"]):
        sent = fake_web(monkeypatch, {"https://app.example.test/": redirect(302, target)})
        r = probe.fetch_live("app.example.test", scope=LAB, allowed_hosts=allowed)
        assert r["redirect_blocked_reason"] == "ambiguous_url"
        assert urls(sent) == ["https://app.example.test/"]


@pytest.mark.parametrize("location, reason", [
    ("http://evil.test\\@www.example.test/", "ambiguous_url"),
    ("https://www.example.test@evil.test/", "out_of_scope"),     # connects to evil.test
    ("//evil.test/x", "out_of_scope"),
    ("https://www.example.test:8443/", "other_port"),
    ("https://www.example.test:99999/", "invalid_url"),
    ("ftp://www.example.test/", "unsupported_url"),
    ("javascript:alert(1)", "unsupported_url"),
    ("file:///etc/passwd", "unsupported_url"),
    ("http://[::1/", "invalid_url"),                             # urljoin itself raises
    ("https://café.example.test/", "ambiguous_url"),             # IDN: parsers disagree
    ("https://8.8.8.8/", "out_of_scope"),                        # the scope has no IPs
    ("https://dev.example.test/", "out_of_scope"),
])
def test_tricky_redirects_are_refused_with_a_reason(monkeypatch, location, reason):
    sent = fake_web(monkeypatch, {"https://www.example.test/": redirect(302, location)})
    r = probe.fetch_live("www.example.test", scope=LAB)
    assert r["redirect_blocked_reason"] == reason
    assert r["chain"] == [] and r["final_url"] == "https://www.example.test/"
    assert urls(sent) == ["https://www.example.test/"]
    assert reason in probe.BLOCK_REASONS


@pytest.mark.parametrize("location", ["/login", "https://shop.example.test/", "http://www.example.test/a",
                                      "https://SHOP.example.test./", "https://www.example.test:443/"])
def test_ordinary_redirects_are_followed_and_stay_in_scope(monkeypatch, location):
    pages = {"https://www.example.test/": redirect(302, location)}
    sent = fake_web(monkeypatch, pages)
    from urllib.parse import urljoin
    pages[urljoin("https://www.example.test/", location)] = Page(body=b"<title>ok</title>")
    r = probe.fetch_live("www.example.test", scope=LAB)
    assert r["title"] == "ok" and len(r["chain"]) == 1 and r["redirect_blocked"] is None
    assert_only_in_scope_hosts_contacted(sent)


def test_a_malformed_location_never_crashes_the_run(monkeypatch):
    fake_web(monkeypatch, {"https://www.example.test/": redirect(302, "http://[::1/"),
                           "https://app.example.test/": Page(body=b"<title>App</title>")})
    out = probe.probe_all({"hosts": {"www.example.test": {"ips": ["8.8.8.8"]},
                                     "app.example.test": {"ips": ["8.8.8.8"]}}}, scope=LAB)
    assert out["hosts"]["www.example.test"]["redirect_blocked_reason"] == "invalid_url"
    assert out["hosts"]["app.example.test"]["title"] == "App"   # the other host's result survives


def test_unsupported_redirect_takes_no_slot_no_log_line_and_no_count(monkeypatch):
    sent = fake_web(monkeypatch, {"https://www.example.test/": redirect(302, "ftp://www.example.test/")})
    limiter, logged = CountingLimiter(), []
    host, rec, err, n = probe.probe_host("www.example.test", scope=LAB, limiter=limiter,
                                         on_request=lambda *a: logged.append(a))
    assert rec["redirect_blocked_reason"] == "unsupported_url"
    assert n == 1 == len(logged) == len(sent) == limiter.slots   # only the homepage


# ---------- private and local addresses (review #4) ----------

@pytest.mark.parametrize("location", ["http://127.0.0.1/admin", "http://169.254.169.254/latest/meta-data",
                                      "http://192.168.1.1/", "http://10.0.0.5:80/", "http://[::1]/"])
def test_unscoped_redirect_to_a_private_ip_is_refused(monkeypatch, location):
    sent = fake_web(monkeypatch, {"https://www.example.test/": redirect(302, location)})
    r = probe.fetch_live("www.example.test", scope=UNSCOPED_CLI)
    assert r["redirect_blocked_reason"] in ("private_address", "invalid_url")
    assert urls(sent) == ["https://www.example.test/"]


def test_a_name_that_resolves_privately_is_refused(monkeypatch):
    monkeypatch.setattr(probe, "RESOLVE", lambda host: ["93.184.216.34", "10.1.2.3"]
                        if host == "intranet.example.test" else ["93.184.216.34"])
    sent = fake_web(monkeypatch, {"https://www.example.test/": redirect(302, "https://intranet.example.test/")})
    r = probe.fetch_live("www.example.test", scope=LAB)
    assert r["redirect_blocked_reason"] == "private_address"
    assert urls(sent) == ["https://www.example.test/"]


def test_a_name_that_doesnt_resolve_is_not_requested(monkeypatch):
    def nxdomain(host):
        raise OSError("no such name")
    monkeypatch.setattr(probe, "RESOLVE", nxdomain)
    sent = fake_web(monkeypatch, {"https://www.example.test/": redirect(302, "https://gone.example.test/")})
    assert probe.fetch_live("www.example.test", scope=LAB)["redirect_blocked_reason"] == "no_dns"
    assert len(sent) == 1


# ---------- the cap and the time limit are enforced (review #6, #9) ----------

def test_the_worst_case_is_exactly_max_requests_and_matches_the_log(monkeypatch):
    # 5 redirects, the 6th HTTPS hop fails on TLS, then a full plain-HTTP chain
    pages = {}
    for scheme in ("https", "http"):
        for i in range(5):
            pages[f"{scheme}://www.example.test/{i}" if i else f"{scheme}://www.example.test/"] = \
                redirect(302, f"{scheme}://www.example.test/{i + 1}")
    pages["https://www.example.test/5"] = requests.exceptions.SSLError
    pages["http://www.example.test/5"] = Page(body=b"<title>end</title>")
    sent = fake_web(monkeypatch, pages)
    logged, limiter = [], CountingLimiter()
    host, rec, err, n = probe.probe_host("www.example.test", scope=LAB, limiter=limiter,
                                         on_request=lambda *a: logged.append(a))
    assert rec["title"] == "end" and rec["https_error"] == "SSLError"
    assert n == len(sent) == len(logged) == limiter.slots == probe.MAX_REQUESTS == 12


def test_the_cap_stops_sending_even_if_the_limits_change(monkeypatch):
    # a backstop: if MAX_REDIRECTS grows past the approved cap, the cap still holds
    sent = fake_web(monkeypatch, {"https://loop.example.test/": redirect(301, "https://loop.example.test/")})
    host, rec, err, n = probe.probe_host("loop.example.test", scope=LAB, max_redirects=50, max_requests=4)
    assert rec is None and err == "RequestCapReached" and n == 4 == len(sent)


def test_the_time_limit_stops_the_next_request_and_isnt_retried(monkeypatch):
    now = [0.0]
    monkeypatch.setattr(probe, "CLOCK", lambda: now[0])
    pages = {"https://slow.example.test/": redirect(302, "https://slow.example.test/2"),
             "https://slow.example.test/2": redirect(302, "https://slow.example.test/3")}
    sent = []

    def slow_get(url, **kwargs):
        sent.append(url)
        now[0] += 40   # every request takes 40 "seconds"
        return pages[url]
    monkeypatch.setattr(probe.requests, "get", slow_get)
    host, rec, err, n = probe.probe_host("slow.example.test", scope=LAB, time_limit=60)
    # after 2 requests it's 80s in: the 3rd is never sent, and a time limit isn't retried over HTTP
    assert err == "HostTimeLimit" and n == 2 == len(sent)


# ---------- text decoding (review #3, #8) ----------

@pytest.mark.parametrize("ctype, body, title", [
    ("text/html", "<title>Café</title>".encode(), "Café"),                       # no charset: utf-8
    ("text/html; charset=iso-8859-1", "<title>Café</title>".encode("latin-1"), "Café"),
    ("text/html; charset=x-nope", "<title>Café</title>".encode(), "Café"),     # unknown: no crash
    ('text/html; charset="UTF-8"', "<title>日本</title>".encode(), "日本"),
])
def test_charset_is_the_stated_one_else_utf8_and_never_crashes(monkeypatch, ctype, body, title):
    fake_web(monkeypatch, {"https://www.example.test/":
                           Page(headers={"Content-Type": ctype}, body=body, encoding="ISO-8859-1")})
    assert probe.fetch_live("www.example.test", scope=LAB)["title"] == title


# ---------- the chain only holds redirects that were followed (review #10) ----------

def test_a_blocked_redirect_is_not_in_the_chain(monkeypatch):
    fake_web(monkeypatch, {"https://www.example.test/": redirect(301, "https://shop.example.test/"),
                           "https://shop.example.test/": redirect(302, "https://evil.test/")})
    r = probe.fetch_live("www.example.test", scope=LAB)
    assert [step["to"] for step in r["chain"]] == ["https://shop.example.test/"]
    assert r["redirect_blocked"] == "https://evil.test/" and r["final_url"] == "https://shop.example.test/"
