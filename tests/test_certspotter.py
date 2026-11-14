import pytest

from monomi.collectors import certspotter


class Resp:
    def __init__(self, status, body=None, headers=None):
        self.status_code = status
        self._body = body
        self.headers = headers or {}

    def json(self):
        return self._body


def fake_get(responses, calls):
    def get(*args, **kwargs):
        calls.append(dict(kwargs["params"]))
        return responses.pop(0)
    return get


def test_rate_limit_waits_then_retries_same_page(monkeypatch):
    calls, sleeps = [], []
    monkeypatch.setattr(certspotter.time, "sleep", sleeps.append)
    monkeypatch.setattr(certspotter.requests, "get", fake_get([
        Resp(429, headers={"Retry-After": "3"}),
        Resp(200, [{"id": "1", "dns_names": ["a.example.com"]}]),
        Resp(200, []),
    ], calls))
    records = certspotter.fetch_raw("example.com")
    assert len(records) == 1
    assert sleeps == [3.0]
    assert "after" not in calls[1]  # retried the first page, didn't skip ahead


def test_rate_limit_gives_up_when_wait_too_long(monkeypatch):
    monkeypatch.setattr(certspotter.time, "sleep", lambda s: pytest.fail("should not wait"))
    monkeypatch.setattr(certspotter.requests, "get", fake_get([
        Resp(429, headers={"Retry-After": "120"}),
    ], []))
    with pytest.raises(RuntimeError, match="rate limit"):
        certspotter.fetch_raw("example.com")


def test_rate_limit_stops_after_retries(monkeypatch):
    sleeps = []
    monkeypatch.setattr(certspotter.time, "sleep", sleeps.append)
    monkeypatch.setattr(certspotter.requests, "get", fake_get([Resp(429)] * 3, []))
    with pytest.raises(RuntimeError, match="rate limit"):
        certspotter.fetch_raw("example.com")
    assert sleeps == [5.0, 5.0]


def test_giving_up_on_429_makes_later_scans_skip(monkeypatch):
    calls = []
    monkeypatch.setattr(certspotter.time, "sleep", lambda s: None)
    monkeypatch.setattr(certspotter.requests, "get", fake_get([Resp(429)] * 3, calls))
    with pytest.raises(RuntimeError, match="rate limit hit"):
        certspotter.fetch_raw("example.com")
    asked = len(calls)
    # The next domain in the sweep doesn't ask Cert Spotter at all
    with pytest.raises(RuntimeError, match="Cert Spotter skipped"):
        certspotter.fetch_raw("example.org")
    assert len(calls) == asked


def test_cooldown_uses_retry_after_when_it_is_a_number():
    assert certspotter.cooldown_seconds(Resp(429, headers={"Retry-After": "120"})) == 120
    assert certspotter.cooldown_seconds(Resp(429, headers={"Retry-After": "99999"})) == certspotter.MAX_COOLDOWN
    assert certspotter.cooldown_seconds(Resp(429)) == certspotter.DEFAULT_COOLDOWN


def test_out_of_quota_mid_way_keeps_pages_already_fetched(monkeypatch):
    from monomi.collectors import pacing
    calls = []
    page = [{"id": "1", "dns_names": ["a.example.com"]}]
    monkeypatch.setattr(certspotter.requests, "get", fake_get([Resp(200, page)], calls))
    monkeypatch.setattr(certspotter.PACER, "limit", 1)  # quota of one query: the 2nd page is skipped
    monkeypatch.setattr(pacing.time, "sleep", lambda s: pytest.fail("should not wait an hour"))
    assert certspotter.fetch_raw("example.com") == page
    assert len(calls) == 1


# --- a cut-short list says so (v1.14: fake [GONE] hosts on the Deriv run) ---

def _page(n):
    return [{"id": str(n), "dns_names": [f"h{n}.example.com"]}]


def test_complete_list_is_not_partial(monkeypatch):
    monkeypatch.setattr(certspotter.requests, "get", fake_get([Resp(200, _page(1)), Resp(200, [])], []))
    records, partial = certspotter.fetch("example.com")
    assert len(records) == 1 and partial is None


def test_429_after_the_first_page_is_partial(monkeypatch):
    monkeypatch.setattr(certspotter.time, "sleep", lambda s: None)
    monkeypatch.setattr(certspotter.requests, "get", fake_get([Resp(200, _page(1))] + [Resp(429)] * 3, []))
    records, partial = certspotter.fetch("example.com")
    assert len(records) == 1 and partial == "stopped after 1 page (rate limit)"


def test_out_of_quota_mid_way_is_partial(monkeypatch):
    from monomi.collectors import pacing
    monkeypatch.setattr(certspotter.requests, "get", fake_get([Resp(200, _page(1))], []))
    monkeypatch.setattr(certspotter.PACER, "limit", 1)
    monkeypatch.setattr(pacing.time, "sleep", lambda s: pytest.fail("should not wait an hour"))
    assert certspotter.fetch("example.com")[1] == "stopped after 1 page (rate limit)"


class NotJSON(Resp):
    def json(self):
        raise ValueError("an HTML error page")


def test_bad_reply_mid_way_is_partial(monkeypatch):
    monkeypatch.setattr(certspotter.requests, "get", fake_get([Resp(200, _page(1)), NotJSON(200)], []))
    assert certspotter.fetch("example.com")[1] == "stopped after 1 page (bad reply)"


def test_page_cap_is_partial(monkeypatch):
    pages = [Resp(200, _page(n)) for n in range(certspotter.MAX_PAGES)]
    monkeypatch.setattr(certspotter.requests, "get", fake_get(pages, []))
    records, partial = certspotter.fetch("example.com")
    assert len(records) == certspotter.MAX_PAGES and partial == f"stopped at the {certspotter.MAX_PAGES}-page cap"


def test_collect_marks_the_record_partial(monkeypatch):
    monkeypatch.setattr(certspotter, "fetch", lambda domain: (_page(1), "stopped after 1 page (rate limit)"))
    assert certspotter.collect("example.com")["partial"] == "stopped after 1 page (rate limit)"
    monkeypatch.setattr(certspotter, "fetch", lambda domain: (_page(1), None))
    assert "partial" not in certspotter.collect("example.com")


def test_scan_warns_and_keeps_the_complete_saved_copy(monkeypatch, capsys):
    from monomi import cli
    from monomi.collectors import saved
    full = {"source": "certspotter", "collected_at": "2026-11-12T12:00:00+00:00", "domain": "lab.test",
            "certificates_seen": 3, "subdomain_count": 3, "subdomains": ["a.lab.test", "b.lab.test", "c.lab.test"]}
    saved.save("lab.test", full)
    cut = {**full, "collected_at": "2026-11-13T12:00:00+00:00", "certificates_seen": 1, "subdomain_count": 1,
           "subdomains": ["a.lab.test"], "partial": "stopped after 1 page (rate limit)"}
    for mod in (cli.crtsh, cli.crtsh_db):
        monkeypatch.setattr(mod, "collect", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("down")))
    monkeypatch.setattr(cli.certspotter, "collect", lambda domain: cut)
    cli.collect_ct({"sources": {}, "errors": {}}, "lab.test")
    assert "Cert Spotter stopped after 1 page (rate limit), so its list may be incomplete" in capsys.readouterr().out
    assert saved.load("lab.test", "certspotter")["subdomain_count"] == 3  # not replaced by part of the list
