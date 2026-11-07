import pytest

from collectors import certspotter


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
    from collectors import pacing
    calls = []
    page = [{"id": "1", "dns_names": ["a.example.com"]}]
    monkeypatch.setattr(certspotter.requests, "get", fake_get([Resp(200, page)], calls))
    monkeypatch.setattr(certspotter.PACER, "limit", 1)  # quota of one query: the 2nd page is skipped
    monkeypatch.setattr(pacing.time, "sleep", lambda s: pytest.fail("should not wait an hour"))
    assert certspotter.fetch_raw("example.com") == page
    assert len(calls) == 1
