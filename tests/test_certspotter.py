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
