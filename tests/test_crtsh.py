import pytest

from collectors import crtsh, pacing
from collectors.pacing import Paced


class Resp:
    def __init__(self, status, text=""):
        self.status_code = status
        self.text = text

    def json(self):
        return []


def fill_crtsh_slots(n):
    """Pretend n crt.sh requests just went out (from this or another run)."""
    for _ in range(n):
        pacing.CRTSH.acquire(max_wait=0)


def test_skipped_before_any_try_when_crtsh_slots_are_used_up(monkeypatch):
    fill_crtsh_slots(5)
    monkeypatch.setattr(crtsh.requests, "get", lambda *a, **k: pytest.fail("should not ask crt.sh"))
    with pytest.raises(Paced, match="crt.sh skipped"):
        crtsh.fetch_raw("example.com", budget=20)


def test_retry_skipped_keeps_the_first_error(monkeypatch):
    fill_crtsh_slots(4)  # the first try takes the 5th slot, the retry finds none left
    monkeypatch.setattr(crtsh.time, "sleep", lambda s: None)
    calls = []
    monkeypatch.setattr(crtsh.requests, "get", lambda *a, **k: calls.append(1) or Resp(502))
    with pytest.raises(RuntimeError) as e:
        crtsh.fetch_raw("example.com", budget=20)
    assert len(calls) == 1
    assert "HTTP 502" in str(e.value) and "crt.sh skipped" in str(e.value)


def test_each_try_takes_a_slot(monkeypatch, pacing_dir):
    monkeypatch.setattr(crtsh.requests, "get", lambda *a, **k: Resp(200, "[]"))
    crtsh.fetch_raw("example.com", budget=20)
    assert (pacing_dir / "crtsh.json").exists()
    fill_crtsh_slots(4)  # 1 + 4 = the full 5
    with pytest.raises(Paced):
        pacing.CRTSH.acquire(max_wait=0)
