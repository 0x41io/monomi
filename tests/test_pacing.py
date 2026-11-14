import importlib.util
import json
import sys
import types

import pytest

from collectors import pacing
from collectors.pacing import Pacer, Paced


class Clock:
    """A fake clock: sleeping just moves time forward, so tests run instantly."""
    def __init__(self, start=1_000_000.0):
        self.now = start
        self.sleeps = []

    def time(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


@pytest.fixture
def clock(monkeypatch):
    c = Clock()
    monkeypatch.setattr(pacing.time, "time", c.time)
    monkeypatch.setattr(pacing.time, "sleep", c.sleep)
    return c


def test_requests_under_the_limit_go_right_away(clock):
    p = Pacer("t", "Test", limit=3, window=60)
    for _ in range(3):
        p.acquire(max_wait=0)
    assert clock.sleeps == []


def test_waits_for_the_oldest_slot_when_full(clock):
    p = Pacer("t", "Test", limit=2, window=60)
    p.acquire(max_wait=0)
    clock.now += 10
    p.acquire(max_wait=0)
    p.acquire(max_wait=60)  # full: waits until the first one is 60s old
    assert clock.sleeps == [50]


def test_skips_when_the_wait_is_too_long(clock):
    p = Pacer("t", "Test", limit=1, window=60)
    p.acquire(max_wait=0)
    with pytest.raises(Paced, match="Test skipped to stay under its rate limit"):
        p.acquire(max_wait=30)
    assert clock.sleeps == []


def test_paced_counts_as_a_runtime_error():
    # collect_ct() catches RuntimeError, so a skip is reported like any failure
    assert issubclass(Paced, RuntimeError)


def test_old_requests_stop_counting(clock):
    p = Pacer("t", "Test", limit=1, window=60)
    p.acquire(max_wait=0)
    clock.now += 61
    p.acquire(max_wait=0)
    assert clock.sleeps == []


def test_count_is_shared_between_pacers_with_the_same_name(clock):
    # Two Pacer objects stand in for two separate Monomi runs reading one file
    Pacer("shared", "Test", limit=1, window=60).acquire(max_wait=0)
    with pytest.raises(Paced):
        Pacer("shared", "Test", limit=1, window=60).acquire(max_wait=0)


def test_cool_down_blocks_until_it_ends(clock):
    p = Pacer("t", "Test", limit=100, window=3600)
    p.cool_down(900)
    with pytest.raises(Paced, match="cooling down after it rate-limited an earlier request; next try in 900s"):
        p.acquire(max_wait=10)
    clock.now += 900
    p.acquire(max_wait=0)


def test_skip_message_names_the_real_reason(clock):
    """The bug from the first OTX run: one request, a 429, then "60 requests per
    60 min" as the reason. A cooldown says cooldown; a full window says the limit."""
    p = Pacer("t", "Test", limit=60, window=3600)
    p.acquire(max_wait=0)
    p.cool_down(600)
    with pytest.raises(Paced) as e:
        p.acquire(max_wait=0)
    assert "cooling down" in str(e.value) and "60 requests" not in str(e.value)

    full = Pacer("f", "Test", limit=1, window=60)
    full.acquire(max_wait=0)
    with pytest.raises(Paced, match="to stay under its rate limit \\(1 requests per 1 min\\)"):
        full.acquire(max_wait=0)


def test_broken_state_file_counts_as_empty(clock, pacing_dir):
    pacing_dir.mkdir()
    (pacing_dir / "t.json").write_text("not json{")
    Pacer("t", "Test", limit=1, window=60).acquire(max_wait=0)
    saved = json.loads((pacing_dir / "t.json").read_text())
    assert saved["sent"] == [clock.now]


def test_wrong_shaped_state_file_counts_as_empty(clock, pacing_dir):
    pacing_dir.mkdir()
    (pacing_dir / "t.json").write_text('["a list", "not a dict"]')
    Pacer("t", "Test", limit=1, window=60).acquire(max_wait=0)


# --- Windows: no fcntl, file locks come from msvcrt ---

def fake_msvcrt(fail=False):
    """Stands in for Windows' msvcrt module and records each lock request."""
    calls = []

    def locking(fd, mode, nbytes):
        calls.append((mode, nbytes))
        if fail:
            raise OSError("lock busy")

    return types.SimpleNamespace(LK_LOCK=1, locking=locking, calls=calls)


def test_module_imports_without_fcntl(monkeypatch):
    """On Windows `import fcntl` fails; the module must still load and use msvcrt."""
    fake = fake_msvcrt()
    monkeypatch.setitem(sys.modules, "fcntl", None)  # None makes `import fcntl` raise ImportError
    monkeypatch.setitem(sys.modules, "msvcrt", fake)
    spec = importlib.util.spec_from_file_location("pacing_on_windows", pacing.__file__)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.fcntl is None
    assert mod.msvcrt is fake


def test_windows_lock_is_used(clock, monkeypatch):
    fake = fake_msvcrt()
    monkeypatch.setattr(pacing, "fcntl", None)
    monkeypatch.setattr(pacing, "msvcrt", fake)
    Pacer("t", "Test", limit=3, window=60).acquire(max_wait=0)
    assert fake.calls == [(fake.LK_LOCK, 1)]


def test_windows_lock_failure_does_not_stop_the_scan(clock, monkeypatch):
    fake = fake_msvcrt(fail=True)
    monkeypatch.setattr(pacing, "fcntl", None)
    monkeypatch.setattr(pacing, "msvcrt", fake)
    p = Pacer("t", "Test", limit=1, window=60)
    p.acquire(max_wait=0)  # lock fails, request still goes through
    with pytest.raises(Paced):  # and the count was still saved
        p.acquire(max_wait=0)
