import json

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
    with pytest.raises(Paced, match="next slot in 900s"):
        p.acquire(max_wait=10)
    clock.now += 900
    p.acquire(max_wait=0)


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
