import threading
import time

import pytest

from monomi import rate
from monomi.rate import Limiter, RateError


class FakeClock:
    """time stands still until something sleeps."""
    def __init__(self):
        self.now = 0.0
        self.slept = []

    def clock(self):
        return self.now

    def sleep(self, seconds):
        self.slept.append(seconds)
        self.now += seconds


def test_ten_requests_at_rate_1_take_at_least_9_seconds():
    c = FakeClock()
    limiter = Limiter(1, clock=c.clock, sleep=c.sleep)
    for _ in range(10):
        limiter.wait()
    assert c.now >= 9


def test_the_first_request_goes_at_once():
    c = FakeClock()
    Limiter(1, clock=c.clock, sleep=c.sleep).wait()
    assert c.slept == []


def test_fractions_space_requests_further_apart():
    c = FakeClock()
    limiter = Limiter(0.5, clock=c.clock, sleep=c.sleep)
    limiter.wait()
    limiter.wait()
    assert c.now == pytest.approx(2.0)


def test_time_already_passed_counts():
    # a slow request between two waits uses up the gap: no extra sleep
    c = FakeClock()
    limiter = Limiter(1, clock=c.clock, sleep=c.sleep)
    limiter.wait()
    c.now += 5
    limiter.wait()
    assert c.slept == []


def test_no_limit_never_sleeps():
    c = FakeClock()
    limiter = Limiter(None, clock=c.clock, sleep=c.sleep)
    for _ in range(50):
        limiter.wait()
    assert c.slept == [] and rate.UNLIMITED.rate is None


def test_the_cap_is_a_total_across_threads():
    # 8 threads, 2 requests each, at 40/s: 16 requests need >= 15/40 s in total
    limiter = Limiter(40)
    start = time.monotonic()
    threads = [threading.Thread(target=lambda: [limiter.wait() for _ in range(2)]) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert time.monotonic() - start >= 15 / 40 - 0.01


@pytest.mark.parametrize("text, expected", [("1", 1.0), ("0.5", 0.5), ("10", 10.0)])
def test_parse_reads_requests_per_second(text, expected):
    assert rate.parse(text) == expected


@pytest.mark.parametrize("text", ["0", "-1", "fast", "", "inf", "nan"])
def test_parse_refuses_bad_rates(text):
    with pytest.raises(RateError):
        rate.parse(text)


def test_choose_defaults_to_1_per_second_only_on_scoped_runs():
    assert rate.choose(None, scoped=True) == rate.SCOPED_DEFAULT == 1.0
    assert rate.choose(None, scoped=False) is None
    assert rate.choose(5.0, scoped=True) == 5.0
    assert rate.choose(5.0, scoped=False) == 5.0


def test_describe():
    assert Limiter(None).describe() == "no limit"
    assert Limiter(1).describe() == "1 request(s)/second"
