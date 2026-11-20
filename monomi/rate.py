"""
--rate: a cap on how many ACTIVE requests Monomi sends per second.

Program rules are getting specific ("automated tooling max 1 request per
second"), and the active checks run several hosts in parallel threads. So
the cap is one Limiter shared by every thread: --rate 1 means one request
per second in total, not one per thread.

How it works: each request books the next free time slot (slots are 1/rate
seconds apart), then sleeps until its slot. Booking happens under a lock,
the sleeping doesn't, so threads queue up in order without blocking each
other. Passive lookups (DNS, Shodan, CT logs) never go through it: they
don't touch the target.
"""

import threading
import time

# With --scope (a bug bounty program) and no --rate, active requests go at
# this rate: forgetting --rate on a program shouldn't break its rules.
SCOPED_DEFAULT = 1.0


class RateError(ValueError):
    """--rate isn't a usable number."""


def parse(text) -> float:
    """--rate N: requests per second, > 0. Fractions are fine (0.5 = one every 2s)."""
    try:
        rate = float(text)
    except (TypeError, ValueError):
        raise RateError(f"--rate needs a number of requests per second, got {text!r}")
    if not rate > 0 or rate == float("inf"):
        raise RateError(f"--rate must be more than 0, got {text!r}")
    return rate


class Limiter:
    """Shared by every thread of one run. rate=None means no limit."""

    def __init__(self, rate: float | None, clock=time.monotonic, sleep=time.sleep):
        self.rate = rate
        self._clock = clock
        self._sleep = sleep
        self._lock = threading.Lock()
        self._next = None   # the earliest time the next request may go

    def wait(self) -> None:
        """Block until this request's slot. Call it right before sending."""
        if self.rate is None:
            return
        with self._lock:
            now = self._clock()
            slot = now if self._next is None else max(now, self._next)
            self._next = slot + 1.0 / self.rate
        if slot > now:
            self._sleep(slot - now)

    def __repr__(self) -> str:
        return f"Limiter({self.rate!r})"   # stable, so signatures read the same every run

    def describe(self) -> str:
        return "no limit" if self.rate is None else f"{self.rate:g} request(s)/second"


UNLIMITED = Limiter(None)


def choose(given: float | None, scoped: bool) -> float | None:
    """The rate for a run: what you gave, else 1/s on a scoped run, else no limit."""
    if given is not None:
        return given
    return SCOPED_DEFAULT if scoped else None
