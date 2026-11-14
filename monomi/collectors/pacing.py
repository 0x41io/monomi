"""
Shared request pacing for the free subdomain sources (CT logs and OTX).

crt.sh (website) and Cert Spotter's free tier both get unhappy when we ask
too often, and a multi-domain sweep is many separate scans: MCP calls in one
server process, or separate CLI runs. So the count of recent requests lives
in a small file (scans/.pacing/<name>.json) that every run shares, instead of
in memory where each run would start from zero.
"""

import json
import os
import threading
import time
from datetime import datetime

from monomi import home

try:
    import fcntl          # Linux and macOS
    msvcrt = None
except ImportError:       # Windows has no fcntl; it locks files with msvcrt instead
    fcntl = None
    import msvcrt

# Inside the monomi folder (one level up from collectors/), next to the other scans
PACING_DIR = home.data_dir("scans", ".pacing")


def _lock_file(f) -> None:
    """Lock the open file so other Monomi runs wait their turn. The lock is
    released when the file closes.

    Pacing is best-effort: if Windows can't get the lock (another run held it
    for ~10 seconds), carry on without it rather than fail the scan.
    """
    if fcntl:
        fcntl.flock(f, fcntl.LOCK_EX)
        return
    try:
        f.seek(0)
        msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)  # lock the first byte; retries for ~10s
    except OSError:
        pass


class Paced(RuntimeError):
    """A request was skipped because the source's limit is used up for now."""


class Pacer:
    """At most `limit` requests per `window` seconds, shared by every Monomi run."""

    def __init__(self, name: str, label: str, limit: int, window: float):
        self.name = name      # file name: scans/.pacing/<name>.json
        self.label = label    # how messages name the source, e.g. "crt.sh"
        self.limit = limit
        self.window = window
        self._lock = threading.Lock()  # threads in one process (the file lock covers other processes)

    def _path(self) -> str:
        return os.path.join(PACING_DIR, f"{self.name}.json")

    def _load(self, f) -> dict:
        """Read the shared state. A missing, empty or broken file counts as 'nothing sent yet'."""
        f.seek(0)
        try:
            state = json.loads(f.read() or "{}")
        except ValueError:
            state = {}
        if not isinstance(state, dict):
            state = {}
        sent = [t for t in state.get("sent", []) if isinstance(t, (int, float))]
        cooldown = state.get("cooldown_until", 0)
        return {"sent": sorted(sent),
                "cooldown_until": cooldown if isinstance(cooldown, (int, float)) else 0}

    def _save(self, f, state: dict) -> None:
        f.seek(0)
        f.truncate()
        json.dump(state, f)

    def _change(self, update):
        """Open the shared file locked, let `update(state, now)` change it, save it.
        Returns whatever update() returns."""
        os.makedirs(PACING_DIR, exist_ok=True)
        with self._lock, open(self._path(), "a+") as f:
            _lock_file(f)
            now = time.time()
            state = self._load(f)
            # Forget requests older than the window: they no longer count
            state["sent"] = [t for t in state["sent"] if t > now - self.window]
            result = update(state, now)
            self._save(f, state)
            return result

    def _wait(self, state: dict, now: float) -> float:
        """Seconds until the next request is allowed (0 = right now)."""
        wait = state["cooldown_until"] - now
        if len(state["sent"]) >= self.limit:
            # The oldest request that still counts frees its slot when it leaves the window
            wait = max(wait, state["sent"][-self.limit] + self.window - now)
        return max(0.0, wait)

    def acquire(self, max_wait: float) -> None:
        """Take one request slot, waiting up to max_wait seconds for it.

        Raises Paced (a RuntimeError, so collectors report it like any other
        failure) if the wait would be longer than max_wait.
        """
        def take(state, now):
            wait = self._wait(state, now)
            if wait > max_wait:
                raise Paced(self._skip_message(wait, now, cooling=state["cooldown_until"] - now >= wait))
            # Book the slot at the time we'll actually send, so other runs count it now
            state["sent"].append(now + wait)
            return wait

        wait = self._change(take)
        if wait > 0:
            time.sleep(wait)  # outside the lock, so other runs aren't blocked meanwhile

    def status(self) -> dict:
        """Requests used in the current window and any cooldown, without taking a slot.

        {"used": 12, "limit": 90, "cooldown_until": None or a time.time() value}
        """
        def look(state, now):
            cooling = state["cooldown_until"] > now
            return {"used": len(state["sent"]), "limit": self.limit,
                    "cooldown_until": state["cooldown_until"] if cooling else None}
        return self._change(look)

    def cool_down(self, seconds: float) -> None:
        """The source told us to back off (e.g. HTTP 429): skip it for `seconds`."""
        def mark(state, now):
            state["cooldown_until"] = max(state["cooldown_until"], now + seconds)
        self._change(mark)

    def _skip_message(self, wait: float, now: float, cooling: bool = False) -> str:
        """Why a request was skipped: a cooldown the source asked for (it
        rate-limited us), or Monomi's own limit. They need different words:
        "60 requests per 60 min" is wrong when only one was sent."""
        at = datetime.fromtimestamp(now + wait).strftime("%H:%M")
        if cooling:
            return (f"{self.label} skipped: cooling down after it rate-limited an earlier "
                    f"request; next try in {wait:.0f}s (about {at})")
        return (f"{self.label} skipped to stay under its rate limit "
                f"({self.limit} requests per {self.window / 60:.0f} min); next slot in "
                f"{wait:.0f}s (about {at})")


# crt.sh's website starts failing above roughly 5 requests a minute
CRTSH = Pacer("crtsh", "crt.sh", limit=5, window=60)
# Cert Spotter's free tier allows 100 queries an hour; keep some headroom.
# Every page we fetch is one query.
CERTSPOTTER = Pacer("certspotter", "Cert Spotter", limit=90, window=3600)
# AlienVault OTX doesn't publish its keyless limit; one request per domain,
# so 60 an hour covers a big sweep, and a 429 starts a cooldown on top.
OTX = Pacer("otx", "AlienVault OTX", limit=60, window=3600)
