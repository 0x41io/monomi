"""
Saved copies of each Certificate Transparency source, per domain.

crt.sh goes down a lot, and Cert Spotter's free tier runs out during big
sweeps. When a source fails, the last good result it gave for this domain
is better than nothing, as long as it's clearly marked as old. So every
good result is saved to scans/<domain>/sources/<source>.json (latest copy
only), and collect_ct() falls back to it when that source fails.

A saved copy keeps its original collected_at, gets "from_saved": true, and
is never used once it's older than MAX_AGE_DAYS.
"""

import json
import os
import re
from datetime import datetime, timedelta, timezone

from monomi import home

# Inside the monomi folder (one level up from collectors/), next to the scan history
SCANS_DIR = home.data_dir("scans")

MAX_AGE_DAYS = 30


def _path(domain: str, source: str) -> str:
    """scans/<domain>/sources/<source>.json, e.g. "crt.sh database" -> crt.sh-database.json."""
    if not domain or os.path.basename(domain) != domain or domain.startswith("."):
        raise ValueError(f"not a safe folder name: {domain!r}")  # never write outside scans/
    name = re.sub(r"[^a-z0-9.-]+", "-", source.lower())
    return os.path.join(SCANS_DIR, domain, "sources", f"{name}.json")


def save(domain: str, record: dict) -> str:
    """Save one source's result as the latest copy for this domain. Returns the path."""
    path = _path(domain, record["source"])
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = f"{path}.{os.getpid()}.tmp"
    with open(tmp, "w") as f:
        json.dump(record, f, indent=2)
    os.replace(tmp, path)  # swap in one step, so another run never reads half a file
    return path


def load(domain: str, source: str, now: datetime | None = None) -> dict | None:
    """The saved copy for this domain and source, or None if missing, broken or too old."""
    try:
        with open(_path(domain, source)) as f:
            record = json.load(f)
        collected = datetime.fromisoformat(record["collected_at"])
    except (OSError, ValueError, KeyError, TypeError):
        return None  # no copy yet, or one we can't trust: same as having none
    now = now or datetime.now(timezone.utc)
    if record.get("source") != source or now - collected > timedelta(days=MAX_AGE_DAYS):
        return None
    record["from_saved"] = True
    return record
