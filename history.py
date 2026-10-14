"""Scan history: save each scan's hostnames and compare against the previous one."""

import json
import os
from datetime import datetime

# Always inside the monomi folder, no matter where the command is run from;
# otherwise each working folder would get its own separate history.
SCANS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scans")


def _domain_dir(domain: str) -> str:
    return os.path.join(SCANS_DIR, domain)


def load_last(domain: str):
    """Return the most recent saved scan for this domain, or None if there isn't one."""
    d = _domain_dir(domain)
    if not os.path.isdir(d):
        return None
    files = sorted(f for f in os.listdir(d) if f.endswith(".json"))
    if not files:
        return None
    with open(os.path.join(d, files[-1])) as f:
        return json.load(f)


def save(domain: str, subdomains: list) -> str:
    """Save this scan as scans/<domain>/<timestamp>.json and return the path."""
    d = _domain_dir(domain)
    os.makedirs(d, exist_ok=True)
    now = datetime.now()
    path = os.path.join(d, now.strftime("%Y-%m-%d_%H%M%S") + ".json")
    with open(path, "w") as f:
        json.dump(
            {
                "target": domain,
                "scanned_at": now.isoformat(timespec="seconds"),
                "subdomains": sorted(subdomains),
            },
            f,
            indent=2,
        )
    return path


def compare(previous: dict, current: list) -> dict:
    """Work out which hostnames are new and which disappeared since the previous scan."""
    old, new = set(previous["subdomains"]), set(current)
    return {
        "previous_scan": previous["scanned_at"],
        "added": sorted(new - old),
        "removed": sorted(old - new),
    }
