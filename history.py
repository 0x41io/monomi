"""Scan history: save each scan's hostnames and compare against the previous one.

Since v1.14 every source's list is kept separately, so one source failing,
being cut short, or joining for the first time can't make hosts look new or
gone. A source that didn't work fully keeps its list from the last scan
("carried"), so its hosts are never reported gone because of it.
"""

import json
import os
from datetime import datetime

# Always inside the monomi folder, no matter where the command is run from;
# otherwise each working folder would get its own separate history.
SCANS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scans")

# Scans saved before v1.14 have one combined list, which came from the
# certificate logs (crt.sh and Cert Spotter). OTX wasn't a source yet.
LEGACY_SOURCES = ("crt.sh", "certspotter")

FRESH, PARTIAL, CARRIED = "fresh", "partial", "carried"


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


def source_lists(scan: dict | None) -> dict[str, list]:
    """Each source's hostnames in a saved scan. An old combined list counts
    as every certificate source's list."""
    if not scan:
        return {}
    if isinstance(scan.get("sources"), dict):
        return {name: list(entry.get("subdomains", [])) for name, entry in scan["sources"].items()}
    return {name: list(scan.get("subdomains", [])) for name in LEGACY_SOURCES}


def build(previous: dict | None, fresh: dict, partial: dict) -> dict[str, dict]:
    """This scan's list for every source, ready to save and compare.

    fresh:   source -> hosts, for sources that worked fully this time
    partial: source -> hosts, for sources that were cut short: they keep last
             scan's list plus whatever they found (found = really seen now)
    Every other source from the previous scan keeps its old list (carried).
    A list that isn't known to be complete (partial, or carried from one
    that was) is marked "incomplete", so the next complete run doesn't call
    the hosts it fills in new.
    """
    before = source_lists(previous)
    was_incomplete = incomplete_sources(previous)
    out = {}
    for name in set(before) | set(fresh) | set(partial):
        if name in fresh:
            out[name] = {"subdomains": sorted(set(fresh[name])), "status": FRESH}
        elif name in partial:
            out[name] = {"subdomains": sorted(set(partial[name]) | set(before.get(name, []))),
                         "status": PARTIAL, "incomplete": True}
        else:
            out[name] = {"subdomains": sorted(before[name]), "status": CARRIED}
            if name in was_incomplete:
                out[name]["incomplete"] = True
    return dict(sorted(out.items()))


def incomplete_sources(scan: dict | None) -> set[str]:
    """Sources whose list in a saved scan isn't known to be complete."""
    if not scan or not isinstance(scan.get("sources"), dict):
        return set()  # before v1.14 only complete scans were saved
    return {name for name, entry in scan["sources"].items()
            if entry.get("incomplete") or entry.get("status") == PARTIAL}


def union(entries: dict[str, dict]) -> list[str]:
    return sorted({h for entry in entries.values() for h in entry["subdomains"]})


def save(domain: str, entries: dict[str, dict]) -> str:
    """Save this scan as scans/<domain>/<timestamp>.json and return the path.

    "subdomains" (every source together) stays for anything that reads the
    old format; "sources" holds each source's own list and status.
    """
    d = _domain_dir(domain)
    os.makedirs(d, exist_ok=True)
    now = datetime.now()
    path = os.path.join(d, now.strftime("%Y-%m-%d_%H%M%S") + ".json")
    with open(path, "w") as f:
        json.dump(
            {
                "target": domain,
                "scanned_at": now.isoformat(timespec="seconds"),
                "subdomains": union(entries),
                "sources": entries,
            },
            f,
            indent=2,
        )
    return path


def compare(previous: dict, entries: dict[str, dict]) -> dict:
    """Which hostnames are new and which disappeared since the previous scan.

    Gone: in the last scan, and in no source's list now. A source that didn't
    work carries its old list, so a failure never makes a host look gone.
    New: not in the last scan, found by a source that was in it too, with a
    complete list. A source joining history for the first time (OTX on its
    first run) doesn't make everything it knows look new: its hosts are its
    starting point ("joined"). A source whose last list was cut short can't
    either: what it adds now may be old, so those are "filled_in", listed
    apart from new.
    """
    before = source_lists(previous)
    unsure = incomplete_sources(previous)
    old = {h for hosts in before.values() for h in hosts}
    from_known = {h for name, entry in entries.items()
                  if name in before and name not in unsure for h in entry["subdomains"]}
    joined = {name: sorted(set(entry["subdomains"]) - old - from_known)
              for name, entry in entries.items() if name not in before}
    filled = {name: sorted(set(entry["subdomains"]) - old - from_known)
              for name, entry in entries.items() if name in unsure}
    return {
        "previous_scan": previous["scanned_at"],
        "added": sorted(from_known - old),
        "removed": sorted(old - set(union(entries))),
        "joined": {name: hosts for name, hosts in joined.items() if hosts},
        "filled_in": {name: hosts for name, hosts in filled.items() if hosts},
    }
