"""Load BBOT's output as an extra source of hostnames (v1.29.0).

BBOT (Black Lantern Security) is a recursive OSINT framework with dozens of
modules. Monomi doesn't run or bundle it: you run BBOT yourself and pass its
output.json, so Monomi stays passive and installs nothing extra. Like the
subfinder import, BBOT is only one more source of names: every host still
goes through Monomi's own checks (DNS, scope, the evidence model, the gate).

What's read: output.json, one event per line (BBOT 1.x to 3.x, checked on a
real 3.1.0 run). A host is kept only if it passes BOTH:
  - BBOT's own scope: a DNS_NAME event at scope_distance 0 (BBOT also finds
    names one hop out, like a provider's nameservers tagged "affiliate,
    distance-1": those are someone else's)
  - Monomi's: the target domain or one of its subdomains
BBOT's own placeholder names are skipped too (v1.29.1, from PlayStation):
when it tests a zone for wildcard DNS it records "_wildcard.<zone>", a name
it made up, not a host (it became a fake "Take over DNS for
_wildcard.nonprod.pcs..." lead).
Every other event type (open ports, technologies, findings, URLs...) is
counted, never used: it came from BBOT's modules, often active ones, and
Monomi's evidence model can't stand behind it. The counts are reported, so
nothing is dropped silently.
"""

import json
import os
from collections import Counter
from datetime import datetime, timezone

from monomi.common import is_hostname

MAX_HOSTS = 5000  # like subfinder: a wide run can list tens of thousands
MAX_BYTES = 200 * 1024 * 1024  # BBOT's output holds every event, so it runs bigger


def _name(event: dict) -> str | None:
    """The hostname a DNS_NAME event is about: BBOT puts it in "data" (a
    string) and "host"; in some versions "data" is null and the value lives
    elsewhere, so "host" is the fallback. Never assumes a type."""
    for key in ("data", "host"):
        value = event.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().lower().rstrip(".")
    return None


def load(path: str, domain: str) -> dict:
    """Read a BBOT output.json. Returns {"hosts": {host: [BBOT modules that
    found it]}, "skipped": [reasons], "not_used": {event type: count},
    "file_time": when the file was last written (UTC), i.e. when BBOT ran}.
    Raises OSError if the file can't be read, ValueError if it's too big or
    isn't BBOT output at all."""
    size = os.path.getsize(path)
    if size > MAX_BYTES:
        raise ValueError(f"the file is {size // (1024 * 1024)} MB; BBOT output over "
                         f"{MAX_BYTES // (1024 * 1024)} MB isn't read")
    file_time = datetime.fromtimestamp(os.path.getmtime(path), timezone.utc).isoformat(timespec="seconds")
    hosts, not_used = {}, Counter()
    bad_lines = out_of_scope = other_domain = not_hostname = placeholders = events = 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except ValueError:
                bad_lines += 1
                continue
            if not isinstance(event, dict) or not isinstance(event.get("type"), str):
                bad_lines += 1
                continue
            events += 1
            if event["type"] != "DNS_NAME":
                if event["type"] != "SCAN":  # the scan's own start/end records
                    not_used[event["type"]] += 1
                continue
            distance = event.get("scope_distance")
            if not isinstance(distance, int) or distance != 0:
                out_of_scope += 1
                continue
            name = _name(event)
            if name and name.startswith("*."):
                name = name[2:]
            if name and name.split(".", 1)[0] == "_wildcard":
                placeholders += 1
            elif not name or not is_hostname(name):
                not_hostname += 1
            elif name != domain and not name.endswith("." + domain):
                other_domain += 1
            else:
                module = event.get("module")
                hosts.setdefault(name, set()).update([module] if isinstance(module, str) and module else [])
    if not events:
        raise ValueError("no BBOT events in it (expected BBOT's output.json, one event per line)")
    skipped = []
    if out_of_scope:
        skipped.append(f"{out_of_scope} DNS name{'s' if out_of_scope != 1 else ''} BBOT itself "
                       "marked out of scope (scope distance above 0)")
    if other_domain:
        skipped.append(f"{other_domain} in-scope DNS name{'s' if other_domain != 1 else ''} not part of {domain}")
    if placeholders:
        skipped.append(f"{placeholders} BBOT wildcard placeholder{'s' if placeholders != 1 else ''} "
                       "(_wildcard.<zone>, a name BBOT made up while testing for wildcard DNS)")
    if not_hostname:
        skipped.append(f"{not_hostname} DNS name{'s' if not_hostname != 1 else ''} that aren't valid hostnames")
    if bad_lines:
        skipped.append(f"{bad_lines} line{'s' if bad_lines != 1 else ''} that aren't BBOT events")
    names = sorted(hosts)
    if len(names) > MAX_HOSTS:
        skipped.append(f"{len(names) - MAX_HOSTS} more hostnames: over the {MAX_HOSTS} limit")
        names = names[:MAX_HOSTS]
    return {"hosts": {h: sorted(hosts[h]) for h in names}, "skipped": skipped,
            "not_used": dict(sorted(not_used.items())), "file_time": file_time}


def to_source(loaded: dict, path: str) -> dict:
    """The import as a Monomi source record, like the ones collectors return.
    collected_at is when BBOT wrote the file: the hostnames are as old as that
    run. imported_at marks it as another tool's data."""
    return {
        "source": "bbot",
        "file": path,
        "collected_at": loaded["file_time"],
        "imported_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "subdomain_count": len(loaded["hosts"]),
        "subdomains": sorted(loaded["hosts"]),
        "found_by": loaded["hosts"],      # host -> the BBOT modules that found it
        "skipped": loaded["skipped"],
        "not_used": loaded["not_used"],   # BBOT event type -> count, never imported
    }
