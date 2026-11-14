"""
Shared helpers used across monomi: version info, hostname checks, timestamps.
"""

import re
from datetime import datetime, timezone

VERSION = "1.15.0"
USER_AGENT = f"0x41-monomi/{VERSION} (passive OSINT research)"
# Active checks (--fingerprint, --exposed-files) contact the target's own
# servers, so they say so plainly: a site owner reading their logs should
# see who came by and why, with a link, not a UA that claims to be passive.
ACTIVE_USER_AGENT = f"0x41-monomi/{VERSION} (active security check; github.com/0x41io/monomi)"

# Real hostnames only use letters, digits, dots, hyphens (and sometimes underscores).
# Certificates can contain any text, so anything else is dropped: it protects the
# terminal (escape codes), the AI prompt, and file names from junk or tricks.
_HOSTNAME_RE = re.compile(r"^[a-z0-9_]([a-z0-9_.-]*[a-z0-9])?$")


def is_hostname(name: str) -> bool:
    """True if name looks like a real hostname (and nothing else)."""
    return len(name) <= 253 and bool(_HOSTNAME_RE.match(name))


_VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")


def parse_version(text) -> tuple[int, int, int] | None:
    """'1.15.0' -> (1, 15, 0), or None unless it's exactly X.Y.Z.

    Versions are compared as numbers, never as text: as text, "1.15.0" sorts
    before "1.9.0", which would make a new scan look older than an old one.
    """
    m = _VERSION_RE.fullmatch(text) if isinstance(text, str) else None
    return tuple(int(n) for n in m.groups()) if m else None


def scan_version(results: dict) -> tuple[int, int, int] | None:
    """Which Monomi saved this scan, from its "monomi_version" (saved since
    v1.15.0). None for older scans, or if the value isn't X.Y.Z: tools that
    need the v1.15 fields (Akashi) refuse those scans instead of guessing."""
    return parse_version(results.get("monomi_version"))


def now_utc() -> str:
    """Current time in UTC as a short ISO string, e.g. 2026-10-21T00:05:00+00:00."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def subdomains_in(names, domain: str) -> list[str]:
    """Clean a pile of certificate names down to the domain's own hostnames.

    Lowercases, turns wildcards (*.example.com) into the name they cover,
    drops anything that isn't a hostname, and keeps only the domain itself
    and its subdomains. Returns a sorted list with no repeats.
    """
    domain = domain.lower()
    found = set()
    for name in names:
        name = name.strip().lower()
        if name.startswith("*."):
            name = name[2:]  # wildcard cert -> the base name it covers
        if is_hostname(name) and (name == domain or name.endswith("." + domain)):
            found.add(name)
    return sorted(found)


def wildcards_in(names, domain: str) -> list[str]:
    """Pick out the wildcard certificate names (*.example.com) for the domain.

    A wildcard cert covers every name under it without listing them, so these
    point to subdomains that CT logs can't show us. Keeps the "*." so it's
    clear they're wildcards. Returns a sorted list with no repeats.
    """
    domain = domain.lower()
    found = set()
    for name in names:
        name = name.strip().lower()
        if not name.startswith("*."):
            continue  # not a wildcard, skip it
        base = name[2:]  # the part after "*."
        if is_hostname(base) and (base == domain or base.endswith("." + domain)):
            found.add(name)
    return sorted(found)
