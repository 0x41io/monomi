"""
Shared helpers used across monomi: version info, hostname checks, timestamps.
"""

import re
from datetime import datetime, timezone

VERSION = "1.1"
USER_AGENT = f"0x41-monomi/{VERSION} (passive OSINT research)"

# Real hostnames only use letters, digits, dots, hyphens (and sometimes underscores).
# Certificates can contain any text, so anything else is dropped: it protects the
# terminal (escape codes), the AI prompt, and file names from junk or tricks.
_HOSTNAME_RE = re.compile(r"^[a-z0-9_]([a-z0-9_.-]*[a-z0-9])?$")


def is_hostname(name: str) -> bool:
    """True if name looks like a real hostname (and nothing else)."""
    return len(name) <= 253 and bool(_HOSTNAME_RE.match(name))


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
