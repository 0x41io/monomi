"""
The research header: an identifying header some bug bounty programs require
on active traffic (e.g. ``X-Intigriti: your-handle`` or
``X-HackerOne-Researcher: your-handle``).

It lives in a small file you point at with ``--research``, one
``Name: value`` header per line. Comments (``#``) and blank lines are
ignored. The file is hashed (sha256), like the scope file, and the hash goes
on every active.log line, so what went out is auditable: the only headers
added are the ones in the exact file you approved.

Monomi owns this module and Akashi imports it (since v1.19), so both tools
read a research file exactly the same way. Passive checks never send it,
they don't contact the target at all; only active requests carry it.
"""

import hashlib
import re
from dataclasses import dataclass

from monomi.common import ACTIVE_USER_AGENT

# A header line: a name (letters, digits, hyphens) then ": value".
LINE_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9-]*):(.*)$")

# Headers that change where or how a request is sent, not who sent it.
# A research file may only identify you, so these are refused.
NOT_ALLOWED = {"host", "content-length", "transfer-encoding", "connection"}


class ResearchError(Exception):
    """The research file can't be used (unreadable or a line isn't a header)."""


@dataclass
class Research:
    headers: dict      # the headers to add to every active request
    sha256: str        # hash of the exact file approved
    path: str

    @property
    def summary(self) -> str:
        return ", ".join(f"{name}: {value}" for name, value in self.headers.items())


def load(path: str) -> Research:
    """Read and hash a research-header file, or raise ResearchError."""
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError as e:
        raise ResearchError(f"can't read {path}: {e}")
    sha = hashlib.sha256(raw).hexdigest()
    headers = {}
    for n, line in enumerate(raw.decode("utf-8", "replace").splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = LINE_RE.match(s)
        if not m:
            raise ResearchError(f"line {n} isn't a 'Name: value' header: {line!r}")
        if m.group(1).lower() in NOT_ALLOWED:
            raise ResearchError(f"line {n}: {m.group(1)} can't be set by a research file "
                                "(it would change where the request goes, not who sent it)")
        headers[m.group(1)] = m.group(2).strip()   # requests refuses a value starting with a space
    if not headers:
        raise ResearchError("no headers found in the research file")
    return Research(headers, sha, path)


def request_headers(research: Research | None = None) -> dict:
    """The headers for one active request: Monomi's User-Agent, plus the
    research headers when a file is loaded. A program that wants its own
    User-Agent can set it in the file; it replaces Monomi's."""
    headers = {"User-Agent": ACTIVE_USER_AGENT}
    if research is not None:
        headers.update(research.headers)
    return headers


def check_pinned(path: str | None, sha256: str | None) -> tuple[Research | None, str | None]:
    """Load the approved research file and check it's exactly what was approved.

    Returns (research, None) when it can be used, (None, None) when none is
    set (that's fine: requests just carry the User-Agent), or (None, why not).
    The MCP server calls this at startup and doctor to report, so both always
    agree. A file edited after approval refuses: a program that requires the
    header must never get requests without it, or with something else in it."""
    if not path:
        return None, None
    fix = f"`python monomi.py mcp setup --research {path}` (and type yes)"
    if not sha256:
        return None, f"the research file has no approved hash; run {fix} again"
    try:
        r = load(path)
    except ResearchError as e:
        return None, f"the research file can't be used ({e}); fix it, then run {fix}"
    if r.sha256 != sha256.lower():
        return None, ("the research file changed since it was approved, so active checks "
                      f"refuse until you approve it again: {fix}")
    return r, None


def sha_of(research: Research | None) -> str | None:
    """The approved file's hash, for active.log (None when no file is loaded)."""
    return research.sha256 if research is not None else None
