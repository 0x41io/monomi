"""scans/active.log: the audit trail of every ACTIVE request and refusal.

One JSON object per line, written BEFORE the request is sent (so a request
that hangs or crashes is still on record). Both the MCP server and the CLI
write here, so one file answers "what did Monomi send, to whom, under
which scope, and what did it refuse?".

    {"time", "event": "request", "via": "mcp"|"cli", "tool", "host", "url",
     "scope_rule": "*.example.com", "scope_sha256": "<the approved file's hash>"}
    {"time", "event": "refused", "via", "tool", "host" (or null), "reason",
     "scope_sha256"}

scope_rule/scope_sha256 are null on a CLI run without --scope. Lines from
before v1.12 have no "event" and count as requests.
"""

import json
import os
import threading

from monomi import home
from monomi.common import now_utc

PATH = home.data_dir("scans", "active.log")
_lock = threading.Lock()  # requests run in parallel threads


def write(path: str, entry: dict) -> None:
    """Add one line to the log (creating the folder if needed)."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    line = json.dumps({"time": now_utc(), **entry})
    with _lock, open(path, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def sha_of(scope) -> str | None:
    """The approved hash of a Scope (None for UNSCOPED_CLI or no scope)."""
    return getattr(scope, "sha256", None) or None


def request(path, via, tool, host, url, scope_rule, scope) -> None:
    """One active request, logged just before it's sent."""
    write(path, {"event": "request", "via": via, "tool": tool, "host": host, "url": url,
                 "scope_rule": scope_rule, "scope_sha256": sha_of(scope)})


def refused(path, via, tool, reason, host=None, scope=None) -> None:
    """Something Monomi refused to send: an out-of-scope host (host set) or a
    whole tool call (host None: active off, no scope, scope changed...)."""
    write(path, {"event": "refused", "via": via, "tool": tool, "host": host,
                 "reason": reason, "scope_sha256": sha_of(scope)})


def is_request(entry: dict) -> bool:
    """Lines without an "event" are from before v1.12, when only requests were logged."""
    return entry.get("event", "request") == "request"
