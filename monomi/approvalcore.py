"""
The approvals core: the plumbing every 0x41 human-approval gate shares.

An agent asks for something active (Monomi's fingerprint_hosts, a 0x41
vet's active proofs, later Akashi's app-logic steps). That request sends
nothing. A person approves it with a typed yes at a real terminal, and the
approval can then be used once, before it expires. What each tool approves
(hosts, plan steps, ...) and what it checks before running stays in that
tool. This module only knows about approval records:

    Store.create()       a pending request: new id, "requested" event, saved
    Store.lock_in()      the person's yes: state "approved", 15-minute expiry
    Store.claim()        every check again, then marked used BEFORE the tool
                         sends anything. Single use, even across processes.

One approval is one JSON file, <folder>/<rid>.json, with every event in it
(refusals too), so it is its own audit trail. "Used" is a second file,
<rid>.used, created in one step that only one process can win (O_EXCL): two
MCP servers can never both run the same approval.

Times are stored in UTC (ISO 8601 with +00:00). Show them to a person with
local_hm(), so "until 10:15" means 10:15 where they are.

Honest limit: an agent with a shell on this machine can fake a terminal.
The gate is against agents that only have MCP tools.

0x41 imports this module, so its public names are locked by a contract test
(tests/test_approvalcore.py). Change them only together with 0x41.
"""

import json
import os
import re
import secrets
import sys
import threading
from datetime import datetime, timedelta, timezone

REQUEST_TTL = timedelta(hours=1)       # a pending request nobody approved
APPROVAL_TTL = timedelta(minutes=15)   # an approval nobody used
ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"  # no 0/o, 1/l/i: easy to type
RID = re.compile(r"[a-z2-9]{4}-[a-z2-9]{4}")

# Load-change-save of one record happens one thread at a time, so two
# events written at once from one process can't lose each other.
_lock = threading.Lock()


class ApprovalError(ValueError):
    """Refused; the message says why. Nothing was sent."""


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso(t: datetime) -> str:
    return t.isoformat(timespec="seconds")


def expired(rec: dict, now: datetime) -> bool:
    """True once the record's current deadline has passed."""
    return now >= datetime.fromisoformat(rec["expires"])


def local_hm(stamp: str) -> str:
    """'HH:MM' in this machine's local time, for messages to a person."""
    return datetime.fromisoformat(stamp).astimezone().strftime("%H:%M")


def new_rid() -> str:
    pick = "".join(secrets.choice(ALPHABET) for _ in range(8))
    return f"{pick[:4]}-{pick[4:]}"


def typed_yes(ask, prompt: str) -> bool:
    """Only the word yes approves. Ctrl+C or Ctrl+D count as no."""
    try:
        return ask(prompt).strip().lower() == "yes"
    except (EOFError, KeyboardInterrupt):
        return False


class Store:
    """Approval records in one folder, for one tool.

    tool names it in refusals ("the person running Monomi ..."), and
    approve_cmd(rid) gives the command that approves an id (Monomi:
    `python monomi.py approve RID --scope FILE`, 0x41: `0x41 approve RID
    --scope FILE`)."""

    def __init__(self, folder: str, tool: str, approve_cmd):
        self.folder = folder
        self.tool = tool
        self.approve_cmd = approve_cmd

    # --- files --------------------------------------------------------------

    def path(self, rid: str) -> str:
        """Only ids shaped like k7m2-x9pq are turned into paths, so an id
        can never name another file."""
        if not isinstance(rid, str) or not RID.fullmatch(rid):
            raise ApprovalError(f"{rid!r} isn't an approval id (they look like k7m2-x9pq)")
        return os.path.join(self.folder, f"{rid}.json")

    def used_path(self, rid: str) -> str:
        return os.path.join(self.folder, f"{rid}.used")

    def exists(self, rid: str) -> bool:
        return os.path.isfile(self.path(rid))

    def load(self, rid: str) -> dict:
        try:
            with open(self.path(rid), encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            raise ApprovalError(f"no approval {rid}")

    def save(self, rec: dict) -> None:
        """Write the record whole (temp file + replace), so a reader never sees half."""
        path = self.path(rec["rid"])
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(rec, f, indent=2)
        os.replace(tmp, path)

    # --- events ---------------------------------------------------------------

    @staticmethod
    def event(rec: dict, event: str, now: datetime, **extra) -> None:
        rec.setdefault("events", []).append({"at": iso(now), "event": event, **extra})

    def refuse(self, rec: dict, reason: str, now: datetime) -> ApprovalError:
        """Write the refusal into the approval's own file, then return the
        error for the caller to raise."""
        try:
            self.event(rec, "refused", now, reason=reason)
            self.save(rec)
        except OSError:
            pass  # the refusal stands even if it can't be written down
        return ApprovalError(reason)

    def note(self, rid: str, event: str, now: datetime | None = None, **extra) -> None:
        """Add an event to an existing record (e.g. what a run did)."""
        now = now or now_utc()
        with _lock:
            rec = self.load(rid)
            self.event(rec, event, now, **extra)
            self.save(rec)

    # --- 1. request -------------------------------------------------------------

    def create(self, fields: dict, now: datetime | None = None, **event_extra) -> dict:
        """A pending request with a new id. Sends nothing, looks nothing up."""
        now = now or now_utc()
        os.makedirs(self.folder, exist_ok=True)
        while True:
            rid = new_rid()
            if not os.path.exists(self.path(rid)):
                break
        rec = {"rid": rid, **fields, "state": "pending",
               "created": iso(now), "expires": iso(now + REQUEST_TTL), "events": []}
        self.event(rec, "requested", now, **event_extra)
        self.save(rec)
        return rec

    # --- 2. approve (terminal) --------------------------------------------------

    def pending(self, rid: str, now: datetime, interactive=None, expired_hint: str = "ask for a new one") -> dict:
        """The record, if it's waiting for a yes, not expired, and a person
        is at a real terminal. Otherwise refuse."""
        rec = self.load(rid)
        if rec["state"] != "pending":
            raise ApprovalError(f"approval {rid} is {rec['state']}, not waiting for a yes")
        if expired(rec, now):
            raise self.refuse(rec, f"request {rid} expired at {rec['expires']}; {expired_hint}", now)
        if not (interactive or (lambda: sys.stdin.isatty()))():
            raise self.refuse(rec, "approving needs a person at a real terminal (stdin isn't one)", now)
        return rec

    def decline(self, rec: dict, now: datetime) -> None:
        rec["state"] = "declined"
        self.event(rec, "declined", now)
        self.save(rec)

    def lock_in(self, rec: dict, fields: dict, now: datetime, **event_extra) -> dict:
        """The person said yes: lock in exactly what they were shown."""
        rec.update({**fields, "state": "approved", "approved_at": iso(now),
                    "expires": iso(now + APPROVAL_TTL)})
        self.event(rec, "approved", now, **event_extra)
        self.save(rec)
        return rec

    # --- 3. claim (MCP) ---------------------------------------------------------

    def claim(self, rid: str, now: datetime | None = None, check=None) -> dict:
        """Every check again, then mark the approval used BEFORE returning it,
        so it runs once even if the run crashes or another process tries too.

        check(rec) is the tool's own last look (pinned files, a plan that
        must still match). It returns None when all is well, or the reason
        to refuse. Returns the used record."""
        now = now or now_utc()
        with _lock:
            rec = self.load(rid)
            if rec["state"] == "used" or os.path.exists(self.used_path(rid)):
                raise self.refuse(rec, f"approval {rid} was already used; each approval runs once", now)
            if rec["state"] != "approved":
                raise self.refuse(rec, f"approval {rid} is {rec['state']}: the person running {self.tool} has to "
                                       f"approve it first with {self.approve_cmd(rid)}", now)
            if expired(rec, now):
                raise self.refuse(rec, f"approval {rid} expired at {rec['expires']}; ask for a new one", now)
            problem = check(rec) if check else None
            if problem:
                raise self.refuse(rec, problem, now)
            # One step only one process can win: two servers can't both use it.
            try:
                fd = os.open(self.used_path(rid), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                raise self.refuse(rec, f"approval {rid} was already used; each approval runs once", now)
            os.close(fd)
            rec["state"] = "used"
            rec["used_at"] = iso(now)
            self.event(rec, "used", now)
            self.save(rec)
            return rec
