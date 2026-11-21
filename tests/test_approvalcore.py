"""
The approvals core (monomi/approvalcore.py), tested on its own, the way
another 0x41 tool uses it: its own folder, its own tool name and command,
its own last check. Monomi's own flow is tested in test_approvals.py.
"""

import inspect
import json
from datetime import datetime, timedelta, timezone

import pytest

from monomi import approvalcore as core

T0 = datetime(2026, 11, 21, 17, 0, tzinfo=timezone.utc)


@pytest.fixture
def store(tmp_path):
    return core.Store(str(tmp_path / "approvals"), "0x41", lambda rid: f"`0x41 approve {rid} --scope FILE`")


def record(store, rid):
    with open(store.path(rid), encoding="utf-8") as f:
        return json.load(f)


def approved(store, now=T0):
    rec = store.create({"job_id": "vet-1", "lead_ids": ["L1"]}, now)
    rec = store.pending(rec["rid"], now, interactive=lambda: True)
    return store.lock_in(rec, {"requests": {"L1": ["GET https://www.lab.test/"]}}, now)


# --- create / pending -----------------------------------------------------------

def test_create_keeps_the_tools_fields_and_sends_nothing(store):
    rec = store.create({"job_id": "vet-1", "lead_ids": ["L1"]}, T0, leads=1)
    assert core.RID.fullmatch(rec["rid"])
    saved = record(store, rec["rid"])
    assert saved["job_id"] == "vet-1" and saved["state"] == "pending"
    assert saved["expires"] == core.iso(T0 + core.REQUEST_TTL)
    assert saved["events"] == [{"at": core.iso(T0), "event": "requested", "leads": 1}]


def test_tool_fields_can_not_overwrite_the_state(store):
    rec = store.create({"state": "approved"}, T0)
    assert rec["state"] == "pending"


def test_pending_refuses_after_the_request_expires_and_writes_it_down(store):
    rid = store.create({}, T0)["rid"]
    with pytest.raises(core.ApprovalError, match="expired.*ask for a new one"):
        store.pending(rid, T0 + core.REQUEST_TTL, interactive=lambda: True)
    assert record(store, rid)["events"][-1]["event"] == "refused"


def test_pending_needs_a_real_terminal(store):
    rid = store.create({}, T0)["rid"]
    with pytest.raises(core.ApprovalError, match="real terminal"):
        store.pending(rid, T0, interactive=lambda: False)


def test_pending_refuses_a_record_that_is_not_waiting(store):
    rid = approved(store)["rid"]
    with pytest.raises(core.ApprovalError, match="not waiting for a yes"):
        store.pending(rid, T0, interactive=lambda: True)


@pytest.mark.parametrize("answer, ok", [("yes", True), (" YES ", True), ("y", False), ("", False)])
def test_only_the_word_yes(answer, ok):
    assert core.typed_yes(lambda q: answer, "?") is ok


@pytest.mark.parametrize("err", [EOFError, KeyboardInterrupt])
def test_ctrl_c_and_ctrl_d_are_a_no(err):
    def ask(q):
        raise err
    assert core.typed_yes(ask, "?") is False


def test_decline_then_claim_refuses(store):
    rec = store.create({}, T0)
    store.decline(rec, T0)
    with pytest.raises(core.ApprovalError, match="declined: the person running 0x41"):
        store.claim(rec["rid"], T0)


# --- claim ------------------------------------------------------------------------

def test_claim_names_the_tool_and_its_own_command(store):
    rid = store.create({}, T0)["rid"]
    with pytest.raises(core.ApprovalError, match=f"running 0x41 has to approve it first with `0x41 approve {rid}"):
        store.claim(rid, T0)


def test_claim_marks_it_used_before_returning(store, tmp_path):
    rid = approved(store)["rid"]
    rec = store.claim(rid, T0)
    assert rec["state"] == "used" and rec["requests"] == {"L1": ["GET https://www.lab.test/"]}
    assert (tmp_path / "approvals" / f"{rid}.used").exists()
    with pytest.raises(core.ApprovalError, match="already used"):
        store.claim(rid, T0)
    assert [e["event"] for e in record(store, rid)["events"]] == ["requested", "approved", "used", "refused"]


def test_a_failed_check_refuses_and_leaves_it_unused(store, tmp_path):
    rid = approved(store)["rid"]
    seen = []

    def check(rec):
        seen.append(rec["requests"])
        return "the plan no longer matches what was approved"

    with pytest.raises(core.ApprovalError, match="plan no longer matches"):
        store.claim(rid, T0, check)
    assert seen and not (tmp_path / "approvals" / f"{rid}.used").exists()
    assert record(store, rid)["state"] == "approved"


def test_the_check_runs_only_after_the_basic_refusals(store):
    rid = store.create({}, T0)["rid"]
    with pytest.raises(core.ApprovalError, match="approve it first"):
        store.claim(rid, T0, check=lambda rec: pytest.fail("check ran on an unapproved record"))


def test_claim_refuses_after_the_approval_expires(store):
    rid = approved(store)["rid"]
    with pytest.raises(core.ApprovalError, match="expired"):
        store.claim(rid, T0 + core.APPROVAL_TTL)


def test_another_process_already_holding_the_marker_wins(store, tmp_path):
    rid = approved(store)["rid"]
    (tmp_path / "approvals" / f"{rid}.used").write_text("")
    with pytest.raises(core.ApprovalError, match="already used"):
        store.claim(rid, T0)


def test_a_race_between_two_processes_has_one_winner(store, tmp_path, monkeypatch):
    # The other process creates the marker AFTER this one's early check but
    # BEFORE its own: only the one-step create (O_EXCL) stops a second run.
    rid = approved(store)["rid"]
    marker = tmp_path / "approvals" / f"{rid}.used"
    real_exists = core.os.path.exists

    def other_process_wins(path):
        if str(path).endswith(".used"):
            marker.write_text("")   # the other process, right now
            return False            # ...too late for our early check
        return real_exists(path)

    monkeypatch.setattr(core.os.path, "exists", other_process_wins)
    with pytest.raises(core.ApprovalError, match="already used"):
        store.claim(rid, T0)
    assert record(store, rid)["state"] == "approved"   # this process never ran it


@pytest.mark.parametrize("rid", ["nope", "../../etc/passwd", "ABCD-EFGH", None])
def test_ids_that_are_not_ids_never_become_paths(store, rid):
    with pytest.raises(core.ApprovalError, match="isn't an approval id"):
        store.claim(rid, T0)


def test_unknown_id(store):
    with pytest.raises(core.ApprovalError, match="no approval"):
        store.claim("abcd-efgh", T0)


def test_note_adds_to_the_audit_trail(store):
    rid = approved(store)["rid"]
    store.claim(rid, T0)
    store.note(rid, "ran", T0, tally={"confirmed": 1})
    assert record(store, rid)["events"][-1] == {"at": core.iso(T0), "event": "ran", "tally": {"confirmed": 1}}


def test_times_are_stored_in_utc_and_shown_in_local_time():
    stamp = core.iso(T0)
    assert stamp.endswith("+00:00")
    assert core.local_hm(stamp) == T0.astimezone().strftime("%H:%M")


# --- contract: what 0x41 imports -----------------------------------------------------
# 0x41's approvals.py is built on these. Changing one of them means changing
# 0x41 in the same release, so the test names them all.

API = {
    "now_utc": "() -> datetime.datetime",
    "iso": "(t: datetime.datetime) -> str",
    "expired": "(rec: dict, now: datetime.datetime) -> bool",
    "local_hm": "(stamp: str) -> str",
    "typed_yes": "(ask, prompt: str) -> bool",
    "Store.__init__": "(self, folder: str, tool: str, approve_cmd)",
    "Store.path": "(self, rid: str) -> str",
    "Store.exists": "(self, rid: str) -> bool",
    "Store.load": "(self, rid: str) -> dict",
    "Store.save": "(self, rec: dict) -> None",
    "Store.refuse": "(self, rec: dict, reason: str, now: datetime.datetime) -> monomi.approvalcore.ApprovalError",
    "Store.note": "(self, rid: str, event: str, now: datetime.datetime | None = None, **extra) -> None",
    "Store.create": "(self, fields: dict, now: datetime.datetime | None = None, **event_extra) -> dict",
    "Store.pending": ("(self, rid: str, now: datetime.datetime, interactive=None, "
                      "expired_hint: str = 'ask for a new one') -> dict"),
    "Store.decline": "(self, rec: dict, now: datetime.datetime) -> None",
    "Store.lock_in": "(self, rec: dict, fields: dict, now: datetime.datetime, **event_extra) -> dict",
    "Store.claim": "(self, rid: str, now: datetime.datetime | None = None, check=None) -> dict",
}


@pytest.mark.parametrize("name", sorted(API))
def test_the_names_0x41_imports_keep_their_signature(name):
    obj = core
    for part in name.split("."):
        obj = getattr(obj, part)
    assert str(inspect.signature(obj)) == API[name]


def test_constants_0x41_relies_on():
    assert core.REQUEST_TTL == timedelta(hours=1) and core.APPROVAL_TTL == timedelta(minutes=15)
    assert issubclass(core.ApprovalError, ValueError)
    assert core.RID.fullmatch("k7m2-x9pq")
