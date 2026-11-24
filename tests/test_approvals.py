"""
Approvals (monomi/approvals.py, issue #27 part B): an agent's request sends
nothing; only a typed yes at a real terminal approves it, with the scope
applied then; the approval runs once, before it expires, and only while the
scope / research files are exactly what was approved. Planted names only
(.test), and no test sends anything.
"""

import json
import os
import sys
from datetime import timedelta

import pytest

from monomi import approvals, cli

D = "lab.test"
T0 = approvals._now()


@pytest.fixture(autouse=True)
def folder(tmp_path, monkeypatch):
    monkeypatch.setattr(approvals, "approvals_dir", lambda: str(tmp_path / "approvals"))
    return tmp_path / "approvals"


@pytest.fixture
def scope_file(tmp_path):
    p = tmp_path / "scope.txt"
    p.write_text(f"{D}\n*.{D}\n!blog.{D}\n")
    return str(p)


@pytest.fixture
def research_file(tmp_path):
    p = tmp_path / "research.txt"
    p.write_text("X-Test: x41ok\n")
    return str(p)


def say(answer):
    return dict(ask=lambda q: answer, out=lambda s: None, interactive=lambda: True)


def approved(scope_file, hosts=(f"www.{D}", f"blog.{D}"), tool="fingerprint_hosts", research=None, now=T0):
    rid = approvals.request(tool, list(hosts), now=now)["approval_id"]
    assert approvals.approve(rid, scope_file, research, now=now, **say("yes")) == 0
    return rid


def record(folder, rid):
    return json.loads((folder / f"{rid}.json").read_text())


# --- request ----------------------------------------------------------------------

def test_request_sends_nothing_and_returns_an_id(folder, monkeypatch):
    import socket
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: pytest.fail("looked something up"))
    r = approvals.request("fingerprint_hosts", [f"WWW.{D}.", f"api.{D}"], now=T0)
    assert approvals.RID.fullmatch(r["approval_id"])
    assert r["hosts"] == [f"api.{D}", f"www.{D}"]          # normalized, sorted
    assert r["max_requests"] == 4
    assert record(folder, r["approval_id"])["state"] == "pending"


def test_request_refuses_unknown_tools_and_no_hosts():
    with pytest.raises(approvals.ApprovalError, match="isn't an active tool"):
        approvals.request("check_takeover", [D])
    with pytest.raises(approvals.ApprovalError, match="no hostnames"):
        approvals.request("fingerprint_hosts", [])


# --- approve ----------------------------------------------------------------------

def test_approve_applies_the_scope_and_shows_every_url(scope_file, folder):
    rid = approvals.request("fingerprint_hosts", [f"www.{D}", f"blog.{D}", "other.test"], now=T0)["approval_id"]
    shown = []
    assert approvals.approve(rid, scope_file, ask=lambda q: "yes", out=shown.append,
                             interactive=lambda: True, now=T0) == 0
    text = "\n".join(shown)
    assert f"GET https://www.{D}/" in text
    assert f"blog.{D}: excluded by !blog.{D}" in text and "other.test: no rule matches" in text
    rec = record(folder, rid)
    assert rec["approved_hosts"] == [f"www.{D}"]           # only what's in scope
    assert rec["scope"]["sha256"] and rec["research"] is None


def test_exposed_files_plan_shows_fixed_urls_rule_and_cap(scope_file):
    rid = approvals.request("check_exposed_files", [f"www.{D}"], now=T0)["approval_id"]
    shown = []
    approvals.approve(rid, scope_file, ask=lambda q: "no", out=shown.append, interactive=lambda: True, now=T0)
    text = "\n".join(shown)
    assert f"GET https://www.{D}/openapi.json" in text and f"GET https://www.{D}/" in text
    assert "never another host" in text and "at most 14" in text
    # v1.24: the plain-HTTP fallback is shown before the yes, like --fingerprint's
    assert f"http://www.{D}/ once, only if HTTPS fails with a TLS error or is refused" in text


@pytest.mark.parametrize("answer", ["y", "YES please", "", "no"])
def test_only_the_word_yes_approves(scope_file, folder, answer):
    rid = approvals.request("fingerprint_hosts", [f"www.{D}"], now=T0)["approval_id"]
    assert approvals.approve(rid, scope_file, now=T0, **say(answer)) == 1
    assert record(folder, rid)["state"] == "declined"
    with pytest.raises(approvals.ApprovalError, match="declined"):
        approvals.claim(rid, now=T0)


def test_approve_needs_a_real_terminal(scope_file):
    rid = approvals.request("fingerprint_hosts", [f"www.{D}"], now=T0)["approval_id"]
    with pytest.raises(approvals.ApprovalError, match="real terminal"):
        approvals.approve(rid, scope_file, ask=lambda q: "yes", out=lambda s: None,
                          interactive=lambda: False, now=T0)


def test_approve_refuses_when_nothing_is_in_scope(scope_file):
    rid = approvals.request("fingerprint_hosts", ["other.test"], now=T0)["approval_id"]
    with pytest.raises(approvals.ApprovalError, match="none of the hosts"):
        approvals.approve(rid, scope_file, now=T0, **say("yes"))


def test_an_old_request_can_not_be_approved(scope_file):
    rid = approvals.request("fingerprint_hosts", [f"www.{D}"], now=T0)["approval_id"]
    with pytest.raises(approvals.ApprovalError, match="expired"):
        approvals.approve(rid, scope_file, now=T0 + approvals.REQUEST_TTL, **say("yes"))


def test_a_bad_scope_file_refuses(tmp_path):
    rid = approvals.request("fingerprint_hosts", [f"www.{D}"], now=T0)["approval_id"]
    with pytest.raises(approvals.ApprovalError, match="scope file"):
        approvals.approve(rid, str(tmp_path / "missing.txt"), now=T0, **say("yes"))


def test_approve_can_not_be_repeated(scope_file):
    rid = approved(scope_file)
    with pytest.raises(approvals.ApprovalError, match="not waiting"):
        approvals.approve(rid, scope_file, now=T0, **say("yes"))


# --- claim ------------------------------------------------------------------------

def test_claim_gives_the_approved_hosts_scope_and_research(scope_file, research_file):
    rid = approved(scope_file, research=research_file)
    got = approvals.claim(rid, now=T0)
    assert got["tool"] == "fingerprint_hosts" and got["hosts"] == [f"www.{D}"]
    assert got["scope"].match(f"www.{D}").allowed and got["research"].headers == {"X-Test": "x41ok"}
    assert got["max_per_host"] == 2


def test_claim_works_once(scope_file, folder):
    rid = approved(scope_file)
    approvals.claim(rid, now=T0)
    with pytest.raises(approvals.ApprovalError, match="already used"):
        approvals.claim(rid, now=T0)
    events = [e["event"] for e in record(folder, rid)["events"]]
    assert events == ["requested", "approved", "used", "refused"]   # its own audit trail


def test_a_second_process_can_not_use_it_too(scope_file, folder):
    # Another MCP server already created the .used marker: this one must refuse
    rid = approved(scope_file)
    (folder / f"{rid}.used").write_text("")
    with pytest.raises(approvals.ApprovalError, match="already used"):
        approvals.claim(rid, now=T0)


def test_a_race_between_two_servers_has_one_winner(scope_file, folder, monkeypatch):
    # The real race: the other server creates the marker AFTER this one's
    # early check but BEFORE its own marker. Only the one-step create
    # (O_EXCL) can stop that, so make the early check miss it.
    rid = approved(scope_file)
    real_exists = os.path.exists

    def other_server_wins(path):
        if str(path).endswith(".used"):
            (folder / f"{rid}.used").write_text("")   # the other server, right now
            return False                               # ...too late for our early check
        return real_exists(path)

    monkeypatch.setattr(approvals.os.path, "exists", other_server_wins)
    with pytest.raises(approvals.ApprovalError, match="already used"):
        approvals.claim(rid, now=T0)


def test_claim_refuses_before_approval(scope_file):
    rid = approvals.request("fingerprint_hosts", [f"www.{D}"], now=T0)["approval_id"]
    with pytest.raises(approvals.ApprovalError, match="approve it first"):
        approvals.claim(rid, now=T0)


def test_claim_refuses_after_expiry(scope_file):
    rid = approved(scope_file)
    with pytest.raises(approvals.ApprovalError, match="expired"):
        approvals.claim(rid, now=T0 + approvals.APPROVAL_TTL)
    assert approvals.claim(approved(scope_file), now=T0 + approvals.APPROVAL_TTL - timedelta(seconds=1))


def test_claim_refuses_if_the_scope_file_changed(scope_file):
    rid = approved(scope_file)
    with open(scope_file, "a") as f:
        f.write("*.other.test\n")
    with pytest.raises(approvals.ApprovalError, match="scope file"):
        approvals.claim(rid, now=T0)


def test_claim_refuses_if_the_research_file_changed(scope_file, research_file):
    rid = approved(scope_file, research=research_file)
    with open(research_file, "w") as f:
        f.write("X-Test: someone-else\n")
    with pytest.raises(approvals.ApprovalError, match="research file"):
        approvals.claim(rid, now=T0)


@pytest.mark.parametrize("rid", ["../../etc/passwd", "abcd", "ABCD-EFGH", "k7m2-x9pq/../x", ""])
def test_ids_that_are_not_ids_are_refused(rid):
    with pytest.raises(approvals.ApprovalError, match="isn't an approval id"):
        approvals.claim(rid)


def test_unknown_id(scope_file):
    with pytest.raises(approvals.ApprovalError, match="no approval"):
        approvals.claim("abcd-efgh")


# --- the command ------------------------------------------------------------------

def test_cli_approve_refusal_exits_2_and_says_nothing_sent(monkeypatch, capsys, scope_file):
    monkeypatch.setattr(sys, "argv", ["monomi.py", "approve", "abcd-efgh", "--scope", scope_file])
    assert cli.main() == 2
    assert "Nothing will be sent" in capsys.readouterr().err


def test_cli_approve_has_no_yes_flag(monkeypatch, scope_file):
    monkeypatch.setattr(sys, "argv", ["monomi.py", "approve", "abcd-efgh", "--scope", scope_file, "--yes"])
    with pytest.raises(SystemExit):
        cli.main()


def test_probe_plan_shows_homepage_redirect_rule_and_cap(scope_file):
    req = approvals.request("probe_hosts", [f"www.{D}"], now=T0)
    assert req["max_requests"] == 12
    shown = []
    approvals.approve(req["approval_id"], scope_file, ask=lambda q: "no", out=shown.append,
                      interactive=lambda: True, now=T0)
    text = " ".join(shown)
    assert f"GET https://www.{D}/" in text and "at most 12" in text
    # v1.25: before the yes, the person sees that redirects stay on the hosts they approve
    assert f"followed only to www.{D} or another host in this approval" in text
    assert "only if the scope allows it" in text and "never requested" in text
