"""Tests for mcp_setup.py: the entry, finding the config, and safe writing.
Every test uses temporary folders, never a real Claude config."""

import json
import os
import sys

import pytest

from monomi import cli, mcp_setup
from monomi.mcp_setup import NAME, SERVER, SetupError

ROI = {"command": "wsl.exe",  # the hand-made entry that worked before setup existed
       "args": ["-e", "/venv/bin/python", "/monomi/mcp_server.py"]}


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


# ---------- the entry ----------

def test_entry_outside_wsl(monkeypatch):
    monkeypatch.setattr(mcp_setup, "in_wsl", lambda: False)
    assert mcp_setup.server_entry() == {"command": sys.executable, "args": [SERVER]}


def test_entry_in_wsl_names_the_distro(monkeypatch):
    monkeypatch.setattr(mcp_setup, "in_wsl", lambda: True)
    monkeypatch.setenv("WSL_DISTRO_NAME", "Ubuntu")
    assert mcp_setup.server_entry() == {
        "command": "wsl.exe",
        "args": ["-d", "Ubuntu", "-e", sys.executable, SERVER]}


def test_entry_in_wsl_without_a_distro_name(monkeypatch):
    monkeypatch.setattr(mcp_setup, "in_wsl", lambda: True)
    monkeypatch.delenv("WSL_DISTRO_NAME", raising=False)
    assert mcp_setup.server_entry()["args"] == ["-e", sys.executable, SERVER]


# ---------- reading ----------

def test_missing_or_empty_config_is_empty(tmp_path):
    assert mcp_setup.load_config(str(tmp_path / "none.json")) == {}
    empty = tmp_path / "empty.json"
    empty.write_text("  \n")
    assert mcp_setup.load_config(str(empty)) == {}


def test_config_saved_with_a_bom_is_read(tmp_path):
    f = tmp_path / "bom.json"
    f.write_bytes(b"\xef\xbb\xbf" + json.dumps({"mcpServers": {}}).encode())
    assert mcp_setup.load_config(str(f)) == {"mcpServers": {}}


@pytest.mark.parametrize("text", ['{"mcpServers": {', "[1, 2]",
                                  '{"mcpServers": [1]}'])
def test_broken_config_is_refused(tmp_path, text):
    f = tmp_path / "bad.json"
    f.write_text(text)
    with pytest.raises(SetupError, match="Nothing was changed"):
        mcp_setup.load_config(str(f))


# ---------- changing ----------

def test_change_status():
    entry = {"command": "x", "args": []}
    assert mcp_setup.change({}, entry) == ("new", None)
    assert mcp_setup.change({"mcpServers": {NAME: entry}}, entry)[0] == "unchanged"
    assert mcp_setup.change({"mcpServers": {NAME: ROI}}, entry) == ("changing", ROI)


def test_only_monomi_changes():
    config = {"preferences": {"theme": "dark"},
              "mcpServers": {"other": {"command": "node"}, NAME: ROI}}
    entry = {"command": "new", "args": []}
    new = mcp_setup.with_entry(config, entry)
    assert new == {"preferences": {"theme": "dark"},
                   "mcpServers": {"other": {"command": "node"}, NAME: entry}}
    assert config["mcpServers"][NAME] == ROI  # the original isn't touched


def test_write_backs_up_then_swaps(tmp_path):
    f = tmp_path / "Claude" / "config.json"
    write_json(f, {"mcpServers": {NAME: ROI}})
    old = f.read_text()
    backup = mcp_setup.write_config(str(f), {"mcpServers": {}})
    assert open(backup).read() == old
    assert json.loads(f.read_text()) == {"mcpServers": {}}
    assert not (tmp_path / "Claude" / "config.json.tmp").exists()


def test_write_new_file_has_no_backup(tmp_path):
    f = tmp_path / "Claude" / "config.json"
    assert mcp_setup.write_config(str(f), {"mcpServers": {}}) is None
    assert f.exists()


# ---------- finding the config ----------

def fake_windows(monkeypatch, tmp_path):
    """WSL on Windows, with %APPDATA% and %LOCALAPPDATA% in tmp_path."""
    folders = {"APPDATA": tmp_path / "Roaming", "LOCALAPPDATA": tmp_path / "Local"}
    monkeypatch.setattr(mcp_setup.platform, "system", lambda: "Linux")
    monkeypatch.setattr(mcp_setup, "in_wsl", lambda: True)
    monkeypatch.setattr(mcp_setup, "windows_folder", lambda var: str(folders[var]))
    standard = folders["APPDATA"] / "Claude" / mcp_setup.CONFIG
    msix = (folders["LOCALAPPDATA"] / "Packages" / "Claude_abc123" / "LocalCache"
            / "Roaming" / "Claude" / mcp_setup.CONFIG)
    # newer MSIX installs: lowercase folder name, as on a real machine
    data = folders["LOCALAPPDATA"] / "Claude-Data" / "claude_abc123" / mcp_setup.CONFIG
    return standard, msix, data


def test_fresh_install_creates_the_standard_file(monkeypatch, tmp_path):
    standard, msix, data = fake_windows(monkeypatch, tmp_path)
    msix.parent.mkdir(parents=True)  # the MSIX folders exist, but no config in them
    data.parent.mkdir(parents=True)
    assert mcp_setup.config_paths() == ([], str(standard))


def test_both_windows_copies_are_found(monkeypatch, tmp_path):
    standard, msix, _ = fake_windows(monkeypatch, tmp_path)
    write_json(standard, {})
    write_json(msix, {})
    assert mcp_setup.config_paths()[0] == [str(standard), str(msix)]


def test_claude_data_copy_is_found(monkeypatch, tmp_path):
    # the copy the app really read on 2026-11-10, which setup used to miss
    standard, _, data = fake_windows(monkeypatch, tmp_path)
    write_json(standard, {})
    write_json(data, {})
    assert mcp_setup.config_paths()[0] == [str(standard), str(data)]


def test_all_three_windows_copies_are_found(monkeypatch, tmp_path):
    standard, msix, data = fake_windows(monkeypatch, tmp_path)
    for path in (standard, msix, data):
        write_json(path, {})
    assert mcp_setup.config_paths()[0] == [str(standard), str(msix), str(data)]


def test_claude_data_copy_alone_is_used_instead_of_creating_one(monkeypatch, tmp_path):
    # no standard file: setup must write the copy the app reads, not make a new one
    standard, _, data = fake_windows(monkeypatch, tmp_path)
    write_json(data, {})
    assert mcp_setup.config_paths() == ([str(data)], str(standard))


def test_no_windows_folder_stops_setup(monkeypatch):
    monkeypatch.setattr(mcp_setup.platform, "system", lambda: "Linux")
    monkeypatch.setattr(mcp_setup, "in_wsl", lambda: True)
    monkeypatch.setattr(mcp_setup, "windows_folder", lambda var: None)
    with pytest.raises(SetupError, match="--print"):
        mcp_setup.config_paths()


# ---------- the whole command ----------

ENTRY = {"command": "wsl.exe", "args": ["-d", "Ubuntu", "-e", "py", "server"]}


def fake_setup(monkeypatch, found, standard, answer="y"):
    monkeypatch.setattr(mcp_setup, "server_entry", lambda: ENTRY)
    monkeypatch.setattr(mcp_setup, "config_paths",
                        lambda: ([str(p) for p in found], str(standard)))
    monkeypatch.setattr("builtins.input", lambda question: answer)


def test_setup_updates_an_old_entry(monkeypatch, tmp_path, capsys):
    f = tmp_path / "config.json"
    write_json(f, {"mcpServers": {NAME: ROI, "other": {"command": "node"}}})
    fake_setup(monkeypatch, [f], f)
    assert mcp_setup.setup() == 0
    data = json.loads(f.read_text())
    assert data["mcpServers"] == {NAME: ENTRY, "other": {"command": "node"}}
    out = capsys.readouterr().out
    assert "monomi: changing" in out and "Backup of the old file" in out
    assert len(list(tmp_path.glob("config.json.bak-*"))) == 1


def test_answering_no_writes_nothing(monkeypatch, tmp_path):
    f = tmp_path / "config.json"
    write_json(f, {"mcpServers": {NAME: ROI}})
    before = f.read_text()
    fake_setup(monkeypatch, [f], f, answer="")  # just Enter = no
    assert mcp_setup.setup() == 0
    assert f.read_text() == before and not list(tmp_path.glob("*.bak-*"))


def test_unchanged_writes_nothing(monkeypatch, tmp_path, capsys):
    f = tmp_path / "config.json"
    write_json(f, {"mcpServers": {NAME: ENTRY}})
    before = f.read_text()
    fake_setup(monkeypatch, [f], f)
    assert mcp_setup.setup() == 0
    assert f.read_text() == before and not list(tmp_path.glob("*.bak-*"))
    assert "already set up" in capsys.readouterr().out


def test_one_broken_file_means_nothing_is_written(monkeypatch, tmp_path):
    good, bad = tmp_path / "good.json", tmp_path / "bad.json"
    write_json(good, {"mcpServers": {}})
    bad.write_text("{oops")
    fake_setup(monkeypatch, [good, bad], good)
    with pytest.raises(SetupError):
        mcp_setup.setup()
    assert json.loads(good.read_text()) == {"mcpServers": {}}


def test_new_install_gets_a_new_file(monkeypatch, tmp_path):
    f = tmp_path / "Claude" / "config.json"
    fake_setup(monkeypatch, [], f)
    assert mcp_setup.setup(yes=True) == 0
    assert json.loads(f.read_text()) == {"mcpServers": {NAME: ENTRY}}


def test_print_only(monkeypatch, capsys):
    monkeypatch.setattr(mcp_setup, "server_entry", lambda: ENTRY)
    assert mcp_setup.main(["setup", "--print"]) == 0
    assert json.loads(capsys.readouterr().out) == {"mcpServers": {NAME: ENTRY}}


def test_setup_error_is_shown_not_crashed(monkeypatch, capsys):
    def broken():
        raise SetupError("no folder")
    monkeypatch.setattr(mcp_setup, "setup", lambda **kwargs: broken())
    assert mcp_setup.main(["setup", "--no-color"]) == 1
    assert "no folder" in capsys.readouterr().out


def test_monomi_mcp_setup_runs_it(monkeypatch, capsys):
    monkeypatch.setattr(mcp_setup, "server_entry", lambda: ENTRY)
    monkeypatch.setattr(sys, "argv", ["monomi.py", "mcp", "setup", "--print"])
    assert cli.main() == 0
    assert json.loads(capsys.readouterr().out)["mcpServers"][NAME] == ENTRY


# ---------- active tools (--allow-active) ----------

class Terminal:
    """A fake sys.stdin: isatty() says whether a person is typing at a terminal."""
    def __init__(self, tty):
        self.tty = tty

    def isatty(self):
        return self.tty


ACTIVE_ENTRY = {**ENTRY, "args": ENTRY["args"] + ["--allow-active"]}


def test_with_active_adds_and_removes_the_flag_once():
    on = mcp_setup.with_active(ENTRY, True)
    assert on == ACTIVE_ENTRY and mcp_setup.is_active(on)
    assert mcp_setup.with_active(on, True) == ACTIVE_ENTRY  # never added twice
    assert mcp_setup.with_active(on, False) == ENTRY and not mcp_setup.is_active(ENTRY)
    assert ENTRY["args"][-1] == "server"  # the original isn't changed
    assert not mcp_setup.is_active(None)


def test_log_path_matches_the_server():
    from monomi import mcp_server
    assert mcp_setup.ACTIVE_LOG == os.path.join(mcp_server.SCANS_DIR, "active.log")
    with pytest.raises(mcp_server.ToolError, match=mcp_setup.ACTIVE_FLAG):
        mcp_server.require_active("fingerprint_hosts")  # its refusal names the same flag


def test_print_with_allow_active(monkeypatch, capsys):
    monkeypatch.setattr(mcp_setup, "server_entry", lambda: ENTRY)
    assert mcp_setup.main(["setup", "--print", "--allow-active"]) == 0
    assert json.loads(capsys.readouterr().out)["mcpServers"][NAME] == ACTIVE_ENTRY


def test_plain_setup_keeps_active_on(monkeypatch, tmp_path, capsys):
    f = tmp_path / "config.json"
    write_json(f, {"mcpServers": {NAME: ACTIVE_ENTRY}})
    before = f.read_text()
    fake_setup(monkeypatch, [f], f)
    assert mcp_setup.setup() == 0
    assert f.read_text() == before  # re-running setup never quietly turns it off
    out = capsys.readouterr().out
    assert "already set up" in out and "active tools: ON" in out


def test_no_active_turns_it_off(monkeypatch, tmp_path):
    f = tmp_path / "config.json"
    write_json(f, {"mcpServers": {NAME: ACTIVE_ENTRY}})
    fake_setup(monkeypatch, [f], f)
    assert mcp_setup.main(["setup", "--no-active"]) == 0
    assert json.loads(f.read_text())["mcpServers"][NAME] == ENTRY


def test_allow_active_refused_without_a_terminal_even_with_yes(monkeypatch, tmp_path, capsys):
    f = tmp_path / "config.json"
    write_json(f, {"mcpServers": {NAME: ENTRY}})
    before = f.read_text()
    fake_setup(monkeypatch, [f], f, answer="yes")
    monkeypatch.setattr(mcp_setup.sys, "stdin", Terminal(False))  # piped, like an agent
    assert mcp_setup.setup(yes=True, active=True) == 0
    assert f.read_text() == before and not list(tmp_path.glob("*.bak-*"))
    assert "type it yourself at a terminal" in capsys.readouterr().out


@pytest.mark.parametrize("answer", ["y", "", "no"])
def test_allow_active_needs_the_full_word_yes(monkeypatch, tmp_path, answer):
    f = tmp_path / "config.json"
    write_json(f, {"mcpServers": {NAME: ENTRY}})
    before = f.read_text()
    fake_setup(monkeypatch, [f], f, answer=answer)
    monkeypatch.setattr(mcp_setup.sys, "stdin", Terminal(True))
    assert mcp_setup.setup(active=True) == 0
    assert f.read_text() == before


def test_allow_active_typed_yes_writes_the_flag(monkeypatch, tmp_path, capsys):
    f = tmp_path / "config.json"
    write_json(f, {"mcpServers": {NAME: ENTRY, "other": {"command": "node"}}})
    fake_setup(monkeypatch, [f], f, answer="yes")
    monkeypatch.setattr(mcp_setup.sys, "stdin", Terminal(True))
    assert mcp_setup.main(["setup", "--allow-active"]) == 0
    data = json.loads(f.read_text())
    assert data["mcpServers"] == {NAME: ACTIVE_ENTRY, "other": {"command": "node"}}
    out = capsys.readouterr().out
    assert "ACTIVE tools send requests" in out and "only takes effect after that restart" in out


def test_allow_active_reaches_the_claude_data_copy(monkeypatch, tmp_path):
    # 2026-11-10: setup wrote the flag to %APPDATA% only, while the app read the
    # Claude-Data copy (an old hand-made entry), so the server started with it off
    standard, _, data = fake_windows(monkeypatch, tmp_path)
    write_json(standard, {"mcpServers": {NAME: ENTRY}})
    write_json(data, {"mcpServers": {NAME: ROI}})
    monkeypatch.setattr(mcp_setup, "server_entry", lambda: ENTRY)
    monkeypatch.setattr("builtins.input", lambda question: "yes")
    monkeypatch.setattr(mcp_setup.sys, "stdin", Terminal(True))
    assert mcp_setup.setup(active=True) == 0
    for path in (standard, data):
        assert json.loads(path.read_text())["mcpServers"][NAME] == ACTIVE_ENTRY


# ---------- scope (v1.12) ----------

SCOPE_TEXT = "example.test\n*.example.test\n!dev.example.test\n*\n"  # last line is rejected


def scope_file(tmp_path, text=SCOPE_TEXT):
    p = tmp_path / "scope.txt"
    p.write_bytes(text.encode())
    return p


def digest(p):
    import hashlib
    return hashlib.sha256(p.read_bytes()).hexdigest()


def test_with_scope_adds_and_removes_the_pair_once():
    e = mcp_setup.with_scope(ENTRY, "/s.txt", "ab" * 32)
    assert e["args"] == ENTRY["args"] + ["--scope", "/s.txt", "--scope-sha256", "ab" * 32]
    assert mcp_setup.scope_args(e) == ("/s.txt", "ab" * 32)
    again = mcp_setup.with_scope(e, "/t.txt", "cd" * 32)
    assert again["args"].count("--scope") == 1 and mcp_setup.scope_args(again)[0] == "/t.txt"
    assert mcp_setup.with_scope(e, None, None) == ENTRY
    assert mcp_setup.scope_args(ENTRY) == (None, None) and mcp_setup.scope_args(None) == (None, None)


def test_entry_order_is_always_scope_then_active(monkeypatch):
    monkeypatch.setattr(mcp_setup, "server_entry", lambda: ENTRY)
    e = mcp_setup.build_entry(True, "/s.txt", "ab" * 32)
    assert e["args"][-5:] == ["--scope", "/s.txt", "--scope-sha256", "ab" * 32, "--allow-active"]


def test_scope_refused_without_a_terminal_even_with_yes(monkeypatch, tmp_path, capsys):
    f = tmp_path / "config.json"
    write_json(f, {"mcpServers": {NAME: ACTIVE_ENTRY}})
    before = f.read_text()
    fake_setup(monkeypatch, [f], f, answer="yes")
    monkeypatch.setattr(mcp_setup.sys, "stdin", Terminal(False))  # piped, like an agent
    assert mcp_setup.setup(yes=True, scope_file=str(scope_file(tmp_path))) == 0
    assert f.read_text() == before
    assert "approve this scope, you have to type it yourself" in capsys.readouterr().out


@pytest.mark.parametrize("answer", ["y", "", "no"])
def test_scope_needs_the_full_word_yes(monkeypatch, tmp_path, answer):
    f = tmp_path / "config.json"
    write_json(f, {"mcpServers": {NAME: ACTIVE_ENTRY}})
    before = f.read_text()
    fake_setup(monkeypatch, [f], f, answer=answer)
    monkeypatch.setattr(mcp_setup.sys, "stdin", Terminal(True))
    assert mcp_setup.setup(scope_file=str(scope_file(tmp_path))) == 0
    assert f.read_text() == before


def test_scope_typed_yes_writes_path_and_hash_to_every_copy(monkeypatch, tmp_path, capsys):
    standard, _, data = fake_windows(monkeypatch, tmp_path)
    write_json(standard, {"mcpServers": {NAME: ACTIVE_ENTRY}})
    write_json(data, {"mcpServers": {NAME: ACTIVE_ENTRY}})
    monkeypatch.setattr(mcp_setup, "server_entry", lambda: ENTRY)
    monkeypatch.setattr("builtins.input", lambda question: "yes")
    monkeypatch.setattr(mcp_setup.sys, "stdin", Terminal(True))
    s = scope_file(tmp_path)
    assert mcp_setup.main(["setup", "--scope", str(s)]) == 0
    for path in (standard, data):
        entry = json.loads(path.read_text())["mcpServers"][NAME]
        assert mcp_setup.scope_args(entry) == (str(s), digest(s))
        assert mcp_setup.is_active(entry)            # active setting kept
    out = capsys.readouterr().out
    # you see every rule and every rejected line before typing yes
    assert "in scope (2):" in out and "*.example.test" in out
    assert "never in scope" in out and "!dev.example.test" in out
    assert "rejected lines (1)" in out and "line 4" in out and "a bare '*'" in out


def test_scope_path_is_saved_absolute(monkeypatch, tmp_path):
    f = tmp_path / "config.json"
    write_json(f, {"mcpServers": {NAME: ENTRY}})
    fake_setup(monkeypatch, [f], f, answer="yes")
    monkeypatch.setattr(mcp_setup.sys, "stdin", Terminal(True))
    scope_file(tmp_path)
    monkeypatch.chdir(tmp_path)
    assert mcp_setup.setup(scope_file="scope.txt") == 0
    path, _ = mcp_setup.scope_args(json.loads(f.read_text())["mcpServers"][NAME])
    assert path == str(tmp_path / "scope.txt")


def test_hash_is_of_the_bytes_that_were_shown(monkeypatch, tmp_path):
    # The file is read once: an edit between "shown" and "written" can't sneak in
    f = tmp_path / "config.json"
    write_json(f, {"mcpServers": {NAME: ENTRY}})
    s = scope_file(tmp_path)
    shown = digest(s)
    fake_setup(monkeypatch, [f], f)

    def type_yes_after_an_edit(question):
        s.write_bytes(b"*.example.test\n*.other.test\n")   # widened while you were reading
        return "yes"
    monkeypatch.setattr("builtins.input", type_yes_after_an_edit)
    monkeypatch.setattr(mcp_setup.sys, "stdin", Terminal(True))
    assert mcp_setup.setup(scope_file=str(s)) == 0
    _, saved = mcp_setup.scope_args(json.loads(f.read_text())["mcpServers"][NAME])
    assert saved == shown != digest(s)   # so the server will refuse the edited file


@pytest.mark.parametrize("text,reason", [("", "no valid rules"), ("*\n", "no valid rules"),
                                         ("!dev.example.test\n", "only exclusions")])
def test_unusable_scope_file_writes_nothing(monkeypatch, tmp_path, capsys, text, reason):
    f = tmp_path / "config.json"
    write_json(f, {"mcpServers": {NAME: ENTRY}})
    before = f.read_text()
    fake_setup(monkeypatch, [f], f, answer="yes")
    monkeypatch.setattr(mcp_setup.sys, "stdin", Terminal(True))
    assert mcp_setup.main(["setup", "--scope", str(scope_file(tmp_path, text))]) == 1
    assert f.read_text() == before
    assert reason in capsys.readouterr().out


def test_missing_scope_file_writes_nothing(monkeypatch, tmp_path, capsys):
    f = tmp_path / "config.json"
    write_json(f, {"mcpServers": {NAME: ENTRY}})
    fake_setup(monkeypatch, [f], f, answer="yes")
    assert mcp_setup.main(["setup", "--scope", str(tmp_path / "nope.txt")]) == 1
    assert "missing" in capsys.readouterr().out


def test_plain_setup_keeps_the_scope(monkeypatch, tmp_path, capsys):
    s = scope_file(tmp_path)
    entry = mcp_setup.with_active(mcp_setup.with_scope(ENTRY, str(s), digest(s)), True)
    f = tmp_path / "config.json"
    write_json(f, {"mcpServers": {NAME: entry}})
    before = f.read_text()
    fake_setup(monkeypatch, [f], f)
    assert mcp_setup.setup() == 0
    assert f.read_text() == before
    assert f"scope: {s} (sha256 {digest(s)[:12]}...)" in capsys.readouterr().out


def test_approving_the_same_scope_again_needs_no_yes(monkeypatch, tmp_path, capsys):
    s = scope_file(tmp_path)
    entry = mcp_setup.with_scope(ENTRY, str(s), digest(s))
    f = tmp_path / "config.json"
    write_json(f, {"mcpServers": {NAME: entry}})
    fake_setup(monkeypatch, [f], f, answer="no")
    assert mcp_setup.setup(scope_file=str(s)) == 0
    assert "already set up" in capsys.readouterr().out


def test_no_scope_clears_it_with_a_plain_y(monkeypatch, tmp_path):
    s = scope_file(tmp_path)
    entry = mcp_setup.with_active(mcp_setup.with_scope(ENTRY, str(s), digest(s)), True)
    f = tmp_path / "config.json"
    write_json(f, {"mcpServers": {NAME: entry}})
    fake_setup(monkeypatch, [f], f, answer="y")   # narrowing: no typed "yes" needed
    monkeypatch.setattr(mcp_setup.sys, "stdin", Terminal(False))
    assert mcp_setup.main(["setup", "--no-scope"]) == 0
    assert json.loads(f.read_text())["mcpServers"][NAME] == ACTIVE_ENTRY


def test_active_on_without_a_scope_warns_after_writing(monkeypatch, tmp_path, capsys):
    f = tmp_path / "config.json"
    write_json(f, {"mcpServers": {NAME: ENTRY}})
    fake_setup(monkeypatch, [f], f, answer="yes")
    monkeypatch.setattr(mcp_setup.sys, "stdin", Terminal(True))
    assert mcp_setup.setup(active=True) == 0
    assert "no scope file is approved, so every active check will refuse" in capsys.readouterr().out


def test_allow_active_and_scope_together_ask_once(monkeypatch, tmp_path):
    f = tmp_path / "config.json"
    write_json(f, {"mcpServers": {NAME: ENTRY}})
    questions = []
    fake_setup(monkeypatch, [f], f)
    monkeypatch.setattr("builtins.input", lambda q: questions.append(q) or "yes")
    monkeypatch.setattr(mcp_setup.sys, "stdin", Terminal(True))
    assert mcp_setup.main(["setup", "--allow-active", "--scope", str(scope_file(tmp_path))]) == 0
    assert questions == ['\nType "yes" to allow active tools and approve this scope: ']


def test_scope_and_no_scope_cant_be_used_together():
    with pytest.raises(SystemExit):
        mcp_setup.main(["setup", "--scope", "x.txt", "--no-scope"])


def test_print_with_scope(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(mcp_setup, "server_entry", lambda: ENTRY)
    s = scope_file(tmp_path)
    assert mcp_setup.main(["setup", "--print", "--allow-active", "--scope", str(s)]) == 0
    entry = json.loads(capsys.readouterr().out)["mcpServers"][NAME]
    assert mcp_setup.scope_args(entry) == (str(s), digest(s)) and mcp_setup.is_active(entry)


def test_scope_flags_match_the_server(tmp_path):
    import inspect

    from monomi import mcp_server
    s = scope_file(tmp_path)
    args = mcp_setup.with_scope({"args": []}, str(s), digest(s))["args"]
    assert args[0] == mcp_setup.SCOPE_FLAG and args[2] == mcp_setup.SCOPE_HASH_FLAG
    # ...and they're the flags the server's own argument parser declares
    server_args = inspect.getsource(mcp_server.main)
    for flag in (mcp_setup.SCOPE_FLAG, mcp_setup.SCOPE_HASH_FLAG, mcp_setup.ACTIVE_FLAG):
        assert f'"{flag}"' in server_args


def test_server_accepts_the_entry_setup_writes(monkeypatch, tmp_path):
    from monomi import mcp_server
    monkeypatch.setattr(mcp_server.mcp, "run", lambda: None)
    s = scope_file(tmp_path)
    entry = mcp_setup.build_entry(True, str(s), digest(s))
    monkeypatch.setattr(mcp_server, "SCOPE", None)              # all three restored after the test
    monkeypatch.setattr(mcp_server, "SCOPE_PROBLEM", "untouched")
    monkeypatch.setattr(mcp_server, "ALLOW_ACTIVE", False)
    mcp_server.main(entry["args"][entry["args"].index(mcp_setup.SCOPE_FLAG):])
    assert mcp_server.SCOPE_PROBLEM is None and mcp_server.ALLOW_ACTIVE is True


# ---------- client adapters (v1.13): the same rules for every MCP client ----------

class ListClient(mcp_setup.Client):
    """A made-up client that stores Monomi as one command list under "tools",
    to prove setup's rules (backup, unchanged, typed yes) don't depend on Claude's shape."""
    key, label, restart = "listy", "the list client", "restart the list client"

    def __init__(self, path):
        self.path = str(path)

    def paths(self):
        return ([self.path] if os.path.exists(self.path) else []), self.path

    def load(self, path):
        return json.loads(open(path).read()) if os.path.exists(path) else {}

    def entry(self, doc):
        run = doc.get("tools", {}).get(NAME)
        return {"command": run[0], "args": run[1:]} if run else None

    def with_entry(self, doc, entry):
        return {**doc, "tools": {**doc.get("tools", {}), NAME: [entry["command"], *entry["args"]]}}

    def dump(self, doc):
        return json.dumps(doc) + "\n"

    def show(self, entry):
        return json.dumps([entry["command"], *entry["args"]])

    def printable(self, entry):
        return json.dumps({"tools": {NAME: [entry["command"], *entry["args"]]}})

    def base(self):
        return {"command": "py", "args": ["server"]}


def test_the_claude_client_is_the_default(monkeypatch, capsys):
    monkeypatch.setattr(mcp_setup, "server_entry", lambda: ENTRY)
    assert mcp_setup.main(["setup", "--print"]) == 0  # no --client given
    assert json.loads(capsys.readouterr().out) == {"mcpServers": {NAME: ENTRY}}


def test_any_client_gets_the_same_safe_write(monkeypatch, tmp_path, capsys):
    f = tmp_path / "list.json"
    write_json(f, {"theme": "dark", "tools": {"other": ["node", "x"]}})
    client = ListClient(f)
    monkeypatch.setattr("builtins.input", lambda question: "y")
    assert mcp_setup.setup(client=client) == 0
    data = json.loads(f.read_text())
    assert data == {"theme": "dark", "tools": {"other": ["node", "x"], NAME: ["py", "server"]}}
    assert len(list(tmp_path.glob("list.json.bak-*"))) == 1  # backed up first
    assert "restart the list client" in capsys.readouterr().out

    assert mcp_setup.setup(client=client) == 0  # a second run changes nothing
    assert "already set up in the list client" in capsys.readouterr().out
    assert len(list(tmp_path.glob("list.json.bak-*"))) == 1


def test_any_client_needs_a_typed_yes_for_active_tools(monkeypatch, tmp_path, capsys):
    f = tmp_path / "list.json"
    write_json(f, {"tools": {NAME: ["py", "server"]}})
    before = f.read_text()
    monkeypatch.setattr("builtins.input", lambda question: "yes")
    monkeypatch.setattr(mcp_setup.sys, "stdin", Terminal(False))  # piped, like an agent
    assert mcp_setup.setup(yes=True, active=True, client=ListClient(f)) == 0
    assert f.read_text() == before
    assert "type it yourself at a terminal" in capsys.readouterr().out


def test_client_flag_picks_the_adapter(monkeypatch, tmp_path, capsys):
    f = tmp_path / "list.json"
    monkeypatch.setitem(mcp_setup.CLIENTS, "listy", ListClient(f))
    assert mcp_setup.main(["setup", "--client", "listy", "--print"]) == 0
    assert json.loads(capsys.readouterr().out) == {"tools": {NAME: ["py", "server"]}}


# ---------- Codex CLI (v1.13): TOML, [mcp_servers.monomi] ----------

CODEX = mcp_setup.CLIENTS["codex"]
CODEX_FILE = """# my Codex settings
model = "gpt-5"   # keep this comment

[mcp_servers.context7]
command = "npx"
args = ["-y", "@upstash/context7-mcp"]
"""


def codex_home(monkeypatch, tmp_path, text=None):
    """Point CODEX_HOME at a temp folder; write config.toml if text is given."""
    monkeypatch.setenv("CODEX_HOME", str(tmp_path))
    monkeypatch.setattr(mcp_setup, "direct_entry", lambda: {"command": "py", "args": ["server"]})
    f = tmp_path / "config.toml"
    if text is not None:
        f.write_text(text, encoding="utf-8")
    return f


def codex_monomi(f):
    import tomlkit
    return tomlkit.parse(f.read_text(encoding="utf-8"))["mcp_servers"][NAME]


def test_codex_config_follows_codex_home(monkeypatch, tmp_path):
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "elsewhere"))
    assert CODEX.paths() == ([], str(tmp_path / "elsewhere" / "config.toml"))
    monkeypatch.delenv("CODEX_HOME")
    assert CODEX.paths()[1] == os.path.join(os.path.expanduser("~/.codex"), "config.toml")


def test_codex_setup_keeps_comments_and_other_servers(monkeypatch, tmp_path, capsys):
    f = codex_home(monkeypatch, tmp_path, CODEX_FILE)
    monkeypatch.setattr("builtins.input", lambda question: "y")
    assert mcp_setup.main(["setup", "--client", "codex"]) == 0
    text = f.read_text(encoding="utf-8")
    assert text.startswith(CODEX_FILE)  # every byte before Monomi's table is untouched
    assert "[mcp_servers.monomi]" in text and "mcpServers" not in text
    assert dict(codex_monomi(f)) == {"command": "py", "args": ["server"]}
    assert len(list(tmp_path.glob("config.toml.bak-*"))) == 1
    assert "start a new Codex session" in capsys.readouterr().out

    assert mcp_setup.main(["setup", "--client", "codex"]) == 0  # nothing left to change
    assert "already set up in Codex" in capsys.readouterr().out


def test_codex_new_file_has_only_monomis_table(monkeypatch, tmp_path):
    f = codex_home(monkeypatch, tmp_path)
    assert mcp_setup.setup(yes=True, client=CODEX) == 0
    assert f.read_text(encoding="utf-8").splitlines()[0] == "[mcp_servers.monomi]"


def test_codex_keeps_your_own_keys_in_monomis_table(monkeypatch, tmp_path):
    f = codex_home(monkeypatch, tmp_path, '[mcp_servers.monomi]\ncommand = "old"\n'
                                          'args = []\ntool_timeout_sec = 120\n')
    assert mcp_setup.setup(yes=True, client=CODEX) == 0
    table = codex_monomi(f)
    assert table["command"] == "py" and table["tool_timeout_sec"] == 120


def test_codex_active_needs_typed_yes_and_writes_the_flag(monkeypatch, tmp_path):
    f = codex_home(monkeypatch, tmp_path, CODEX_FILE)
    monkeypatch.setattr("builtins.input", lambda question: "yes")
    monkeypatch.setattr(mcp_setup.sys, "stdin", Terminal(False))  # piped, like an agent
    assert mcp_setup.setup(yes=True, active=True, client=CODEX) == 0
    assert f.read_text(encoding="utf-8") == CODEX_FILE  # refused: nothing written
    monkeypatch.setattr(mcp_setup.sys, "stdin", Terminal(True))
    assert mcp_setup.setup(active=True, client=CODEX) == 0
    assert list(codex_monomi(f)["args"]) == ["server", "--allow-active"]


@pytest.mark.parametrize("text", ['model = "unclosed', "mcp_servers = 5\n"])
def test_codex_broken_or_strange_config_is_never_overwritten(monkeypatch, tmp_path, text):
    f = codex_home(monkeypatch, tmp_path, text)
    with pytest.raises(SetupError, match="Nothing was changed"):
        mcp_setup.setup(yes=True, client=CODEX)
    assert f.read_text(encoding="utf-8") == text and not list(tmp_path.glob("*.bak-*"))


def test_codex_print_and_windows_paths(monkeypatch, capsys):
    win = {"command": "C:\\Users\\me\\monomi\\venv\\Scripts\\python.exe",
           "args": ["C:\\Users\\me\\monomi\\mcp_server.py"]}
    monkeypatch.setattr(mcp_setup, "direct_entry", lambda: win)
    assert mcp_setup.main(["setup", "--client", "codex", "--print"]) == 0
    import tomlkit
    printed = tomlkit.parse(capsys.readouterr().out)
    assert dict(printed["mcp_servers"][NAME]) == win  # backslashes survive the round trip


def test_codex_starts_the_server_directly_even_in_wsl(monkeypatch):
    monkeypatch.setattr(mcp_setup, "in_wsl", lambda: True)
    assert CODEX.base()["command"] != "wsl.exe"


# ---------- OpenCode (v1.13): JSON / JSONC, V1 and V2 shapes ----------

OPENCODE = mcp_setup.CLIENTS["opencode"]
OC_ENTRY = {"type": "local", "command": ["py", "server"]}


def opencode_home(monkeypatch, tmp_path, data=None, name="opencode.json"):
    """A fake home with ~/.config/opencode; writes the config if data is given."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))  # what ~ means on Windows
    monkeypatch.setattr(mcp_setup, "direct_entry", lambda: {"command": "py", "args": ["server"]})
    f = tmp_path / ".config" / "opencode" / name
    if data is not None:
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")
    return f


def test_opencode_v1_file_gets_the_v1_shape(monkeypatch, tmp_path, capsys):
    f = opencode_home(monkeypatch, tmp_path, {"$schema": "https://opencode.ai/config.json",
                                              "theme": "dark",
                                              "mcp": {"other": {"type": "local", "command": ["node"]}}})
    monkeypatch.setattr("builtins.input", lambda question: "y")
    assert mcp_setup.main(["setup", "--client", "opencode"]) == 0
    data = json.loads(f.read_text())
    assert data["mcp"] == {"other": {"type": "local", "command": ["node"]}, NAME: OC_ENTRY}
    assert data["theme"] == "dark" and data["$schema"].endswith("config.json")
    assert len(list(f.parent.glob("opencode.json.bak-*"))) == 1
    assert "quit OpenCode and start it again" in capsys.readouterr().out

    assert mcp_setup.main(["setup", "--client", "opencode"]) == 0  # nothing left to change
    assert "already set up in OpenCode" in capsys.readouterr().out


def test_opencode_v2_file_gets_the_v2_shape(monkeypatch, tmp_path):
    f = opencode_home(monkeypatch, tmp_path, {"mcp": {"timeout": {"startup": 45000},
                                                      "servers": {"other": {"type": "local"}}}})
    assert mcp_setup.setup(yes=True, client=OPENCODE) == 0
    mcp = json.loads(f.read_text())["mcp"]
    assert mcp["servers"][NAME] == OC_ENTRY and NAME not in mcp  # never two shapes in one file
    assert mcp["timeout"] == {"startup": 45000}


def test_opencode_new_file_and_print_use_the_v1_shape(monkeypatch, tmp_path, capsys):
    f = opencode_home(monkeypatch, tmp_path)
    assert mcp_setup.setup(yes=True, client=OPENCODE) == 0
    assert json.loads(f.read_text()) == {"mcp": {NAME: OC_ENTRY}}
    capsys.readouterr()  # drop setup's own messages, keep only what --print shows
    assert mcp_setup.main(["setup", "--client", "opencode", "--print"]) == 0
    assert json.loads(capsys.readouterr().out) == {"mcp": {NAME: OC_ENTRY}}


def test_opencode_keeps_your_own_keys_in_monomis_object(monkeypatch, tmp_path):
    f = opencode_home(monkeypatch, tmp_path, {"mcp": {NAME: {
        "type": "local", "command": ["old"], "environment": {"X": "1"}, "timeout": 20000}}})
    assert mcp_setup.setup(yes=True, client=OPENCODE) == 0
    assert json.loads(f.read_text())["mcp"][NAME] == {**OC_ENTRY, "environment": {"X": "1"}, "timeout": 20000}


def test_opencode_file_with_comments_is_never_rewritten(monkeypatch, tmp_path):
    text = '{\n  // my servers\n  "mcp": {"other": {"type": "local", "command": ["node"]},},\n}\n'
    f = opencode_home(monkeypatch, tmp_path, text, name="opencode.jsonc")
    with pytest.raises(SetupError, match="comments or trailing commas") as e:
        mcp_setup.setup(yes=True, client=OPENCODE)
    assert "--client opencode --print" in str(e.value)  # says how to get the entry instead
    assert f.read_text() == text and not list(f.parent.glob("*.bak-*"))


def test_opencode_jsonc_without_comments_is_edited(monkeypatch, tmp_path):
    f = opencode_home(monkeypatch, tmp_path, {"mcp": {}}, name="opencode.jsonc")
    assert OPENCODE.paths() == ([str(f)], str(f.parent / "opencode.json"))
    assert mcp_setup.setup(yes=True, client=OPENCODE) == 0
    assert json.loads(f.read_text())["mcp"][NAME] == OC_ENTRY


def test_opencode_active_needs_typed_yes(monkeypatch, tmp_path):
    f = opencode_home(monkeypatch, tmp_path, {"mcp": {NAME: OC_ENTRY}})
    before = f.read_text()
    monkeypatch.setattr("builtins.input", lambda question: "yes")
    monkeypatch.setattr(mcp_setup.sys, "stdin", Terminal(False))  # piped, like an agent
    assert mcp_setup.setup(yes=True, active=True, client=OPENCODE) == 0
    assert f.read_text() == before
    monkeypatch.setattr(mcp_setup.sys, "stdin", Terminal(True))
    assert mcp_setup.setup(active=True, client=OPENCODE) == 0
    assert json.loads(f.read_text())["mcp"][NAME]["command"] == ["py", "server", "--allow-active"]


def test_opencode_strange_config_is_never_overwritten(monkeypatch, tmp_path):
    f = opencode_home(monkeypatch, tmp_path, {"mcp": ["not", "an", "object"]})
    with pytest.raises(SetupError, match="doesn't look like an OpenCode config"):
        mcp_setup.setup(yes=True, client=OPENCODE)
    assert not list(f.parent.glob("*.bak-*"))


# ---------- Hermes Agent (v1.13): YAML, mcp_servers.monomi ----------

HERMES = mcp_setup.CLIENTS["hermes"]
HERMES_FILE = """# Hermes settings
model:
  provider: openrouter   # keep me
mcp_servers:
  filesystem:
    command: "npx"
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/home/user/projects"]
"""


def hermes_home(monkeypatch, tmp_path, text=None):
    """Point HERMES_HOME at a temp folder; write config.yaml if text is given."""
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setattr(mcp_setup, "direct_entry", lambda: {"command": "py", "args": ["server"]})
    f = tmp_path / "config.yaml"
    if text is not None:
        f.write_text(text, encoding="utf-8")
    return f


def hermes_monomi(f):
    from ruamel.yaml import YAML
    return YAML(typ="safe").load(f.read_text(encoding="utf-8"))["mcp_servers"][NAME]


def test_hermes_config_follows_hermes_home(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "profile"))
    assert HERMES.paths() == ([], str(tmp_path / "profile" / "config.yaml"))
    monkeypatch.delenv("HERMES_HOME")
    assert HERMES.paths()[1] == os.path.join(os.path.expanduser("~/.hermes"), "config.yaml")


def test_hermes_setup_keeps_comments_quotes_and_other_servers(monkeypatch, tmp_path, capsys):
    f = hermes_home(monkeypatch, tmp_path, HERMES_FILE)
    monkeypatch.setattr("builtins.input", lambda question: "y")
    assert mcp_setup.main(["setup", "--client", "hermes"]) == 0
    text = f.read_text(encoding="utf-8")
    assert text.startswith(HERMES_FILE)  # every byte before Monomi's entry is untouched
    assert text.endswith("  monomi:\n    command: py\n    args: [server]\n")
    assert hermes_monomi(f) == {"command": "py", "args": ["server"]}
    assert len(list(tmp_path.glob("config.yaml.bak-*"))) == 1
    assert "/reload-mcp" in capsys.readouterr().out

    assert mcp_setup.main(["setup", "--client", "hermes"]) == 0  # nothing left to change
    assert "already set up in Hermes" in capsys.readouterr().out


def test_hermes_keeps_the_files_own_list_indentation(monkeypatch, tmp_path):
    text = "toolsets:\n    - web\n    - terminal\nmcp_servers:\n    other:\n        command: node\n"
    f = hermes_home(monkeypatch, tmp_path, text)
    assert mcp_setup.setup(yes=True, client=HERMES) == 0
    assert f.read_text(encoding="utf-8").startswith(text)


def test_hermes_new_or_empty_file(monkeypatch, tmp_path):
    for start in (None, "", "mcp_servers:\n"):
        f = hermes_home(monkeypatch, tmp_path, start)
        assert mcp_setup.setup(yes=True, client=HERMES) == 0
        assert hermes_monomi(f) == {"command": "py", "args": ["server"]}
        f.unlink()


def test_hermes_keeps_your_own_keys_in_monomis_entry(monkeypatch, tmp_path):
    f = hermes_home(monkeypatch, tmp_path, "mcp_servers:\n  monomi:\n    command: old\n"
                                           "    timeout: 120\n    env: {X: '1'}\n")
    assert mcp_setup.setup(yes=True, client=HERMES) == 0
    assert hermes_monomi(f) == {"command": "py", "args": ["server"], "timeout": 120, "env": {"X": "1"}}


def test_hermes_active_needs_typed_yes(monkeypatch, tmp_path):
    f = hermes_home(monkeypatch, tmp_path, HERMES_FILE)
    monkeypatch.setattr("builtins.input", lambda question: "yes")
    monkeypatch.setattr(mcp_setup.sys, "stdin", Terminal(False))  # piped, like an agent
    assert mcp_setup.setup(yes=True, active=True, client=HERMES) == 0
    assert f.read_text(encoding="utf-8") == HERMES_FILE
    monkeypatch.setattr(mcp_setup.sys, "stdin", Terminal(True))
    assert mcp_setup.setup(active=True, client=HERMES) == 0
    assert hermes_monomi(f)["args"] == ["server", "--allow-active"]


@pytest.mark.parametrize("text", ["model: [unclosed\n", "mcp_servers: [a, b]\n", "- just\n- a list\n"])
def test_hermes_broken_or_strange_config_is_never_overwritten(monkeypatch, tmp_path, text):
    f = hermes_home(monkeypatch, tmp_path, text)
    with pytest.raises(SetupError, match="Nothing was changed"):
        mcp_setup.setup(yes=True, client=HERMES)
    assert f.read_text(encoding="utf-8") == text and not list(tmp_path.glob("*.bak-*"))


def test_hermes_print_and_windows_paths(monkeypatch, capsys):
    win = {"command": "C:\\Users\\me\\monomi\\venv\\Scripts\\python.exe",
           "args": ["C:\\Users\\me\\monomi\\mcp_server.py"]}
    monkeypatch.setattr(mcp_setup, "direct_entry", lambda: win)
    assert mcp_setup.main(["setup", "--client", "hermes", "--print"]) == 0
    from ruamel.yaml import YAML
    assert YAML(typ="safe").load(capsys.readouterr().out)["mcp_servers"][NAME] == win


@pytest.mark.parametrize("text, expected", [
    ("a: 1\n", (2, 0)),                                   # nothing nested: ruamel's defaults
    ("mcp_servers:\n  x:\n    command: c\n", (2, 0)),
    ("toolsets:\n    - web\nmcp:\n    x: 1\n", (4, 4)),  # list first: ruamel's guess got this wrong
    ("toolsets:\n- web\nmcp:\n  x: 1\n", (2, 0)),
    ("toolsets:\n  - web\nmcp:\n  x: 1\n", (2, 2)),
])
def test_hermes_measures_the_files_own_indentation(text, expected):
    assert HERMES._indentation(text) == expected


@pytest.mark.parametrize("text", [
    "toolsets:\n  - web\n  - terminal\nmcp_servers:\n  other:\n    command: node\n",
    "toolsets:\n- web\nmcp_servers:\n  other:\n    command: node\n",
])
def test_hermes_keeps_other_list_styles_too(monkeypatch, tmp_path, text):
    f = hermes_home(monkeypatch, tmp_path, text)
    assert mcp_setup.setup(yes=True, client=HERMES) == 0
    assert f.read_text(encoding="utf-8").startswith(text)
