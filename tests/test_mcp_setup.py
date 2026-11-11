"""Tests for mcp_setup.py: the entry, finding the config, and safe writing.
Every test uses temporary folders, never a real Claude config."""

import json
import os
import sys

import pytest

import mcp_setup
import monomi
from mcp_setup import NAME, SERVER, SetupError

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
    return standard, msix


def test_fresh_install_creates_the_standard_file(monkeypatch, tmp_path):
    standard, msix = fake_windows(monkeypatch, tmp_path)
    msix.parent.mkdir(parents=True)  # the MSIX folder exists, but no config in it
    assert mcp_setup.config_paths() == ([], str(standard))


def test_both_windows_copies_are_found(monkeypatch, tmp_path):
    standard, msix = fake_windows(monkeypatch, tmp_path)
    write_json(standard, {})
    write_json(msix, {})
    assert mcp_setup.config_paths()[0] == [str(standard), str(msix)]


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
    assert monomi.main() == 0
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
    import mcp_server
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
    assert "typed by you at a terminal" in capsys.readouterr().out


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
