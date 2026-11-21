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


# ---------- v1.20: no active setting, old flags stripped ----------

# A v1.19 entry with every old flag, in the order v1.19 wrote them
ACTIVE_ENTRY = {**ENTRY, "args": ENTRY["args"] + [
    "--scope", "/lab/scope.txt", "--scope-sha256", "ab" * 32,
    "--research", "/lab/research.txt", "--research-sha256", "cd" * 32, "--allow-active"]}


def test_legacy_flags_are_named_in_order_and_stripped_with_their_values():
    assert mcp_setup.legacy_flags(ACTIVE_ENTRY) == [
        "--scope", "--scope-sha256", "--research", "--research-sha256", "--allow-active"]
    assert mcp_setup.without_legacy(ACTIVE_ENTRY) == ENTRY
    assert mcp_setup.legacy_flags(ENTRY) == [] and mcp_setup.legacy_flags(None) == []
    assert ACTIVE_ENTRY["args"][-1] == "--allow-active"   # the original isn't changed


def test_build_entry_never_writes_an_old_flag():
    assert mcp_setup.build_entry(ACTIVE_ENTRY) == ENTRY
    assert mcp_setup.build_entry(ACTIVE_ENTRY, "2")["args"] == ENTRY["args"] + ["--rate", "2"]


def test_setup_strips_old_flags_from_every_copy_and_keeps_the_rate(monkeypatch, tmp_path, capsys):
    a, b = tmp_path / "roaming.json", tmp_path / "packaged.json"
    old = {**ACTIVE_ENTRY, "args": ACTIVE_ENTRY["args"] + ["--rate", "0.5"]}
    for f in (a, b):
        write_json(f, {"mcpServers": {NAME: old}})
    fake_setup(monkeypatch, [a, b], a, answer="y")   # a plain y: removing needs no typed yes
    assert mcp_setup.main(["setup"]) == 0
    for f in (a, b):
        assert json.loads(f.read_text())["mcpServers"][NAME] == {
            **ENTRY, "args": ENTRY["args"] + ["--rate", "0.5"]}
    out = capsys.readouterr().out
    assert "removing flags not used since v1.20: --scope, --scope-sha256" in out
    assert "each one needs your approval in a terminal" in out


def test_a_clean_entry_is_already_set_up(monkeypatch, tmp_path, capsys):
    f = tmp_path / "config.json"
    write_json(f, {"mcpServers": {NAME: ENTRY}})
    fake_setup(monkeypatch, [f], f)
    assert mcp_setup.setup() == 0
    assert "already set up" in capsys.readouterr().out


@pytest.mark.parametrize("old", ["--allow-active", "--no-active", "--scope", "--no-scope",
                                 "--research", "--no-research"])
def test_the_old_options_are_gone(old):
    with pytest.raises(SystemExit):
        mcp_setup.main(["setup", old] + (["x.txt"] if old in ("--scope", "--research") else []))


def test_print_never_has_an_old_flag(monkeypatch, capsys):
    monkeypatch.setattr(mcp_setup, "server_entry", lambda: ACTIVE_ENTRY)
    assert mcp_setup.main(["setup", "--print", "--rate", "2"]) == 0
    assert json.loads(capsys.readouterr().out)["mcpServers"][NAME] == {
        **ENTRY, "args": ENTRY["args"] + ["--rate", "2"]}


def test_the_server_starts_from_what_setup_writes_with_no_note(monkeypatch, capsys):
    from monomi import mcp_server
    monkeypatch.setattr(mcp_server.mcp, "run", lambda: None)
    entry = mcp_setup.build_entry(ENTRY, "2")
    mcp_server.main(entry["args"][entry["args"].index(mcp_setup.RATE_FLAG):])
    assert mcp_server.LIMITER.rate == 2.0 and mcp_server.RATE_PROBLEM is None
    assert "ignoring" not in capsys.readouterr().err


def test_setup_and_the_server_agree_on_the_old_flags_and_the_log():
    from monomi import mcp_server
    assert mcp_server.LEGACY_FLAGS == mcp_setup.LEGACY_FLAGS
    assert mcp_setup.ACTIVE_LOG == os.path.join(mcp_server.SCANS_DIR, "active.log")


def test_another_client_loses_the_old_flags_too(monkeypatch, tmp_path):
    # Every client goes through the same build_entry, so one non-Claude
    # client (Codex, TOML) proves the rule isn't Claude-only
    f = codex_home(monkeypatch, tmp_path, CODEX_FILE + '\n[mcp_servers.monomi]\ncommand = "py"\n'
                   'args = ["server", "--scope", "s.txt", "--scope-sha256", "ab", "--allow-active"]\n')
    assert mcp_setup.setup(yes=True, client=mcp_setup.CLIENTS["codex"]) == 0
    assert list(codex_monomi(f)["args"]) == ["server"]
    assert "context7" in f.read_text(encoding="utf-8")   # other servers untouched


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
    # Built the same way as the code: "~/.hermes" would give a mixed C:\Users\x/.hermes on Windows
    assert HERMES.paths()[1] == os.path.join(os.path.expanduser(os.path.join("~", ".hermes")), "config.yaml")


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


# ---------- --rate (v1.19) ----------

def test_rate_is_a_plain_write_and_is_kept_by_plain_setup(monkeypatch, tmp_path):
    f = tmp_path / "config.json"
    write_json(f, {"mcpServers": {NAME: ACTIVE_ENTRY}})
    fake_setup(monkeypatch, [f], f, answer="y")
    assert mcp_setup.main(["setup", "--rate", "0.50"]) == 0
    entry = json.loads(f.read_text())["mcpServers"][NAME]
    assert mcp_setup.rate_arg(entry) == "0.5"
    assert mcp_setup.main(["setup", "--yes"]) == 0                     # keeps it
    assert mcp_setup.rate_arg(json.loads(f.read_text())["mcpServers"][NAME]) == "0.5"
    assert mcp_setup.main(["setup", "--no-rate", "--yes"]) == 0        # back to the default
    assert mcp_setup.rate_arg(json.loads(f.read_text())["mcpServers"][NAME]) is None


def test_bad_rate_writes_nothing(monkeypatch, tmp_path, capsys):
    f = tmp_path / "config.json"
    write_json(f, {"mcpServers": {NAME: ACTIVE_ENTRY}})
    before = f.read_text()
    fake_setup(monkeypatch, [f], f)
    assert mcp_setup.main(["setup", "--rate", "0"]) == 1
    assert f.read_text() == before
