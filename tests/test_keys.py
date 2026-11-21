"""
The suite key file (monomi/keys.py, issue #27 part A): Monomi loads only
the keys it uses, only from a file nobody else can read, never printed; it
leaves the other 0x41 tools' keys alone; `mcp keys` writes it from the
terminal's keys without showing them. Every test uses a temp file and a
stand-in environment (a dict), so no real key or env var is touched.
"""

import os
import stat
import sys

import pytest

from monomi import cli, doctor, keys, mcp_server

OTX, NVD = "otx-secret-1234", "nvd-secret-5678"


@pytest.fixture
def keyfile(tmp_path):
    def make(text, mode=0o600):
        path = tmp_path / "keys.env"
        path.write_text(text)
        os.chmod(path, mode)
        return str(path)
    return make


def test_path_is_the_shared_suite_file():
    assert keys.keys_path().endswith(os.path.join(".config", "0x41", "keys.env"))


def test_load_puts_otx_in_the_environment_names_only(keyfile):
    env = {}
    notes = keys.load(keyfile(f"# mine\nexport OTX_API_KEY=\"{OTX}\"\n"), env)
    assert env == {"OTX_API_KEY": OTX}
    assert "keys loaded" in notes[0] and "OTX_API_KEY" in notes[0]
    assert OTX not in "".join(notes)


def test_other_suite_keys_stay_in_the_file_but_are_not_loaded(keyfile):
    # NVD_API_KEY is kaidoku's (0x41 mcp loads it): Monomi neither loads it nor complains
    env = {}
    notes = keys.load(keyfile(f"OTX_API_KEY={OTX}\nNVD_API_KEY={NVD}\n"), env)
    assert env == {"OTX_API_KEY": OTX}
    assert not any("NVD" in n for n in notes)


def test_unknown_names_are_ignored_with_a_note(keyfile):
    env = {}
    notes = keys.load(keyfile(f"ANTHROPIC_API_KEY=sk-ant-secret\nOTX_API_KEY={OTX}\n"), env)
    assert env == {"OTX_API_KEY": OTX}
    assert any("ANTHROPIC_API_KEY ignored" in n for n in notes)
    assert "sk-ant-secret" not in "".join(notes)


@pytest.mark.skipif(os.name != "posix", reason="Unix permissions")
@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o660])
def test_a_file_others_can_read_is_refused(keyfile, mode):
    env = {}
    path = keyfile(f"OTX_API_KEY={OTX}\n", mode)
    notes = keys.load(path, env)
    assert env == {}
    assert "refused" in notes[0] and f"chmod 600 {path}" in notes[0]


@pytest.mark.skipif(os.name != "posix", reason="symlinks")
def test_a_link_is_refused(tmp_path, keyfile):
    real = keyfile(f"OTX_API_KEY={OTX}\n")
    link = tmp_path / "link.env"
    link.symlink_to(real)
    env = {}
    assert "is a link" in keys.load(str(link), env)[0] and env == {}


def test_a_key_already_set_wins(keyfile):
    env = {"OTX_API_KEY": "from-the-shell"}
    notes = keys.load(keyfile(f"OTX_API_KEY={OTX}\n"), env)
    assert env == {"OTX_API_KEY": "from-the-shell"}
    assert any("kept: OTX_API_KEY" in n for n in notes)


def test_no_file_is_fine_and_says_how_to_make_one(tmp_path):
    env = {}
    notes = keys.load(str(tmp_path / "missing.env"), env)
    assert env == {} and "no key file" in notes[0] and "mcp keys" in notes[0]


def test_bad_lines_are_noted_by_line_number_not_content(keyfile):
    env = {}
    notes = keys.load(keyfile("just-a-secret-string\nOTX_API_KEY=\n"), env)
    assert env == {}
    assert any("line 1 isn't NAME=value" in n for n in notes)
    assert any("OTX_API_KEY is empty" in n for n in notes)
    assert "just-a-secret-string" not in "".join(notes)


# --- monomi.py mcp keys -----------------------------------------------------------

def test_write_from_env_writes_a_private_file_without_showing_values(tmp_path):
    path = tmp_path / "cfg" / "0x41" / "keys.env"
    shown = []
    code = keys.write_from_env(str(path), {"OTX_API_KEY": OTX, "ANTHROPIC_API_KEY": "sk"},
                               ask=lambda q: "y", out=shown.append)
    assert code == 0
    text = path.read_text()
    assert f"OTX_API_KEY={OTX}" in text and "ANTHROPIC" not in text
    assert OTX not in "".join(shown)
    if os.name == "posix":
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
        assert stat.S_IMODE(os.stat(path.parent).st_mode) == 0o700
    env = {}
    keys.load(str(path), env)  # and the server can read what it wrote
    assert env == {"OTX_API_KEY": OTX}


def test_write_keeps_the_other_tools_keys(keyfile):
    # 0x41 wrote NVD_API_KEY; Monomi rewriting the file must not drop it
    path = keyfile(f"NVD_API_KEY={NVD}\n")
    keys.write_from_env(path, {"OTX_API_KEY": OTX}, ask=lambda q: "y", out=lambda s: None)
    found, _ = keys.read(path)
    assert found == {"NVD_API_KEY": NVD, "OTX_API_KEY": OTX}


@pytest.mark.skipif(os.name != "posix", reason="Unix permissions")
def test_write_fixes_loose_permissions(keyfile):
    path = keyfile(f"NVD_API_KEY={NVD}\n", 0o644)
    keys.write_from_env(path, {"OTX_API_KEY": OTX}, ask=lambda q: "y", out=lambda s: None)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_write_asks_first(tmp_path):
    path = tmp_path / "keys.env"
    assert keys.write_from_env(str(path), {"OTX_API_KEY": OTX}, ask=lambda q: "n", out=lambda s: None) == 0
    assert not path.exists()


def test_write_with_nothing_set(tmp_path):
    shown = []
    assert keys.write_from_env(str(tmp_path / "k.env"), {}, ask=lambda q: "y", out=shown.append) == 1
    assert "nothing to write" in shown[0]


def test_cli_mcp_keys_runs_the_writer(monkeypatch):
    monkeypatch.setattr(keys, "write_from_env", lambda: 7)
    monkeypatch.setattr(sys, "argv", ["monomi.py", "mcp", "keys"])
    assert cli.main() == 7


# --- the server -------------------------------------------------------------------

def test_the_server_loads_keys_at_start_and_prints_only_names(keyfile, monkeypatch, capsys):
    path = keyfile(f"OTX_API_KEY={OTX}\n")
    monkeypatch.setattr(keys, "keys_path", lambda: path)
    monkeypatch.delenv("OTX_API_KEY", raising=False)
    monkeypatch.setattr(mcp_server.mcp, "run", lambda: None)
    try:
        mcp_server.main([])
        assert os.environ.get("OTX_API_KEY") == OTX  # every tool call sees it
    finally:
        os.environ.pop("OTX_API_KEY", None)
    got = capsys.readouterr()
    assert got.out == ""  # stdout is the MCP channel
    assert "keys loaded" in got.err and "OTX_API_KEY" in got.err and OTX not in got.err


# --- doctor -----------------------------------------------------------------------

def test_doctor_no_file_and_no_key_is_ok(tmp_path):
    r = doctor.key_file_result(str(tmp_path / "none.env"), {})
    assert r["status"] == doctor.OK


def test_doctor_key_only_in_terminal_warns(tmp_path):
    r = doctor.key_file_result(str(tmp_path / "none.env"), {"OTX_API_KEY": OTX})
    assert r["status"] == doctor.WARN and "mcp keys" in r["fix"]
    assert OTX not in r["detail"]


@pytest.mark.skipif(os.name != "posix", reason="Unix permissions")
def test_doctor_refused_file_fails(keyfile):
    r = doctor.key_file_result(keyfile(f"OTX_API_KEY={OTX}\n", 0o644), {})
    assert r["status"] == doctor.FAIL and "refused" in r["detail"]


def test_doctor_good_file_is_ok_names_only(keyfile):
    r = doctor.key_file_result(keyfile(f"OTX_API_KEY={OTX}\nNVD_API_KEY={NVD}\n"), {"OTX_API_KEY": OTX})
    assert r["status"] == doctor.OK and "OTX_API_KEY" in r["detail"]
    assert OTX not in r["detail"] and NVD not in r["detail"]


def test_doctor_runs_the_key_file_check_like_every_other(keyfile, monkeypatch, capsys):
    # The 1.20 lab check crashed doctor: the check returned one result, not a
    # list. Go through run_all() and show(), the way `monomi.py doctor` does.
    path = keyfile(f"OTX_API_KEY={OTX}\n")
    monkeypatch.setattr(keys, "keys_path", lambda: path)
    results = doctor.run_all([doctor.check_key_file])
    assert [r["name"] for r in results] == ["key file"]
    doctor.show(results)
    out = capsys.readouterr().out
    assert "OTX_API_KEY (private)" in out and OTX not in out
