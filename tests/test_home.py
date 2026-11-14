"""Where Monomi keeps its data (monomi/home.py).

data_home(): MONOMI_HOME if set, else the repo folder when running from one,
else ~/.monomi. The tests that matter most run a fresh Python in a subprocess:
every module builds its folder constants once, at import, so only a fresh
Python shows what a real run would use."""

import json
import os
import shutil
import subprocess
import sys

from monomi import doctor, home, mcp_setup

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Prints every data path and code path Monomi would use, as JSON
SHOW_PATHS = """
import json
from monomi import activelog, aws_ranges, cli, doctor, history, home, mcp_server, mcp_setup, report
from monomi.collectors import pacing, saved
print(json.dumps({
    "where": home.where_data_lives(),
    "scans": [history.SCANS_DIR, saved.SCANS_DIR, mcp_server.SCANS_DIR],
    "mcp_results": mcp_server.RESULTS_DIR,
    "pacing": pacing.PACING_DIR,
    "active_log": [activelog.PATH, mcp_setup.ACTIVE_LOG, mcp_server.ACTIVE_LOG],
    "reports": [report.REPORTS_DIR, cli.REPORTS_DIR, doctor.folders()["reports/"]],
    "cache": aws_ranges.CACHE_DIR,
    "server_args": mcp_setup.server_args(),
    "packages": [name for name, _ in doctor.read_requirements()],
}))
"""


def paths_seen(pythonpath, cwd, home_dir, monomi_home=None):
    env = {k: v for k, v in os.environ.items() if k != home.ENV_VAR}
    env.update(PYTHONPATH=pythonpath, HOME=str(home_dir), USERPROFILE=str(home_dir))
    if monomi_home:
        env[home.ENV_VAR] = str(monomi_home)
    out = subprocess.run([sys.executable, "-c", SHOW_PATHS], capture_output=True, text=True,
                         cwd=cwd, env=env, timeout=60)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


def assert_all_under(seen, data):
    data = str(data)
    assert seen["scans"] == [os.path.join(data, "scans")] * 3
    assert seen["mcp_results"] == os.path.join(data, "scans", "mcp")
    assert seen["pacing"] == os.path.join(data, "scans", ".pacing")
    assert seen["active_log"] == [os.path.join(data, "scans", "active.log")] * 3
    assert seen["reports"] == [os.path.join(data, "reports")] * 3
    assert seen["cache"] == os.path.join(data, "cache")


# ---------- running from the repo (python monomi.py, pip install -e .) ----------

def test_repo_copy_keeps_data_where_it_always_was(tmp_path):
    seen = paths_seen(REPO, tmp_path, tmp_path / "home")
    assert seen["where"] == [REPO, "running from the Monomi repo folder"]
    assert_all_under(seen, REPO)
    # The Claude config keeps pointing at the root wrapper, so old configs still match
    assert seen["server_args"] == [os.path.join(REPO, "mcp_server.py")]


def test_this_repo_counts_as_a_repo_copy():
    assert home.running_from_repo()


# ---------- a plain pip install (no repo folder) ----------

def installed_copy(tmp_path):
    """The monomi/ package alone in a folder, the way a plain `pip install`
    puts it in site-packages: no pyproject.toml, no wrappers, no tests."""
    site = tmp_path / "site-packages"
    shutil.copytree(os.path.join(REPO, "monomi"), site / "monomi",
                    ignore=shutil.ignore_patterns("__pycache__"))
    # pip also writes a .dist-info folder; its METADATA lists the dependencies
    # (built from requirements.txt), which doctor reads when there's no repo
    info = site / "monomi-0.0.0.dist-info"
    info.mkdir()
    with open(os.path.join(REPO, "requirements.txt"), encoding="utf-8") as f:
        needs = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    info.joinpath("METADATA").write_text(
        "Metadata-Version: 2.1\nName: monomi\nVersion: 0.0.0\n"
        + "".join(f"Requires-Dist: {n}\n" for n in needs), encoding="utf-8")
    return site


def test_installed_package_writes_to_home_dot_monomi(tmp_path):
    site = installed_copy(tmp_path)
    seen = paths_seen(str(site), tmp_path, tmp_path / "home")
    data = tmp_path / "home" / ".monomi"
    assert seen["where"] == [str(data), "installed package, no repo folder"]
    assert_all_under(seen, data)
    assert not any(str(site) in str(v) for v in seen.values())  # nothing inside site-packages
    # No wrapper file to point at, so the Claude config runs the installed module
    assert seen["server_args"] == ["-m", "monomi.mcp_server"]


def test_leftover_git_folder_doesnt_make_it_a_repo_copy(tmp_path):
    # Grok's case: a .git (or other project files) next to the installed package
    site = installed_copy(tmp_path)
    (site / ".git").mkdir()
    (site / "requirements.txt").write_text("requests\n")
    seen = paths_seen(str(site), tmp_path, tmp_path / "home")
    assert seen["where"][1] == "installed package, no repo folder"


def test_monomi_home_wins_over_everything(tmp_path):
    for pythonpath in (REPO, str(installed_copy(tmp_path))):
        seen = paths_seen(pythonpath, tmp_path, tmp_path / "home", monomi_home=tmp_path / "data")
        assert seen["where"] == [str(tmp_path / "data"), "MONOMI_HOME is set"]
        assert_all_under(seen, tmp_path / "data")


def test_monomi_home_understands_tilde(tmp_path, monkeypatch):
    monkeypatch.setenv(home.ENV_VAR, "~/monomi-data")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    assert home.data_home() == str(tmp_path / "monomi-data")


def test_blank_monomi_home_is_ignored(monkeypatch):
    monkeypatch.setenv(home.ENV_VAR, "   ")
    assert home.where_data_lives() == (REPO, "running from the Monomi repo folder")


def test_only_monomis_own_pyproject_counts(tmp_path):
    assert not home.running_from_repo(str(tmp_path))  # nothing there
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "something-else"\n')
    assert not home.running_from_repo(str(tmp_path))
    (tmp_path / "pyproject.toml").write_text("this isn't [valid toml")
    assert not home.running_from_repo(str(tmp_path))
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "monomi"\n')
    assert home.running_from_repo(str(tmp_path))


def test_installed_doctor_reads_packages_from_the_package_metadata(tmp_path):
    # No requirements.txt in a plain install: the same list comes from the metadata
    seen = paths_seen(str(installed_copy(tmp_path)), tmp_path, tmp_path / "home")
    wanted = [name for name, _ in doctor.read_requirements(os.path.join(REPO, "requirements.txt"))]
    assert seen["packages"] == wanted and "requests" in wanted


def test_requirement_lines_uses_metadata_outside_the_repo(monkeypatch):
    monkeypatch.setattr(home, "running_from_repo", lambda folder=None: False)
    monkeypatch.setattr(doctor.importlib.metadata, "requires", lambda name: ["requests>=2.34.2", "psycopg[binary]>=3.2"])
    assert doctor.read_requirements() == [("requests", "2.34.2"), ("psycopg", "3.2")]


def test_doctor_says_where_data_lives(monkeypatch, tmp_path):
    monkeypatch.setattr(doctor, "folders", lambda: {"scans/": str(tmp_path / "scans")})
    monkeypatch.setattr(home, "where_data_lives", lambda: ("/somewhere", "MONOMI_HOME is set"))
    [r] = doctor.check_folders()
    assert r["detail"].endswith("writable in /somewhere (MONOMI_HOME is set)")


def test_server_args_follow_where_monomi_runs(monkeypatch):
    assert mcp_setup.server_args() == [mcp_setup.SERVER]
    monkeypatch.setattr(home, "running_from_repo", lambda folder=None: False)
    assert mcp_setup.server_args() == ["-m", "monomi.mcp_server"]
    assert mcp_setup.direct_entry() == {"command": sys.executable, "args": ["-m", "monomi.mcp_server"]}


# ---------- the hosts_file fence moves with the data folder ----------

FENCE = """
import json, sys
from monomi import mcp_server
results = {}
for name, path in [("inside", sys.argv[1]), ("outside", sys.argv[2])]:
    try:
        results[name] = mcp_server.load_hosts_file(path)
    except mcp_server.ToolError as e:
        results[name] = "refused: " + str(e)
print(json.dumps(results))
"""


def test_hosts_file_fence_follows_monomi_home(tmp_path):
    data = tmp_path / "data"
    (data / "scans").mkdir(parents=True)
    inside = data / "scans" / "hosts.txt"
    inside.write_text("a.lab.test\n")
    outside = tmp_path / "elsewhere" / "hosts.txt"  # readable by this process, but not Monomi's
    outside.parent.mkdir()
    outside.write_text("b.lab.test\n")
    env = {**os.environ, "PYTHONPATH": REPO, home.ENV_VAR: str(data)}
    out = subprocess.run([sys.executable, "-c", FENCE, str(inside), str(outside)],
                         capture_output=True, text=True, cwd=tmp_path, env=env, timeout=60)
    assert out.returncode == 0, out.stderr
    result = json.loads(out.stdout)
    assert result["inside"] == ["a.lab.test\n"]
    assert result["outside"].startswith("refused: hosts_file must be inside Monomi's scans folder")
    assert str(data / "scans") in result["outside"]


# ---------- tests never touch the real data folder ----------

def test_tests_run_with_a_throwaway_data_folder():
    # tests/conftest.py sets MONOMI_HOME before Monomi loads, so a test can't
    # write into the real scans/ folder or the real scans/active.log
    test_home = os.environ[home.ENV_VAR]  # set by conftest.py (never import conftest: it would run again)
    assert os.path.basename(test_home).startswith("monomi-tests-")
    from monomi import activelog, cli, history, mcp_server, mcp_setup, report
    from monomi.collectors import saved
    assert home.data_home() == test_home != REPO
    for path in (history.SCANS_DIR, mcp_server.SCANS_DIR, mcp_server.ACTIVE_LOG, mcp_setup.ACTIVE_LOG,
                 report.REPORTS_DIR, cli.REPORTS_DIR):
        assert path.startswith(test_home), path
    # The per-test fixtures go further still: each test gets its own folder
    assert not activelog.PATH.startswith(REPO) and not saved.SCANS_DIR.startswith(REPO)
