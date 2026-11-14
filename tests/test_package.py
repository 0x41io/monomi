"""Monomi is one package, `monomi`, plus two small wrappers at the repo root
(monomi.py and mcp_server.py) so old commands and MCP configs keep working.

Each test runs a fresh Python in a subprocess, so nothing this test file has
already imported can make a broken layout look fine."""

import os
import subprocess
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Every module that used to sit loose at the repo root. None of these names may
# show up as a top-level module after importing monomi: another tool (Akashi)
# may have its own scope.py or report.py, and Python would mix them up.
OLD_TOP_LEVEL = ["activelog", "analysis", "aws_ranges", "categorize", "cli", "collectors", "common",
                 "dnscheck", "doctor", "emailauth", "enrich", "evidence", "exposed", "fingerprint",
                 "gate", "headers", "history", "importers", "internetdb", "mcp_setup", "paths",
                 "report", "scope", "suggest", "takeover", "threatintel", "ui"]


def run(args, cwd):
    return subprocess.run([sys.executable, *args], capture_output=True, text=True, cwd=cwd, timeout=60)


def test_root_wrapper_runs_from_another_folder(tmp_path):
    # Like typing `python ~/0x41-recon/monomi.py --help` from your home folder
    out = run([os.path.join(REPO, "monomi.py"), "--help"], cwd=tmp_path)
    assert out.returncode == 0, out.stderr
    assert out.stdout.startswith("usage: monomi.py")


def test_mcp_wrapper_runs_from_another_folder(tmp_path):
    # The Claude app starts the server by this file's full path, from its own folder
    out = run([os.path.join(REPO, "mcp_server.py"), "--help"], cwd=tmp_path)
    assert out.returncode == 0, out.stderr
    assert "Monomi MCP server" in out.stdout


def test_package_wins_over_the_root_file():
    # From the repo root, `import monomi` must load the monomi/ folder, never the
    # monomi.py wrapper sitting next to it
    code = "import monomi, monomi.evidence; print(monomi.__file__); print(monomi.__version__)"
    out = run(["-c", code], cwd=REPO)
    assert out.returncode == 0, out.stderr
    path, version = out.stdout.split()
    assert path == os.path.join(REPO, "monomi", "__init__.py")
    from monomi.common import VERSION
    assert version == VERSION


def test_wrapper_and_package_work_in_the_same_python():
    # Grok's check: running the wrapper must not break importing the package
    # (or the other way round) inside one Python process
    code = ("import runpy, sys; sys.path.insert(0, '.'); sys.argv = ['monomi.py', '--help']\n"
            "try:\n    runpy.run_path('monomi.py', run_name='__main__')\n"
            "except SystemExit as e:\n    assert e.code == 0, e.code\n"
            "from monomi import evidence, takeover; print('ok')")
    out = run(["-c", code], cwd=REPO)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip().endswith("ok")


@pytest.mark.parametrize("entry", ["monomi", "monomi.cli", "monomi.mcp_server", "monomi.doctor"])
def test_no_loose_top_level_modules(entry, tmp_path):
    # Run from a folder that is NOT the repo, with the repo only on the import path,
    # the same way an installed package is found
    code = (f"import sys, {entry}\n"
            f"loose = sorted(n for n in {OLD_TOP_LEVEL!r} if n in sys.modules)\n"
            "print(','.join(loose))")
    env = {**os.environ, "PYTHONPATH": REPO}
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                         cwd=tmp_path, env=env, timeout=60)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "", f"loose top-level modules after importing {entry}: {out.stdout}"


def test_python_dash_m_runs_the_cli(tmp_path):
    # monomi/__main__.py: `python -m monomi example.com` works like monomi.py
    env = {**os.environ, "PYTHONPATH": REPO}
    out = subprocess.run([sys.executable, "-m", "monomi", "--help"], capture_output=True, text=True,
                         cwd=tmp_path, env=env, timeout=60)
    assert out.returncode == 0, out.stderr
    assert "passive domain recon" in out.stdout


def test_pyproject_reads_the_version_and_dependencies_from_their_one_home():
    # pyproject.toml must not grow its own copy of the version or dependency list
    import tomllib
    with open(os.path.join(REPO, "pyproject.toml"), "rb") as f:
        project = tomllib.load(f)
    assert "version" not in project["project"] and "dependencies" not in project["project"]
    assert project["tool"]["setuptools"]["dynamic"]["version"] == {"attr": "monomi.common.VERSION"}
    assert project["tool"]["setuptools"]["dynamic"]["dependencies"] == {"file": ["requirements.txt"]}
    assert project["project"]["scripts"] == {"monomi": "monomi.cli:main", "monomi-mcp": "monomi.mcp_server:main"}


def test_doctor_and_pyproject_agree_on_the_minimum_python():
    import tomllib
    from monomi import doctor
    with open(os.path.join(REPO, "pyproject.toml"), "rb") as f:
        wanted = tomllib.load(f)["project"]["requires-python"]
    assert wanted == ">=" + ".".join(map(str, doctor.MIN_PYTHON))
