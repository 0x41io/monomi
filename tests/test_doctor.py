"""Tests for doctor.py: every check's ok / warn / fail, with nothing real
called (no real API, no real package list)."""

import sys

import anthropic
import pytest

import doctor
import monomi
from doctor import FAIL, OK, WARN

KEY = "sk-ant-api03-" + "x" * 90  # a made-up key, never a real one


def statuses(results):
    return [r["status"] for r in results]


# ---------- helpers ----------

def test_version_tuple():
    assert doctor.version_tuple("2.34.2") == (2, 34, 2)
    assert doctor.version_tuple("1.0rc1") == (1, 0)
    assert doctor.version_tuple("3.10") > doctor.version_tuple("3.9")
    assert doctor.version_tuple("dev") == ()


def test_read_requirements(tmp_path):
    f = tmp_path / "requirements.txt"
    f.write_text("requests>=2.34.2\n# a comment\n\n"
                 "psycopg[binary]>=3.2\nrich\n", encoding="utf-8")
    assert doctor.read_requirements(f) == [
        ("requests", "2.34.2"), ("psycopg", "3.2"), ("rich", None)]


def test_plural():
    assert doctor.plural(1, "warning") == "1 warning"
    assert doctor.plural(0, "problem") == "0 problems"


# ---------- Setup ----------

def test_python_ok():
    assert statuses(doctor.check_python()) == [OK]


def test_python_too_old(monkeypatch):
    monkeypatch.setattr(doctor, "MIN_PYTHON", (99, 0))
    [r] = doctor.check_python()
    assert r["status"] == FAIL and "99.0" in r["fix"]


def fake_packages(monkeypatch, installed):
    reqs = [("requests", "2.34.2"), ("anthropic", "0.40"), ("psycopg", "3.2")]
    monkeypatch.setattr(doctor, "read_requirements", lambda: reqs)
    monkeypatch.setattr(doctor, "installed_version", installed.get)


def test_packages_all_good(monkeypatch):
    fake_packages(monkeypatch, {"requests": "2.34.2", "anthropic": "0.45.1",
                                "psycopg": "3.2.10"})
    [r] = doctor.check_packages()
    assert r["status"] == OK
    assert r["detail"] == "packages: requests, anthropic, psycopg"


def test_missing_or_old_package_fails(monkeypatch):
    fake_packages(monkeypatch, {"requests": "2.31.0", "anthropic": "0.45.1"})
    [r] = doctor.check_packages()
    assert r["status"] == FAIL
    assert "missing: psycopg" in r["detail"]
    assert "too old: requests 2.31.0 (needs 2.34.2)" in r["detail"]
    assert r["fix"] == doctor.PIP_FIX


def test_missing_anthropic_is_only_a_warning(monkeypatch):
    fake_packages(monkeypatch, {"requests": "2.34.2", "psycopg": "3.2"})
    results = doctor.check_packages()
    assert statuses(results) == [OK, WARN]
    assert "--ai is off" in results[1]["detail"]


def test_no_requirements_file(monkeypatch, tmp_path):
    monkeypatch.setattr(doctor, "REQUIREMENTS", str(tmp_path / "nope.txt"))
    assert statuses(doctor.check_packages()) == [WARN]


def test_folders_writable(monkeypatch, tmp_path):
    monkeypatch.setattr(doctor, "folders", lambda: {
        "scans/": str(tmp_path / "scans"), "cache/": str(tmp_path / "cache")})
    [r] = doctor.check_folders()
    assert r["status"] == OK and (tmp_path / "scans").is_dir()


def test_folder_that_cant_be_made_fails(monkeypatch, tmp_path):
    blocker = tmp_path / "a-file"
    blocker.write_text("not a folder")
    monkeypatch.setattr(doctor, "folders", lambda: {
        "scans/": str(blocker / "scans")})  # a folder inside a file can't exist
    [r] = doctor.check_folders()
    assert r["status"] == FAIL and "scans/" in r["detail"]


# ---------- Claude API ----------

def test_no_key_is_a_warning(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    [r] = doctor.check_api_key()
    assert r["status"] == WARN and "--ai is off" in r["detail"]


@pytest.mark.parametrize("bad", [f'"{KEY}"', f"{KEY} ", f"'{KEY}'"])
def test_key_with_quotes_or_spaces_fails(monkeypatch, bad):
    monkeypatch.setenv("ANTHROPIC_API_KEY", bad)
    [r] = doctor.check_api_key()
    assert r["status"] == FAIL


def test_key_is_never_shown(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", KEY)
    monkeypatch.setattr(doctor, "check_api_access", lambda: [])
    [r] = doctor.check_api_key()
    assert r["status"] == OK
    assert KEY not in r["detail"] and KEY[8:] not in r["detail"]
    assert f"{len(KEY)} chars" in r["detail"]


def test_key_with_wrong_start_is_a_warning(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-proj-abc123")
    monkeypatch.setattr(doctor, "check_api_access", lambda: [])
    assert statuses(doctor.check_api_key()) == [WARN]


class Model:
    def __init__(self, id):
        self.id = id


def fake_client(monkeypatch, models=None, error=None):
    """Replace anthropic.Anthropic with a fake that lists `models` or raises `error`."""
    class Models:
        def list(self, limit):
            if error:
                raise error
            return [Model(m) for m in models]

    class Client:
        def __init__(self, **kwargs):
            self.models = Models()

    monkeypatch.setattr(anthropic, "Anthropic", Client)


class FakeResponse:
    """Just enough of an HTTP response for anthropic's error classes
    (so the tests don't depend on which HTTP library anthropic uses)."""
    def __init__(self, code):
        self.status_code, self.headers, self.request = code, {}, None


def http_error(cls, code):
    return cls("nope", response=FakeResponse(code), body=None)


def test_key_accepted_shows_the_model(monkeypatch):
    monkeypatch.delenv("CLAUDE_MODEL", raising=False)
    fake_client(monkeypatch, ["claude-opus-x", "claude-sonnet-x"])
    [r] = doctor.check_api_access()
    assert r["status"] == OK and "claude-sonnet-x" in r["detail"]


def test_claude_model_not_in_the_list(monkeypatch):
    monkeypatch.setenv("CLAUDE_MODEL", "claude-typo")
    fake_client(monkeypatch, ["claude-sonnet-x"])
    [r] = doctor.check_api_access()
    assert r["status"] == WARN and "claude-typo" in r["detail"]


def test_claude_model_in_the_list(monkeypatch):
    monkeypatch.setenv("CLAUDE_MODEL", "claude-opus-x")
    fake_client(monkeypatch, ["claude-opus-x", "claude-sonnet-x"])
    [r] = doctor.check_api_access()
    assert r["status"] == OK and "(from $CLAUDE_MODEL)" in r["detail"]


@pytest.mark.parametrize("error, status", [
    (http_error(anthropic.AuthenticationError, 401), FAIL),
    (http_error(anthropic.PermissionDeniedError, 403), FAIL),
    (http_error(anthropic.InternalServerError, 500), WARN),
    (anthropic.APIConnectionError(request=None), WARN),
])
def test_api_errors(monkeypatch, error, status):
    fake_client(monkeypatch, error=error)
    [r] = doctor.check_api_access()
    assert r["status"] == status and r["fix"]


# ---------- running and showing ----------

def test_a_crashing_check_becomes_a_fail_line():
    def check_boom():
        raise ValueError("oops")

    results = doctor.run_all([doctor.check_python, check_boom])
    assert statuses(results) == [OK, FAIL]
    assert "boom check crashed: ValueError: oops" in results[1]["detail"]


def test_show_counts(capsys):
    doctor.show([doctor.result("Setup", "a", OK, "fine"),
                 doctor.result("Setup", "b", WARN, "meh", "do this")])
    out = capsys.readouterr().out
    assert "fix: do this" in out
    assert "1 ok · 1 warning · 0 problems: ready to scan" in out


def test_exit_code_is_1_when_anything_fails(monkeypatch, capsys):
    monkeypatch.setattr(doctor, "run_all",
                        lambda: [doctor.result("Setup", "a", FAIL, "broken")])
    assert doctor.main(["--no-color"]) == 1
    monkeypatch.setattr(doctor, "run_all",
                        lambda: [doctor.result("Setup", "a", WARN, "meh")])
    assert doctor.main(["--no-color"]) == 0


def test_monomi_doctor_runs_the_doctor(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["monomi.py", "doctor", "--no-color"])
    monkeypatch.setattr(doctor, "run_all", lambda: [])
    assert monomi.main() == 0
    assert "monomi doctor" in capsys.readouterr().out
