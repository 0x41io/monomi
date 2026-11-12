import pytest

import activelog
import dnscheck
from collectors import pacing, saved


@pytest.fixture(autouse=True)
def pacing_dir(tmp_path, monkeypatch):
    """Every test gets its own empty pacing folder, never the real scans/.pacing."""
    monkeypatch.setattr(pacing, "PACING_DIR", str(tmp_path / "pacing"))
    return tmp_path / "pacing"


@pytest.fixture(autouse=True)
def saved_dir(tmp_path, monkeypatch):
    """Every test gets its own empty folder for saved source copies, never the real scans/."""
    monkeypatch.setattr(saved, "SCANS_DIR", str(tmp_path / "scans"))
    return tmp_path / "scans"


@pytest.fixture(autouse=True)
def active_log(tmp_path, monkeypatch):
    """CLI active checks log to a temp file in every test, never the real scans/active.log."""
    path = tmp_path / "active.log"
    monkeypatch.setattr(activelog, "PATH", str(path))
    return path


@pytest.fixture(autouse=True)
def no_retry_pause(monkeypatch):
    """The DoH retry doesn't wait in tests."""
    monkeypatch.setattr(dnscheck, "RETRY_PAUSE", 0)


def pytest_addoption(parser):
    parser.addoption("--update-golden", action="store_true",
                     help="rewrite tests/golden/expected/ from the current code")
