import os
import shutil
import tempfile

# Before any Monomi module loads: point every data folder (scans/, reports/,
# cache/, scans/active.log) at a throwaway folder. Monomi builds those paths
# once, when a module is imported, so this has to come first. It keeps tests
# (including tests that start Monomi in a subprocess, which inherit this) from
# ever writing into the real scans/ folder or the real active-request log.
TEST_HOME = tempfile.mkdtemp(prefix="monomi-tests-")
os.environ["MONOMI_HOME"] = TEST_HOME

import pytest  # noqa: E402

from monomi import activelog, dnscheck  # noqa: E402
from monomi.collectors import otx, pacing, saved  # noqa: E402


def pytest_sessionfinish(session, exitstatus):
    shutil.rmtree(TEST_HOME, ignore_errors=True)


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


@pytest.fixture(autouse=True)
def no_otx_network(monkeypatch):
    """No test reaches the real AlienVault OTX: scans in tests see it as failed.
    test_otx.py keeps a reference to the real fetch_raw for its own tests."""
    def off(domain, timeout=None):
        raise RuntimeError("AlienVault OTX is off in tests")
    monkeypatch.setattr(otx, "fetch_raw", off)


def pytest_addoption(parser):
    parser.addoption("--update-golden", action="store_true",
                     help="rewrite tests/golden/expected/ from the current code")
