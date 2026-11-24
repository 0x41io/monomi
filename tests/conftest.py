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

from monomi import activelog, dnscheck, enrich  # noqa: E402
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
def no_wildcard_probes(monkeypatch):
    """The wildcard check asks DNS about made-up names: off in every test
    (no wildcards found) unless a test fakes its own answers.
    test_enrich.py keeps a reference to the real one for its own tests."""
    monkeypatch.setattr(enrich, "wildcard_answers", lambda zones: ({}, None))


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


@pytest.fixture(autouse=True)
def mcp_no_rate_limit(monkeypatch):
    """The MCP server's active tools don't wait for --rate slots in tests (the
    real default is 1/s), and start with no rate problem. Tests of the rate
    itself set mcp_server.LIMITER on their own."""
    from monomi import mcp_server, rate
    monkeypatch.setattr(mcp_server, "LIMITER", rate.Limiter(None))
    monkeypatch.setattr(mcp_server, "RATE_PROBLEM", None)


@pytest.fixture(autouse=True)
def probe_dns_is_public(monkeypatch):
    """--probe checks where every redirect's host resolves (v1.25). No test
    reaches real DNS: every name resolves to a public address unless a test
    sets probe.RESOLVE itself."""
    from monomi import probe
    monkeypatch.setattr(probe, "RESOLVE", lambda host: ["93.184.216.34"])
