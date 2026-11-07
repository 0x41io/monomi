import pytest

from collectors import pacing


@pytest.fixture(autouse=True)
def pacing_dir(tmp_path, monkeypatch):
    """Every test gets its own empty pacing folder, never the real scans/.pacing."""
    monkeypatch.setattr(pacing, "PACING_DIR", str(tmp_path / "pacing"))
    return tmp_path / "pacing"
