"""
Golden-file tests: real scans, frozen.

Each file in tests/golden/fixtures/ is a saved Monomi scan (--json). The test
runs it through build_evidence() and build_paths() and compares the result
to the matching file in tests/golden/expected/. If a change moves a finding
or an attack path, this test fails and shows what moved.

To see exactly what moved, run pytest tests/test_golden.py -vv.
When the change is meant to happen, rewrite the expected files with
    pytest tests/test_golden.py --update-golden
and check the difference with git diff before committing.
"""
import json
from pathlib import Path

import pytest

from monomi import evidence
from monomi.paths import build_paths

GOLDEN = Path(__file__).parent / "golden"
FIXTURES = sorted((GOLDEN / "fixtures").glob("*.json"))
FROZEN_TIME = "2000-01-01T00:00:00Z"


def run(results):
    """What evidence + paths make from one scan."""
    ev = evidence.build_evidence(results)
    return {"evidence": ev, "paths": build_paths(results, ev)}


@pytest.mark.parametrize("fixture", FIXTURES, ids=[f.stem for f in FIXTURES])
def test_golden(fixture, request, monkeypatch):
    # build_evidence stamps "now" on some facts; freeze it so every run matches
    monkeypatch.setattr(evidence, "now_utc", lambda: FROZEN_TIME)
    got = run(json.loads(fixture.read_text(encoding="utf-8")))
    expected_file = GOLDEN / "expected" / fixture.name

    if request.config.getoption("--update-golden"):
        expected_file.write_text(json.dumps(got, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        pytest.skip(f"rewrote {expected_file.name}")

    assert expected_file.exists(), f"no expected file yet: run pytest {__file__} --update-golden"
    expected = json.loads(expected_file.read_text(encoding="utf-8"))
    assert got["paths"] == expected["paths"]
    assert got["evidence"] == expected["evidence"]


def test_there_are_fixtures():
    """An empty fixtures folder would make the golden tests pass by doing nothing."""
    assert FIXTURES
