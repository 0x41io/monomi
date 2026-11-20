import hashlib

import pytest

from monomi import research
from monomi.common import ACTIVE_USER_AGENT
from monomi.research import ResearchError


def write(tmp_path, text):
    p = tmp_path / "research.txt"
    p.write_bytes(text.encode())
    return str(p)


def test_reads_headers_and_hashes_the_exact_file(tmp_path):
    text = "# my handle\nX-Intigriti: x41ok\n\nX-Bug-Bounty:  x41ok \n"
    r = research.load(write(tmp_path, text))
    assert r.headers == {"X-Intigriti": "x41ok", "X-Bug-Bounty": "x41ok"}
    assert r.sha256 == hashlib.sha256(text.encode()).hexdigest()
    assert r.summary == "X-Intigriti: x41ok, X-Bug-Bounty: x41ok"


def test_a_line_that_isnt_a_header_is_refused(tmp_path):
    with pytest.raises(ResearchError, match="line 2"):
        research.load(write(tmp_path, "X-Intigriti: x41ok\nnot a header\n"))


def test_an_empty_file_is_refused(tmp_path):
    with pytest.raises(ResearchError, match="no headers"):
        research.load(write(tmp_path, "# only a comment\n\n"))


def test_a_missing_file_is_refused(tmp_path):
    with pytest.raises(ResearchError, match="can't read"):
        research.load(str(tmp_path / "nope.txt"))


@pytest.mark.parametrize("name", ["Host", "content-length", "Transfer-Encoding", "Connection"])
def test_headers_that_change_where_a_request_goes_are_refused(tmp_path, name):
    with pytest.raises(ResearchError, match="can't be set"):
        research.load(write(tmp_path, f"{name}: x\n"))


def test_request_headers_without_a_file_is_just_the_user_agent():
    assert research.request_headers(None) == {"User-Agent": ACTIVE_USER_AGENT}


def test_request_headers_adds_the_file_and_lets_it_set_the_user_agent(tmp_path):
    r = research.load(write(tmp_path, "X-Intigriti: x41ok\nUser-Agent: Intigriti-x41ok\n"))
    assert research.request_headers(r) == {"User-Agent": "Intigriti-x41ok", "X-Intigriti": "x41ok"}


def test_sha_of():
    assert research.sha_of(None) is None
    assert research.sha_of(research.Research({"A": "b"}, "abc", "f")) == "abc"
