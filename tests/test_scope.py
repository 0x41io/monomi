import hashlib

import pytest

from monomi import scope
from monomi.scope import UNSCOPED_CLI

# Test names use the reserved .test suffix, and shared suffixes are built
# from pieces, so no real domain appears (the chat app turns those into links).
D = "example.test"
UK = "co" + ".uk"
VERCEL = "vercel" + ".app"


def make(text: str) -> scope.Scope:
    return scope.from_bytes(text.encode(), "scope.txt")


def allowed(s: scope.Scope, host: str) -> bool:
    return s.match(host).allowed


# --- Matching -------------------------------------------------------------

def test_exact_rule_matches_only_that_host():
    s = make(D)
    assert allowed(s, D)
    assert not allowed(s, "www." + D)
    assert not allowed(s, "other.test")


def test_wildcard_matches_subdomains_but_not_the_apex():
    s = make("*." + D)
    assert allowed(s, "www." + D)
    assert allowed(s, "a.b." + D)      # any depth
    assert not allowed(s, D)           # the apex must be listed separately
    assert s.match(D).reason == "no rule matches"


def test_wildcard_does_not_match_a_lookalike_suffix():
    s = make("*." + D)
    assert not allowed(s, "evil" + D)          # "evilexample.test" isn't under it
    assert not allowed(s, D + ".attacker.test")


def test_exclusion_wins_over_wildcard():
    s = make(f"*.{D}\n!blog.{D}\n")
    m = s.match("blog." + D)
    assert not m.allowed
    assert m.reason == f"excluded by !blog.{D}"
    assert allowed(s, "www." + D)


def test_exclusion_wins_whatever_the_order():
    s = make(f"!blog.{D}\n*.{D}\nblog.{D}\n")   # even an exact inclusion loses
    assert not allowed(s, "blog." + D)


def test_exact_exclusion_does_not_exclude_its_subdomains():
    s = make(f"*.{D}\n!dev.{D}\n")
    assert not allowed(s, "dev." + D)
    assert allowed(s, "api.dev." + D)


def test_wildcard_exclusion():
    s = make(f"*.{D}\n!*.dev.{D}\n")
    assert not allowed(s, "api.dev." + D)
    assert allowed(s, "dev." + D)              # the wildcard doesn't cover dev itself


def test_match_reports_the_rule_that_allowed_it():
    s = make(f"{D}\n*.{D}\n")
    assert s.match(D).rule == D
    assert s.match("www." + D).rule == "*." + D
    assert s.match("www." + D).reason == f"allowed by *.{D}"
    assert s.match("other.test").rule is None


def test_matching_is_case_insensitive_and_drops_one_trailing_dot():
    s = make("*.Example.TEST")
    assert allowed(s, "WWW.example.test")
    assert allowed(s, "www.example.test.")
    assert s.match("WWW.example.test.").host == "www.example.test"


def test_two_trailing_dots_are_never_in_scope():
    s = make("*." + D)
    assert not allowed(s, "www." + D + "..")
    assert s.match("www." + D + "..").reason == "not a valid hostname"


@pytest.mark.parametrize("host", ["", "   ", "*." + D, "https://www." + D,
                                  "www." + D + "/x", "wwẃ." + D, None, 123])
def test_things_that_arent_hostnames_are_never_in_scope(host):
    s = make("*." + D)
    assert not allowed(s, host)


def test_empty_file_puts_nothing_in_scope():
    s = make("")
    assert s.problem() == "the scope file has no valid rules"
    assert not allowed(s, D)
    assert s.match(D).reason.startswith("no usable scope")


def test_only_exclusions_puts_nothing_in_scope():
    s = make(f"!blog.{D}\n")
    assert s.problem() == "the scope file has only exclusions, so nothing is in scope"
    assert not allowed(s, "www." + D)


# --- Parsing --------------------------------------------------------------

def test_comments_and_blank_lines_are_ignored():
    s = make(f"# In scope\n\n{D}   # main site\n   \n*.{D}\n")
    assert [r.text for r in s.rules] == [D, "*." + D]
    assert s.rejected == []


def test_port_and_one_trailing_dot_are_dropped_from_rules():
    s = make(f"{D}:443\n*.{D}.\n")
    assert [r.text for r in s.rules] == [D, "*." + D]


def test_two_trailing_dots_are_rejected():
    s = make(D + "..")
    assert s.rules == []
    assert s.rejected[0]["line"] == 1


@pytest.mark.parametrize("line,reason_start", [
    ("*", "a bare '*'"),
    ("!*", "a bare '*'"),
    ("*.*." + D, "'*' is only allowed"),
    ("www*." + D, "'*' is only allowed"),
    ("com", "'com' is a single label"),
    ("*.com", "'com' is a single label"),
    ("localhost", "'localhost' is a single label"),
    (UK, f"'{UK}' is shared"),
    ("*." + UK, f"'{UK}' is shared"),
    ("*." + VERCEL, f"'{VERCEL}' is shared"),
    ("wwẃ." + D, "contains non-ASCII"),
    ("https://" + D, "looks like a URL"),
    (D + "/login", "looks like a URL"),
    ("10.0.0.1", "IP addresses"),
    ("10.0.0.0/8", "IP addresses"),
    ("2001:db8::1", "IP addresses"),
    ("!", "a lone '!'"),
    ("!!" + D, "more than one '!'"),
    ("exa mple.test", "not a valid hostname"),
    ("-bad." + D, "not a valid hostname"),
])
def test_bad_lines_are_rejected_with_a_reason(line, reason_start):
    s = make(f"{D}\n{line}\n")
    assert len(s.rules) == 1                  # the good line still counts
    assert s.rejected[0]["line"] == 2
    assert s.rejected[0]["reason"].startswith(reason_start)


def test_a_domain_under_a_shared_suffix_is_accepted():
    s = make(f"example.{UK}\n*.example.{UK}\nmyapp.{VERCEL}\n")
    assert s.rejected == []
    assert allowed(s, "www.example." + UK)
    assert allowed(s, "myapp." + VERCEL)
    assert not allowed(s, "someone-else." + VERCEL)


def test_rejected_lines_never_count_as_rules():
    s = make(f"*\n*.{UK}\n")
    assert s.problem() == "the scope file has no valid rules"
    assert not allowed(s, "www.example." + UK)


def test_windows_bom_and_crlf_are_handled():
    s = scope.from_bytes(("﻿" + f"{D}\r\n*.{D}\r\n").encode("utf-8"))
    assert [r.text for r in s.rules] == [D, "*." + D]


# --- Hashing and loading --------------------------------------------------

def test_hash_is_sha256_of_the_exact_bytes():
    data = f"{D}\n".encode()
    assert scope.from_bytes(data).sha256 == hashlib.sha256(data).hexdigest()


def test_any_byte_change_changes_the_hash():
    a = scope.from_bytes(f"{D}\n".encode())
    b = scope.from_bytes(f"{D} \n".encode())   # same rules, one extra space
    assert [r.text for r in a.rules] == [r.text for r in b.rules]
    assert a.sha256 != b.sha256


def test_load_reads_the_file(tmp_path):
    p = tmp_path / "scope.txt"
    p.write_bytes(f"*.{D}\n".encode())
    s = scope.load(str(p))
    assert s.problem() is None
    assert s.path == str(p)
    assert s.sha256 == hashlib.sha256(p.read_bytes()).hexdigest()


def test_missing_file_is_a_problem_not_a_crash(tmp_path):
    s = scope.load(str(tmp_path / "nope.txt"))
    assert s.problem().startswith("the scope file is missing")
    assert not allowed(s, D)


def test_unreadable_file_is_a_problem_not_a_crash(tmp_path):
    s = scope.load(str(tmp_path))            # a folder can't be read as a file
    assert s.problem().startswith("the scope file can't be read")


def test_non_utf8_file_is_a_problem():
    s = scope.from_bytes(b"\xff\xfe\x00bad")
    assert s.problem() == "the scope file isn't UTF-8 text"
    assert not allowed(s, D)


def test_unscoped_marker_is_its_own_thing():
    assert repr(UNSCOPED_CLI) == "UNSCOPED_CLI"
    assert not isinstance(UNSCOPED_CLI, scope.Scope)


# --- check_pinned: the approved file must still be exactly what was approved

def write_scope(tmp_path, text):
    p = tmp_path / "scope.txt"
    p.write_bytes(text.encode())
    return str(p), hashlib.sha256(text.encode()).hexdigest()


def test_pinned_scope_that_matches_is_usable(tmp_path):
    path, digest = write_scope(tmp_path, f"*.{D}\n")
    s, problem = scope.check_pinned(path, digest)
    assert problem is None and allowed(s, "www." + D)


def test_pinned_hash_is_compared_case_insensitively(tmp_path):
    path, digest = write_scope(tmp_path, f"*.{D}\n")
    assert scope.check_pinned(path, digest.upper())[1] is None


def test_no_scope_file_is_refused():
    s, problem = scope.check_pinned(None, None)
    assert s is None and problem == scope.NO_SCOPE
    assert "mcp setup --scope" in problem


def test_scope_without_an_approved_hash_is_refused(tmp_path):
    path, _ = write_scope(tmp_path, f"*.{D}\n")
    s, problem = scope.check_pinned(path, None)
    assert s is None and "no approved hash" in problem


def test_scope_edited_after_approval_is_refused(tmp_path):
    path, digest = write_scope(tmp_path, f"*.{D}\n")
    (tmp_path / "scope.txt").write_bytes(f"*.{D}\n*.other.test\n".encode())  # widened
    s, problem = scope.check_pinned(path, digest)
    assert "changed since it was approved" in problem
    assert path in problem                       # the fix names the file


def test_pinned_file_that_vanished_is_refused(tmp_path):
    path, digest = write_scope(tmp_path, f"*.{D}\n")
    (tmp_path / "scope.txt").unlink()
    assert scope.check_pinned(path, digest)[1].startswith("the scope file is missing")


def test_pinned_file_with_no_valid_rules_is_refused_even_if_hash_matches(tmp_path):
    path, digest = write_scope(tmp_path, "*\n")
    assert scope.check_pinned(path, digest)[1] == "the scope file has no valid rules"


# --- check_url: the last check before every active request -------------------

LAB = make(f"{D}\n*.{D}\n!dev.{D}\n")


def test_check_url_returns_the_rule_that_allowed_it():
    assert scope.check_url(LAB, f"https://www.{D}/") == "*." + D
    assert scope.check_url(LAB, f"https://{D}/openapi.json") == D


def test_check_url_reads_the_host_from_the_url_itself():
    # ports, case and paths don't change which host is checked
    assert scope.check_url(LAB, f"http://WWW.{D}:8080/x?y=1") == "*." + D
    with pytest.raises(scope.OutOfScope, match="no rule matches"):
        scope.check_url(LAB, f"https://evil.test/{D}")          # the path doesn't count
    with pytest.raises(scope.OutOfScope):
        scope.check_url(LAB, f"https://www.{D}.evil.test/")     # a lookalike suffix


def test_check_url_refuses_exclusions():
    with pytest.raises(scope.OutOfScope, match=f"excluded by !dev.{D}"):
        scope.check_url(LAB, f"https://dev.{D}/")


@pytest.mark.parametrize("url", ["", "not a url", "https:///x", "https://[::1/"])
def test_check_url_refuses_urls_without_a_usable_host(url):
    with pytest.raises(scope.OutOfScope):
        scope.check_url(LAB, url)


def test_out_of_scope_is_a_requests_error():
    # so every existing "host didn't answer" handler catches it: no crash, no request
    import requests
    assert issubclass(scope.OutOfScope, requests.RequestException)


def test_unscoped_cli_allows_without_a_rule():
    assert scope.check_url(UNSCOPED_CLI, "https://anything.test/") is None


@pytest.mark.parametrize("bad", [None, "", "*.example.test", object()])
def test_anything_but_a_scope_or_the_marker_is_an_error_never_a_pass(bad):
    with pytest.raises(TypeError):
        scope.check_url(bad, f"https://www.{D}/")
    with pytest.raises(TypeError):
        scope.split(bad, ["www." + D])


def test_split_sorts_hosts_with_reasons():
    inside, outside = scope.split(LAB, ["www." + D, "dev." + D, "evil.test", D])
    assert inside == ["www." + D, D]
    assert outside == [{"host": "dev." + D, "reason": f"excluded by !dev.{D}"},
                       {"host": "evil.test", "reason": "no rule matches"}]


def test_split_unscoped_keeps_everything():
    assert scope.split(UNSCOPED_CLI, ["a.test", "b.test"]) == (["a.test", "b.test"], [])
