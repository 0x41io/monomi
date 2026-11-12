import json

import activelog
import scope


def lines(path):
    return [json.loads(x) for x in path.read_text().splitlines()]


def test_request_line_has_rule_hash_and_via(tmp_path):
    log = tmp_path / "scans" / "active.log"   # the folder is created
    s = scope.from_bytes(b"*.example.test\n")
    activelog.request(str(log), "mcp", "fingerprint_hosts", "www.example.test",
                      "https://www.example.test/", "*.example.test", s)
    [line] = lines(log)
    assert line["time"]
    assert {k: v for k, v in line.items() if k != "time"} == {
        "event": "request", "via": "mcp", "tool": "fingerprint_hosts",
        "host": "www.example.test", "url": "https://www.example.test/",
        "scope_rule": "*.example.test", "scope_sha256": s.sha256}


def test_refusal_line(tmp_path):
    log = tmp_path / "active.log"
    s = scope.from_bytes(b"*.example.test\n")
    activelog.refused(str(log), "cli", "--fingerprint", "no rule matches", "evil.test", s)
    activelog.refused(str(log), "mcp", "fingerprint_hosts", "active checks are off")
    first, second = lines(log)
    assert first["event"] == "refused" and first["host"] == "evil.test"
    assert first["scope_sha256"] == s.sha256 and first["via"] == "cli"
    assert second["host"] is None and second["scope_sha256"] is None


def test_unscoped_cli_requests_have_no_rule_or_hash(tmp_path):
    log = tmp_path / "active.log"
    activelog.request(str(log), "cli", "--fingerprint", "h", "https://h/", None, scope.UNSCOPED_CLI)
    [line] = lines(log)
    assert line["scope_rule"] is None and line["scope_sha256"] is None


def test_old_lines_without_an_event_count_as_requests():
    assert activelog.is_request({"time": "t", "tool": "fingerprint_hosts", "host": "app"})
    assert activelog.is_request({"event": "request"})
    assert not activelog.is_request({"event": "refused"})


def test_lines_are_appended_never_overwritten(tmp_path):
    log = tmp_path / "active.log"
    for i in range(3):
        activelog.refused(str(log), "mcp", "t", f"r{i}")
    assert [x["reason"] for x in lines(log)] == ["r0", "r1", "r2"]
