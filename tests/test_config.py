from __future__ import annotations

from pathlib import Path

import pytest

from mcpfw.config import ConfigError, load_config, parse_config
from mcpfw.labels import UNKNOWN_TOOL, ToolLabels

ROOT = Path(__file__).resolve().parent.parent
BASE = Path("/cfg")


def minimal(**overrides):
    data = {"upstreams": {"workspace": {"command": "python", "args": ["server.py"]}}}
    data.update(overrides)
    return data


def parse(data):
    return parse_config(data, base_dir=BASE, source="firewall.yaml")


# --- valid configs -------------------------------------------------------------------------------


def test_example_config_loads():
    config = load_config(ROOT / "firewall.example.yaml")
    assert config.mode == "enforce" and config.approver == "elicit" and config.spotlight
    assert set(config.upstreams) == {"workspace", "weather"}

    ws = config.upstreams["workspace"]
    assert ws.transport == "stdio" and ws.args == ("demo/servers/workspace.py",)
    assert ws.cwd == ROOT
    assert config.labels_for("workspace", "read_inbox").trusted_fields == {"from", "to", "date"}
    assert config.labels_for("workspace", "send_email") == ToolLabels(sink=True, irreversible=True)
    assert config.pins_file == ROOT / ".mcpfw" / "pins.json"
    assert config.warnings == ()


def test_defaults():
    config = parse(minimal())
    assert config.mode == "enforce" and config.approver == "elicit" and config.spotlight is True
    assert config.user_task is None
    assert config.default_labels == UNKNOWN_TOOL
    assert config.audit_log == BASE / ".mcpfw" / "audit.jsonl"


def test_unlisted_tool_gets_default_labels_marked_unknown():
    config = parse(minimal(default_labels={"untrusted": True, "sink": True, "private": True}))
    labels = config.labels_for("workspace", "mystery")
    assert labels.private and labels.untrusted and labels.sink and not labels.known
    assert config.labels_for("nope", "x") is config.default_labels


def test_http_upstream():
    config = parse({"upstreams": {"remote": {"url": "https://mcp.example.com/mcp"}}})
    assert config.upstreams["remote"].transport == "http" and config.upstreams["remote"].cwd is None


def test_relative_cwd_resolves_against_config_dir():
    config = parse({"upstreams": {"a": {"command": "node", "cwd": "servers/a"}}})
    assert config.upstreams["a"].cwd == BASE / "servers" / "a"


@pytest.mark.parametrize(
    "overrides, expected",
    [
        ({"approver": "approve"}, "benchmarks only"),
        ({"mode": "monitor"}, "blocks nothing"),
        ({"default_labels": {}}, "looser than the worst-case"),
    ],
)
def test_risky_settings_produce_warnings(overrides, expected):
    warnings = parse(minimal(**overrides)).warnings
    assert any(expected in w for w in warnings), warnings


# --- done-when: malformed configs fail with readable messages -------------------------------------


@pytest.mark.parametrize(
    "data, message",
    [
        ([], "firewall.yaml: top level must be a mapping"),
        (minimal(mod="enforce"), "unknown key(s) ['mod']"),
        (minimal(mode="block"), "mode: must be one of enforce, monitor; got 'block'"),
        (minimal(approver="human"), "approver: must be one of elicit, tty, deny, approve"),
        (minimal(spotlight="yes"), "spotlight: must be true or false, got 'yes'"),
        (minimal(user_task=42), "user_task: must be a string or null"),
        ({}, "upstreams: must be a non-empty mapping"),
        ({"upstreams": {}}, "upstreams: must be a non-empty mapping"),
        ({"upstreams": {"ws": {}}}, "upstreams.ws: set exactly one of 'command' (stdio) or 'url' (HTTP)"),
        (
            {"upstreams": {"ws": {"command": "py", "url": "https://x.example.com"}}},
            "set exactly one of 'command'",
        ),
        ({"upstreams": {"ws": {"url": "ftp://x"}}}, "upstreams.ws.url: must be an http(s) URL"),
        ({"upstreams": {"my__srv": {"command": "py"}}}, "upstreams.my__srv: server name must use"),
        ({"upstreams": {"ws": {"command": "py", "args": "server.py"}}}, "upstreams.ws.args: must be a list"),
        ({"upstreams": {"ws": {"command": "py", "env": {"A": 1}}}}, "upstreams.ws.env: must be a mapping"),
        ({"upstreams": {"ws": {"command": "py", "comand": "x"}}}, "upstreams.ws: unknown key(s) ['comand']"),
        (
            {"upstreams": {"ws": {"command": "py", "tools": {"send": {"sink": "yes"}}}}},
            "upstreams.ws.tools.send: 'sink' must be true or false, got 'yes'",
        ),
        (
            {"upstreams": {"ws": {"command": "py", "tools": {"send": {"sinc": True}}}}},
            "upstreams.ws.tools.send: unknown label key(s) ['sinc']",
        ),
        (
            {"upstreams": {"ws": {"command": "py", "tools": ["send"]}}},
            "upstreams.ws.tools: must be a mapping",
        ),
        (minimal(default_labels={"untrusted": 1}), "default_labels: 'untrusted' must be true or false"),
    ],
)
def test_malformed_config_fails_readably(data, message):
    with pytest.raises(ConfigError) as exc:
        parse(data)
    assert message in str(exc.value)
    assert str(exc.value).startswith("firewall.yaml: ")


def test_invalid_yaml_reports_line(tmp_path):
    path = tmp_path / "firewall.yaml"
    path.write_text("mode: enforce\nupstreams:\n  ws: {command: python\n", encoding="utf-8")
    with pytest.raises(ConfigError, match=r"invalid YAML at line \d+, column \d+"):
        load_config(path)


def test_missing_file_is_readable(tmp_path):
    with pytest.raises(ConfigError, match="cannot read config"):
        load_config(tmp_path / "nope.yaml")
