"""``mcpfw`` command line.

    mcpfw run    --config firewall.yaml [--mode monitor] [--user-task "..."] [--approver tty]
    mcpfw scan   --config firewall.yaml           # read-only; exit 1 if any tool is quarantined
    mcpfw pins   --config firewall.yaml --list | --reset KEY [KEY ...] | --reset-all
    mcpfw report --config firewall.yaml | --audit audit.jsonl [--session ID]

All diagnostics go to stderr: under ``run``, stdout is the MCP channel.
Exit codes: 0 ok, 1 findings (scan) or nothing to reset (pins), 2 usage/config error.
"""

from __future__ import annotations

import argparse
import logging
import sys
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any, TextIO

import anyio

from mcpfw import __version__
from mcpfw.audit import read_events
from mcpfw.config import APPROVERS, MODES, ConfigError, FirewallConfig, UpstreamError, load_config
from mcpfw.descriptions import PinStore
from mcpfw.labels import ToolLabels

log = logging.getLogger("mcpfw")


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        stream=sys.stderr,
        level=getattr(logging, args.log_level.upper()),
        format="mcpfw %(levelname)s %(message)s",
    )
    try:
        return args.func(args)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2
    except UpstreamError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mcpfw", description="Prompt-injection firewall proxy for MCP.")
    parser.add_argument("--version", action="version", version=f"mcpfw {__version__}")
    parser.add_argument("--log-level", default="warning", choices=["debug", "info", "warning", "error"])
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run the firewall as an MCP server on stdio")
    run.add_argument("--config", required=True, type=Path)
    run.add_argument("--mode", choices=MODES, help="override the config's mode")
    run.add_argument("--approver", choices=APPROVERS, help="override the config's approver")
    run.add_argument("--user-task", help="trusted task text for this session")
    run.set_defaults(func=_cmd_run)

    scan = sub.add_parser("scan", help="list and scan upstream tools without running an agent")
    scan.add_argument("--config", required=True, type=Path)
    scan.set_defaults(func=_cmd_scan)

    pins = sub.add_parser("pins", help="inspect or reset pinned tool definitions")
    pins.add_argument("--config", required=True, type=Path)
    group = pins.add_mutually_exclusive_group(required=True)
    group.add_argument("--list", action="store_true", help="list pinned tools")
    group.add_argument("--reset", nargs="+", metavar="KEY", help="re-approve these tools (server__tool)")
    group.add_argument("--reset-all", action="store_true", help="forget every pin")
    pins.set_defaults(func=_cmd_pins)

    report = sub.add_parser("report", help="summarize an audit log")
    source = report.add_mutually_exclusive_group(required=True)
    source.add_argument("--config", type=Path, help="use the config's audit_log")
    source.add_argument("--audit", type=Path, help="path to an audit JSONL file")
    report.add_argument("--session", help="only this session id")
    report.set_defaults(func=_cmd_report)
    return parser


# --- run -----------------------------------------------------------------------------------------


def _cmd_run(args: argparse.Namespace) -> int:
    from mcpfw.proxy import Firewall  # imported lazily so `report`/`pins` stay light

    config = _with_overrides(load_config(args.config), args)
    firewall = Firewall(config, user_task=args.user_task)
    log.info(
        "mcpfw %s: mode=%s approver=%s upstreams=%s",
        __version__,
        config.mode,
        config.approver,
        ",".join(config.upstreams),
    )

    async def serve() -> None:
        async with firewall:
            await firewall.serve_stdio()

    anyio.run(serve)
    return 0


def _with_overrides(config: FirewallConfig, args: argparse.Namespace) -> FirewallConfig:
    changes: dict[str, Any] = {}
    warnings = list(config.warnings)
    if args.mode:
        changes["mode"] = args.mode
        if args.mode == "monitor" and config.mode != "monitor":
            warnings.append("mode 'monitor' logs decisions but blocks nothing")
    if args.approver:
        changes["approver"] = args.approver
        if args.approver == "approve" and config.approver != "approve":
            warnings.append("approver 'approve' auto-approves every ASK decision; use it for benchmarks only")
    return replace(config, **changes, warnings=tuple(warnings)) if changes else config


# --- scan ----------------------------------------------------------------------------------------


def _cmd_scan(args: argparse.Namespace, out: TextIO | None = None) -> int:
    from mcpfw.proxy import Firewall

    out = out or sys.stdout
    config = load_config(args.config)
    firewall = Firewall(config, read_only=True)

    async def scan() -> None:
        async with firewall:
            await firewall.refresh_tools()

    anyio.run(scan)
    reports = sorted(firewall.tool_report.values(), key=lambda r: r.key)
    width = max((len(r.key) for r in reports), default=10)
    for r in reports:
        status = r.status.upper() if r.status != "ok" else "ok"
        pin = f"pin:{r.pin}" if r.pin else "pin:-"
        print(f"{r.key:<{width}}  {status:<11} {pin:<11} {_labels_text(r.labels)}", file=out)
        if r.reason and r.status != "ok":
            print(f"{'':<{width}}    {r.reason}", file=out)
        for finding in r.findings:
            print(f"{'':<{width}}    - {finding}", file=out)

    quarantined = sum(r.status == "quarantined" for r in reports)
    unlabeled = sum(r.status == "unlabeled" for r in reports)
    print(
        f"\n{len(reports)} tool(s): {len(reports) - quarantined} visible, {quarantined} quarantined, "
        f"{unlabeled} unlabeled. Pins file not modified.",
        file=out,
    )
    return 1 if quarantined else 0


def _labels_text(labels: ToolLabels) -> str:
    flags = [n for n in ("untrusted", "private", "sink", "irreversible") if getattr(labels, n)]
    text = ",".join(flags) or "benign"
    if labels.trusted_fields:
        text += f" trusted_fields={','.join(sorted(labels.trusted_fields))}"
    return text


# --- pins ----------------------------------------------------------------------------------------


def _cmd_pins(args: argparse.Namespace, out: TextIO | None = None) -> int:
    out = out or sys.stdout
    path = load_config(args.config).pins_file
    store = PinStore.from_json(path.read_text(encoding="utf-8")) if path.exists() else PinStore()

    if args.list:
        for key, digest in sorted(store.pins.items()):
            print(f"{key}  {digest[:12]}", file=out)
        print(f"{len(store.pins)} pinned tool(s) in {path}", file=out)
        return 0

    if args.reset_all:
        removed = sorted(store.pins)
        store.pins.clear()
    else:
        removed = [key for key in args.reset if store.reset(key)]
        for key in sorted(set(args.reset) - set(removed)):
            print(f"not pinned: {key}", file=sys.stderr)

    if removed:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(store.to_json(), encoding="utf-8")
    for key in removed:
        print(f"reset: {key} (will be re-pinned on next listing; review its description first)", file=out)
    return 0 if removed else 1


# --- report --------------------------------------------------------------------------------------


def _cmd_report(args: argparse.Namespace, out: TextIO | None = None) -> int:
    out = out or sys.stdout
    path = args.audit or load_config(args.config).audit_log
    if not path.exists():
        print(f"error: no audit log at {path}", file=sys.stderr)
        return 2
    events = [e for e in read_events(path) if not args.session or e.get("session") == args.session]
    out.write(format_report(events, source=str(path)))
    return 0


def format_report(events: Iterable[dict[str, Any]], *, source: str) -> str:
    events = list(events)
    calls = [e for e in events if e.get("event") == "call"]
    sessions = {e.get("session") for e in events}
    actions = Counter(c.get("action") for c in calls)
    asks = [c for c in calls if c.get("action") == "ASK"]
    rules = Counter(h for c in calls for h in c.get("hits") or [])
    tools = Counter(c.get("tool") for c in calls)
    pending = sum(e.get("event") == "approval_pending" for e in events)

    lines = [
        f"Audit log: {source}",
        f"Sessions: {len(sessions)}   Calls: {len(calls)}   Approval prompts: {pending}",
        "Decisions: "
        + "  ".join(f"{a} {actions.get(a, 0)}" for a in ("ALLOW", "ASK", "BLOCK"))
        + f"   (ASK approved {sum(c.get('approved') is True for c in asks)},"
        f" denied {sum(c.get('approved') is False for c in asks)})",
    ]
    monitor = sum(c.get("mode") == "monitor" and c.get("action") != "ALLOW" for c in calls)
    if monitor:
        lines.append(f"Monitor mode: {monitor} call(s) would have been stopped but were forwarded")
    if rules:
        lines.append("Rule hits: " + "  ".join(f"{r} {n}" for r, n in sorted(rules.items())))
    if tools:
        lines.append("Top tools: " + "  ".join(f"{t} {n}" for t, n in tools.most_common(5)))

    stopped = [c for c in calls if not c.get("forwarded")]
    if stopped:
        lines.append("\nStopped calls:")
        for c in stopped:
            why = c.get("rule") or c.get("error") or "-"
            lines.append(f"  {c.get('ts', '')[:19]}  {c.get('tool')}  {c.get('action')}  {why}")
            if c.get("reason"):
                lines.append(f"      {c['reason']}")

    latest: dict[str, dict[str, Any]] = {}
    for e in events:
        if e.get("event") == "tool":
            latest[e.get("tool")] = e
    flagged = [e for e in latest.values() if e.get("status") in ("quarantined", "unlabeled")]
    if flagged:
        lines.append("\nFlagged tools (latest status):")
        for e in sorted(flagged, key=lambda e: (e.get("status"), e.get("tool"))):
            lines.append(f"  {e.get('tool')}  {e.get('status')}  {e.get('reason') or ''}".rstrip())
    return "\n".join(lines) + "\n"


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
