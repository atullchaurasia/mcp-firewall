"""Load and validate ``firewall.yaml``.

The config is a trust root (written by the operator), so it is validated strictly: unknown keys,
wrong types and ambiguous upstreams are errors with a message naming the file and key path, because a
silently ignored typo could disable a protection.

Relative paths (``pins_file``, ``audit_log``, an upstream's ``cwd``) resolve against the config file's
directory, since MCP clients launch the firewall from an unpredictable working directory. Upstreams
without ``cwd`` run in the config directory too.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

import yaml

from mcpfw.labels import UNKNOWN_TOOL, LabelConfigError, ToolLabels

MODES = ("enforce", "monitor")
APPROVERS = ("elicit", "tty", "deny", "approve")
NAMESPACE_SEP = "__"

_TOP_KEYS = {
    "mode",
    "spotlight",
    "approver",
    "user_task",
    "pins_file",
    "audit_log",
    "default_labels",
    "upstreams",
}
_UPSTREAM_KEYS = {"command", "args", "env", "cwd", "url", "tools"}
_SERVER_NAME_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]|_(?!_))*")


class ConfigError(ValueError):
    """A malformed config. The message names the file and the offending key."""


class UpstreamError(RuntimeError):
    """An upstream server could not be started or connected to."""

    def __init__(self, name: str, upstream: UpstreamConfig, cause: BaseException) -> None:
        how = upstream.url or " ".join([upstream.command or "", *upstream.args]).strip()
        super().__init__(f"upstream '{name}' ({how}) failed to connect: {_root_message(cause)}")
        self.name = name


def _root_message(exc: BaseException) -> str:
    """Innermost useful message, unwrapping exception groups from task groups."""
    while getattr(exc, "exceptions", None):  # ExceptionGroup (3.11+) or the anyio backport on 3.10
        exc = exc.exceptions[0]  # type: ignore[attr-defined]
    return f"{type(exc).__name__}: {exc}"


@dataclass(frozen=True)
class UpstreamConfig:
    name: str
    command: str | None = None
    args: tuple[str, ...] = ()
    env: Mapping[str, str] | None = None
    cwd: Path | None = None
    url: str | None = None
    tools: Mapping[str, ToolLabels] = field(default_factory=dict)

    @property
    def transport(self) -> str:
        return "stdio" if self.command else "http"


@dataclass(frozen=True)
class FirewallConfig:
    upstreams: Mapping[str, UpstreamConfig]
    mode: str = "enforce"
    spotlight: bool = True
    approver: str = "elicit"
    user_task: str | None = None
    pins_file: Path = Path(".mcpfw/pins.json")
    audit_log: Path = Path(".mcpfw/audit.jsonl")
    default_labels: ToolLabels = UNKNOWN_TOOL
    source: str = "<config>"
    warnings: tuple[str, ...] = ()

    def labels_for(self, server: str, tool: str) -> ToolLabels:
        """Configured labels for ``server``'s ``tool``, or ``default_labels`` (``known=False``)."""
        upstream = self.upstreams.get(server)
        if upstream is not None and tool in upstream.tools:
            return upstream.tools[tool]
        return self.default_labels


def load_config(path: Path | str) -> FirewallConfig:
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"{path}: cannot read config ({exc.strerror or exc})") from exc
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f" at line {mark.line + 1}, column {mark.column + 1}" if mark else ""
        problem = getattr(exc, "problem", None) or "invalid YAML"
        raise ConfigError(f"{path}: invalid YAML{where}: {problem}") from exc
    return parse_config(data, base_dir=path.resolve().parent, source=str(path))


def parse_config(data: Any, *, base_dir: Path, source: str = "<config>") -> FirewallConfig:
    """Validate an already-parsed YAML document."""
    err = _Errors(source)
    if not isinstance(data, Mapping):
        err.fail("", f"top level must be a mapping, got {_type(data)}")

    err.unknown_keys("", data, _TOP_KEYS)
    warnings: list[str] = []

    mode = err.choice("mode", data.get("mode", "enforce"), MODES)
    approver = err.choice("approver", data.get("approver", "elicit"), APPROVERS)
    spotlight = err.boolean("spotlight", data.get("spotlight", True))
    user_task = data.get("user_task")
    if user_task is not None and not isinstance(user_task, str):
        err.fail("user_task", f"must be a string or null, got {_type(user_task)}")

    pins_file = _resolve(base_dir, err.string("pins_file", data.get("pins_file", ".mcpfw/pins.json")))
    audit_log = _resolve(base_dir, err.string("audit_log", data.get("audit_log", ".mcpfw/audit.jsonl")))

    default_labels = UNKNOWN_TOOL
    if "default_labels" in data:
        default_labels = _replace_known(err.labels("default_labels", data["default_labels"]))
        if not default_labels.is_at_least_as_strict_as(UNKNOWN_TOOL):
            warnings.append(
                "default_labels is looser than the worst-case default (untrusted + sink); "
                "unlabeled tools will get weaker protection"
            )

    raw_upstreams = data.get("upstreams")
    if not isinstance(raw_upstreams, Mapping) or not raw_upstreams:
        err.fail("upstreams", "must be a non-empty mapping of server name → settings")
    upstreams = {
        str(name): _parse_upstream(err, str(name), spec, base_dir) for name, spec in raw_upstreams.items()
    }

    if approver == "approve":
        warnings.append("approver 'approve' auto-approves every ASK decision; use it for benchmarks only")
    if mode == "monitor":
        warnings.append("mode 'monitor' logs decisions but blocks nothing")

    return FirewallConfig(
        upstreams=upstreams,
        mode=mode,
        spotlight=spotlight,
        approver=approver,
        user_task=user_task,
        pins_file=pins_file,
        audit_log=audit_log,
        default_labels=default_labels,
        source=source,
        warnings=tuple(warnings),
    )


def _parse_upstream(err: _Errors, name: str, spec: Any, base_dir: Path) -> UpstreamConfig:
    where = f"upstreams.{name}"
    if not _SERVER_NAME_RE.fullmatch(name):
        err.fail(
            where,
            "server name must use letters, digits, '-' or single '_' "
            f"('{NAMESPACE_SEP}' is reserved for tool namespacing)",
        )
    if not isinstance(spec, Mapping):
        err.fail(where, f"must be a mapping with 'command' or 'url', got {_type(spec)}")
    err.unknown_keys(where, spec, _UPSTREAM_KEYS)

    command, url = spec.get("command"), spec.get("url")
    if (command is None) == (url is None):
        err.fail(where, "set exactly one of 'command' (stdio) or 'url' (HTTP)")
    if command is not None:
        err.string(f"{where}.command", command)
    if url is not None and not (isinstance(url, str) and re.match(r"https?://", url)):
        err.fail(f"{where}.url", f"must be an http(s) URL, got {url!r}")

    args = spec.get("args", [])
    if not isinstance(args, list) or not all(isinstance(a, (str, int, float)) for a in args):
        err.fail(f"{where}.args", "must be a list of strings")

    env = spec.get("env")
    if env is not None and not (
        isinstance(env, Mapping) and all(isinstance(k, str) and isinstance(v, str) for k, v in env.items())
    ):
        err.fail(f"{where}.env", "must be a mapping of string → string")

    cwd = spec.get("cwd")
    cwd_path = _resolve(base_dir, err.string(f"{where}.cwd", cwd)) if cwd is not None else base_dir

    raw_tools = spec.get("tools") or {}
    if not isinstance(raw_tools, Mapping):
        err.fail(f"{where}.tools", f"must be a mapping of tool name → labels, got {_type(raw_tools)}")
    tools = {str(t): err.labels(f"{where}.tools.{t}", labels) for t, labels in raw_tools.items()}

    return UpstreamConfig(
        name=name,
        command=command,
        args=tuple(str(a) for a in args),
        env=dict(env) if env is not None else None,
        cwd=cwd_path if command is not None else None,
        url=url,
        tools=tools,
    )


class _Errors:
    """Raises ConfigError with ``<file>: <key.path>: <message>``."""

    def __init__(self, source: str) -> None:
        self.source = source

    def fail(self, where: str, message: str) -> None:
        prefix = f"{self.source}: {where}: " if where else f"{self.source}: "
        raise ConfigError(prefix + message)

    def unknown_keys(self, where: str, data: Mapping[str, Any], allowed: set[str]) -> None:
        unknown = sorted(str(k) for k in set(data) - allowed)
        if unknown:
            self.fail(where or "top level", f"unknown key(s) {unknown}; allowed: {sorted(allowed)}")

    def choice(self, where: str, value: Any, choices: tuple[str, ...]) -> str:
        if value not in choices:
            self.fail(where, f"must be one of {', '.join(choices)}; got {value!r}")
        return value

    def boolean(self, where: str, value: Any) -> bool:
        if not isinstance(value, bool):
            self.fail(where, f"must be true or false, got {value!r}")
        return value

    def string(self, where: str, value: Any) -> str:
        if not isinstance(value, str) or not value:
            self.fail(where, f"must be a non-empty string, got {value!r}")
        return value

    def labels(self, where: str, value: Any) -> ToolLabels:
        try:
            return ToolLabels.from_config(value, where=where)
        except LabelConfigError as exc:
            raise ConfigError(f"{self.source}: {exc}") from exc


def _resolve(base_dir: Path, value: str) -> Path:
    path = Path(value).expanduser()
    return path if path.is_absolute() else base_dir / path


def _replace_known(labels: ToolLabels) -> ToolLabels:
    return replace(labels, known=False)


def _type(value: Any) -> str:
    return "null" if value is None else type(value).__name__
