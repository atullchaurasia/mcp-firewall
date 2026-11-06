"""Append-only JSONL audit log.

One JSON object per line. Every call decision is logged, plus tool scan / pin events. Argument
values and tool outputs are never written: calls are logged as a SHA-256 of the canonical arguments
and a structural preview (argument names with value types and lengths), so the log can be shared
for debugging or the thesis without leaking private data.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from collections.abc import Callable, Iterator, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mcpfw.policy import Decision

PREVIEW_CHARS = 80


def args_sha256(args: Mapping[str, Any] | None) -> str:
    canonical = json.dumps(args or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def redacted_preview(args: Mapping[str, Any] | None, limit: int = PREVIEW_CHARS) -> str:
    """Argument names with value shapes only, e.g. ``{to: str(13), body: str(240)}``."""
    parts = [f"{key}: {_shape(value)}" for key, value in (args or {}).items()]
    text = "{" + ", ".join(parts) + "}"
    return text if len(text) <= limit else text[: limit - 2] + "…}"


def _shape(value: Any) -> str:
    if isinstance(value, bool) or value is None:
        return type(value).__name__
    if isinstance(value, (str, bytes)):
        return f"{type(value).__name__}({len(value)})"
    if isinstance(value, (int, float)):
        return type(value).__name__
    if isinstance(value, Mapping):
        return f"dict({len(value)})"
    if isinstance(value, (list, tuple)):
        return f"list({len(value)})"
    return type(value).__name__


class AuditLog:
    """Writes events to a JSONL file, opening it per write so each line is flushed immediately."""

    def __init__(
        self,
        path: Path | str,
        *,
        session_id: str | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.path = Path(path)
        self.session_id = session_id or uuid.uuid4().hex[:12]
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, event: str, **fields: Any) -> dict[str, Any]:
        record = {"ts": self._clock().isoformat(), "session": self.session_id, "event": event, **fields}
        line = json.dumps(record, ensure_ascii=False, default=str)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
        return record

    def log_call(
        self,
        tool: str,
        args: Mapping[str, Any] | None,
        decision: Decision,
        *,
        mode: str,
        forwarded: bool,
        approved: bool | None = None,
        latency_ms: float | None = None,
        error: str | None = None,
    ) -> dict[str, Any]:
        """Log one tool call. ``approved`` is set only when a human was asked (ASK)."""
        return self.write(
            "call",
            tool=tool,
            args_sha256=args_sha256(args),
            args_preview=redacted_preview(args),
            action=decision.action.name,
            rule=decision.rule,
            reason=decision.reason if decision.hits else None,
            hits=[h.rule_id for h in decision.hits],
            mode=mode,
            approved=approved,
            forwarded=forwarded,
            latency_ms=None if latency_ms is None else round(latency_ms, 2),
            error=error,
        )

    def log_tool(self, tool: str, *, status: str, reason: str | None = None, **fields: Any) -> dict[str, Any]:
        """Log a tool-listing event: ``status`` is e.g. "pinned", "ok", "quarantined", "unlabeled"."""
        return self.write("tool", tool=tool, status=status, reason=reason, **fields)


class NullAuditLog(AuditLog):
    """Discards events (read-only commands such as ``mcpfw scan``)."""

    def __init__(self) -> None:
        self.path = None  # type: ignore[assignment]
        self.session_id = "none"
        self._clock = lambda: datetime.now(timezone.utc)

    def write(self, event: str, **fields: Any) -> dict[str, Any]:
        return {"ts": self._clock().isoformat(), "session": self.session_id, "event": event, **fields}


class Stopwatch:
    """Tiny helper for ``latency_ms``."""

    def __init__(self) -> None:
        self._start = time.perf_counter()

    @property
    def ms(self) -> float:
        return (time.perf_counter() - self._start) * 1000


def read_events(path: Path | str) -> Iterator[dict[str, Any]]:
    """Yield events from an audit log, skipping blank lines; a corrupt line raises with its number."""
    with Path(path).open(encoding="utf-8") as f:
        for number, line in enumerate(f, start=1):
            if not line.strip():
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{number}: invalid JSON in audit log ({exc.msg})") from exc
