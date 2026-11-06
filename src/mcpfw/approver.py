"""Human approval for ASK decisions.

Backends:

- ``ElicitApprover``: asks through the MCP client with a form elicitation (a boolean ``approve`` field).
- ``TtyApprover``: asks on the controlling terminal, never stdin/stdout (those carry the MCP channel).
  Uses ``/dev/tty`` on POSIX and ``CONIN$``/``CONOUT$`` on Windows.
- ``DenyApprover``: refuses everything (security benchmark runs, headless deployments).
- ``ApproveApprover``: accepts everything. **Benchmark utility runs only.**

Elicitation has two transports, chosen per request:

- **Back-channel** (handshake-era protocol): ``ctx.session.elicit_form`` sends a request to the client
  mid-call and awaits the answer.
- **Input-required** (2026-07-28 protocol, no back-channel): ``approve`` returns ``InputRequired``; the
  proxy returns its ``InputRequiredResult`` and the client retries the call with the answer in
  ``input_responses``. ``request_state`` carries a random single-use token; the firewall remembers which
  tool and argument hash the token was issued for, so an approval cannot be replayed or moved to
  different arguments.

Secure default: any error, timeout, expiry, missing capability, decline, cancel, mismatch or malformed
answer is a deny. The prompt shows the human the real (truncated) arguments, because nobody can judge
"send email" without seeing the recipient; that text goes only to the user's own client/terminal,
never to the audit log.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol, TextIO

import anyio
import mcp_types as types

from mcpfw.audit import args_sha256
from mcpfw.policy import Decision

log = logging.getLogger(__name__)

DEFAULT_TIMEOUT_S = 120.0
ARGS_SHOWN_CHARS = 600
INPUT_KEY = "mcpfw_approval"
_MAX_PENDING = 256

APPROVAL_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "approve": {
            "type": "boolean",
            "title": "Allow this call?",
            "description": "Approve only if you expected the agent to do this.",
            "default": False,
        }
    },
    "required": ["approve"],
}


@dataclass(frozen=True)
class ApprovalRequest:
    tool: str
    args: Mapping[str, Any]
    decision: Decision
    # From the incoming CallToolRequestParams, set on an input-required retry.
    input_responses: Mapping[str, Any] | None = None
    request_state: str | None = None


@dataclass(frozen=True)
class Approval:
    approved: bool
    via: str  # backend name, for the audit log
    note: str | None = None  # why it was denied, if not by the human


@dataclass(frozen=True)
class InputRequired:
    """The answer must come from the client on a retry; return ``result`` from ``call_tool``."""

    result: types.InputRequiredResult
    via: str = "elicit"


class Approver(Protocol):
    name: str

    async def approve(self, request: ApprovalRequest, ctx: Any) -> Approval | InputRequired: ...


def approval_message(request: ApprovalRequest) -> str:
    """Text shown to the human."""
    reasons = "\n".join(f"  - {hit.label}: {hit.reason}" for hit in request.decision.hits)
    return (
        f"MCP Firewall: the agent wants to call '{request.tool}'.\n"
        f"Why this needs approval:\n{reasons}\n"
        f"Arguments:\n  {_show_args(request.args)}\n"
        "Only approve if you asked for this."
    )


def _show_args(args: Mapping[str, Any]) -> str:
    text = json.dumps(dict(args), ensure_ascii=False, default=str)
    return text if len(text) <= ARGS_SHOWN_CHARS else text[: ARGS_SHOWN_CHARS - 1] + "…"


def _approved_in(result: Any) -> bool:
    """Only an explicit accept with ``approve`` exactly True counts."""
    if getattr(result, "action", None) != "accept":
        return False
    content = getattr(result, "content", None) or {}
    return content.get("approve") is True


def _denial_note(result: Any) -> str:
    action = getattr(result, "action", None)
    return "user did not approve" if action == "accept" else f"user chose {action or 'nothing'}"


# --- backends ------------------------------------------------------------------------------------


class DenyApprover:
    name = "deny"

    async def approve(self, request: ApprovalRequest, ctx: Any) -> Approval:
        return Approval(False, self.name, "approver is 'deny'")


class ApproveApprover:
    """Approves everything. Only for benchmark utility runs."""

    name = "approve"

    async def approve(self, request: ApprovalRequest, ctx: Any) -> Approval:
        return Approval(True, self.name)


@dataclass(frozen=True)
class _Pending:
    tool: str
    args_sha256: str
    expires_at: float


class ElicitApprover:
    name = "elicit"

    def __init__(
        self, timeout_s: float = DEFAULT_TIMEOUT_S, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self.timeout_s = timeout_s
        self._clock = clock
        self._pending: dict[str, _Pending] = {}

    async def approve(self, request: ApprovalRequest, ctx: Any) -> Approval | InputRequired:
        if request.request_state is not None or request.input_responses:
            return self._resume(request)

        session = getattr(ctx, "session", None)
        if session is None:
            return Approval(False, self.name, "no client session to ask")
        caps = getattr(session, "client_capabilities", None)
        if caps is None or getattr(caps, "elicitation", None) is None:
            return Approval(False, self.name, "client does not support elicitation")

        if getattr(session, "can_send_request", False):
            return await self._ask_back_channel(request, ctx, session)
        return self._ask_input_required(request)

    async def _ask_back_channel(self, request: ApprovalRequest, ctx: Any, session: Any) -> Approval:
        try:
            with anyio.fail_after(self.timeout_s):
                result = await session.elicit_form(
                    approval_message(request),
                    APPROVAL_SCHEMA,
                    related_request_id=getattr(ctx, "request_id", None),
                )
        except TimeoutError:
            return Approval(False, self.name, f"no answer within {self.timeout_s:g}s")
        except Exception as exc:  # any failure to ask is a deny
            log.warning("elicitation failed: %r", exc)
            return Approval(False, self.name, f"elicitation failed ({type(exc).__name__})")
        if _approved_in(result):
            return Approval(True, self.name)
        return Approval(False, self.name, _denial_note(result))

    def _ask_input_required(self, request: ApprovalRequest) -> InputRequired:
        self._expire()
        if len(self._pending) >= _MAX_PENDING:
            self._pending.pop(next(iter(self._pending)))  # drop the oldest
        token = secrets.token_urlsafe(24)
        self._pending[token] = _Pending(
            request.tool, args_sha256(request.args), self._clock() + self.timeout_s
        )
        elicit = types.ElicitRequest(
            params=types.ElicitRequestFormParams(
                message=approval_message(request), requested_schema=APPROVAL_SCHEMA
            )
        )
        return InputRequired(
            types.InputRequiredResult(input_requests={INPUT_KEY: elicit}, request_state=token), self.name
        )

    def _resume(self, request: ApprovalRequest) -> Approval:
        """Validate an input-required retry. Tokens are single-use and bound to tool + arguments."""
        self._expire()
        pending = self._pending.pop(request.request_state or "", None)
        if pending is None:
            return Approval(False, self.name, "approval token unknown, used or expired")
        if pending.tool != request.tool or pending.args_sha256 != args_sha256(request.args):
            return Approval(False, self.name, "approval does not match this call's tool and arguments")
        result = (request.input_responses or {}).get(INPUT_KEY)
        if result is None:
            return Approval(False, self.name, "no approval answer in the retry")
        if _approved_in(result):
            return Approval(True, self.name)
        return Approval(False, self.name, _denial_note(result))

    def _expire(self) -> None:
        now = self._clock()
        for token in [t for t, p in self._pending.items() if p.expires_at <= now]:
            del self._pending[token]


TtyOpener = Callable[[], tuple[TextIO, TextIO]]


def open_console() -> tuple[TextIO, TextIO]:
    """Open the controlling terminal for (reading, writing), bypassing the MCP stdio channel."""
    if os.name == "nt":
        return open("CONIN$", encoding="utf-8"), open("CONOUT$", "w", encoding="utf-8")
    tty_in = open("/dev/tty", encoding="utf-8")
    return tty_in, open("/dev/tty", "w", encoding="utf-8")


class TtyApprover:
    name = "tty"

    def __init__(self, timeout_s: float = DEFAULT_TIMEOUT_S, opener: TtyOpener = open_console) -> None:
        self.timeout_s = timeout_s
        self._opener = opener
        self._lock = anyio.Lock()  # one prompt at a time

    async def approve(self, request: ApprovalRequest, ctx: Any) -> Approval:
        async with self._lock:
            try:
                with anyio.fail_after(self.timeout_s):
                    answer = await anyio.to_thread.run_sync(self._ask, request, abandon_on_cancel=True)
            except TimeoutError:
                return Approval(False, self.name, f"no answer within {self.timeout_s:g}s")
            except Exception as exc:
                log.warning("terminal approval failed: %r", exc)
                return Approval(False, self.name, f"terminal unavailable ({type(exc).__name__})")
        if answer.strip().lower() in ("y", "yes"):
            return Approval(True, self.name)
        return Approval(False, self.name, "user did not approve")

    def _ask(self, request: ApprovalRequest) -> str:
        reader, writer = self._opener()
        try:
            writer.write("\n" + approval_message(request) + "\nAllow? [y/N] ")
            writer.flush()
            return reader.readline()
        finally:
            for stream in (reader, writer):
                try:
                    stream.close()
                except Exception:
                    pass


def make_approver(name: str, *, timeout_s: float = DEFAULT_TIMEOUT_S) -> Approver:
    if name == "elicit":
        return ElicitApprover(timeout_s)
    if name == "tty":
        return TtyApprover(timeout_s)
    if name == "deny":
        return DenyApprover()
    if name == "approve":
        return ApproveApprover()
    raise ValueError(f"unknown approver {name!r}")
