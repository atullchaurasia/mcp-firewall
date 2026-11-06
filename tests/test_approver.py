"""Approver tests.

Elicitation is tested end-to-end with an in-process Client and a real low-level Server, in both protocol
modes: "auto" (2026-07-28, input-required round trip) and "legacy" (handshake, back-channel request).
"""

from __future__ import annotations

import io
from typing import Any

import anyio
import mcp_types as types
import pytest
from mcp import Client
from mcp.server.lowlevel import Server

from mcpfw.approver import (
    APPROVAL_SCHEMA,
    INPUT_KEY,
    ApprovalRequest,
    ApproveApprover,
    DenyApprover,
    ElicitApprover,
    InputRequired,
    TtyApprover,
    approval_message,
    make_approver,
)
from mcpfw.policy import Action, Decision, RuleHit

pytestmark = pytest.mark.anyio

DECISION = Decision(
    Action.ASK,
    (RuleHit("R2", "lethal_trifecta", Action.ASK, "untrusted content was read from ws__read_inbox"),),
)
ARGS = {"to": "bob@example.com", "body": "summary"}
REQUEST = ApprovalRequest("ws__send_email", ARGS, DECISION)
MODES = ["auto", "legacy"]


@pytest.fixture
def anyio_backend():
    return "asyncio"


def approval_server(approver) -> Server:
    """A server whose tools ask ``approver`` (as the proxy will) and report the outcome as text."""

    async def on_list_tools(ctx, params):
        return types.ListToolsResult(tools=[types.Tool(name="send", input_schema={"type": "object"})])

    async def on_call_tool(ctx, params: types.CallToolRequestParams):
        request = ApprovalRequest(
            "ws__send_email",
            params.arguments or {},
            DECISION,
            input_responses=params.input_responses,
            request_state=params.request_state,
        )
        outcome = await approver.approve(request, ctx)
        if isinstance(outcome, InputRequired):
            return outcome.result
        text = f"approved={outcome.approved} via={outcome.via} note={outcome.note}"
        return types.CallToolResult(content=[types.TextContent(type="text", text=text)])

    return Server("approval-test", on_list_tools=on_list_tools, on_call_tool=on_call_tool)


async def call_with(approver, callback=None, *, mode="auto", args=ARGS) -> str:
    kwargs: dict[str, Any] = {"mode": mode}
    if callback is not None:
        kwargs["elicitation_callback"] = callback
    async with Client(approval_server(approver), **kwargs) as client:
        result = await client.call_tool("send", dict(args))
    return result.content[0].text


def answering(action: str, content: dict[str, Any] | None = None, seen: list | None = None):
    async def callback(context, params):
        if seen is not None:
            seen.append(params)
        return types.ElicitResult(action=action, content=content)

    return callback


APPROVE = ("accept", {"approve": True})


# --- done-when: approve and decline through a real client, both protocol modes -------------------


@pytest.mark.parametrize("mode", MODES)
async def test_elicit_user_approves(mode):
    seen: list = []
    text = await call_with(ElicitApprover(), answering(*APPROVE, seen), mode=mode)
    assert text == "approved=True via=elicit note=None"

    params = seen[0]
    assert "ws__send_email" in params.message and "R2 lethal_trifecta" in params.message
    assert "bob@example.com" in params.message  # the human sees the real destination
    assert params.requested_schema["properties"]["approve"]["type"] == "boolean"


@pytest.mark.parametrize("mode", MODES)
async def test_elicit_user_declines(mode):
    text = await call_with(ElicitApprover(), answering("decline"), mode=mode)
    assert text == "approved=False via=elicit note=user chose decline"


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize(
    "action, content, note",
    [
        ("cancel", None, "user chose cancel"),
        ("accept", {"approve": False}, "user did not approve"),
        ("accept", None, "user did not approve"),
        ("accept", {"approve": "true"}, "user did not approve"),  # strings are not approval
    ],
)
async def test_elicit_anything_but_explicit_approval_denies(mode, action, content, note):
    text = await call_with(ElicitApprover(), answering(action, content), mode=mode)
    assert text == f"approved=False via=elicit note={note}"


@pytest.mark.parametrize("mode", MODES)
async def test_elicit_without_client_support_denies(mode):
    text = await call_with(ElicitApprover(), mode=mode)  # no callback → capability not advertised
    assert text == "approved=False via=elicit note=client does not support elicitation"


async def test_back_channel_client_error_denies():
    async def failing(context, params):
        return types.ErrorData(code=-32603, message="UI crashed")

    text = await call_with(ElicitApprover(), failing, mode="legacy")
    assert text.startswith("approved=False via=elicit note=elicitation failed")


async def test_back_channel_timeout_denies():
    async def slow(context, params):
        await anyio.sleep(5)
        return types.ElicitResult(action="accept", content={"approve": True})

    text = await call_with(ElicitApprover(timeout_s=0.2), slow, mode="legacy")
    assert text == "approved=False via=elicit note=no answer within 0.2s"


# --- input-required: approvals are single-use and bound to the call ------------------------------


async def first_round(client: Client, args=ARGS) -> types.InputRequiredResult:
    result = await client.session.call_tool("send", dict(args), allow_input_required=True)
    assert isinstance(result, types.InputRequiredResult)
    assert set(result.input_requests) == {INPUT_KEY}
    return result


def approved_response() -> dict[str, Any]:
    return {INPUT_KEY: types.ElicitResult(action="accept", content={"approve": True})}


async def retry(client: Client, state: str | None, args=ARGS) -> str:
    result = await client.session.call_tool(
        "send",
        dict(args),
        input_responses=approved_response(),
        request_state=state,
        allow_input_required=True,
    )
    return result.content[0].text


async def test_input_required_approval_cannot_be_moved_to_other_arguments():
    async with Client(approval_server(ElicitApprover()), elicitation_callback=answering(*APPROVE)) as client:
        pending = await first_round(client)
        text = await retry(client, pending.request_state, args={"to": "drop@evil.co", "body": "summary"})
    assert text == "approved=False via=elicit note=approval does not match this call's tool and arguments"


async def test_input_required_approval_is_single_use():
    async with Client(approval_server(ElicitApprover()), elicitation_callback=answering(*APPROVE)) as client:
        pending = await first_round(client)
        assert (await retry(client, pending.request_state)).startswith("approved=True")
        replay = await retry(client, pending.request_state)
    assert replay == "approved=False via=elicit note=approval token unknown, used or expired"


@pytest.mark.parametrize("state", ["forged-token", None])
async def test_input_required_forged_or_missing_token_denies(state):
    async with Client(approval_server(ElicitApprover()), elicitation_callback=answering(*APPROVE)) as client:
        text = await retry(client, state)
    assert text == "approved=False via=elicit note=approval token unknown, used or expired"


async def test_input_required_token_expires():
    now = [1000.0]
    approver = ElicitApprover(timeout_s=60, clock=lambda: now[0])
    async with Client(approval_server(approver), elicitation_callback=answering(*APPROVE)) as client:
        pending = await first_round(client)
        now[0] += 61
        text = await retry(client, pending.request_state)
    assert text == "approved=False via=elicit note=approval token unknown, used or expired"


async def test_input_required_retry_without_answer_denies():
    async with Client(approval_server(ElicitApprover()), elicitation_callback=answering(*APPROVE)) as client:
        pending = await first_round(client)
        result = await client.session.call_tool(
            "send",
            dict(ARGS),
            input_responses={},
            request_state=pending.request_state,
            allow_input_required=True,
        )
    assert result.content[0].text == "approved=False via=elicit note=no approval answer in the retry"


# --- tty -----------------------------------------------------------------------------------------


def fake_tty(answer: str, written: list[str]):
    class Writer(io.StringIO):
        def close(self):
            written.append(self.getvalue())
            super().close()

    return lambda: (io.StringIO(answer), Writer())


@pytest.mark.parametrize("answer, approved", [("y\n", True), ("YES\n", True), ("n\n", False), ("\n", False)])
async def test_tty_answers(answer, approved):
    written: list[str] = []
    approval = await TtyApprover(opener=fake_tty(answer, written)).approve(REQUEST, ctx=None)
    assert approval.approved is approved and approval.via == "tty"
    assert "Allow? [y/N]" in written[0] and "bob@example.com" in written[0]


async def test_tty_unavailable_denies():
    def no_terminal():
        raise OSError("no tty")

    approval = await TtyApprover(opener=no_terminal).approve(REQUEST, ctx=None)
    assert not approval.approved and "terminal unavailable" in approval.note


# --- trivial backends + factory ------------------------------------------------------------------


async def test_deny_and_approve_backends():
    assert (await DenyApprover().approve(REQUEST, None)).approved is False
    assert (await ApproveApprover().approve(REQUEST, None)).approved is True


def test_make_approver():
    names = ("elicit", "tty", "deny", "approve")
    assert [make_approver(n).name for n in names] == list(names)
    with pytest.raises(ValueError):
        make_approver("human")


def test_message_and_schema():
    message = approval_message(ApprovalRequest("t", {"body": "x" * 2000}, DECISION))
    assert "…" in message and len(message) < 1000
    assert APPROVAL_SCHEMA["required"] == ["approve"]
