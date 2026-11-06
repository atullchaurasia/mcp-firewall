"""Policy engine: decide ALLOW / ASK / BLOCK for a tool call before it is forwarded.

Every rule is evaluated; the most severe action wins (ties go to the earlier rule). All hits are kept
on the ``Decision`` so the audit log shows every reason, not just the winner.

Rules
-----
R0 ``quarantined_tool`` (BLOCK)
    The tool's description was flagged by the scanner or changed since it was pinned. The proxy hides
    such tools, but an agent can still call one by name, so the call is blocked here too.
R1 ``tainted_destination`` (BLOCK)
    A sink call whose arguments contain an atom (email, domain, URL, long number) seen only in
    untrusted content. This is the core exfiltration signal: the attacker chose the destination.
R2 ``lethal_trifecta`` (ASK)
    A sink call after untrusted content entered the session, when private data was also seen or the
    arguments contain private data. Catches exfiltration to destinations R1 cannot attribute
    (obfuscated or agent-reconstructed addresses).
R3 ``untrusted_irreversible`` (ASK)
    An irreversible call after untrusted content entered the session.

Rules can be disabled by id (``disabled={"R2"}``) for benchmark ablations only.

Pure and synchronous (no MCP or I/O), so it is unit-testable in isolation. Reasons never contain
private data: R1 shows only attacker-supplied domains/addresses and redacts numbers.
"""

from __future__ import annotations

from collections.abc import Collection, Iterable, Mapping
from dataclasses import dataclass
from enum import IntEnum
from typing import Any

from mcpfw.labels import ToolLabels
from mcpfw.taint import TaintLedger

RULE_IDS = ("R0", "R1", "R2", "R3")
_MAX_LISTED_ATOMS = 3


class Action(IntEnum):
    """Ordered by severity so ``max()`` picks the strictest."""

    ALLOW = 0
    ASK = 1
    BLOCK = 2


@dataclass(frozen=True)
class RuleHit:
    rule_id: str
    name: str
    action: Action
    reason: str

    @property
    def label(self) -> str:
        return f"{self.rule_id} {self.name}"


@dataclass(frozen=True)
class Decision:
    """The outcome for one call. ``hits`` holds every rule that fired, most severe first."""

    action: Action
    hits: tuple[RuleHit, ...] = ()

    @property
    def rule(self) -> str | None:
        return self.hits[0].label if self.hits else None

    @property
    def reason(self) -> str:
        return self.hits[0].reason if self.hits else "no rule matched"

    def agent_message(self) -> str:
        """Message returned to the agent (as an error result) when the call is not executed."""
        return (
            f"Blocked by MCP Firewall ({self.rule}): {self.reason}. "
            "Do not retry this action; tell the user what happened."
        )


ALLOW = Decision(Action.ALLOW)


def evaluate(
    tool: str,
    labels: ToolLabels,
    args: Mapping[str, Any] | None,
    ledger: TaintLedger,
    *,
    quarantine_reason: str | None = None,
    disabled: Collection[str] = (),
) -> Decision:
    """Run all enabled rules for a call to ``tool`` and return the most severe decision."""
    unknown = set(disabled) - set(RULE_IDS)
    if unknown:
        raise ValueError(f"unknown rule id(s) to disable: {sorted(unknown)}")
    args = args or {}
    hits: list[RuleHit] = []

    def hit(rule_id: str, name: str, action: Action, reason: str) -> None:
        if rule_id not in disabled:
            hits.append(RuleHit(rule_id, name, action, reason))

    # R0
    if quarantine_reason is not None:
        hit("R0", "quarantined_tool", Action.BLOCK, f"tool '{tool}' is quarantined: {quarantine_reason}")

    if labels.sink:
        # R1
        tainted = ledger.tainted_only_atoms(args)
        if tainted:
            sources = sorted(set().union(*tainted.values()))
            hit(
                "R1",
                "tainted_destination",
                Action.BLOCK,
                f"'{tool}' arguments contain {_describe_atoms(tainted)} that appeared only in untrusted "
                f"content from {', '.join(sources)}",
            )

        # R2
        if ledger.seen_untrusted:
            leak = ledger.private_leak(args)
            if leak is not None or ledger.seen_private:
                untrusted = ", ".join(ledger.untrusted_sources)
                if leak is not None:
                    private = f"the arguments contain private data from {', '.join(sorted(leak.sources))}"
                else:
                    private = f"private data was read from {', '.join(ledger.private_sources)}"
                hit(
                    "R2",
                    "lethal_trifecta",
                    Action.ASK,
                    f"'{tool}' can send data out, untrusted content was read from {untrusted}, and {private}",
                )

    # R3
    if labels.irreversible and ledger.seen_untrusted:
        hit(
            "R3",
            "untrusted_irreversible",
            Action.ASK,
            f"'{tool}' cannot be undone and untrusted content was read from "
            f"{', '.join(ledger.untrusted_sources)}",
        )

    if not hits:
        return ALLOW
    # Stable sort: most severe first, rule order preserved within the same severity.
    hits.sort(key=lambda h: h.action, reverse=True)
    return Decision(hits[0].action, tuple(hits))


def _describe_atoms(atoms: Iterable[str]) -> str:
    """Human-readable atom list for reasons: URLs are left out (their host is listed separately)
    and numbers are redacted, since a number could be an account id from a private source."""
    shown: list[str] = []
    redacted = 0
    for atom in sorted(atoms):
        if atom.isdigit():
            redacted += 1
        elif "://" not in atom:
            shown.append(atom)
    parts = [f"'{a}'" for a in shown[:_MAX_LISTED_ATOMS]]
    if len(shown) > _MAX_LISTED_ATOMS:
        parts.append(f"{len(shown) - _MAX_LISTED_ATOMS} more")
    if redacted:
        parts.append(f"{redacted} redacted number(s)")
    return ("destination(s) " + ", ".join(parts)) if parts else "destination(s)"
