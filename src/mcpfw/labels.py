"""Security labels for tools.

Labels describe what a tool's output may contain and what calling it can do. They come from the
operator's config (trusted). MCP ``ToolAnnotations`` come from the upstream server (untrusted), so
they may only make labels *stricter*, never looser: a malicious server must not be able to talk the
firewall out of a protection by claiming ``readOnlyHint: true``.

This module is pure and synchronous on purpose (no MCP imports) so it can be unit-tested in isolation.
Annotations are read duck-typed, from either an object with snake_case attributes (``mcp_types``
models) or a mapping with camelCase or snake_case keys (raw JSON).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from typing import Any

_BOOL_FIELDS = ("untrusted", "private", "sink", "irreversible")
_ALLOWED_KEYS = frozenset((*_BOOL_FIELDS, "trusted_fields"))


class LabelConfigError(ValueError):
    """Raised when a tool's label config is malformed."""


@dataclass(frozen=True)
class ToolLabels:
    """Security labels for one tool.

    ``trusted_fields`` lists JSON keys in an untrusted tool's output that the server verifies itself
    (e.g. an email's ``from``), so atoms found there are not treated as attacker-controlled.
    ``known`` is False for tools absent from the config, so callers can warn about them.
    """

    untrusted: bool = False
    private: bool = False
    sink: bool = False
    irreversible: bool = False
    trusted_fields: frozenset[str] = field(default_factory=frozenset)
    known: bool = True

    @classmethod
    def from_config(cls, data: Mapping[str, Any] | None, *, where: str = "tool") -> ToolLabels:
        """Build labels from a config mapping such as ``{untrusted: true, trusted_fields: [from]}``.

        Missing keys default to False, so ``{}`` means a benign tool. Unknown keys and non-boolean
        values are rejected rather than ignored: a typo like ``sinc: true`` silently dropping a
        protection is exactly the failure we want to make loud. ``where`` names the tool in errors.
        """
        if data is None:
            data = {}
        if not isinstance(data, Mapping):
            raise LabelConfigError(f"{where}: labels must be a mapping, got {type(data).__name__}")

        unknown = set(data) - _ALLOWED_KEYS
        if unknown:
            raise LabelConfigError(
                f"{where}: unknown label key(s) {sorted(unknown)}; allowed: {sorted(_ALLOWED_KEYS)}"
            )

        flags: dict[str, bool] = {}
        for name in _BOOL_FIELDS:
            value = data.get(name, False)
            if not isinstance(value, bool):
                raise LabelConfigError(f"{where}: '{name}' must be true or false, got {value!r}")
            flags[name] = value

        return cls(**flags, trusted_fields=_parse_trusted_fields(data.get("trusted_fields"), where))

    def tightened_by_annotations(self, annotations: Any) -> ToolLabels:
        """Return labels made stricter by a server's ``ToolAnnotations``; never looser.

        Only hints the server set explicitly count (``None`` means "not stated"):

        - ``destructiveHint: true`` → ``irreversible``
        - ``openWorldHint: true`` → ``untrusted`` (output comes from outside the user's control)
        - ``openWorldHint: true`` and not ``readOnlyHint: true`` → also ``sink`` (writes to the world)

        ``readOnlyHint``, ``idempotentHint`` and any ``false`` value are ignored, because they could
        only loosen labels. ``trusted_fields`` is never extended by annotations.
        """
        if annotations is None:
            return self

        destructive = _hint(annotations, "destructive_hint", "destructiveHint")
        open_world = _hint(annotations, "open_world_hint", "openWorldHint")
        read_only = _hint(annotations, "read_only_hint", "readOnlyHint")

        return replace(
            self,
            irreversible=self.irreversible or destructive is True,
            untrusted=self.untrusted or open_world is True,
            sink=self.sink or (open_world is True and read_only is not True),
        )

    def is_at_least_as_strict_as(self, other: ToolLabels) -> bool:
        """True if every protection in ``other`` is also present here.

        Fewer trusted fields is stricter, since trusted fields exempt data from taint.
        """
        return (
            all(getattr(self, n) or not getattr(other, n) for n in _BOOL_FIELDS)
            and self.trusted_fields <= other.trusted_fields
        )


#: Labels for tools not listed in the config: assume the worst (attacker-controlled output that
#: can also carry data out). The proxy logs a warning when it falls back to these.
UNKNOWN_TOOL = ToolLabels(untrusted=True, sink=True, known=False)


def _parse_trusted_fields(value: Any, where: str) -> frozenset[str]:
    if value is None:
        return frozenset()
    if isinstance(value, str) or not isinstance(value, Iterable):
        raise LabelConfigError(f"{where}: 'trusted_fields' must be a list of strings, got {value!r}")
    items = list(value)
    bad = [v for v in items if not isinstance(v, str) or not v]
    if bad:
        raise LabelConfigError(f"{where}: 'trusted_fields' entries must be non-empty strings, got {bad!r}")
    return frozenset(items)


def _hint(annotations: Any, snake: str, camel: str) -> bool | None:
    """Read one annotation hint from a model object or a raw mapping; non-bools count as unset."""
    if isinstance(annotations, Mapping):
        value = annotations.get(camel, annotations.get(snake))
    else:
        value = getattr(annotations, snake, None)
    return value if isinstance(value, bool) else None
