"""Tool-description scanning (poisoning) and pinning (rug pulls).

Tool names, descriptions and input schemas come from upstream servers and are untrusted, yet the
agent reads them as instructions. ``scan_tool`` looks for the known poisoning patterns; any finding
quarantines the tool (rule R0). ``PinStore`` records a hash of each approved definition so a later
change is detected and quarantined until an operator re-approves it.

The scanner is heuristic and evadable (see CLAUDE.md section 12); it is tuned so that ordinary,
real-world descriptions produce zero findings, because a false finding hides a working tool.

Pure and synchronous (no MCP or I/O). ``PinStore`` serialises to/from JSON text; the proxy owns the
file.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

MAX_DESCRIPTION_CHARS = 2000
_SNIPPET_CHARS = 80

# --- hidden characters ---------------------------------------------------------------------------

_HIDDEN_RANGES = (
    (0x00AD, 0x00AD),  # soft hyphen
    (0x180E, 0x180E),  # Mongolian vowel separator
    (0x200B, 0x200F),  # zero-width space/joiners, LRM/RLM
    (0x202A, 0x202E),  # bidi embedding/override
    (0x2060, 0x2064),  # word joiner, invisible operators
    (0x2066, 0x2069),  # bidi isolates
    (0xFEFF, 0xFEFF),  # zero-width no-break space / BOM
    (0xE0000, 0xE007F),  # Unicode tag characters (can smuggle invisible ASCII)
)


def _is_hidden(ch: str) -> bool:
    cp = ord(ch)
    return any(lo <= cp <= hi for lo, hi in _HIDDEN_RANGES)


def _visible(text: str) -> str:
    """Text as patterns should see it: hidden chars removed, NFKC-folded (fullwidth → ASCII)."""
    return unicodedata.normalize("NFKC", "".join(ch for ch in text if not _is_hidden(ch)))


# --- patterns ------------------------------------------------------------------------------------


def _rx(*patterns: str) -> list[re.Pattern[str]]:
    return [re.compile(p, re.IGNORECASE | re.DOTALL) for p in patterns]


_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "override_instructions": _rx(
        r"\b(ignore|disregard|forget|override)\s+(all\s+|any\s+)?(of\s+)?(the\s+|your\s+)?"
        r"(previous|prior|above|earlier|preceding|system|original)\s+"
        r"(instructions?|prompts?|rules|directions|messages?)",
        r"\bnew\s+(system\s+)?instructions?\s*:",
        r"\binstead\s+of\s+(what|doing\s+what)\s+the\s+user\s+(asked|requested|wants)",
    ),
    "fake_tag": _rx(
        r"<\s*/?\s*(important|system|instructions?|admin|critical|secret|hidden|sys|assistant)\b[^>]*>",
        r"\[\s*(system|important|admin|instructions?)\s*\]",
        r"<!--",
        r"^\s*#{1,6}\s*(system|instructions?)\b",
    ),
    "concealment": _rx(
        r"\b(do\s+not|don'?t|never|must\s+not)\s+(tell|inform|mention|reveal|show|notify|alert|disclose)"
        r"\b.{0,30}?\b(user|human)\b",
        r"\b(do\s+not|don'?t|never)\s+(mention|tell|reveal|disclose)\s+(that|this|it|anything)\b",
        r"\bwithout\s+(telling|informing|notifying|alerting|asking)\s+(the\s+)?(user|human)",
        r"\b(the\s+)?user\s+(must|should|need|needs)\s+not\s+(know|see|notice|be\s+told)",
        r"\bkeep\s+(this|it)\s+(a\s+)?(secret|hidden|confidential|between\s+us)",
        r"\b(silently|secretly|covertly|quietly)\s+(send|forward|upload|copy|include|add|attach|read"
        r"|exfiltrate|post|bcc|cc)\b",
    ),
    "secret_file": _rx(
        r"~?/?\.ssh\b",
        r"\bid_(rsa|dsa|ecdsa|ed25519)\b",
        r"\.aws/credentials",
        r"/etc/(passwd|shadow)\b",
        r"\.git-credentials|\.netrc\b|\.npmrc\b|\.pypirc\b|\.kube/config",
        r"\bmcp\.json\b|claude_desktop_config|\.cursor/",
        r"\bwallet\.dat\b",
        r"(?<![\w.])\.env\b",
    ),
    "role_manipulation": _rx(
        r"\byou\s+are\s+now\b",
        r"\bfrom\s+now\s+on\b",
        r"\bact\s+as\s+(a|an|the|if)\b",
        r"\bpretend\s+(to\s+be|you)\b",
        r"\byour\s+(new\s+)?(role|task|job|goal|purpose|objective)\s+is\b",
        r"\b(developer|god|admin|jailbreak|dan)\s+mode\b",
        r"\b(the\s+)?(assistant|ai|model|llm)\s+(must|should|will)\s+(always|now|never)\b",
    ),
    "tool_shadowing": _rx(
        r"\bwhen\s+this\s+tool\s+is\s+(available|present|installed|loaded|enabled)",
        r"\b(all|every|any)\s+(other\s+)?tools?\s+(must|should)\b",
        r"\b(all|every)\s+(emails?|messages?|requests?|files?)\s+(must|should)\s+(also\s+)?(be\s+)?"
        r"(sent|forwarded|copied|cc'?d|bcc'?d|routed)",
        r"\b(modif|chang|overrid)\w*\s+(the\s+)?behaviou?r\s+of\b",
    ),
}

_EMAIL_RE = re.compile(r"[a-z0-9._%+-]+@((?:[a-z0-9-]+\.)+[a-z]{2,})", re.IGNORECASE)
_SEND_URL_RE = re.compile(
    r"\b(send|forward|post|upload|transmit|exfiltrat|report|bcc|cc|copy)\w*\b[^\n]{0,60}?(https?://[^\s\"'<>]+)",
    re.IGNORECASE,
)
_PLACEHOLDER_DOMAIN_RE = re.compile(r"(^|\.)(example\.(com|org|net)|example|test|localhost|invalid)$")

# Schema keys whose string values are machine syntax, not prose.
_SCHEMA_SKIP_KEYS = frozenset({"pattern", "format", "type", "$ref", "$schema", "$id"})


# --- findings ------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Finding:
    kind: str
    location: str  # "name", "description" or "input_schema.<path>"
    snippet: str  # <= 80 chars, hidden characters shown as \\u escapes

    def __str__(self) -> str:
        return f"{self.kind} in {self.location}: {self.snippet!r}"


def scan_tool(
    name: str,
    description: str | None,
    input_schema: Mapping[str, Any] | None = None,
    *,
    other_tool_names: Iterable[str] = (),
) -> list[Finding]:
    """Scan one tool's metadata and return every finding (empty list = clean).

    ``other_tool_names`` are tools on *other* upstream servers (bare and/or namespaced). A description
    that names one of them is trying to influence a different server's tool (cross-tool shadowing).
    Only identifier-like names (containing ``_``, ``-`` or a namespace) are matched, since plain words
    such as "search" appear in normal prose.
    """
    findings: list[Finding] = []
    others = [n for n in set(other_tool_names) if n != name and re.search(r"[_\-]", n)]

    findings += _scan_hidden(name, "name")
    findings += _scan_text(description or "", "description", others, check_length=True)
    for location, text in _schema_strings(input_schema or {}, "input_schema"):
        findings += _scan_text(text, location, others, check_length=True)
    return findings


def quarantine_reason(findings: Iterable[Finding]) -> str:
    """One-line summary for R0 and the audit log."""
    kinds = sorted({f.kind for f in findings})
    return "suspicious tool metadata (" + ", ".join(kinds) + ")"


def _scan_text(text: str, location: str, other_tools: list[str], *, check_length: bool) -> list[Finding]:
    findings = _scan_hidden(text, location)
    visible = _visible(text)

    if check_length and len(visible) > MAX_DESCRIPTION_CHARS:
        findings.append(Finding("excessive_length", location, f"{len(visible)} characters"))

    for kind, patterns in _PATTERNS.items():
        for pattern in patterns:
            match = pattern.search(visible)
            if match:
                findings.append(Finding(kind, location, _snippet(match.group(0))))
                break

    for match in _EMAIL_RE.finditer(visible):
        if not _PLACEHOLDER_DOMAIN_RE.search(match.group(1).lower()):
            findings.append(Finding("hardcoded_recipient", location, _snippet(match.group(0))))
            break
    for match in _SEND_URL_RE.finditer(visible):
        host = re.sub(r"^https?://", "", match.group(2)).split("/")[0].split(":")[0].lower()
        if not _PLACEHOLDER_DOMAIN_RE.search(host):
            findings.append(Finding("hardcoded_recipient", location, _snippet(match.group(0))))
            break

    lowered = visible.lower()
    for other in other_tools:
        if re.search(rf"(?<![\w-]){re.escape(other.lower())}(?![\w-])", lowered):
            findings.append(Finding("tool_shadowing", location, f"mentions other server's tool '{other}'"))
            break

    return findings


def _scan_hidden(text: str, location: str) -> list[Finding]:
    hidden = [ch for ch in text if _is_hidden(ch)]
    if not hidden:
        return []
    # Decoded tag-character text goes first: it is the most useful part for a human reviewer.
    smuggled = "".join(chr(ord(ch) - 0xE0000) for ch in hidden if 0xE0020 <= ord(ch) <= 0xE007E)
    if smuggled:
        detail = f"tag text {_snippet(smuggled)[:48]!r}; {len(hidden)} hidden char(s)"
    else:
        codes = sorted({f"U+{ord(ch):04X}" for ch in hidden})
        detail = f"{len(hidden)} hidden character(s): {', '.join(codes[:5])}"
    return [Finding("hidden_unicode", location, detail[:_SNIPPET_CHARS])]


def _schema_strings(node: Any, path: str) -> Iterator[tuple[str, str]]:
    """Every prose string in a JSON Schema: values and property names, with a dotted location."""
    if isinstance(node, Mapping):
        for key, value in node.items():
            key = str(key)
            child = f"{path}.{key}"
            if path.endswith(".properties"):
                yield child, key  # property names are shown to the model too
            if key in _SCHEMA_SKIP_KEYS:
                continue
            yield from _schema_strings(value, child)
    elif isinstance(node, list):
        for i, item in enumerate(node):
            yield from _schema_strings(item, f"{path}[{i}]")
    elif isinstance(node, str):
        yield path, node


def _snippet(text: str) -> str:
    text = " ".join(text.split())
    return text if len(text) <= _SNIPPET_CHARS else text[: _SNIPPET_CHARS - 1] + "…"


# --- pinning -------------------------------------------------------------------------------------


def fingerprint(
    name: str,
    description: str | None,
    input_schema: Mapping[str, Any] | None = None,
    annotations: Mapping[str, Any] | None = None,
) -> str:
    """SHA-256 over a canonical JSON form of everything the model sees about the tool."""
    canonical = json.dumps(
        {
            "name": name,
            "description": description or "",
            "input_schema": input_schema or {},
            "annotations": annotations or {},
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class PinStatus(Enum):
    NEW = "new"  # first sighting; now pinned
    MATCH = "match"  # same as pinned
    CHANGED = "changed"  # differs from pinned: possible rug pull


@dataclass(frozen=True)
class PinResult:
    status: PinStatus
    pinned: str
    current: str

    @property
    def reason(self) -> str | None:
        if self.status is not PinStatus.CHANGED:
            return None
        return (
            f"definition changed since it was pinned (sha256 {self.pinned[:12]}… → {self.current[:12]}…); "
            "possible rug pull, re-approve with 'mcpfw pins --reset'"
        )


@dataclass
class PinStore:
    """Map of namespaced tool name → pinned fingerprint.

    A changed definition is *not* re-pinned automatically: it stays quarantined until ``reset``.
    """

    pins: dict[str, str] = field(default_factory=dict)

    def check(self, key: str, current: str) -> PinResult:
        pinned = self.pins.get(key)
        if pinned is None:
            self.pins[key] = current
            return PinResult(PinStatus.NEW, current, current)
        if pinned == current:
            return PinResult(PinStatus.MATCH, pinned, current)
        return PinResult(PinStatus.CHANGED, pinned, current)

    def reset(self, key: str) -> bool:
        """Forget a pin so the next sighting re-pins it. Returns False if it was not pinned."""
        return self.pins.pop(key, None) is not None

    def to_json(self) -> str:
        return json.dumps({"version": 1, "pins": dict(sorted(self.pins.items()))}, indent=2)

    @classmethod
    def from_json(cls, text: str) -> PinStore:
        data = json.loads(text)
        if (
            not isinstance(data, Mapping)
            or data.get("version") != 1
            or not isinstance(data.get("pins"), Mapping)
        ):
            raise ValueError('pins file must look like {"version": 1, "pins": {...}}')
        pins = data["pins"]
        bad = [k for k, v in pins.items() if not (isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v))]
        if bad:
            raise ValueError(f"pins file has invalid fingerprints for: {sorted(bad)[:5]}")
        return cls(dict(pins))
