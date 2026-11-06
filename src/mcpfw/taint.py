"""Provenance ("taint") tracking at the tool boundary.

The firewall cannot see inside the model, so it tracks provenance from outside: it records which
*atoms* (identifiers an attacker must control to exfiltrate data) entered the agent's context from
trusted vs untrusted sources, and fingerprints private outputs so they can be recognised if they later
appear in a sink call's arguments.

- **Atoms**: emails (+ their domain), URLs (+ their host), bare domains, numbers with >= 8 digits.
  Normalised to lowercase, ``www.`` stripped, numbers reduced to digits only.
- **Private fingerprints**: 6-word shingles and long numbers taken from private outputs.

Pure and synchronous (no MCP or I/O), so it is unit-testable in isolation.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from mcpfw.labels import ToolLabels

SHINGLE_SIZE = 6
MIN_NUMBER_DIGITS = 8
USER_TASK_SOURCE = "user_task"

_EMAIL_RE = re.compile(r"[a-z0-9._%+-]+@((?:[a-z0-9-]+\.)+[a-z]{2,})")
_URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s<>\"'`]+")
_URL_TRAILING = ".,;:!?)]}'\""
_DOMAIN_RE = re.compile(
    r"(?<![\w@.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24}))(?!\.?[\w@-])"
)
# Digit groups joined by single spaces or hyphens, so "4111 1111 1111 1111" is one number.
_NUMBER_RE = re.compile(r"(?<![a-z0-9.])\d(?:[ -]?\d)*(?![a-z0-9])")
_DIGIT_RUN_RE = re.compile(r"\d+")
_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}|\d{2}-\d{2}-\d{4}")
_WORD_RE = re.compile(r"\w+")

# Bare domains (no scheme, no @) are only recognised for these TLDs, because "self.data" or
# "config.yaml" in ordinary text must not become atoms (a false atom can trigger a BLOCK). Domains
# inside URLs and email addresses are always recognised, whatever their TLD.
_BARE_GTLDS = frozenset(
    "com net org edu gov mil int info biz xyz online site tech store cloud io ai co".split()
)
# Two-letter labels that are ccTLDs but far more often file extensions or code tokens.
_NOT_BARE_TLDS = frozenset("py md sh rs pl js ts gz so id cs db rb go ml mm hs".split())


# --- atom extraction -----------------------------------------------------------------------------


def extract_atoms(text: str) -> set[str]:
    """Return the normalised atoms found in ``text``.

    Emails also yield their domain and URLs their host, so a destination is caught even when the
    attacker varies the local part or path (``x@evil.co`` vs ``y@evil.co``).
    """
    text = text.lower()
    atoms: set[str] = set()

    for match in _EMAIL_RE.finditer(text):
        domain = _strip_www(match.group(1))
        local = match.group(0)[: -len(match.group(1))]
        atoms.add(local + domain)
        atoms.add(domain)

    for match in _URL_RE.finditer(text):
        url = match.group(0).rstrip(_URL_TRAILING).rstrip("/")
        atoms.add(url)
        try:
            host = urlsplit(url).hostname
        except ValueError:
            host = None
        if host:
            atoms.add(_strip_www(host))

    for match in _DOMAIN_RE.finditer(text):
        tld = match.group(2)
        if tld in _BARE_GTLDS or (len(tld) == 2 and tld not in _NOT_BARE_TLDS):
            atoms.add(_strip_www(match.group(1)))

    atoms.update(extract_numbers(text))
    return atoms


def extract_numbers(text: str) -> set[str]:
    """Numbers with >= 8 digits, as digits only.

    Both the separator-joined form and each unbroken digit run are returned, so formatting
    differences ("4111 1111 1111 1111" vs "4111111111111111") and accidental joins of two adjacent
    numbers both still match. A match that is exactly a dash date (2026-11-06) is skipped.
    """
    numbers: set[str] = set()
    for match in _NUMBER_RE.finditer(text):
        raw = match.group(0)
        if _DATE_RE.fullmatch(raw):
            continue
        joined = re.sub(r"[ -]", "", raw)
        if len(joined) >= MIN_NUMBER_DIGITS:
            numbers.add(joined)
        numbers.update(r for r in _DIGIT_RUN_RE.findall(raw) if len(r) >= MIN_NUMBER_DIGITS)
    return numbers


def _strip_www(host: str) -> str:
    return host[4:] if host.startswith("www.") else host


# --- text helpers --------------------------------------------------------------------------------


def shingles(text: str, n: int = SHINGLE_SIZE) -> set[str]:
    """Sliding windows of ``n`` lowercase words. Texts shorter than ``n`` words yield nothing."""
    words = _WORD_RE.findall(text.lower())
    return {" ".join(words[i : i + n]) for i in range(len(words) - n + 1)}


def flatten_strings(value: Any) -> list[str]:
    """All strings in a JSON-like value: str leaves, dict keys, and ints/floats as text.

    Keys are included because an upstream server could echo attacker text into them.
    """
    return list(_walk(value))


def _walk(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, bool) or value is None:
        return
    elif isinstance(value, (int, float)):
        yield str(value)
    elif isinstance(value, Mapping):
        for key, item in value.items():
            yield str(key)
            yield from _walk(item)
    elif isinstance(value, Iterable) and not isinstance(value, (bytes, bytearray)):
        for item in value:
            yield from _walk(item)


def split_trusted_fields(value: Any, trusted_fields: Iterable[str]) -> tuple[list[str], list[str]]:
    """Split a JSON-like value into (trusted strings, untrusted strings).

    Any dict key listed in ``trusted_fields``, at any depth, makes its whole subtree trusted (e.g.
    ``from``/``to`` of each email in an inbox list). Strings are never parsed here, so attacker text
    inside a body cannot fake a trusted key.
    """
    fields = frozenset(trusted_fields)
    trusted: list[str] = []
    untrusted: list[str] = []

    def visit(node: Any) -> None:
        if isinstance(node, Mapping):
            for key, item in node.items():
                if key in fields:
                    trusted.extend(_walk(item))
                else:
                    untrusted.append(str(key))
                    visit(item)
        elif isinstance(node, (list, tuple)):
            for item in node:
                visit(item)
        else:
            untrusted.extend(_walk(node))

    visit(value)
    return trusted, untrusted


def _maybe_parse_json(output: Any) -> Any:
    """Parse a top-level JSON string once, so trusted fields work for text-only tool results.

    Only the outermost string is parsed; nested strings stay opaque. Operators should only set
    ``trusted_fields`` on tools whose whole output is structured by the server.
    """
    if isinstance(output, str) and output.lstrip()[:1] in ("{", "["):
        try:
            return json.loads(output)
        except ValueError:
            return output
    return output


# --- ledger --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class PrivateLeak:
    """Evidence that sink arguments contain private data.

    Deliberately carries counts and source tools only, never the private text itself, so it can be
    logged safely.
    """

    shingle_hits: int
    number_hits: int
    sources: frozenset[str]


@dataclass
class TaintLedger:
    """Per-session record of where data in the agent's context came from.

    Atom and fingerprint stores are excluded from ``repr`` because atoms can themselves be private
    (an account number or address from a private file); only source tool names are shown.
    """

    trusted_atoms: set[str] = field(default_factory=set, repr=False)
    tainted_atoms: dict[str, set[str]] = field(default_factory=dict, repr=False)  # atom -> sources
    untrusted_sources: dict[str, None] = field(default_factory=dict)  # ordered set
    private_sources: dict[str, None] = field(default_factory=dict)  # ordered set
    _private_shingles: dict[str, set[str]] = field(default_factory=dict, repr=False)
    _private_numbers: dict[str, set[str]] = field(default_factory=dict, repr=False)

    @property
    def seen_untrusted(self) -> bool:
        return bool(self.untrusted_sources)

    @property
    def seen_private(self) -> bool:
        return bool(self.private_sources)

    def add_user_task(self, text: str) -> None:
        """The user's task text is a trust root: its atoms are trusted."""
        self._add_trusted([text])

    def record_output(self, tool: str, labels: ToolLabels, output: Any) -> None:
        """Record a tool's output.

        Untrusted output: atoms in ``trusted_fields`` are trusted, all others tainted by ``tool``.
        Otherwise every atom is trusted (e.g. a contacts list). Private output (whole output,
        including trusted fields) is fingerprinted for leak detection.
        """
        output = _maybe_parse_json(output)

        if labels.untrusted:
            trusted, untrusted = split_trusted_fields(output, labels.trusted_fields)
            self._add_trusted(trusted)
            for text in untrusted:
                for atom in extract_atoms(text):
                    self.tainted_atoms.setdefault(atom, set()).add(tool)
            self.untrusted_sources[tool] = None
        else:
            self._add_trusted(flatten_strings(output))

        if labels.private:
            for text in flatten_strings(output):
                for shingle in shingles(text):
                    self._private_shingles.setdefault(shingle, set()).add(tool)
                for number in extract_numbers(text.lower()):
                    self._private_numbers.setdefault(number, set()).add(tool)
            self.private_sources[tool] = None

    def tainted_only_atoms(self, args: Any) -> dict[str, frozenset[str]]:
        """Atoms in ``args`` that were seen only in untrusted content, mapped to their source tools.

        An atom that also came from a trusted source is not returned. Atoms never seen anywhere are
        not returned either (the agent may have invented or de-obfuscated them; R2 covers that).
        """
        found: dict[str, frozenset[str]] = {}
        for text in flatten_strings(args):
            for atom in extract_atoms(text):
                if atom in self.tainted_atoms and atom not in self.trusted_atoms:
                    found[atom] = frozenset(self.tainted_atoms[atom])
        return found

    def private_leak(self, args: Any) -> PrivateLeak | None:
        """Return evidence if ``args`` contain a private 6-word window or private long number."""
        shingle_hits = number_hits = 0
        sources: set[str] = set()
        for text in flatten_strings(args):
            for shingle in shingles(text):
                if shingle in self._private_shingles:
                    shingle_hits += 1
                    sources |= self._private_shingles[shingle]
            for number in extract_numbers(text.lower()):
                if number in self._private_numbers:
                    number_hits += 1
                    sources |= self._private_numbers[number]
        if not (shingle_hits or number_hits):
            return None
        return PrivateLeak(shingle_hits, number_hits, frozenset(sources))

    def _add_trusted(self, texts: Iterable[str]) -> None:
        for text in texts:
            self.trusted_atoms |= extract_atoms(text)
