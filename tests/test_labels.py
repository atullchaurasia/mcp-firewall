from __future__ import annotations

import itertools
from dataclasses import dataclass

import pytest

from mcpfw.labels import UNKNOWN_TOOL, LabelConfigError, ToolLabels

HINT_VALUES = (None, True, False)


@dataclass
class FakeAnnotations:
    """Stand-in for mcp_types.ToolAnnotations (snake_case attributes), keeping this test MCP-free."""

    read_only_hint: bool | None = None
    destructive_hint: bool | None = None
    idempotent_hint: bool | None = None
    open_world_hint: bool | None = None


def all_label_combos():
    for untrusted, private, sink, irreversible in itertools.product((False, True), repeat=4):
        for fields in (frozenset(), frozenset({"from", "to"})):
            yield ToolLabels(untrusted, private, sink, irreversible, fields)


def all_annotation_combos():
    for ro, de, idem, ow in itertools.product(HINT_VALUES, repeat=4):
        yield FakeAnnotations(ro, de, idem, ow)


# --- from_config ---------------------------------------------------------------------------------


def test_from_config_full():
    labels = ToolLabels.from_config({"untrusted": True, "trusted_fields": ["from", "to", "date"]})
    assert labels == ToolLabels(untrusted=True, trusted_fields=frozenset({"from", "to", "date"}))
    assert labels.known


@pytest.mark.parametrize("data", [{}, None])
def test_from_config_empty_means_benign(data):
    labels = ToolLabels.from_config(data)
    assert not (labels.untrusted or labels.private or labels.sink or labels.irreversible)
    assert labels.trusted_fields == frozenset()


@pytest.mark.parametrize(
    "data, message",
    [
        ({"sinc": True}, "unknown label key"),
        ({"sink": "yes"}, "'sink' must be true or false"),
        ({"private": 1}, "'private' must be true or false"),
        ({"trusted_fields": "from"}, "must be a list of strings"),
        ({"trusted_fields": ["from", 3]}, "non-empty strings"),
        ({"trusted_fields": [""]}, "non-empty strings"),
        (["untrusted"], "must be a mapping"),
    ],
)
def test_from_config_rejects_malformed(data, message):
    with pytest.raises(LabelConfigError, match=message) as exc:
        ToolLabels.from_config(data, where="workspace__send_email")
    assert "workspace__send_email" in str(exc.value)


# --- UNKNOWN_TOOL ----------------------------------------------------------------------------------


def test_unknown_tool_is_worst_case():
    assert UNKNOWN_TOOL.untrusted and UNKNOWN_TOOL.sink
    assert not UNKNOWN_TOOL.known
    assert UNKNOWN_TOOL.trusted_fields == frozenset()


# --- annotations: tighten ------------------------------------------------------------------------


def test_destructive_hint_makes_irreversible():
    assert ToolLabels().tightened_by_annotations(FakeAnnotations(destructive_hint=True)).irreversible


def test_open_world_makes_untrusted_and_sink():
    labels = ToolLabels().tightened_by_annotations(FakeAnnotations(open_world_hint=True))
    assert labels.untrusted and labels.sink


def test_open_world_read_only_is_untrusted_but_not_sink():
    labels = ToolLabels().tightened_by_annotations(FakeAnnotations(open_world_hint=True, read_only_hint=True))
    assert labels.untrusted and not labels.sink


def test_raw_mapping_camel_case_annotations():
    labels = ToolLabels().tightened_by_annotations({"destructiveHint": True, "openWorldHint": True})
    assert labels.irreversible and labels.untrusted and labels.sink


def test_unset_hints_change_nothing():
    base = ToolLabels(private=True)
    assert base.tightened_by_annotations(FakeAnnotations()) == base
    assert base.tightened_by_annotations(None) == base


def test_non_bool_hint_values_are_ignored():
    base = ToolLabels()
    assert base.tightened_by_annotations({"destructiveHint": "true", "openWorldHint": 1}) == base


# --- annotations: never loosen -------------------------------------------------------------------


def test_read_only_hint_cannot_remove_sink_or_irreversible():
    base = ToolLabels(sink=True, irreversible=True)
    labels = base.tightened_by_annotations(
        FakeAnnotations(read_only_hint=True, destructive_hint=False, open_world_hint=False)
    )
    assert labels == base


def test_unknown_tool_stays_worst_case_under_any_annotations():
    for ann in all_annotation_combos():
        labels = UNKNOWN_TOOL.tightened_by_annotations(ann)
        assert labels.is_at_least_as_strict_as(UNKNOWN_TOOL)
        assert not labels.known


def test_annotations_never_loosen_exhaustive():
    """Every label combination x every annotation combination: result is at least as strict."""
    for base in all_label_combos():
        for ann in all_annotation_combos():
            result = base.tightened_by_annotations(ann)
            assert result.is_at_least_as_strict_as(base), (base, ann, result)
            assert result.trusted_fields == base.trusted_fields
            assert result.known == base.known


def test_real_mcp_tool_annotations_model():
    """Same behavior with the real SDK model (only the test imports MCP, the module does not)."""
    mcp_types = pytest.importorskip("mcp_types")
    ann = mcp_types.ToolAnnotations(readOnlyHint=True, destructiveHint=True)
    labels = ToolLabels(sink=True).tightened_by_annotations(ann)
    assert labels.sink and labels.irreversible


# --- strictness helper ---------------------------------------------------------------------------


def test_is_at_least_as_strict_as():
    assert ToolLabels(sink=True).is_at_least_as_strict_as(ToolLabels())
    assert not ToolLabels().is_at_least_as_strict_as(ToolLabels(sink=True))
    # Adding trusted fields loosens.
    assert not ToolLabels(trusted_fields=frozenset({"from"})).is_at_least_as_strict_as(ToolLabels())
