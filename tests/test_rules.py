import re

import pytest
from pydantic import ValidationError

from scope_core.rules import ScopeRules


class _StubTarget:
    """A structurally-shaped stand-in for a caller's own rules-of-engagement
    row -- proves `from_target` reads via the `_HasRulesOfEngagement`
    protocol rather than requiring any concrete class."""

    def __init__(
        self,
        in_scope_regex: list[str],
        out_of_scope_regex: list[str],
        banned_actions: list[str],
    ) -> None:
        self.in_scope_regex = in_scope_regex
        self.out_of_scope_regex = out_of_scope_regex
        self.banned_actions = banned_actions


def test_defaults_are_empty() -> None:
    rules = ScopeRules()
    assert rules.in_scope_regex == []
    assert rules.out_of_scope_regex == []
    assert rules.banned_actions == []


def test_extra_field_forbidden() -> None:
    with pytest.raises(ValidationError):
        ScopeRules(unexpected="nope")


def test_frozen_rejects_mutation() -> None:
    rules = ScopeRules(in_scope_regex=["a"])
    with pytest.raises(ValidationError):
        rules.in_scope_regex = ["b"]


def test_invalid_regex_fails_at_construction() -> None:
    with pytest.raises(ValidationError):
        ScopeRules(in_scope_regex=["[unterminated"])


def test_invalid_out_of_scope_regex_also_fails_at_construction() -> None:
    with pytest.raises(ValidationError):
        ScopeRules(out_of_scope_regex=["(unterminated"])


def test_patterns_compiled_once_at_construction() -> None:
    rules = ScopeRules(in_scope_regex=[r"\d+"], out_of_scope_regex=[r"admin"])
    assert all(isinstance(p, re.Pattern) for p in rules._in_scope_compiled)
    assert all(isinstance(p, re.Pattern) for p in rules._out_of_scope_compiled)


def test_from_target_maps_a_structurally_shaped_source() -> None:
    stub = _StubTarget(
        in_scope_regex=[r"^example\.com$"],
        out_of_scope_regex=[r"^admin\.example\.com$"],
        banned_actions=["destructive_wipe"],
    )
    rules = ScopeRules.from_target(stub)
    assert rules.in_scope_regex == [r"^example\.com$"]
    assert rules.out_of_scope_regex == [r"^admin\.example\.com$"]
    assert rules.banned_actions == ["destructive_wipe"]


def test_from_target_copies_lists_not_aliases() -> None:
    stub = _StubTarget(in_scope_regex=["a"], out_of_scope_regex=[], banned_actions=[])
    rules = ScopeRules.from_target(stub)
    stub.in_scope_regex.append("b")
    assert rules.in_scope_regex == ["a"]
