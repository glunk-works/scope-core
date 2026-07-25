import pytest

from scope_core.rules import ScopeRules
from scope_core.validate import ScopeViolation, is_action_banned, is_in_scope, validate_target


def test_empty_in_scope_denies_everything() -> None:
    rules = ScopeRules()
    with pytest.raises(ScopeViolation):
        validate_target(rules, "example.com")


def test_in_scope_match_allows() -> None:
    rules = ScopeRules(in_scope_regex=[r"^example\.com$"])
    assert validate_target(rules, "example.com") is None


def test_no_in_scope_match_denies() -> None:
    rules = ScopeRules(in_scope_regex=[r"^example\.com$"])
    with pytest.raises(ScopeViolation):
        validate_target(rules, "other.com")


def test_out_of_scope_vetoes_even_when_in_scope_also_matches() -> None:
    rules = ScopeRules(
        in_scope_regex=[r"example\.com"],
        out_of_scope_regex=[r"^admin\.example\.com$"],
    )
    with pytest.raises(ScopeViolation) as exc_info:
        validate_target(rules, "admin.example.com")
    assert exc_info.value.candidate == "admin.example.com"


def test_violation_is_a_raise_not_a_falsy_return() -> None:
    rules = ScopeRules()
    try:
        result = validate_target(rules, "x")
    except ScopeViolation:
        pass
    else:
        pytest.fail(f"validate_target should have raised, returned {result!r} instead")


def test_allowed_candidate_returns_none() -> None:
    rules = ScopeRules(in_scope_regex=[r".*"])
    assert validate_target(rules, "anything") is None


def test_scope_violation_reason_distinguishes_veto_from_no_match() -> None:
    out_of_scope_rules = ScopeRules(in_scope_regex=[r".*"], out_of_scope_regex=[r"^admin\."])
    with pytest.raises(ScopeViolation) as out_of_scope_exc:
        validate_target(out_of_scope_rules, "admin.example.com")
    assert "out-of-scope" in out_of_scope_exc.value.reason

    no_match_rules = ScopeRules(in_scope_regex=[r"^example\.com$"])
    with pytest.raises(ScopeViolation) as no_match_exc:
        validate_target(no_match_rules, "other.com")
    assert "in-scope" in no_match_exc.value.reason


def test_unanchored_in_scope_pattern_matches_a_superstring_host() -> None:
    # Documented behavior, not a bug: `validate_target` matches via
    # `re.search`, so an unanchored pattern matches anywhere in the
    # candidate. An operator relying on exact-host scope must anchor their
    # pattern (`^example\.com$`) -- this pins the documented contract so a
    # future change to the matching semantics can't silently drift.
    rules = ScopeRules(in_scope_regex=[r"example\.com"])
    assert validate_target(rules, "example.com.attacker.net") is None


def test_is_action_banned_true() -> None:
    rules = ScopeRules(banned_actions=["destructive_wipe"])
    assert is_action_banned(rules, "destructive_wipe") is True


def test_is_action_banned_false() -> None:
    rules = ScopeRules(banned_actions=["destructive_wipe"])
    assert is_action_banned(rules, "read_only_scan") is False


def test_is_action_banned_never_raises_on_empty_rules() -> None:
    rules = ScopeRules()
    assert is_action_banned(rules, "anything") is False


def test_is_in_scope_true_on_in_scope_match() -> None:
    rules = ScopeRules(in_scope_regex=[r"^example\.com$"])
    assert is_in_scope(rules, "example.com") is True


def test_is_in_scope_false_on_no_in_scope_match() -> None:
    rules = ScopeRules(in_scope_regex=[r"^example\.com$"])
    assert is_in_scope(rules, "other.com") is False


def test_is_in_scope_false_on_out_of_scope_veto() -> None:
    rules = ScopeRules(
        in_scope_regex=[r"example\.com"],
        out_of_scope_regex=[r"^admin\.example\.com$"],
    )
    assert is_in_scope(rules, "admin.example.com") is False


def test_is_in_scope_false_on_empty_in_scope() -> None:
    rules = ScopeRules()
    assert is_in_scope(rules, "example.com") is False


def test_is_in_scope_never_raises() -> None:
    rules = ScopeRules()
    # A candidate that would raise `ScopeViolation` from `validate_target`
    # must just return False here -- that's the whole point of the
    # non-raising predicate for bulk-filter callers.
    assert is_in_scope(rules, "anything") is False


def test_is_in_scope_and_validate_target_agree_across_a_case_matrix() -> None:
    # Parity: `is_in_scope`'s boolean and `validate_target`'s raise/no-raise
    # must decide identically for every case, since `validate_target` is
    # now defined in terms of `is_in_scope` for the in-scope half.
    cases = [
        (ScopeRules(), "example.com"),
        (ScopeRules(in_scope_regex=[r"^example\.com$"]), "example.com"),
        (ScopeRules(in_scope_regex=[r"^example\.com$"]), "other.com"),
        (ScopeRules(in_scope_regex=[r".*"]), "anything"),
        (
            ScopeRules(in_scope_regex=[r"example\.com"], out_of_scope_regex=[r"^admin\."]),
            "admin.example.com",
        ),
        (
            ScopeRules(in_scope_regex=[r"example\.com"], out_of_scope_regex=[r"^admin\."]),
            "www.example.com",
        ),
    ]
    for rules, candidate in cases:
        allowed = is_in_scope(rules, candidate)
        if allowed:
            assert validate_target(rules, candidate) is None
        else:
            with pytest.raises(ScopeViolation):
                validate_target(rules, candidate)
