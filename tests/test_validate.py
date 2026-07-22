import pytest

from scope_core.rules import ScopeRules
from scope_core.validate import ScopeViolation, is_action_banned, validate_target


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
