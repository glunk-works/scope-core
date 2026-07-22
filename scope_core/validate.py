"""The structural scope check -- a fail-closed allowlist over `ScopeRules`,
plus the pure banned-action classifier.
"""

from __future__ import annotations

from scope_core.rules import ScopeRules


class ScopeViolation(Exception):
    """Raised by `validate_target` when a candidate is out of scope.

    Carries the candidate and the vetoing reason so a caller can surface it
    as a gate/escalation signal without re-deriving why the check failed.
    """

    def __init__(self, candidate: str, reason: str) -> None:
        # `candidate` is embedded verbatim (not run through
        # `scope_core.sanitize`) -- within the plan's stated bound (the
        # candidate is already caller-held), but a caller logging a
        # ScopeViolation raised from attacker-influenceable candidate text
        # should sanitize it first if that log is displayed/terminal-rendered.
        self.candidate = candidate
        self.reason = reason
        super().__init__(f"{candidate!r} is out of scope: {reason}")


def validate_target(rules: ScopeRules, candidate: str) -> None:
    """Fail-closed allowlist: allowed iff >=1 in-scope match AND 0
    out-of-scope matches. An out-of-scope match always vetoes (deny wins),
    and an empty `in_scope_regex` denies everything. Raises `ScopeViolation`
    on any denial; never returns a falsy value, never silently no-ops.

    Patterns are matched via `re.search` (substring, not implicitly
    anchored) -- an `in_scope_regex`/`out_of_scope_regex` entry like
    `example\\.com` also matches `example.com.attacker.net`. Operators
    writing rules-of-engagement patterns that must match a whole host
    exactly should anchor them (`^example\\.com$`).
    """
    for pattern in rules._out_of_scope_compiled:
        if pattern.search(candidate):
            raise ScopeViolation(candidate, "matched an out-of-scope rule")
    if not any(pattern.search(candidate) for pattern in rules._in_scope_compiled):
        raise ScopeViolation(candidate, "no in-scope rule matched")


def is_action_banned(rules: ScopeRules, action: str) -> bool:
    """Pure classifier: is `action` in this target's banned-actions list.

    No raise, no escalation -- the reject-vs-escalate policy belongs to
    whichever consumer issues actions, not this leaf primitive.
    """
    return action in rules.banned_actions
