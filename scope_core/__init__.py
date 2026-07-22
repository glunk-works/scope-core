"""scope-core: shared scope-enforcement and ingestion-sanitization
primitives for glunk-works bounty tooling (loop-orchestrator, bounty-infra).

A pure leaf package: no I/O, no credentials, no framework coupling, no
runtime import outside the standard library and pydantic (enforced by
`tests/test_boundary.py`).
"""

from scope_core.rules import ScopeRules
from scope_core.sanitize import DEFAULT_MAX_LEN, sanitize
from scope_core.validate import ScopeViolation, is_action_banned, validate_target

__all__ = [
    "DEFAULT_MAX_LEN",
    "ScopeRules",
    "ScopeViolation",
    "is_action_banned",
    "sanitize",
    "validate_target",
]
