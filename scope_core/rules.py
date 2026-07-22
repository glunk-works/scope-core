"""`ScopeRules` -- the frozen value object the scope validator decides
against. `from_target` reads a caller's rules-of-engagement
(`in_scope_regex`/`out_of_scope_regex`/`banned_actions`) via a structural
`Protocol`, not a concrete class -- any caller-held object with those three
list attributes satisfies it. This is what lets loop-orchestrator's Postgres
`targets` row and bounty-infra's S3-hosted RoE both be adapted without this
package importing either.
"""

from __future__ import annotations

import re
from typing import Protocol

from pydantic import BaseModel, ConfigDict, PrivateAttr, model_validator


class _HasRulesOfEngagement(Protocol):
    in_scope_regex: list[str]
    out_of_scope_regex: list[str]
    banned_actions: list[str]


class ScopeRules(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    in_scope_regex: list[str] = []
    out_of_scope_regex: list[str] = []
    banned_actions: list[str] = []

    _in_scope_compiled: list[re.Pattern[str]] = PrivateAttr(default_factory=list)
    _out_of_scope_compiled: list[re.Pattern[str]] = PrivateAttr(default_factory=list)

    @model_validator(mode="after")
    def _compile_patterns(self) -> ScopeRules:
        # Compiled once here so an invalid pattern is a construction-time
        # error, not a per-call surprise deep inside `validate_target`.
        try:
            self._in_scope_compiled = [re.compile(p) for p in self.in_scope_regex]
            self._out_of_scope_compiled = [re.compile(p) for p in self.out_of_scope_regex]
        except re.error as exc:
            raise ValueError(f"invalid scope regex: {exc}") from exc
        return self

    @classmethod
    def from_target(cls, source: _HasRulesOfEngagement) -> ScopeRules:
        return cls(
            in_scope_regex=list(source.in_scope_regex),
            out_of_scope_regex=list(source.out_of_scope_regex),
            banned_actions=list(source.banned_actions),
        )
