# scope-core

Shared scope-enforcement and ingestion-sanitization primitives for
`glunk-works` bounty tooling.

Extracted from `glunk-works/loop-orchestrator`'s `tools/scope_validator` +
`tools/ingest` (bounty-loop Phase 0, sprint 45) into a standalone package so
both `loop-orchestrator` and `glunk-works/bounty-infra` depend on one
definition of "in scope" instead of maintaining two. Background:
`bounty-infra`'s `sprints/SC_scope_core_extraction/sprint_plan.md`.

## What's here

- `scope_core.ScopeRules` / `scope_core.validate_target` /
  `scope_core.ScopeViolation` / `scope_core.is_action_banned` — a frozen,
  fail-closed scope allowlist. `validate_target` allows a candidate iff it
  matches at least one `in_scope_regex` pattern and zero
  `out_of_scope_regex` patterns; an out-of-scope match always vetoes, and an
  **empty `in_scope_regex` denies everything**. Patterns match via
  `re.search` (unanchored) — a caller's rules-of-engagement patterns must
  anchor (`^example\.com$`) to mean an exact host.
- `scope_core.sanitize` / `scope_core.DEFAULT_MAX_LEN` — a structural,
  deterministic normalizer (ANSI CSI strip, C0/C1 control strip, Unicode
  `Cf`-category + variation-selector strip, NFKC normalize, whitespace
  collapse, hard truncate) for attacker-influenceable text before it reaches
  a triage LLM prompt. Not an injection-phrase blocklist — the caller's
  prompt template is still responsible for structurally fencing untrusted
  text. **Display-only**: sanitizing changes bytes (NFKC folds some
  characters), so never validate or scan a sanitized value — validate and
  act on the exact bytes received, sanitize only on the way to a log line
  or a prompt.

Pure leaf package: no I/O, no credentials, no framework coupling beyond
pydantic. `tests/test_boundary.py` enforces that `scope_core` imports
nothing outside the standard library and pydantic.

## Development

```bash
pip install hatch
hatch run lint:check   # ruff check + ruff format --check
hatch run test:run     # pytest ./tests/
```

## Distribution

Not published to PyPI. Consumers pin a commit SHA via a PEP 508 direct
reference:

```
scope-core @ https://github.com/glunk-works/scope-core/archive/<sha>.tar.gz
```
