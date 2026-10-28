# scope-core — decisions and threat model

**Status:** `scope-core` 0.1.0, a pure leaf package (`ScopeRules`, `validate_target`,
`is_in_scope`, `is_action_banned`, `sanitize`, `normalize`) consumed by commit-SHA pin from
`glunk-works/loop-orchestrator` and `glunk-works/bounty-infra`.

**Next action:** land the glunk-works/claude-workbench#410 approval-gate cutover.

## Decisions (SC-D*)

None recorded yet.

## Threat model

### What scope-core guards

Two primitives that both consumers depend on, so that "in scope" has one definition:

- **Scope enforcement** (`scope_core/rules.py`, `scope_core/validate.py`). `validate_target`
  is a fail-closed allowlist: a candidate passes only with at least one `in_scope_regex`
  match and no `out_of_scope_regex` match. An out-of-scope match always vetoes, and an empty
  `in_scope_regex` denies everything. `is_in_scope` is the same decision without the raise.
  `is_action_banned` is an exact-string membership test against `banned_actions`.
- **Ingestion sanitization** (`scope_core/sanitize.py`). `sanitize` strips ANSI CSI escapes,
  C0/C1 controls, Unicode `Cf` characters (bidi overrides, zero-width characters, the Tags
  block) and variation selectors, NFKC-normalizes, collapses whitespace and hard-truncates.
  `normalize` is the same structural prefix without the collapse or truncation, for
  identifiers.

### Where untrusted input enters

- **Rules of engagement**: `ScopeRules.from_target` reads `in_scope_regex`,
  `out_of_scope_regex` and `banned_actions` from a consumer-held object
  (loop-orchestrator's Postgres `targets` row, bounty-infra's S3-hosted RoE). Patterns are
  compiled at construction, so an invalid regex fails there.
- **Candidates**: the string passed to `validate_target` / `is_in_scope`, and the action
  passed to `is_action_banned`, come from the consumer.
- **Scanner and target text**: passed to `sanitize` / `normalize` on its way to a log line
  or a triage LLM prompt. This text is attacker-influenceable.

### What a bypass would cost

- **Scope**: a candidate wrongly allowed means a consumer acts against a host or asset outside
  the program's rules of engagement. Patterns match with `re.search`, unanchored, so an
  unanchored `example\.com` also allows `example.com.attacker.net`; anchoring is the
  rule author's job, and the docstring and README say so.
- **Sanitization**: text that keeps its control, escape or invisible characters can spoof a
  terminal or log display, or carry hidden content into a triage prompt. `sanitize` bounds
  shape and size only. It is not an injection-phrase blocklist, so fencing untrusted text
  stays the caller's prompt template's job. It is display-only: a sanitized value must never
  be validated or scanned, since NFKC changes bytes.
- **`ScopeViolation`** embeds the candidate verbatim. A consumer that displays it from
  attacker-influenceable input should sanitize it first; nothing here enforces that.

### What holds the boundary

- `tests/test_boundary.py` keeps `scope_core` importing nothing outside the standard library
  and pydantic, so a new runtime dependency cannot reach both consumers unnoticed.
- CI (`.github/workflows/ci.yml`) runs lint, and tests on Python 3.11 and 3.14, the two ends
  of bounty-infra's supported range.
