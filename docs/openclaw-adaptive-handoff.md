# OpenClaw handoff: adaptive auto-pass MVP

This document is the validation and deployment handoff for the adaptive
auto-pass change. The implementation intentionally defaults to `off`; do not
enable `enforce` until the shadow and runtime checks below pass against the
installed OpenClaw build.

## Intended contract

- `off` preserves the existing grant/window behavior.
- `shadow` evaluates and logs safe-file eligibility without writing adaptive
  state or changing the gate result.
- `suggest` may add a bounded-lease hint after repeated matching approvals,
  but never creates an authorization from `allow-once`.
- `enforce` owns reuse only for eligible safe-file calls. It must ignore legacy
  allow-always grants and approval windows for those calls. An auto-pass is
  possible only after atomically consuming a lease created by an explicit
  `allow-always` resolution.
- Eligibility is restricted to complete `builtin.file-mutation-semantics`
  reports with exactly `local-write` / `filesystem`, analyzer-verified absolute
  paths, a narrow path-bound grant fingerprint, no explicit user rule, and no
  destructive, critical, unknown, partial, dynamic, or Code Mode semantics.
- `allow-once` is evidence only in `enforce`; it authorizes exactly the current
  call and creates neither a legacy window nor an adaptive lease.
- The lease has a fixed expiry and a finite use budget. One use is deducted
  before execution and is not refunded based on tool outcome.

## Required automated validation

Run the repository's build, typecheck, manifest-schema validation, and complete
test suite first. Add focused coverage for all cases below.

### Configuration and state

- All four modes parse; invalid modes fall back to `off`.
- `ttlMs`, `maxUses`, and `suggestAfterApprovals` clamp to their documented
  bounds; malformed/accessor/prototype-backed values fail closed.
- Missing, legacy, future-version, malformed, oversized, expired, ruleset-
  mismatched, fingerprint-mismatched, or config-mismatched state never grants.
- State contains only opaque digests, counters, timestamps, and versions; no
  raw path, command, content, params, or secret is persisted or logged.
- Concurrent consume calls cannot exceed `remainingUses`; persistence failure
  or an unknown session key produces another approval rather than an auto-pass.
- A consumed use is not restored when `after_tool_call` reports an error.

### Eligibility

- Eligible: canonical `write`, `edit`, and non-delete/non-move `apply_patch`
  calls with complete analysis and absolute Windows, POSIX, or UNC targets.
- Ineligible: relative paths, malformed/conflicting paths, unknown envelope
  fields, delete/move patches, filesystem roots, incomplete/empty/unknown
  analysis, explicit user rules, param-scoped rules, critical decisions, exec,
  build/test/format, git commit/push, Code Mode, network, credentials,
  privilege, deployment, obfuscation, and destructive effects.
- Different tool identity, policy identity, ruleset, effect/category set, drive,
  UNC share, or exact directory set must miss the lease.

### Runtime hook behavior

- `off`, `shadow`, and `suggest` never auto-pass because of adaptive state.
- `shadow` leaves the exact hook return value unchanged.
- `suggest` keeps description length within the host's 512-character limit and
  never removes higher-priority risk/target information.
- In `enforce`, pre-existing legacy safe-file grants/windows are ignored.
- `enforce` + `allow-once` does not open either a legacy window or an adaptive
  lease; the next matching call prompts again.
- `enforce` + explicit `allow-always` persists an adaptive lease only after the
  durable session update succeeds. Subsequent exact matches consume one use.
- Exhausted, expired, revoked, corrupt, or persistence-failed leases prompt.
- `deny` revokes matching evidence/lease; timeout/cancel never increase trust.
- Critical/unknown calls continue to bypass all reusable authorization.
- The final parameter seal still restores the gate-time snapshot on adaptive
  hits, including with lower-priority parameter-mutating plugins.

## Installed-OpenClaw canary

1. Install the build with `adaptiveAutoPass.mode: "shadow"` and leave all other
   gate settings unchanged.
2. Exercise absolute-path write/edit/apply_patch calls plus the existing shell
   adversarial corpus. Confirm zero decision changes and no sensitive telemetry.
3. Switch to `suggest`; confirm hints only after the configured approval count
   and confirm every call still follows legacy authorization behavior.
4. Drain existing safe-file legacy windows/grants, then enable `enforce` for a
   small interactive cohort. Confirm one new explicit `allow-always` approval is
   required before reuse.
5. Exercise budget exhaustion, expiry, denial, Gateway restart, state corruption,
   concurrent calls, and persistence failure. Every ambiguous case must prompt.
6. Keep a config kill switch back to `off`. Note that rollback restores legacy
   behavior and may make still-valid legacy grants/windows visible again; drain
   or clear them first when a strict rollback is required.

Do not promote build/test/format/git commit to adaptive `enforce` from this MVP.
Those intents need authoritative execution cwd/repository identity and a
host-enforced sandbox before a plugin can safely bind their transitive effects.
