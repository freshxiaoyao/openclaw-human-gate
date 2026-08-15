# Approval reuse and adaptive leases

Human Gate reduces repeated prompts without treating every call to the same
tool as equivalent. Reuse is derived from complete semantic analysis and a
versioned authorization fingerprint. If a safe fingerprint cannot be built,
the call asks again.

## Approval window

```json5
approvalWindow: {
  mode: "turn",          // "off" | "turn" | "time" (default "turn")
  scope: "path",         // default: exact analyzer-verified directory set
  pathFallback: "none",  // "none" | "category" | "effect"
  ttlMs: 300000,         // for "time" mode only
  bypassCritical: true   // critical calls always prompt
}
```

- `mode: "turn"` reuses matching approval for the current agent run. A new user
  turn resets it.
- `mode: "time"` reuses matching approval for `ttlMs`.
- `mode: "off"` prompts for every gated call.
- `scope: "path"` is the safe default. The key includes tool and policy
  identity, complete effect and category sets, and the sorted exact set of all
  analyzer-verified target directories. Multiple directories never collapse to
  a shared ancestor.
- `scope: "category"` includes tool and policy identity plus complete effect
  and finding-category sets.
- `scope: "effect"` includes tool and policy identity plus the complete effect
  set.
- `scope: "same-tool"` is a compatibility scope keyed by complete tool and
  matched-policy identity, not only the visible tool name.
- `scope: "destructive"` is the broadest legacy compatibility scope. Use it
  only when deliberately preserving old behavior.
- `pathFallback: "none"` declines reuse when a verified path scope cannot be
  built. `category` and `effect` are explicit broader opt-ins.
- `bypassCritical: true` prevents critical calls from using an open window.

### Path scope

File targets are parent-directory scoped. For example,
`C:\repo\src\foo.ts` can share a window with `C:\repo\src\bar.ts`, but not with
a system, SSH, `.git`, or unrelated workspace directory. A multi-file call is
keyed by its exact normalized directory set; the implementation does not use a
common ancestor as an authorization boundary.

Normalization is lexical and performs no filesystem reads. Relative targets
require a host-authoritative execution cwd. OpenClaw 2026.7.1 does not expose
that field to plugin hooks, so relative writes deliberately ask again and do
not offer `allow-always`. Use absolute tool targets until the host exposes
resolved execution targets.

The window opens only after `allow-once` or `allow-always` and only when complete
analysis produces a reusable fingerprint. Empty semantics, an `unknown` effect
or category, partial or failed analysis, an unverified path with
`pathFallback: "none"`, missing trusted session identity, or missing run
identity in turn mode never open a window. `deny`, `timeout`, and `cancelled`
do not open one.

## Development-loop intents

The command analyzer recognizes a conservative set of complete,
window-eligible intents with distinct categories:

- Build: `npm run build`, `yarn build`, `make`, `tsc`, `cargo build`, `go build`.
- Test: `npm test`, `pytest`, `cargo test`, `go test`, `jest`, `vitest`.
- Format: `prettier --write`, `eslint --fix`, `gofmt -w`, `rustfmt`, `black`.
- Git commit: `git commit` is a local history write; `git push` remains a
  network write.

Only a single, non-dynamic invocation without pipes or redirections is
reusable. Compound commands such as `npm test && npm run build` and check-only
formatters such as `prettier --check` stay fail-closed.

These intents have no verified file targets, so the default path scope cannot
open a window for them. To reuse them per turn or time box while keeping
relative file writes per-approval, opt into category fallback:

```json5
approvalWindow: {
  mode: "turn",
  scope: "path",
  pathFallback: "category",
  bypassCritical: true
}
```

Command classification covers only the visible invocation. Build scripts, test
runners, formatters, Git hooks, plugins, and configuration can have transitive
side effects that cannot be proven safe from a command name alone.

## Bounded `allow-always`

`allow-always` is stricter than a temporary window. Human Gate offers and
remembers it only when a narrow path-bound grant fingerprint can be built from
the complete policy identity and semantic sets. A broad destructive, effect,
or category window therefore cannot become a broad remembered grant.

Critical calls bypass reusable authorization and do not offer `allow-always`.
Every grant is a bounded lease that expires `allowAlwaysTtlMs` after it is
granted (four hours by default). Old grants without an expiry are discarded on
upgrade.

## Experimental adaptive safe-file leases

Adaptive auto-pass is a separate, default-off controller. Its production scope
is deliberately narrow: recognized `write`, `edit`, and non-delete/non-move
`apply_patch` calls whose semantic report is complete, whose only effect and
category are `local-write` and `filesystem`, and whose analyzer-verified targets
are absolute paths with a path-bound grant fingerprint.

```json5
adaptiveAutoPass: {
  mode: "off",              // "off" | "shadow" | "suggest" | "enforce"
  ttlMs: 900000,            // fixed lifetime; 1 minute..1 hour
  maxUses: 20,              // deducted before execution; never refunded
  suggestAfterApprovals: 2  // allow-once evidence needed for a suggestion
}
```

- `off` preserves existing grant and window behavior.
- `shadow` emits bounded candidate metadata but changes no decision, approval
  text, or state.
- `suggest` keeps legacy authorization behavior and may add a preview-only
  lease hint after repeated matching `allow-once` approvals. Those approvals
  are evidence only and never create authority.
- `enforce` owns reuse for eligible safe-file calls. Existing legacy grants and
  windows are ignored for those calls. `allow-once` authorizes only the current
  call; explicit `allow-always` creates a path-bound lease with fixed expiry and
  a finite use budget.

Every adaptive use is atomically deducted from session state before execution.
Expired, exhausted, malformed, version- or config-mismatched, and persistence-
failed leases ask again. Tool success is not treated as evidence, and a failed
tool call does not refund a consumed authorization. A `deny` resolution revokes
matching adaptive evidence and lease state.

The controller rejects relative paths, delete or move patches, explicit user-
policy matches, param-scoped rules, critical, destructive, unknown or partial
analysis, commands, build, test, format, Git operations, network writes, and
Code Mode. Adaptive enforcement for command workflows requires authoritative
execution cwd and repository identity plus a host sandbox.

### Rollback

Switching from `enforce` to `off`, `shadow`, or `suggest` restores legacy
behavior and can expose a still-valid legacy grant or window that predates
enforcement. For an emergency prompt-every-call rollback, also set:

```json5
rememberAllowAlways: false,
approvalWindow: {
  mode: "off"
}
```

Keep those settings until older state has drained.

## Migration from `match`

Existing explicit values remain accepted: `match: "same-tool"` maps to
`scope: "same-tool"`, and `match: "destructive"` maps to
`scope: "destructive"`. If both fields are present, `scope` wins. New or
unconfigured installations resolve to `scope: "path"` and
`pathFallback: "none"`; `match` is deprecated and has no schema default.

Fingerprint and persisted-state formats are versioned. On upgrade, incompatible
approval windows and remembered grants are discarded so the next call asks
again instead of reviving a broader authorization key.
