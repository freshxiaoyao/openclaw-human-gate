# openclaw-human-gate

[![npm version](https://img.shields.io/npm/v/openclaw-human-gate.svg)](https://www.npmjs.com/package/openclaw-human-gate)

[![npm downloads](https://img.shields.io/npm/dm/openclaw-human-gate.svg)](https://www.npmjs.com/package/openclaw-human-gate)

Human-in-the-loop approval middleware for [OpenClaw](https://github.com/openclaw/openclaw).

Intercepts tool execution with a `before_tool_call` hook and routes selected
calls through OpenClaw's **built-in** approval flow. When a call needs human
confirmation, the agent run is paused and the approval request is pushed to
every connected approval surface — the official TUI, the Control UI (Web), and
any chat channel that supports `/approve`. This plugin does **not** implement
its own terminal UI; it reuses OpenClaw's.

```
                 Agent
                   |
              Tool call
                   ↓
          Human Gate Plugin
          /             \
     auto               require-approval
                               ↓
                       OpenClaw approval flow
                       (TUI / Web UI / /approve)
                               ↓
                       allow-once / allow-always / deny
```

## Features

- **`before_tool_call` interception** — every tool call is classified before
  execution via a priority-60 hook.
- **Built-in approval workflow** — selected calls pause the run and ask the
  human through OpenClaw's own approval surfaces (TUI / Control UI / chat
  `/approve`); no custom UI to learn.
- **Three policy modes per rule** — `auto` (pass), `require-approval` (prompt),
  `block` (deny with reason), with a configurable `defaultMode` fallback.
- **Zero-config fail-closed defaults** — reads pass, destructive calls
  (`exec`, `apply_patch`, `code_mode_exec`) prompt, and anything unrecognised
  prompts too (`defaultMode: "require-approval"`).
- **Approval window** — approving one destructive call auto-passes matching
  calls for the rest of the turn (or a time box), so multi-step refactors
  don't prompt once per file.
- **`allow-always` per session** — grant once, skip re-prompting for that
  session.
- **Auto-pass for cron / heartbeat** — scheduled runs are never blocked on an
  approval nobody can see.
- **`human_gate_ask` tool** — Claude Code-style "ask the human" for
  clarification or decisions.

## How it works

OpenClaw already ships a first-class approval mechanism: a `before_tool_call`
hook may return `{ requireApproval: { ... } }`, and the Gateway handles pausing
the run, rendering the prompt in the TUI / Control UI, enforcing the timeout,
and applying the decision. `deny`, `timeout`, and `cancelled` fail closed
(blocked).

This plugin is the **policy layer** on top of that mechanism: it decides which
calls need approval, with what severity and timeout, and remembers
`allow-always` decisions per session so the human is not re-prompted.

## Default posture (fail-closed)

The plugin does **not** intercept every tool by default — that would be
unusable. Instead it classifies each call and prompts for anything that might
have side effects; reads pass through:

1. **User rules** (first match wins) — explicit override.
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

## Auto-pass system contexts (cron / heartbeat)

Scheduled runs (cron jobs, heartbeat) have no human at the keyboard, so an
approval prompt would stall them indefinitely. By default the gate
**auto-passes approval prompts** in sessions whose key contains a matching
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
- Matching is **exact per `:`-delimited segment**, not substring: `:cron:`
  matches `agent:main:cron:run-1` but not `agent:x:cronx:`. Keys may be
  written with or without colons (`":cron:"`, `":heartbeat"`, `"subagent"`
  all work); a bare value matches only a standalone segment.
- Add your own segments (e.g. `:subagent:`) to auto-pass other run kinds;
  remove the defaults to gate everything again.
- Regular interactive sessions never match these, so approvals still apply
  when a human is present.

## Approval window (less popup fatigue)

Gating every write means a multi-step task (refactor 10 files) prompts 10
times. The approval window fixes this: after you approve **one** destructive
call, further matching calls auto-pass for a turn or a time box.

```json5
approvalWindow: {
  mode: "turn",          // "off" | "turn" | "time"  (default "turn")
  match: "same-tool",    // "same-tool" (default) | "destructive"
  ttlMs: 300000,         // for "time" mode only
  bypassCritical: true   // severity "critical" always prompts (e.g. prod deploys)
}
```

- `mode: "turn"` — once approved, same-class writes auto-pass for the rest of
  the current agent run; a new user turn resets. (default)
- `mode: "time"` — once approved, same-class writes auto-pass for `ttlMs`.
- `mode: "off"` — prompt every destructive call (per-call behavior).
- `match: "same-tool"` — only the approved tool name shares the window (safer default; e.g. approving `apply_patch` does not auto-approve `exec`).
- `match: "destructive"` — one shared window for all gated writes (broadest and lowest-friction; opt in deliberately).
- `bypassCritical: true` — `severity: "critical"` calls (e.g. a `deploy-prod`
  rule) always prompt even when a window is open.

The window is opened automatically when you approve a call (allow-once or
allow-always). `deny` / `timeout` / `cancelled` do not open it. It is stored
per session. This is separate from `allow-always`, which is a permanent
per-(rule, tool) grant for the whole session.

## Install

```bash
# from ClawHub / npm (once published)
openclaw plugins install openclaw-human-gate

# from a local tarball (for development)
npm pack --pack-destination /tmp
# uninstall first if an older version is installed, then install the new pack
openclaw plugins uninstall human-gate
openclaw plugins install npm-pack:/tmp/openclaw-human-gate-0.1.3.tgz

# inspect
openclaw plugins inspect human-gate --runtime --json
```

Requires OpenClaw `>= 2026.7.1` (Node 22.22.3+ / 24.15+ / 25.9+).

## Screenshots

> Screenshots go here — approval prompt in the Control UI / TUI, and an example
> `human_gate_ask` question in chat. (TODO: add captures)

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
          approvalWindow: {
            mode: "turn",
            match: "same-tool",
            ttlMs: 300000,
            bypassCritical: true
          },
          rules: [
            {
              id: "deploy-prod",
              toolName: "deploy_service",
              mode: "require-approval",
              severity: "critical",
              allowedDecisions: ["allow-once", "deny"],
              timeoutMs: 300000,
              reason: "Deploy to production"
            },
            {
              id: "read-only-auto",
              toolNamePattern: "^(read_|get_|list_).*",
              mode: "auto"
            },
            {
              id: "block-rm",
              toolNamePattern: "^rm_.*",
              mode: "block",
              reason: "Destructive rm_* tools are blocked"
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
| `mode`            | `auto` \| `require-approval` \| `block` (required)        | Decision for a matched call.                                            |
| `severity`        | `info` \| `warning` \| `critical`                         | Shown in the approval UI. Defaults to `defaultSeverity`.               |
| `allowedDecisions`| `["allow-once","allow-always","deny"]`                    | Decisions offered to the approver.                                      |
| `timeoutMs`       | integer (1000–600000)                                     | Approval timeout. Defaults to `defaultTimeoutMs`.                       |
| `reason`          | string                                                    | Human-readable reason in the approval request / block reason.           |

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

The approval popup shows a bounded summary: tool name/kind, up to four derived
paths, selected safe scalar parameters (`command`, `file_path`, `url`,
`environment`, etc.), policy reason, and rule id. It never dumps the complete
params object, reducing accidental secret exposure and keeping the prompt
readable.

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
- `src/policy.ts` — rule-matching engine (pure).
- `src/config.ts` — resolves `api.pluginConfig` over built-in defaults.
- `src/state.ts` — per-session allow-always store backed by session extensions.
- `src/window.ts` — per-session approval window backed by session extensions.
- `src/in-memory-handle.ts` — deprecated compatibility placeholder; no process-global session state is used.
- `src/types.ts` — plugin config, rule types, and ask-tool parsing/formatting.
- `src/sdk-shim.d.ts` — structural types for the OpenClaw SDK surfaces used
  (mirrors the documented contract; real types come from `openclaw/plugin-sdk/*`
  in a source checkout).

## Notes

- `block: true` is terminal and skips lower-priority hooks.
- `params` rewriting (returning `{ params }`) is applied only after approval
  succeeds — useful for a future "Modify" path.
- `allow-always` grants are scoped to a session via plugin-owned session
  extensions and do not survive a new session. If a hook invocation has no
  trusted `sessionKey`, Human Gate does not persist a grant or approval window.
- Non-bundled plugins do not need `allowConversationAccess` for
  `before_tool_call`; it is only required for prompt-content hooks.
