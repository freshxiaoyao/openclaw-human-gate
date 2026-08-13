# Human Gate architecture

## Product boundary

Human Gate is a policy and presentation layer over OpenClaw's native plugin
approval flow. It does not execute commands, mutate tool parameters, implement
an approval UI, or read target files to enrich a preview.

The v0.2 production minimum is intentionally **upgrade-only**:

- the base policy remains the authority for ordinary tool classification;
- semantic analysis may raise the minimum mode or severity;
- analysis never turns a gated call into an automatic pass;
- malformed, oversized, or unsupported inputs do not receive a wider grant;
- an explicit block is terminal and its operator-facing reason is preserved.

## Request pipeline

```mermaid
flowchart LR
  A["before_tool_call"] --> B["Parameter snapshot"]
  B --> C["Base policy"]
  B --> D["Analyzer registry"]
  C --> E["Monotonic decision reducer"]
  D --> E
  E --> F{"Effective mode"}
  F -->|block| G["Block"]
  F -->|auto| H["Pass"]
  F -->|require approval| I["Unattended policy"]
  I --> J["Grant and window checks"]
  J --> K["Preview provider registry"]
  K --> L["Sanitize, redact, budget"]
  L --> M["Native OpenClaw approval"]
```

The same structured-clone snapshot is used for analysis, preview generation,
and the `params` returned alongside `requireApproval`. A value that cannot be
cloned is blocked. This prevents approval of one object followed by execution
of a caller-mutated object.

## Extension contracts

`ToolCallAnalyzer` is a synchronous, pure, no-I/O contract:

```ts
interface ToolCallAnalyzer {
  readonly id: string;
  readonly priority: number;
  supports(context: ToolCallContext): boolean;
  analyze(context: ToolCallContext): AnalysisResult;
}
```

An analyzer returns findings and minimum constraints, not a final decision.
`AnalyzerRegistry` combines all matching results monotonically. Stable finding
IDs are suitable for tests and audit logs; raw parameters are not logged.

`ApprovalPreviewProvider` follows the same separation:

```ts
interface ApprovalPreviewProvider {
  readonly id: string;
  readonly priority: number;
  supports(context: ToolCallContext): boolean;
  build(context: ToolCallContext, config: ApprovalPreviewConfig): PreviewSection | undefined;
}
```

Providers return untrusted preview material. Only `ApprovalPresenter` may turn
that material into the host description, enforcing centralized sanitization,
redaction, indentation, and the 512-character OpenClaw limit. A provider
failure suppresses its advisory preview but never suppresses the gate.

## Command semantics

Ordinary shell execution and Code Mode are separate analyzers. Code Mode's
`command` field is JavaScript/TypeScript source, not a shell command.

The shell analyzer scans POSIX, PowerShell, and CMD syntax and takes the union
of risk findings because the hook does not expose an authoritative runtime
shell. The scanner recognizes quoted tokens, control operators, redirections,
dynamic expansion, and nested `sh -c`, `cmd /c`, and PowerShell `-Command`
wrappers up to a configured depth. It never expands variables, resolves
aliases/functions, or evaluates input.

The MVP promotes these classes to critical:

- remote content piped to an interpreter;
- recursive forced deletion;
- Git force-push and destructive history/worktree operations;
- destructive infrastructure commands and apparent production deployments;
- encoded or dynamic execution;
- likely credential-source plus network-sink combinations;
- dynamic Code Mode evaluation.

Output redirection, privilege elevation, dynamic expansion, and partial
analysis produce warning findings. They never justify auto-authorization.

Beyond the critical corpus, the shell analyzer recognizes a conservative set
of dev-loop intents as complete and window-eligible: `build`, `test`, `format`,
and `git commit` (distinct categories `dev-build`, `dev-test`, `dev-format`,
and `source-control`). Completeness still requires a single, non-dynamic,
operator/redirection-free invocation across all three dialects; anything
ambiguous or compound stays fail-closed.

## Critical invariants

A critical effective decision:

- requires approval unless an explicit user block already applies;
- removes `allow-always` from the available decisions;
- bypasses previously stored `allow-always` grants;
- bypasses approval windows;
- is blocked in unattended cron/heartbeat contexts by default;
- uses timeout behavior `deny`.

These invariants close the loop between semantic classification and the
existing approval-window implementation.

## Preview security

Only data already present in hook parameters is previewed. Human Gate does not
read the filesystem; additional reads could expose unrelated secrets and
would introduce time-of-check/time-of-use ambiguity. Relative authorization
targets require a host-authoritative execution cwd; an agent workspace path is
not substituted for it. OpenClaw 2026.7.1 does not expose that cwd in plugin
hook context, so relative paths intentionally produce no reusable fingerprint.
Best-effort `derivedPaths` are preview hints only, never an authorization base.

The preview pipeline removes ANSI/OSC sequences and unsafe control characters,
marks bidirectional controls, redacts common tokens/credentials/private keys,
limits scanning work, limits files and lines, indents untrusted body content,
and finally applies the host's hard description budget. Redaction is defense in
depth, not a complete DLP system; operators should still avoid routing approval
messages to untrusted channels.

## Known limits and next increments

- Cron/heartbeat detection is a session-key heuristic because the hook exposes
  no authoritative trigger kind.
- Semantic window keys are versioned and include policy/tool identity. The
  default path scope also includes complete effects/categories and an
  analyzer-verified bounded exact set of lexical parent directories. Empty,
  partial, or unknown reports do not produce reusable authorization.
- `allow-always` uses a separate, narrower path-bound fingerprint even when a
  broader compatibility window scope is configured. Grants are a **bounded
  session/task lease** that expires `allowAlwaysTtlMs` after granting (default
  4h); legacy v1 grants, windows, and grants without an expiry are deliberately
  discarded.
- Path normalization is lexical and performs no filesystem I/O. It cannot
  resolve symlinks or junctions. Multiple targets are never collapsed into a
  broader common ancestor.
- Ordinary shell commands outside the narrowly classified dev-loop corpus
  (Git commit/push, build, test, format) do not open reusable semantic windows.
  The safe default is another prompt, not a guessed command scope.
- The scanner is not a complete shell AST. Here-documents, process substitution,
  aliases, functions, and runtime expansion remain intentionally untrusted.
- Redaction patterns are bounded and best-effort.
- A final ordinary-hook parameter seal restores the gate-time snapshot after
  finite-priority plugin rewrites. The host exposes no reserved finalizer slot;
  installed plugins are trusted in-process code, and another plugin can still
  use the same non-finite priority or bypass hooks entirely. A future host-owned
  final-params digest/finalizer remains the stronger boundary.

An adaptive mode that auto-passes analyzed commands is explicitly deferred.
It should only be considered after corpus-based false-negative measurement and
authoritative shell/runtime metadata are available.
