/**
 * Plugin-owned types for openclaw-human-gate.
 *
 * These describe the plugin's configuration shape and policy model. They are
 * independent of the OpenClaw SDK surface (see `sdk-shim.d.ts` for the SDK
 * contract this plugin relies on).
 */

/** How a matched tool call should be handled. */
export type GateMode = "auto" | "require-approval" | "block";

export type GateSeverity = "info" | "warning" | "critical";

export type PolicySource = "user" | "builtin" | "classifier" | "default";

export type ApprovalDecision =
  | "allow-once"
  | "allow-always"
  | "deny"
  | "timeout"
  | "cancelled";

/** JSON scalar supported by parameter-level policy matching. Objects and
 * arrays are deliberately excluded so equality stays unambiguous. */
export type ParamScalar = string | number | boolean | null;

/** One condition over a direct, own tool parameter. Operator objects are
 * mutually exclusive and validated strictly at runtime. */
export type ParamCondition =
  | { key: string; equals: ParamScalar }
  | { key: string; in: ParamScalar[] }
  | { key: string; missing: true };

/** A deliberately one-level boolean expression. Nested matcher trees are not
 * supported, keeping authorization rules inspectable and bounded. */
export type RuleParamMatcher =
  | { all: ParamCondition[] }
  | { any: ParamCondition[] };

/** A single policy rule. First match wins. */
export interface GateRule {
  /** Stable rule id, used in logs and allow-always keys. */
  id: string;
  /** Exact tool name to match. Omit to match any tool. */
  toolName?: string;
  /** Regex (source string) matched against toolName. Omit for no pattern. */
  toolNamePattern?: string;
  /** Match host toolKind discriminator (e.g. `code_mode_exec`, `exec`, `apply_patch`). */
  toolKind?: string;
  /** Match direct, own tool parameters with one `all` or `any` expression.
   * Conditions support `equals`, `in`, or `missing: true`. Invalid matchers,
   * accessors, and inherited values never match. */
  paramMatcher?: RuleParamMatcher;
  /** Decision for a matched call. */
  mode: GateMode;
  /** Severity passed to the approval UI. Defaults to config defaultSeverity. */
  severity?: GateSeverity;
  /** Decisions offered to the approver. */
  allowedDecisions?: Array<"allow-once" | "allow-always" | "deny">;
  /** Approval timeout in ms. Defaults to config defaultTimeoutMs. */
  timeoutMs?: number;
  /** Human-readable reason shown in the approval request / block reason. */
  reason?: string;
}

export interface HumanGateConfig {
  /** Fallback decision for a tool that no rule and no classifier matches.
   *  Default: "require-approval" (fail-closed — an unrecognized tool must be
   *  approved by a human). Set to "auto" only if you accept unknown tools
   *  passing through ungated. */
  defaultMode: GateMode;
  defaultSeverity: GateSeverity;
  defaultTimeoutMs: number;
  /** Persist allow-always decisions per session as a bounded lease (never
   *  unlimited). The lease expires allowAlwaysTtlMs after it is granted. */
  rememberAllowAlways: boolean;
  /** Hard upper bound for a persisted allow-always grant. The native button
   *  still reads "allow-always"; internally the grant is a session/task lease
   *  that expires after this many milliseconds. */
  allowAlwaysTtlMs: number;
  /** When true (default), the built-in read-only / destructive classifier
   *  runs after user rules so reads pass through and writes get gated without
   *  listing every tool. Set false to disable classification and rely solely
   *  on explicit rules + defaultMode. */
  useClassifiers: boolean;
  /** Parameter-aware, upgrade-only analysis. It may tighten a built-in or
   * fallback decision, but never downgrades one. */
  semanticAnalysis: SemanticAnalysisConfig;
  /** Bounded and redacted approval descriptions. */
  previews: ApprovalPreviewConfig;
  /** Behavior for critical calls in contexts where nobody can approve. */
  unattendedPolicy: UnattendedPolicyConfig;
  /** Approval window: after the human approves one completely analyzed call,
   *  matching semantic fingerprints may auto-pass for a turn or time box. */
  approvalWindow: ApprovalWindowConfig;
  /** Ordered policy rules. First match wins. */
  rules: GateRule[];
  /** Session-key `:`-delimited segments that auto-pass the approval prompt
   *  (no human to ask): cron isolated runs and heartbeat isolated runs by
   *  default. Matching is exact per segment, not substring (`":cron:"`
   *  matches `agent:main:cron:run-1` but not `x:cronx:`). Auto-pass exempts
   *  ONLY require-approval prompts — `block` rules are still enforced. */
  autoPassSessionKeys: string[];
}

export interface SemanticAnalysisConfig {
  enabled: boolean;
  /** Maximum source characters inspected by one analyzer. */
  maxCommandLength: number;
  /** Maximum nested shell-wrapper levels inspected (`sh -c`, `cmd /c`, etc.). */
  maxWrapperDepth: number;
  /** Maximum findings retained across all analyzers. */
  maxFindings: number;
}

export interface ApprovalPreviewConfig {
  enabled: boolean;
  /** OpenClaw's plugin approval contract currently caps descriptions at 512. */
  maxDescriptionChars: number;
  maxSectionChars: number;
  maxLines: number;
  maxFiles: number;
  redactSecrets: boolean;
}

export interface UnattendedPolicyConfig {
  /** Critical calls cannot wait for approval; block is the safe default. */
  critical: "block" | "auto";
}

/** Reduces popup fatigue for multi-step write tasks. */
export interface ApprovalWindowConfig {
  /** "off" = prompt every gated call (per-call behavior).
   *  "turn" = matching fingerprints auto-pass for the current agent run.
   *  "time" = matching fingerprints auto-pass until their fixed expiry. */
  mode: "off" | "turn" | "time";
  /** Time-box duration for mode "time". Ignored otherwise. */
  ttlMs: number;
  /** Semantic authorization boundary. Every semantic scope retains the full
   * tool identity, so it can only narrow the legacy same-tool behavior. */
  scope: "destructive" | "same-tool" | "effect" | "category" | "path";
  /** Explicit behavior when `scope: "path"` has no verified absolute target.
   * `none` is fail-closed and opens no reusable authorization. */
  pathFallback: "none" | "category" | "effect";
  /** When true (default), severity "critical" calls always prompt even if a
   *  window is open (e.g. production deploys never get auto-passed). */
  bypassCritical: boolean;
}

export const DEFAULT_CONFIG: HumanGateConfig = {
  defaultMode: "require-approval",
  defaultSeverity: "warning",
  defaultTimeoutMs: 300_000,
  rememberAllowAlways: true,
  allowAlwaysTtlMs: 14_400_000,
  useClassifiers: true,
  semanticAnalysis: {
    enabled: true,
    maxCommandLength: 16_384,
    maxWrapperDepth: 3,
    maxFindings: 8,
  },
  previews: {
    enabled: true,
    maxDescriptionChars: 512,
    maxSectionChars: 220,
    maxLines: 12,
    maxFiles: 4,
    redactSecrets: true,
  },
  unattendedPolicy: {
    critical: "block",
  },
  approvalWindow: {
    mode: "turn",
    ttlMs: 300_000,
    scope: "path",
    pathFallback: "none",
    bypassCritical: true,
  },
  rules: [],
  autoPassSessionKeys: [":cron:", ":heartbeat"],
};

/** host toolKind values that always have side effects → require approval. */
export const DESTRUCTIVE_TOOL_KINDS = new Set<string>([
  "exec",
  "code_mode_exec",
  "apply_patch",
]);

/** host toolKind values that are pure observation → auto. Keep conservative:
 *  only kinds we know are read-only. Unknown kinds are NOT assumed read-only. */
export const READONLY_TOOL_KINDS = new Set<string>([
  "read",
  "search",
  "glob",
  "grep",
  "fetch",
]);

/** Destructive / read-only vocabulary for the name classifier.
 *
 * Tokens are matched against the *whole* tool name after splitting it into
 * segments (camelCase, snake_case, kebab-case, digits). Destructive tokens are
 * checked FIRST, so a composite name like `readWriteFile` or `getDeleteUser`
 * is gated even though it also contains a read-only token. A name that
 * contains neither a destructive nor a read-only token is unknown and falls
 * through to `defaultMode` (which defaults to `require-approval`). */
export const DESTRUCTIVE_NAME_TOKENS: readonly string[] = [
  "write", "edit", "delete", "remove", "rm", "rmdir", "mkdir",
  "move", "rename", "deploy", "publish", "install", "uninstall",
  "exec", "run", "apply", "patch", "create", "update", "kill",
  "send", "post", "put", "push", "commit", "flush", "drop",
  "truncate", "grant", "revoke",
];

export const READONLY_NAME_TOKENS: readonly string[] = [
  "read", "get", "list", "search", "glob", "grep", "view", "show",
  "status", "ping", "fetch", "head", "cat", "ls", "find", "whoami",
  "echo", "inspect", "describe", "explain", "query", "count",
];

/** Explicit built-in rules for known destructive toolKinds, applied after user
 *  rules. These carry severity / allowedDecisions defaults; the name-token
 *  classifier synthesises a lighter-weight decision for matched names. */
export const BUILTIN_DESTRUCTIVE_RULES: GateRule[] = [
  {
    id: "builtin:exec",
    toolKind: "exec",
    mode: "require-approval",
    severity: "warning",
    allowedDecisions: ["allow-once", "allow-always", "deny"],
    reason: "Shell command execution",
  },
  {
    id: "builtin:apply-patch",
    toolName: "apply_patch",
    mode: "require-approval",
    severity: "warning",
    allowedDecisions: ["allow-once", "allow-always", "deny"],
    reason: "Filesystem write via apply_patch",
  },
  {
    id: "builtin:code-mode-exec",
    toolKind: "code_mode_exec",
    mode: "require-approval",
    severity: "warning",
    allowedDecisions: ["allow-once", "deny"],
    reason: "Code Mode execution",
  },
];

/** Result of evaluating the policy against one tool call. */
export interface PolicyDecision {
  mode: GateMode;
  source: PolicySource;
  rule?: GateRule;
  /** Resolved severity/timeout/allowedDecisions (rule overrides config defaults). */
  severity: GateSeverity;
  timeoutMs: number;
  allowedDecisions: Array<"allow-once" | "allow-always" | "deny">;
  reason: string;
}

/** Key used to remember an allow-always decision for a rule. */
export function allowAlwaysKey(ruleId: string, toolName: string): string {
  return `${ruleId}::${toolName}`;
}

// ── Ask User (Claude Code-style chat prompt) ──

/** Input for the human_gate_ask tool (validated from raw params). */
export interface AskToolInput {
  /** The question to ask the human (required). */
  question: string;
  /** Optional labeled choices (e.g. ["A: Go ahead", "B: Let me check first"]). */
  choices?: string[];
  /** Allow the human to type a free-form answer instead of picking a choice. */
  allowFreeText?: boolean;
  /** Context info to help the human understand why this is being asked. */
  context?: string;
}

/** Structured `details` returned by the ask tool (not entered into prompt
 *  replay; consumed by Code Mode / Tool Search / programmatic callers). */
export interface AskToolDetails {
  question: string;
  choices: string[];
  allowFreeText: boolean;
  context?: string;
}

/** Parse + validate raw tool params into AskToolInput. Throws on missing
 *  question. Strips non-string choices. */
export function parseAskInput(params: unknown): AskToolInput {
  const o = typeof params === "object" && params !== null
    ? (params as Record<string, unknown>)
    : {};
  const question = typeof o.question === "string" ? o.question.trim() : "";
  if (!question) {
    throw new Error("human_gate_ask: 'question' (string) is required");
  }
  const rawChoices = Array.isArray(o.choices) ? o.choices : [];
  const choices = rawChoices
    .filter((c): c is string => typeof c === "string")
    .map((c) => c.trim())
    .filter(Boolean)
    .slice(0, 8);
  const context = typeof o.context === "string" ? o.context.trim() : "";
  return {
    question: question.slice(0, 2000),
    choices: choices.length > 0 ? choices.map((c) => c.slice(0, 500)) : undefined,
    allowFreeText: typeof o.allowFreeText === "boolean" ? o.allowFreeText : undefined,
    context: context ? context.slice(0, 2000) : undefined,
  };
}

/** Format the question + choices as text for the tool result `content`,
 *  which the agent presents in chat. The agent is instructed to wait. */
export function formatAskForChat(p: AskToolInput): string {
  const lines: string[] = [
    "The AI needs your input before continuing.",
  ];
  if (p.context) lines.push("", `Context: ${p.context}`);
  lines.push("", `Q: ${p.question}`);
  const choices = p.choices ?? [];
  const allowFree = p.allowFreeText ?? choices.length === 0;
  if (choices.length > 0) {
    lines.push("", "Options:");
    for (let i = 0; i < choices.length; i++) {
      lines.push(`  ${i + 1}. ${choices[i]}`);
    }
    if (allowFree) {
      lines.push("  (or reply with your own answer)");
    }
  } else {
    lines.push("", "(reply with your answer)");
  }
  lines.push(
    "",
    "Reply in chat — the AI will wait for your response before taking any further action.",
  );
  // Tool result text has no documented hard cap, but keep it reasonable.
  return lines.join("\n");
}

/** Resolve the structured details value for the tool result. */
export function askDetails(p: AskToolInput): AskToolDetails {
  const choices = p.choices ?? [];
  return {
    question: p.question,
    choices,
    allowFreeText: p.allowFreeText ?? choices.length === 0,
    context: p.context,
  };
}
