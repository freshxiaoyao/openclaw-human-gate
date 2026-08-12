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
export type ApprovalDecision = "allow-once" | "allow-always" | "deny" | "timeout" | "cancelled";
/** JSON scalar supported by parameter-level policy matching. Objects and
 * arrays are deliberately excluded so equality stays unambiguous. */
export type ParamScalar = string | number | boolean | null;
/** One condition over a direct, own tool parameter. Operator objects are
 * mutually exclusive and validated strictly at runtime. */
export type ParamCondition = {
    key: string;
    equals: ParamScalar;
} | {
    key: string;
    in: ParamScalar[];
} | {
    key: string;
    missing: true;
};
/** A deliberately one-level boolean expression. Nested matcher trees are not
 * supported, keeping authorization rules inspectable and bounded. */
export type RuleParamMatcher = {
    all: ParamCondition[];
} | {
    any: ParamCondition[];
};
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
    /** Persist allow-always decisions per session. */
    rememberAllowAlways: boolean;
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
    /** Approval window: after the human approves one destructive call, further
     *  matching calls auto-pass for a turn or a time box, so a multi-step write
     *  task does not prompt once per file. */
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
    /** "off" = prompt every destructive call (per-call behavior).
     *  "turn" = after one approval, same-class calls auto-pass for the rest of
     *           the current agent run (keyed by runId; a new user turn resets).
     *  "time" = after one approval, same-class calls auto-pass for ttlMs. */
    mode: "off" | "turn" | "time";
    /** Time-box duration for mode "time". Ignored otherwise. */
    ttlMs: number;
    /** "destructive" = any gated write shares one window (broadest, least
     *  prompting). "same-tool" = only the same toolName shares the window. */
    match: "destructive" | "same-tool";
    /** When true (default), severity "critical" calls always prompt even if a
     *  window is open (e.g. production deploys never get auto-passed). */
    bypassCritical: boolean;
}
export declare const DEFAULT_CONFIG: HumanGateConfig;
/** host toolKind values that always have side effects → require approval. */
export declare const DESTRUCTIVE_TOOL_KINDS: Set<string>;
/** host toolKind values that are pure observation → auto. Keep conservative:
 *  only kinds we know are read-only. Unknown kinds are NOT assumed read-only. */
export declare const READONLY_TOOL_KINDS: Set<string>;
/** Destructive / read-only vocabulary for the name classifier.
 *
 * Tokens are matched against the *whole* tool name after splitting it into
 * segments (camelCase, snake_case, kebab-case, digits). Destructive tokens are
 * checked FIRST, so a composite name like `readWriteFile` or `getDeleteUser`
 * is gated even though it also contains a read-only token. A name that
 * contains neither a destructive nor a read-only token is unknown and falls
 * through to `defaultMode` (which defaults to `require-approval`). */
export declare const DESTRUCTIVE_NAME_TOKENS: readonly string[];
export declare const READONLY_NAME_TOKENS: readonly string[];
/** Explicit built-in rules for known destructive toolKinds, applied after user
 *  rules. These carry severity / allowedDecisions defaults; the name-token
 *  classifier synthesises a lighter-weight decision for matched names. */
export declare const BUILTIN_DESTRUCTIVE_RULES: GateRule[];
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
export declare function allowAlwaysKey(ruleId: string, toolName: string): string;
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
export declare function parseAskInput(params: unknown): AskToolInput;
/** Format the question + choices as text for the tool result `content`,
 *  which the agent presents in chat. The agent is instructed to wait. */
export declare function formatAskForChat(p: AskToolInput): string;
/** Resolve the structured details value for the tool result. */
export declare function askDetails(p: AskToolInput): AskToolDetails;
//# sourceMappingURL=types.d.ts.map