/**
 * Policy engine: given a tool call and the resolved config, pick a decision.
 *
 * Evaluation order (first match wins):
 *  1. User rules           — explicit override (highest authority)
 *  2. Built-in destructive toolKind rules (exec / apply_patch / code_mode_exec)
 *  3. Name-token classifier (when useClassifiers)
 *     - destructive token in name  → require-approval (checked FIRST, so
 *       composite names like `readWriteFile` never slip through as reads)
 *     - read-only token / kind     → auto (pass through)
 *     - neither                    → unknown
 *  4. config.defaultMode    — fallback for unknowns (defaults to
 *     `require-approval`: fail-closed; unrecognized tools must be approved).
 *
 * Design intent: reads pass through; anything with side-effect vocabulary is
 * gated; anything unrecognized is gated unless the operator opts into
 * fail-open (`defaultMode: "auto"`).
 */
import { type HumanGateConfig, type PolicyDecision, type RuleParamMatcher } from "./types.js";
/** Split a tool name into lowercase segments.
 *
 * Handles camelCase (`readWriteFile` -> read, write, file), snake_case
 * (`remove_old_files` -> remove, old, files), kebab-case, and digit
 * boundaries (`list2` -> list, 2). Names that cannot be segmented reliably
 * (e.g. all-lowercase run-together words like `frobnicate` or `scatter`)
 * yield their whole lowercase form as a single segment — they will only hit
 * a token if the entire name is a vocabulary word (`cat`, `exec`).
 */
export declare function tokenizeName(name: string): string[];
/** Only simple top-level names are supported. Dotted/bracketed paths and
 * prototype-control names are rejected instead of being interpreted. */
export declare function isSafeDirectParamKey(key: string): boolean;
/** Runtime validation mirrors the manifest schema. A matcher has exactly one
 * top-level `all` or `any` array and cannot contain nested boolean groups. */
export declare function isValidRuleParamMatcher(value: unknown): value is RuleParamMatcher;
/** Match direct-own parameter constraints without invoking accessors or
 * traversing prototypes. Invalid matchers and missing required values fail. */
export declare function matchRuleParamMatcher(matcher: unknown, toolParams: Readonly<Record<string, unknown>> | undefined): boolean;
export declare function evaluatePolicy(toolName: string, toolKind: string | undefined, config: HumanGateConfig, toolParams?: Readonly<Record<string, unknown>>): PolicyDecision;
/** True when a session key belongs to an unattended context (cron isolated
 *  runs, heartbeat runs, subagents) that must not stall on an approval
 *  popup nobody can see.
 *
 *  Matching is exact per `:`-delimited segment — NOT a loose substring match —
 *  so `:cron:` never matches a key like `cronx:` or `x:cronology`. Configured
 *  keys may be written with or without surrounding colons (`":cron:"`,
 *  `":heartbeat"`, `"subagent"` all work); a bare value matches only a
 *  standalone segment.
 */
export declare function isAutoPassContext(sessionKey: string, keys: readonly string[]): boolean;
//# sourceMappingURL=policy.d.ts.map