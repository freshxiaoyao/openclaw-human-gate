import type { EffectiveDecision } from "../analysis/decision.js";
import type { AuthorizationFingerprint } from "../scope.js";
export declare const ADAPTIVE_ELIGIBILITY_VERSION: "safe-file-v1";
export type AdaptiveIneligibleReason = "not-require-approval" | "explicit-user-policy" | "param-scoped-policy" | "critical" | "analysis-incomplete" | "not-reusable" | "wrong-analyzer-family" | "unsupported-effects" | "unsupported-categories" | "missing-target" | "non-absolute-target" | "missing-path-fingerprint" | "missing-session" | "remember-disabled" | "missing-tool-call-id";
export interface AdaptiveEligibilityInput {
    decision: EffectiveDecision;
    fingerprint: AuthorizationFingerprint | undefined;
    isParamScopedRule: boolean;
    sessionKey: string | undefined;
    toolCallId: string | undefined;
    rememberAllowAlways: boolean;
}
export interface AdaptiveEligibility {
    eligible: boolean;
    version: typeof ADAPTIVE_ELIGIBILITY_VERSION;
    reasonCodes: AdaptiveIneligibleReason[];
    fingerprint?: AuthorizationFingerprint;
    targetCount: number;
}
/** Absolute means independent of process cwd. In particular, `C:foo` and
 * `\\foo` are rejected even though some platform helpers treat them as rooted. */
export declare function isStrictAbsoluteTarget(value: string): boolean;
/**
 * Closed eligibility predicate for the first adaptive MVP. It intentionally
 * does not accept command/dev-loop intents: `complete` there describes shell
 * syntax, not transitive script, hook, network, or filesystem behavior.
 */
export declare function evaluateAdaptiveEligibility(input: AdaptiveEligibilityInput): AdaptiveEligibility;
//# sourceMappingURL=eligibility.d.ts.map