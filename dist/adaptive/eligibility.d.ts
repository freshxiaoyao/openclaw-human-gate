import type { EffectiveDecision } from "../analysis/decision.js";
import type { AuthorizationFingerprint } from "../scope.js";
export declare const ADAPTIVE_ELIGIBILITY_VERSION: "safe-file-v2";
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
    /** True when every *semantic* precondition passes (the call is a safe-file
     * write) regardless of whether a lease can be minted right now. Adaptive
     * ownership is decided on this flag, never on `eligible`, so a missing
     * optional toolCallId/session can never fall back to a legacy grant. */
    semanticEligible: boolean;
}
/** Absolute means independent of process cwd AND correct for the host
 * platform. On Windows a leading-slash path (`/foo`) is drive-relative and
 * must not mint a lease; on POSIX, drive-letter and UNC paths are not
 * absolute. `C:foo` and `\foo` remain rejected on every platform. */
export declare function isStrictAbsoluteTarget(value: string): boolean;
/**
 * Closed eligibility predicate for the first adaptive MVP. It intentionally
 * does not accept command/dev-loop intents: `complete` there describes shell
 * syntax, not transitive script, hook, network, or filesystem behavior.
 */
export declare function evaluateAdaptiveEligibility(input: AdaptiveEligibilityInput): AdaptiveEligibility;
//# sourceMappingURL=eligibility.d.ts.map