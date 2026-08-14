export const ADAPTIVE_ELIGIBILITY_VERSION = "safe-file-v1";
function exactSet(values, expected) {
    const actualSet = new Set(values);
    const expectedSet = new Set(expected);
    if (actualSet.size !== values.length || expectedSet.size !== expected.length)
        return false;
    if (actualSet.size !== expectedSet.size)
        return false;
    return [...actualSet].every((value) => expectedSet.has(value));
}
/** Absolute means independent of process cwd. In particular, `C:foo` and
 * `\\foo` are rejected even though some platform helpers treat them as rooted. */
export function isStrictAbsoluteTarget(value) {
    if (value.length === 0 || value.trim() !== value || /[\0\r\n]/.test(value))
        return false;
    if (/^(?:\\\\|\/\/)[?.][\\/]/.test(value))
        return false;
    if (/^[A-Za-z]:[\\/]/.test(value))
        return true;
    if (/^(?:\\\\|\/\/)[^\\/]+[\\/][^\\/]+(?:[\\/]|$)/.test(value))
        return true;
    return value.startsWith("/") && !value.startsWith("//");
}
/**
 * Closed eligibility predicate for the first adaptive MVP. It intentionally
 * does not accept command/dev-loop intents: `complete` there describes shell
 * syntax, not transitive script, hook, network, or filesystem behavior.
 */
export function evaluateAdaptiveEligibility(input) {
    const { decision, fingerprint } = input;
    const report = decision.semanticReport;
    const reasons = [];
    if (decision.mode !== "require-approval")
        reasons.push("not-require-approval");
    if (decision.source === "user")
        reasons.push("explicit-user-policy");
    if (input.isParamScopedRule)
        reasons.push("param-scoped-policy");
    if (decision.severity === "critical")
        reasons.push("critical");
    if (!report.complete)
        reasons.push("analysis-incomplete");
    if (!decision.windowEligible || !report.windowEligible)
        reasons.push("not-reusable");
    if (!exactSet(report.analyzerIds, ["builtin.file-mutation-semantics"])) {
        reasons.push("wrong-analyzer-family");
    }
    if (!exactSet(report.effects, ["local-write"]))
        reasons.push("unsupported-effects");
    if (!exactSet(report.categories, ["filesystem"]))
        reasons.push("unsupported-categories");
    if (report.verifiedTargets.length === 0)
        reasons.push("missing-target");
    if (report.verifiedTargets.some((target) => !isStrictAbsoluteTarget(target.path))) {
        reasons.push("non-absolute-target");
    }
    // Permanent/adaptive grantKey is always the narrow full path fingerprint,
    // even when the temporary approval-window projection is category/effect.
    if (!fingerprint?.grantKey) {
        reasons.push("missing-path-fingerprint");
    }
    if (!input.sessionKey)
        reasons.push("missing-session");
    if (!input.rememberAllowAlways)
        reasons.push("remember-disabled");
    if (!input.toolCallId)
        reasons.push("missing-tool-call-id");
    return {
        eligible: reasons.length === 0,
        version: ADAPTIVE_ELIGIBILITY_VERSION,
        reasonCodes: reasons,
        ...(reasons.length === 0 && fingerprint ? { fingerprint } : {}),
        targetCount: report.verifiedTargets.length,
    };
}
//# sourceMappingURL=eligibility.js.map