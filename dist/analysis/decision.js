const MODE_RANK = {
    auto: 0,
    "require-approval": 1,
    block: 2,
};
const SEVERITY_RANK = {
    info: 0,
    warning: 1,
    critical: 2,
};
function maxMode(a, b) {
    if (!b)
        return a;
    return MODE_RANK[a] >= MODE_RANK[b] ? a : b;
}
function maxSeverity(a, b) {
    if (!b)
        return a;
    return SEVERITY_RANK[a] >= SEVERITY_RANK[b] ? a : b;
}
/** Semantic analysis is upgrade-only across every policy source, including an
 * explicit broad auto rule. Operators can disable semantic analysis globally,
 * but an `auto` rule cannot accidentally whitelist dangerous parameters. */
export function reduceDecision(base, report) {
    const mode = maxMode(base.mode, report.minimumMode);
    const severity = maxSeverity(base.severity, report.minimumSeverity);
    const critical = severity === "critical";
    const allowedDecisions = critical
        ? base.allowedDecisions.filter((item) => item !== "allow-always")
        : [...base.allowedDecisions];
    if (critical && !allowedDecisions.includes("deny"))
        allowedDecisions.push("deny");
    const semanticReason = report.findings.find((finding) => finding.severity === "critical") ??
        report.findings[0];
    const reason = base.mode === "block"
        ? base.reason
        : semanticReason
            ? `${base.reason}; semantic risk: ${semanticReason.title}`
            : base.reason;
    const reusableSemantics = report.complete &&
        report.analyzerIds.length > 0 &&
        report.effects.length > 0 &&
        report.categories.length > 0 &&
        !report.effects.includes("unknown") &&
        !report.categories.includes("unknown");
    return {
        ...base,
        mode,
        severity,
        allowedDecisions,
        reason,
        semanticReport: report,
        // Reusable authorization is stricter than the one-shot decision. Empty,
        // partial, or unknown semantics may still be approved once, but can never
        // inherit an earlier approval or open a window for a later call.
        windowEligible: reusableSemantics && report.windowEligible && !critical,
    };
}
//# sourceMappingURL=decision.js.map