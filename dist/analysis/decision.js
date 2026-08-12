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
    return {
        ...base,
        mode,
        severity,
        allowedDecisions,
        reason,
        semanticReport: report,
        windowEligible: report.windowEligible && !critical,
    };
}
//# sourceMappingURL=decision.js.map