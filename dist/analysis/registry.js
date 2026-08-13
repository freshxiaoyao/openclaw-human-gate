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
function higherMode(a, b) {
    if (!a)
        return b;
    if (!b)
        return a;
    return MODE_RANK[a] >= MODE_RANK[b] ? a : b;
}
function higherSeverity(a, b) {
    if (!a)
        return b;
    if (!b)
        return a;
    return SEVERITY_RANK[a] >= SEVERITY_RANK[b] ? a : b;
}
function analyzerFailure(analyzerId) {
    const finding = {
        id: "analysis.failed",
        category: "unknown",
        severity: "warning",
        confidence: "low",
        title: "Semantic analysis failed",
        explanation: `Analyzer ${analyzerId} could not classify this call; approval is required.`,
    };
    return {
        analyzerId,
        findings: [finding],
        effects: ["unknown"],
        categories: ["unknown"],
        verifiedTargets: [],
        complete: false,
        minimumMode: "require-approval",
        minimumSeverity: "warning",
        windowEligible: false,
    };
}
/** Runs matching analyzers and monotonically combines their safety constraints. */
export class AnalyzerRegistry {
    maxFindings;
    analyzers;
    constructor(analyzers, maxFindings) {
        this.maxFindings = maxFindings;
        this.analyzers = [...analyzers].sort((a, b) => b.priority - a.priority);
    }
    analyze(context) {
        const findings = [];
        const effects = new Set();
        const categories = new Set();
        const targets = new Map();
        const analyzerIds = [];
        let minimumMode;
        let minimumSeverity;
        let windowEligible = true;
        let complete = true;
        for (const analyzer of this.analyzers) {
            let result;
            try {
                if (!analyzer.supports(context))
                    continue;
                result = analyzer.analyze(context);
            }
            catch {
                result = analyzerFailure(analyzer.id);
            }
            analyzerIds.push(analyzer.id);
            findings.push(...result.findings);
            for (const effect of result.effects)
                effects.add(effect);
            for (const category of result.categories ?? [])
                categories.add(category);
            for (const target of result.verifiedTargets ?? []) {
                const key = `${target.source}\u0000${target.parameter ?? ""}\u0000${target.path}`;
                targets.set(key, target);
            }
            minimumMode = higherMode(minimumMode, result.minimumMode);
            minimumSeverity = higherSeverity(minimumSeverity, result.minimumSeverity);
            windowEligible = windowEligible && result.windowEligible;
            // Older/custom analyzers that omit completeness cannot authorize reuse.
            complete = complete && result.complete === true;
        }
        const uniqueFindings = [...new Map(findings.map((finding) => [finding.id, finding])).values()].sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]);
        return {
            findings: uniqueFindings.slice(0, Math.max(1, this.maxFindings)),
            effects: [...effects],
            categories: [...categories],
            verifiedTargets: [...targets.values()],
            complete: analyzerIds.length > 0 && complete,
            minimumMode,
            minimumSeverity,
            windowEligible: analyzerIds.length > 0 && complete && windowEligible,
            analyzerIds,
        };
    }
}
//# sourceMappingURL=registry.js.map