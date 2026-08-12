export function extractCode(context) {
    if (context.toolKind !== "code_mode_exec")
        return undefined;
    const code = context.params.code ?? context.params.command;
    return typeof code === "string" && code.trim() ? code : undefined;
}
export class CodeModeAnalyzer {
    config;
    id = "builtin.code-mode-semantics";
    priority = 110;
    constructor(config) {
        this.config = config;
    }
    supports(context) {
        return context.toolKind === "code_mode_exec";
    }
    analyze(context) {
        const source = extractCode(context);
        if (!source) {
            const finding = {
                id: "code.input-missing",
                category: "unknown",
                severity: "warning",
                confidence: "low",
                title: "Code Mode input is not reviewable",
                explanation: "The normalized code/command parameter is missing or not a string.",
            };
            return {
                analyzerId: this.id,
                findings: [finding],
                effects: ["unknown"],
                minimumMode: "require-approval",
                minimumSeverity: "warning",
                windowEligible: false,
            };
        }
        const truncated = source.length > this.config.maxCommandLength;
        const code = source.slice(0, this.config.maxCommandLength);
        const excerpt = code.slice(0, 320);
        const findings = [];
        if (/\b(?:eval\s*\(|Function\s*\(|WebAssembly\.compile\b)/.test(code)) {
            findings.push({
                id: "code.dynamic-execution",
                category: "obfuscation",
                severity: "critical",
                confidence: "medium",
                title: "Code constructs executable logic dynamically",
                explanation: "Dynamic evaluation makes the effective operation difficult to review.",
                evidence: { source: "content", excerpt },
            });
        }
        if (/\btools\.(?:call|exec)\s*\(/.test(code)) {
            findings.push({
                id: "code.tool-invocation",
                category: "execution",
                severity: "warning",
                confidence: "high",
                title: "Code invokes another tool",
                explanation: "Nested tools remain independently gated; this code execution still needs approval.",
                evidence: { source: "content", excerpt },
            });
        }
        if (truncated) {
            findings.unshift({
                id: "code.input-truncated",
                category: "unknown",
                severity: "warning",
                confidence: "low",
                title: "Code exceeds analysis limit",
                explanation: "Only the configured prefix was analyzed; approval-window reuse is disabled.",
                evidence: { source: "content", excerpt },
            });
        }
        const critical = findings.some((finding) => finding.severity === "critical");
        return {
            analyzerId: this.id,
            findings,
            effects: ["code-execution"],
            minimumMode: "require-approval",
            minimumSeverity: critical ? "critical" : "warning",
            windowEligible: findings.length === 0 && !truncated,
        };
    }
}
//# sourceMappingURL=code.js.map