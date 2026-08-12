import type { GateMode, GateSeverity } from "../types.js";
/** Immutable, host-derived input shared by semantic analyzers and previews. */
export interface ToolCallContext {
    toolName: string;
    toolKind?: string;
    toolInputKind?: string;
    params: Readonly<Record<string, unknown>>;
    derivedPaths: readonly string[];
}
export type ToolEffect = "read-only" | "local-write" | "network-write" | "code-execution" | "privilege-change" | "destructive" | "unknown";
export type RiskCategory = "filesystem" | "network" | "execution" | "credentials" | "privilege" | "source-control" | "deployment" | "obfuscation" | "unknown";
export interface RiskFinding {
    id: string;
    category: RiskCategory;
    severity: GateSeverity;
    confidence: "high" | "medium" | "low";
    title: string;
    explanation: string;
    evidence?: {
        source: "command" | "argument" | "operator" | "path" | "content";
        excerpt?: string;
    };
}
export interface AnalysisResult {
    analyzerId: string;
    findings: RiskFinding[];
    effects: ToolEffect[];
    minimumMode?: GateMode;
    minimumSeverity?: GateSeverity;
    /** False means an earlier approval must never suppress this call. */
    windowEligible: boolean;
}
/** Small, pure extension point. An analyzer must never execute the input. */
export interface ToolCallAnalyzer {
    readonly id: string;
    readonly priority: number;
    supports(context: ToolCallContext): boolean;
    analyze(context: ToolCallContext): AnalysisResult;
}
export interface SemanticReport {
    findings: RiskFinding[];
    effects: ToolEffect[];
    minimumMode?: GateMode;
    minimumSeverity?: GateSeverity;
    windowEligible: boolean;
    analyzerIds: string[];
}
export declare const EMPTY_SEMANTIC_REPORT: SemanticReport;
//# sourceMappingURL=types.d.ts.map