import type { SemanticReport, ToolCallAnalyzer, ToolCallContext } from "./types.js";
/** Runs matching analyzers and monotonically combines their safety constraints. */
export declare class AnalyzerRegistry {
    private readonly maxFindings;
    private readonly analyzers;
    constructor(analyzers: readonly ToolCallAnalyzer[], maxFindings: number);
    analyze(context: ToolCallContext): SemanticReport;
}
//# sourceMappingURL=registry.d.ts.map