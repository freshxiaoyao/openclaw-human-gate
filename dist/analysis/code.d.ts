import type { SemanticAnalysisConfig } from "../types.js";
import type { AnalysisResult, ToolCallAnalyzer, ToolCallContext } from "./types.js";
export declare function extractCode(context: ToolCallContext): string | undefined;
export declare class CodeModeAnalyzer implements ToolCallAnalyzer {
    private readonly config;
    readonly id = "builtin.code-mode-semantics";
    readonly priority = 110;
    constructor(config: SemanticAnalysisConfig);
    supports(context: ToolCallContext): boolean;
    analyze(context: ToolCallContext): AnalysisResult;
}
//# sourceMappingURL=code.d.ts.map