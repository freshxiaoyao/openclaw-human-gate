import type { SemanticAnalysisConfig } from "../types.js";
import type { AnalysisResult, ToolCallAnalyzer, ToolCallContext } from "./types.js";
/** Semantic classifier for the plugin's strictly known filesystem mutation
 * tools. It never promotes host-derived paths into verified targets. */
export declare class FileMutationAnalyzer implements ToolCallAnalyzer {
    private readonly config;
    readonly id = "builtin.file-mutation-semantics";
    readonly priority = 105;
    constructor(config: SemanticAnalysisConfig);
    supports(context: ToolCallContext): boolean;
    analyze(context: ToolCallContext): AnalysisResult;
}
//# sourceMappingURL=file-mutation.d.ts.map