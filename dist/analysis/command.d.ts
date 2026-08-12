import type { SemanticAnalysisConfig } from "../types.js";
import type { AnalysisResult, ToolCallAnalyzer, ToolCallContext } from "./types.js";
export interface ExtractedCommand {
    key: string;
    value: string;
}
export declare function extractCommand(context: ToolCallContext): ExtractedCommand | undefined;
export declare class CommandAnalyzer implements ToolCallAnalyzer {
    private readonly config;
    readonly id = "builtin.command-semantics";
    readonly priority = 100;
    constructor(config: SemanticAnalysisConfig);
    supports(context: ToolCallContext): boolean;
    analyze(context: ToolCallContext): AnalysisResult;
}
//# sourceMappingURL=command.d.ts.map