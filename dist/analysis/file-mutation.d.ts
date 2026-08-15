import type { SemanticAnalysisConfig } from "../types.js";
import type { AnalysisResult, ToolCallAnalyzer, ToolCallContext } from "./types.js";
/** Canonical mutation-tool vocabulary, exported so policy layers (e.g.
 * self-protection) share the analyzer's single source of truth and never
 * drift from the envelope shapes the analyzer actually recognizes. */
export declare const MUTATION_TOOL_NAMES: {
    readonly write: Set<string>;
    readonly edit: Set<string>;
    readonly applyPatch: "apply_patch";
};
export declare const MUTATION_PATH_KEYS: readonly ["path", "filePath", "file_path"];
export declare const MUTATION_PATCH_KEYS: readonly ["input", "patch", "patchText", "patch_text"];
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