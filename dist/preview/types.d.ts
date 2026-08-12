import type { ToolCallContext } from "../analysis/types.js";
import type { ApprovalPreviewConfig } from "../types.js";
export interface PreviewSection {
    title: string;
    body: string;
}
export interface ApprovalPreviewProvider {
    readonly id: string;
    readonly priority: number;
    supports(context: ToolCallContext): boolean;
    build(context: ToolCallContext, config: ApprovalPreviewConfig): PreviewSection | undefined;
}
//# sourceMappingURL=types.d.ts.map