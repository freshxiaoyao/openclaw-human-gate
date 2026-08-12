import type { EffectiveDecision } from "../analysis/decision.js";
import type { ToolCallContext } from "../analysis/types.js";
import type { ApprovalPreviewConfig } from "../types.js";
import type { ApprovalPreviewProvider } from "./types.js";
export declare class ApprovalPresenter {
    private readonly config;
    private readonly providers;
    constructor(config: ApprovalPreviewConfig, providers?: readonly ApprovalPreviewProvider[]);
    private preview;
    describe(context: ToolCallContext, decision: EffectiveDecision): string;
}
//# sourceMappingURL=presenter.d.ts.map