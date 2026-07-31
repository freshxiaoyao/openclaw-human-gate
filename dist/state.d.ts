/**
 * Per-session allow-always memory.
 *
 * When a human picks "allow-always" for a (rule, tool) pair, we record it in a
 * plugin-owned session extension so the same combination is auto-approved for
 * the rest of the session. Falls back to pure in-memory storage when the
 * session extension is unavailable (e.g. older OpenClaw runtimes).
 */
import type { SessionExtensionHandle } from "openclaw/plugin-sdk/plugin-entry";
export interface AllowAlwaysState {
    /** Map of `${ruleId}::${toolName}` -> ISO timestamp granted. */
    grants: Record<string, string>;
}
export declare class AllowAlwaysStore {
    private readonly handle;
    /** In-memory fallback when session extension is unavailable. */
    private readonly memory;
    constructor(handle: SessionExtensionHandle<AllowAlwaysState> | null);
    private state;
    private write;
    isGranted(ruleId: string, toolName: string): boolean;
    grant(ruleId: string, toolName: string): void;
    revoke(ruleId: string, toolName: string): void;
    snapshot(): AllowAlwaysState;
}
//# sourceMappingURL=state.d.ts.map