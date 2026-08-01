/** Per-session approval windows backed by OpenClaw session extensions. */
import type { ApprovalWindowConfig, PolicyDecision } from "./types.js";
export interface WindowEntry {
    runId?: string;
    openedAt: number;
}
export interface WindowState {
    windows: Record<string, WindowEntry>;
}
export type WindowStateReader = (sessionKey: string) => WindowState | undefined;
export type WindowStateUpdater = (sessionKey: string, update: (current: WindowState) => WindowState) => Promise<void>;
export declare class ApprovalWindowStore {
    private readonly read;
    private readonly update;
    constructor(read: WindowStateReader, update: WindowStateUpdater);
    private keyFor;
    bypasses(cfg: ApprovalWindowConfig, decision: PolicyDecision): boolean;
    isOpen(cfg: ApprovalWindowConfig, sessionKey: string, toolName: string, runId: string | undefined, now: number): boolean;
    open(cfg: ApprovalWindowConfig, sessionKey: string, toolName: string, runId: string | undefined, now: number): Promise<void>;
    snapshot(sessionKey: string): WindowState;
}
//# sourceMappingURL=window.d.ts.map