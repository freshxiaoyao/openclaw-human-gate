/**
 * Per-session approval windows.
 *
 * After one destructive call is approved, subsequent matching calls can
 * auto-pass for the same run or a bounded time. State is stored per match key,
 * rather than as one global slot, so approving an `exec` call does not evict an
 * existing `apply_patch` window (and vice versa).
 *
 * The store is defensive: if the host session extension throws after
 * registration, it transparently falls back to process memory.
 */
import type { SessionExtensionHandle } from "openclaw/plugin-sdk/plugin-entry";
import type { ApprovalWindowConfig, PolicyDecision } from "./types.js";
export interface WindowEntry {
    runId?: string;
    openedAt: number;
}
export interface WindowState {
    windows: Record<string, WindowEntry>;
}
export declare class ApprovalWindowStore {
    private readonly handle;
    private readonly memory;
    constructor(handle: SessionExtensionHandle<WindowState> | null);
    private keyFor;
    private state;
    private write;
    bypasses(cfg: ApprovalWindowConfig, decision: PolicyDecision): boolean;
    isOpen(cfg: ApprovalWindowConfig, toolName: string, runId: string | undefined, now: number): boolean;
    open(cfg: ApprovalWindowConfig, toolName: string, runId: string | undefined, now: number): void;
    snapshot(): WindowState;
}
//# sourceMappingURL=window.d.ts.map