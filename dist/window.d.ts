/** Versioned, semantic per-session approval windows. */
import type { PolicyDecision } from "./types.js";
import { AUTHORIZATION_FINGERPRINT_VERSION, type AuthorizationFingerprint, type SemanticApprovalScope } from "./scope.js";
export declare const WINDOW_STATE_VERSION: 2;
export declare const MAX_WINDOW_ENTRIES = 128;
export interface ApprovalWindowRuntimeConfig {
    mode: "off" | "turn" | "time";
    ttlMs: number;
    bypassCritical: boolean;
}
export interface WindowEntry {
    scopeKey: string;
    scope: SemanticApprovalScope;
    fingerprintVersion: typeof AUTHORIZATION_FINGERPRINT_VERSION;
    rulesetVersion: string;
    mode: "turn" | "time";
    openedAt: number;
    expiresAt?: number;
    runId?: string;
}
export interface WindowState {
    version: typeof WINDOW_STATE_VERSION;
    windows: Record<string, WindowEntry>;
}
export type WindowStateReader = (sessionKey: string) => WindowState | undefined;
export type WindowStateUpdater = (sessionKey: string, update: (current: WindowState) => WindowState) => Promise<void>;
/** Strictly parse v2 state. Legacy/unversioned state is intentionally lost. */
export declare function normalizeWindowState(value: unknown): WindowState;
export declare class ApprovalWindowStore {
    private readonly read;
    private readonly update;
    constructor(read: WindowStateReader, update: WindowStateUpdater);
    bypasses(cfg: Pick<ApprovalWindowRuntimeConfig, "bypassCritical">, decision: PolicyDecision): boolean;
    isOpen(cfg: ApprovalWindowRuntimeConfig, sessionKey: string, fingerprint: AuthorizationFingerprint | undefined, runId: string | undefined, now: number): boolean;
    open(cfg: ApprovalWindowRuntimeConfig, sessionKey: string, fingerprint: AuthorizationFingerprint | undefined, runId: string | undefined, now: number): Promise<boolean>;
    snapshot(sessionKey: string): WindowState;
}
//# sourceMappingURL=window.d.ts.map