/** Owner-issued, session-scoped temporary lease for ordinary shell exec calls. */
import type { SessionStateReader, SessionStateUpdater } from "./state.js";
export declare const EXEC_LEASE_STATE_VERSION: 1;
export declare const EXEC_LEASE_POLICY_VERSION: "ordinary-exec-v1";
export declare const MIN_EXEC_LEASE_MS = 60000;
export declare const MAX_EXEC_LEASE_MS = 3600000;
export declare const DEFAULT_EXEC_LEASE_MS = 900000;
export interface ExecLease {
    policyVersion: typeof EXEC_LEASE_POLICY_VERSION;
    grantedAt: string;
    expiresAt: string;
    issuedTtlMs: number;
}
export interface ExecLeaseState {
    version: typeof EXEC_LEASE_STATE_VERSION;
    lease?: ExecLease;
}
export declare function normalizeExecLeaseState(value: unknown): ExecLeaseState;
export type ExecLeaseStatus = {
    active: false;
} | {
    active: true;
    expiresAt: string;
    remainingMs: number;
};
export declare class ExecLeaseStore {
    private readonly read;
    private readonly update;
    constructor(read: SessionStateReader<ExecLeaseState>, update: SessionStateUpdater<ExecLeaseState>);
    status(sessionKey: string, now?: number): ExecLeaseStatus;
    isActive(sessionKey: string, now?: number): boolean;
    grant(sessionKey: string, ttlMs: number, now?: number): Promise<ExecLeaseStatus>;
    revoke(sessionKey: string): Promise<void>;
}
/** Parse `15m`, `1h`, or a bare minute count. */
export declare function parseExecLeaseDuration(raw: string): number | undefined;
export declare function isOrdinaryExec(toolName: string, toolKind?: string, toolInputKind?: string): boolean;
//# sourceMappingURL=exec-lease.d.ts.map