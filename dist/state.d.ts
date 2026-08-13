/** Per-session, semantically scoped allow-always state. */
import type { AuthorizationFingerprint } from "./scope.js";
export declare const ALLOW_ALWAYS_STATE_VERSION: 3;
export interface AllowAlwaysGrant {
    fingerprintKey: string;
    fingerprintVersion: number;
    rulesetVersion: string;
    grantedAt: string;
    /** Hard upper bound: allow-always is a bounded session/task lease, never an
     * unlimited grant. Old grants without this field are discarded on load. */
    expiresAt: string;
}
export interface AllowAlwaysState {
    version: typeof ALLOW_ALWAYS_STATE_VERSION;
    /** Map of opaque semantic scope digest to validated grant metadata. */
    grants: Record<string, AllowAlwaysGrant>;
}
export type SessionStateReader<T> = (sessionKey: string) => T | undefined;
export type SessionStateUpdater<T> = (sessionKey: string, update: (current: T) => T) => Promise<void>;
/** Strict v2 parser. Legacy/unversioned grants intentionally become empty. */
export declare function normalizeAllowAlwaysState(value: unknown): AllowAlwaysState;
export declare class AllowAlwaysStore {
    private readonly read;
    private readonly update;
    private readonly ttlMs;
    constructor(read: SessionStateReader<AllowAlwaysState>, update: SessionStateUpdater<AllowAlwaysState>, ttlMs: number);
    isGranted(sessionKey: string, fingerprint: AuthorizationFingerprint, now: number): boolean;
    grant(sessionKey: string, fingerprint: AuthorizationFingerprint, now: number): Promise<void>;
    revoke(sessionKey: string, fingerprint: AuthorizationFingerprint): Promise<void>;
    snapshot(sessionKey: string): AllowAlwaysState;
}
//# sourceMappingURL=state.d.ts.map