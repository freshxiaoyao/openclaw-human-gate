/** Per-session, semantically scoped allow-always state. */
import type { AuthorizationFingerprint } from "./scope.js";
export declare const ALLOW_ALWAYS_STATE_VERSION: 2;
export interface AllowAlwaysGrant {
    fingerprintKey: string;
    fingerprintVersion: number;
    rulesetVersion: string;
    grantedAt: string;
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
    constructor(read: SessionStateReader<AllowAlwaysState>, update: SessionStateUpdater<AllowAlwaysState>);
    isGranted(sessionKey: string, fingerprint: AuthorizationFingerprint): boolean;
    grant(sessionKey: string, fingerprint: AuthorizationFingerprint): Promise<void>;
    revoke(sessionKey: string, fingerprint: AuthorizationFingerprint): Promise<void>;
    snapshot(sessionKey: string): AllowAlwaysState;
}
//# sourceMappingURL=state.d.ts.map