import type { ApprovalDecision, AdaptiveAutoPassConfig } from "../types.js";
import { type AuthorizationFingerprint } from "../scope.js";
import { ADAPTIVE_ELIGIBILITY_VERSION } from "./eligibility.js";
export declare const ADAPTIVE_STATE_VERSION: 1;
export interface AdaptiveObservation {
    fingerprintKey: string;
    approvalCount: number;
    lastApprovedAt: string;
    /** Bounded replay tombstones for approval callbacks. */
    grantOriginToolCallIds: string[];
}
export interface AdaptiveLease {
    fingerprintKey: string;
    fingerprintVersion: number;
    rulesetVersion: string;
    eligibilityVersion: typeof ADAPTIVE_ELIGIBILITY_VERSION;
    origin: "explicit-allow-always";
    originToolCallId: string;
    grantedAt: string;
    expiresAt: string;
    issuedTtlMs: number;
    maxUses: number;
    remainingUses: number;
}
export interface AdaptiveState {
    version: typeof ADAPTIVE_STATE_VERSION;
    observations: Record<string, AdaptiveObservation>;
    leases: Record<string, AdaptiveLease>;
}
export type AdaptiveStateReader = (sessionKey: string) => AdaptiveState | undefined;
export type AdaptiveStateUpdater = (sessionKey: string, update: (current: AdaptiveState) => AdaptiveState) => Promise<void>;
export type AdaptiveConsumeOutcome = "consumed" | "missing" | "expired" | "exhausted" | "mismatch" | "clock-rollback";
export interface AdaptiveConsumeResult {
    outcome: AdaptiveConsumeOutcome;
    remainingBefore?: number;
    remainingAfter?: number;
    expiresAt?: string;
}
/** Strict parser. Unknown/legacy/future state becomes empty. */
export declare function normalizeAdaptiveState(value: unknown): AdaptiveState;
export declare class AdaptiveLeaseStore {
    private readonly read;
    private readonly update;
    private readonly config;
    constructor(read: AdaptiveStateReader, update: AdaptiveStateUpdater, config: Pick<AdaptiveAutoPassConfig, "ttlMs" | "maxUses">);
    approvalCount(sessionKey: string, fingerprint: AuthorizationFingerprint): number;
    observeApproval(sessionKey: string, fingerprint: AuthorizationFingerprint, decision: ApprovalDecision, now: number): Promise<void>;
    grant(sessionKey: string, fingerprint: AuthorizationFingerprint, now: number, originToolCallId: string | undefined): Promise<boolean>;
    consume(sessionKey: string, fingerprint: AuthorizationFingerprint, now: number): Promise<AdaptiveConsumeResult>;
    revoke(sessionKey: string, fingerprint: AuthorizationFingerprint): Promise<void>;
    snapshot(sessionKey: string): AdaptiveState;
}
//# sourceMappingURL=state.d.ts.map