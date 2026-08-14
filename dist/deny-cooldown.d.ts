/**
 * Per-session deny cooldown (remit-style).
 *
 * After an explicit `deny`, matching calls auto-block for a short window
 * instead of prompting the same question again. The cooldown is keyed by the
 * semantic scope key when one exists, else `ruleId::toolName`. It converts
 * ask → block only: it never touches auto or block decisions, it never
 * survives the window, and a clock rollback cannot extend it.
 */
export declare const DENY_COOLDOWN_STATE_VERSION: 1;
export interface DenyCooldownEntry {
    /** Semantic scope key when available, else `ruleId::toolName`. */
    scopeKey: string;
    deniedAt: number;
    expiresAt: number;
}
export interface DenyCooldownState {
    version: typeof DENY_COOLDOWN_STATE_VERSION;
    denials: Record<string, DenyCooldownEntry>;
}
export type DenyStateReader = (sessionKey: string) => DenyCooldownState | undefined;
export type DenyStateUpdater = (sessionKey: string, update: (current: DenyCooldownState) => DenyCooldownState) => Promise<void>;
/** Strict v1 parser. Legacy/unversioned state intentionally becomes empty. */
export declare function normalizeDenyCooldownState(value: unknown): DenyCooldownState;
export declare class DenyCooldownStore {
    private readonly read;
    private readonly update;
    private readonly cooldownMs;
    constructor(read: DenyStateReader, update: DenyStateUpdater, cooldownMs: number);
    /** True when a recent explicit deny covers this scope key. */
    isCoolingDown(sessionKey: string, scopeKey: string, now: number): boolean;
    /** Record an explicit deny. Best-effort: store failure simply means the
     *  next matching call asks again (fail toward asking). */
    recordDeny(sessionKey: string, scopeKey: string, now: number): Promise<void>;
    snapshot(sessionKey: string): DenyCooldownState;
}
//# sourceMappingURL=deny-cooldown.d.ts.map