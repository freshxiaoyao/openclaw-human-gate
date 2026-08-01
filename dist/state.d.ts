/** Per-session allow-always state backed by OpenClaw session extensions. */
export interface AllowAlwaysState {
    /** Map of `${ruleId}::${toolName}` -> ISO timestamp granted. */
    grants: Record<string, string>;
}
export type SessionStateReader<T> = (sessionKey: string) => T | undefined;
export type SessionStateUpdater<T> = (sessionKey: string, update: (current: T) => T) => Promise<void>;
export declare class AllowAlwaysStore {
    private readonly read;
    private readonly update;
    constructor(read: SessionStateReader<AllowAlwaysState>, update: SessionStateUpdater<AllowAlwaysState>);
    isGranted(sessionKey: string, ruleId: string, toolName: string): boolean;
    grant(sessionKey: string, ruleId: string, toolName: string): Promise<void>;
    revoke(sessionKey: string, ruleId: string, toolName: string): Promise<void>;
    snapshot(sessionKey: string): AllowAlwaysState;
}
//# sourceMappingURL=state.d.ts.map