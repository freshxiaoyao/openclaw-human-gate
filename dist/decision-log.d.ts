/**
 * Best-effort decision audit trail.
 *
 * A bounded in-memory ring buffer plus an optional append-only JSONL file.
 * Records carry a session digest (never the raw session key) and scope
 * digests — never raw parameter values. Recording is best-effort by design:
 * a log write failure must never change an enforcement outcome.
 */
export declare const DECISION_LOG_VERSION: 1;
export declare const DEFAULT_MAX_ENTRIES = 512;
/** Oldest ask timestamps kept for flood counting. askRate() windows are
 * clamped to this retention, so the ask window is bounded even when nothing
 * ever calls askRate(). */
export declare const ASK_WINDOW_RETENTION_MS = 3600000;
export type DecisionOutcome = "block" | "auto" | "ask" | "allow-once" | "allow-always" | "deny" | "timeout" | "cancelled";
export interface DecisionLogEntry {
    ts: number;
    /** SHA-256 digest of the session key; the raw key is never stored. */
    sessionDigest: string;
    sessionId?: string;
    toolName: string;
    ruleId?: string;
    decision: DecisionOutcome;
    severity?: string;
    /** Short digest of the semantic scope key when one exists. */
    scopeDigest?: string;
    reason?: string;
    latencyMs?: number;
}
export interface DecisionLogConfig {
    enabled: boolean;
    maxEntries: number;
    filePath?: string;
}
/** Stable, bounded digest of a session key for the audit trail. */
export declare function digestSessionKey(sessionKey: string): string;
export declare class DecisionLog {
    private readonly config;
    private readonly entries;
    private readonly askWindow;
    /** Resolved once at construction — never on the decision hot path. */
    private readonly logPath;
    /** Serialized async appends preserve line order without blocking the gate. */
    private fileQueue;
    constructor(config: DecisionLogConfig);
    get enabled(): boolean;
    record(entry: DecisionLogEntry): void;
    /** Snapshot of the ring buffer, oldest first. */
    snapshot(): DecisionLogEntry[];
    /** Number of ask decisions in the trailing `ms` window (flood counter).
     *  The window is clamped to ASK_WINDOW_RETENTION_MS. */
    askRate(ms: number, now?: number): number;
    /** Await pending file appends (tests / shutdown). Resolves immediately when
     *  file logging is disabled. Never rejects. */
    flush(): Promise<void>;
    private bound;
    private enqueueAppend;
}
//# sourceMappingURL=decision-log.d.ts.map