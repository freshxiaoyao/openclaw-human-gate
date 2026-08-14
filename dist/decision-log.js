/**
 * Best-effort decision audit trail.
 *
 * A bounded in-memory ring buffer plus an optional append-only JSONL file.
 * Records carry a session digest (never the raw session key) and scope
 * digests — never raw parameter values. Recording is best-effort by design:
 * a log write failure must never change an enforcement outcome.
 */
import { createHash } from "node:crypto";
import { homedir } from "node:os";
import { isAbsolute, join, dirname } from "node:path";
import { appendFileSync, mkdirSync } from "node:fs";
export const DECISION_LOG_VERSION = 1;
export const DEFAULT_MAX_ENTRIES = 512;
const MAX_SESSION_ID = 64;
const MAX_TOOL_NAME = 200;
const MAX_RULE_ID = 200;
const MAX_SCOPE_DIGEST = 64;
const MAX_REASON = 500;
/** Stable, bounded digest of a session key for the audit trail. */
export function digestSessionKey(sessionKey) {
    return createHash("sha256").update(String(sessionKey), "utf8").digest("hex").slice(0, 24);
}
export class DecisionLog {
    config;
    entries = [];
    askWindow = [];
    constructor(config) {
        this.config = config;
    }
    get enabled() {
        return this.config.enabled;
    }
    record(entry) {
        if (!this.config.enabled)
            return;
        const bounded = this.bound(entry);
        this.entries.push(bounded);
        if (this.entries.length > this.config.maxEntries)
            this.entries.shift();
        if (bounded.decision === "ask")
            this.askWindow.push(bounded.ts);
        if (this.config.filePath)
            this.appendFile(bounded);
    }
    /** Snapshot of the ring buffer, oldest first. */
    snapshot() {
        return [...this.entries];
    }
    /** Number of ask decisions in the trailing `ms` window (flood counter). */
    askRate(ms, now = Date.now()) {
        if (!Number.isFinite(ms) || ms <= 0)
            return 0;
        const cutoff = now - ms;
        while (this.askWindow.length > 0 && this.askWindow[0] < cutoff)
            this.askWindow.shift();
        return this.askWindow.length;
    }
    bound(entry) {
        const ts = Number.isFinite(entry.ts) && entry.ts >= 0 ? Math.trunc(entry.ts) : Date.now();
        const out = {
            ts,
            sessionDigest: typeof entry.sessionDigest === "string" ? entry.sessionDigest.slice(0, 24) : "",
            toolName: String(entry.toolName ?? "unknown").slice(0, MAX_TOOL_NAME),
            decision: entry.decision,
        };
        if (typeof entry.sessionId === "string" && entry.sessionId.length > 0) {
            out.sessionId = entry.sessionId.slice(0, MAX_SESSION_ID);
        }
        if (typeof entry.ruleId === "string" && entry.ruleId.length > 0) {
            out.ruleId = entry.ruleId.slice(0, MAX_RULE_ID);
        }
        if (typeof entry.severity === "string" && entry.severity.length > 0) {
            out.severity = entry.severity;
        }
        if (typeof entry.scopeDigest === "string" && entry.scopeDigest.length > 0) {
            out.scopeDigest = entry.scopeDigest.slice(0, MAX_SCOPE_DIGEST);
        }
        if (typeof entry.reason === "string" && entry.reason.length > 0) {
            out.reason = entry.reason.slice(0, MAX_REASON);
        }
        const latencyMs = entry.latencyMs;
        if (typeof latencyMs === "number" && Number.isFinite(latencyMs)) {
            out.latencyMs = Math.max(0, Math.trunc(latencyMs));
        }
        return out;
    }
    appendFile(entry) {
        try {
            const path = resolveLogPath(this.config.filePath ?? "");
            if (!path)
                return;
            appendFileSync(path, `${JSON.stringify(entry)}\n`, { encoding: "utf8" });
        }
        catch {
            // Best-effort audit trail: never throw into the gate.
        }
    }
}
function resolveLogPath(raw) {
    const expanded = raw === "~"
        ? homedir()
        : raw.startsWith("~/") || raw.startsWith("~\\")
            ? join(homedir(), raw.slice(2))
            : raw;
    if (!isAbsolute(expanded))
        return undefined; // relative paths are ambiguous
    try {
        mkdirSync(dirname(expanded), { recursive: true });
    }
    catch {
        return undefined;
    }
    return expanded;
}
//# sourceMappingURL=decision-log.js.map