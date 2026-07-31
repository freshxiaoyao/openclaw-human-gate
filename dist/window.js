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
const DESTRUCTIVE_KEY = "__destructive__";
export class ApprovalWindowStore {
    handle;
    memory = { windows: {} };
    constructor(handle) {
        this.handle = handle;
    }
    keyFor(cfg, toolName) {
        return cfg.match === "same-tool" ? toolName : DESTRUCTIVE_KEY;
    }
    state() {
        if (!this.handle)
            return this.memory;
        try {
            const current = this.handle.get();
            // Migrate the original single-window shape without trusting it for an
            // auto-pass: a fresh approval will repopulate the new keyed shape.
            if (current && current.windows && typeof current.windows === "object") {
                return current;
            }
        }
        catch {
            // Fall through to process memory.
        }
        return this.memory;
    }
    write(next) {
        this.memory.windows = next.windows;
        if (!this.handle)
            return;
        try {
            this.handle.set(next);
        }
        catch {
            // Process-memory copy above remains authoritative for this runtime.
        }
    }
    bypasses(cfg, decision) {
        return cfg.bypassCritical && decision.severity === "critical";
    }
    isOpen(cfg, toolName, runId, now) {
        if (cfg.mode === "off")
            return false;
        const entry = this.state().windows[this.keyFor(cfg, toolName)];
        if (!entry)
            return false;
        if (cfg.mode === "turn") {
            // Missing runId is not a safe turn boundary, so fail closed.
            return runId !== undefined && entry.runId === runId;
        }
        return now >= entry.openedAt && now - entry.openedAt < cfg.ttlMs;
    }
    open(cfg, toolName, runId, now) {
        if (cfg.mode === "off")
            return;
        // A turn-scoped window cannot be bounded safely without a run id.
        if (cfg.mode === "turn" && !runId)
            return;
        const current = this.state();
        const next = { windows: { ...current.windows } };
        next.windows[this.keyFor(cfg, toolName)] = { runId, openedAt: now };
        this.write(next);
    }
    snapshot() {
        const current = this.state();
        return { windows: { ...current.windows } };
    }
}
//# sourceMappingURL=window.js.map