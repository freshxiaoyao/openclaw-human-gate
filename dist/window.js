/** Per-session approval windows backed by OpenClaw session extensions. */
const DESTRUCTIVE_KEY = "__destructive__";
function normalizeState(value) {
    if (!value || typeof value !== "object" || !value.windows || typeof value.windows !== "object") {
        return { windows: {} };
    }
    return { windows: { ...value.windows } };
}
export class ApprovalWindowStore {
    read;
    update;
    constructor(read, update) {
        this.read = read;
        this.update = update;
    }
    keyFor(cfg, toolName) {
        return cfg.match === "same-tool" ? toolName : DESTRUCTIVE_KEY;
    }
    bypasses(cfg, decision) {
        return cfg.bypassCritical && decision.severity === "critical";
    }
    isOpen(cfg, sessionKey, toolName, runId, now) {
        if (cfg.mode === "off")
            return false;
        const entry = normalizeState(this.read(sessionKey)).windows[this.keyFor(cfg, toolName)];
        if (!entry)
            return false;
        if (cfg.mode === "turn") {
            // Missing runId is not a safe turn boundary, so fail closed.
            return runId !== undefined && entry.runId === runId;
        }
        return now >= entry.openedAt && now - entry.openedAt < cfg.ttlMs;
    }
    async open(cfg, sessionKey, toolName, runId, now) {
        if (cfg.mode === "off")
            return;
        // A turn-scoped window cannot be bounded safely without a run id.
        if (cfg.mode === "turn" && !runId)
            return;
        await this.update(sessionKey, (current) => {
            const next = normalizeState(current);
            next.windows[this.keyFor(cfg, toolName)] = { runId, openedAt: now };
            return next;
        });
    }
    snapshot(sessionKey) {
        return normalizeState(this.read(sessionKey));
    }
}
//# sourceMappingURL=window.js.map