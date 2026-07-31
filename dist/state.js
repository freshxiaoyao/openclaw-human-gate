/**
 * Per-session allow-always memory.
 *
 * When a human picks "allow-always" for a (rule, tool) pair, we record it in a
 * plugin-owned session extension so the same combination is auto-approved for
 * the rest of the session. Falls back to pure in-memory storage when the
 * session extension is unavailable (e.g. older OpenClaw runtimes).
 */
import { allowAlwaysKey } from "./types.js";
export class AllowAlwaysStore {
    handle;
    /** In-memory fallback when session extension is unavailable. */
    memory = { grants: {} };
    constructor(handle) {
        this.handle = handle ?? null;
    }
    state() {
        if (!this.handle)
            return this.memory;
        try {
            return this.handle.get() ?? this.memory;
        }
        catch {
            return this.memory;
        }
    }
    write(state) {
        if (!this.handle) {
            this.memory.grants = state.grants;
            return;
        }
        try {
            this.handle.set(state);
        }
        catch {
            this.memory.grants = state.grants;
        }
    }
    isGranted(ruleId, toolName) {
        const state = this.state();
        return Boolean(state.grants[allowAlwaysKey(ruleId, toolName)]);
    }
    grant(ruleId, toolName) {
        const current = this.state();
        const next = { grants: { ...current.grants } };
        next.grants[allowAlwaysKey(ruleId, toolName)] = new Date().toISOString();
        this.write(next);
    }
    revoke(ruleId, toolName) {
        const current = this.state();
        const next = { grants: { ...current.grants } };
        delete next.grants[allowAlwaysKey(ruleId, toolName)];
        this.write(next);
    }
    snapshot() {
        return this.state();
    }
}
//# sourceMappingURL=state.js.map