/** Per-session allow-always state backed by OpenClaw session extensions. */
import { allowAlwaysKey } from "./types.js";
function normalizeState(value) {
    if (!value || typeof value !== "object" || !value.grants || typeof value.grants !== "object") {
        return { grants: {} };
    }
    return { grants: { ...value.grants } };
}
export class AllowAlwaysStore {
    read;
    update;
    constructor(read, update) {
        this.read = read;
        this.update = update;
    }
    isGranted(sessionKey, ruleId, toolName) {
        const state = normalizeState(this.read(sessionKey));
        return Boolean(state.grants[allowAlwaysKey(ruleId, toolName)]);
    }
    async grant(sessionKey, ruleId, toolName) {
        await this.update(sessionKey, (current) => {
            const next = normalizeState(current);
            next.grants[allowAlwaysKey(ruleId, toolName)] = new Date().toISOString();
            return next;
        });
    }
    async revoke(sessionKey, ruleId, toolName) {
        await this.update(sessionKey, (current) => {
            const next = normalizeState(current);
            delete next.grants[allowAlwaysKey(ruleId, toolName)];
            return next;
        });
    }
    snapshot(sessionKey) {
        return normalizeState(this.read(sessionKey));
    }
}
//# sourceMappingURL=state.js.map