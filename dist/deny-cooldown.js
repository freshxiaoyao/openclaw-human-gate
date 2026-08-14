/**
 * Per-session deny cooldown (remit-style).
 *
 * After an explicit `deny`, matching calls auto-block for a short window
 * instead of prompting the same question again. The cooldown is keyed by the
 * semantic scope key when one exists, else `ruleId::toolName`. It converts
 * ask → block only: it never touches auto or block decisions, it never
 * survives the window, and a clock rollback cannot extend it.
 */
export const DENY_COOLDOWN_STATE_VERSION = 1;
const MAX_DENIALS = 128;
function emptyState() {
    return { version: DENY_COOLDOWN_STATE_VERSION, denials: {} };
}
/** Strict v1 parser. Legacy/unversioned state intentionally becomes empty. */
export function normalizeDenyCooldownState(value) {
    if (!value || typeof value !== "object" || Array.isArray(value))
        return emptyState();
    const candidate = value;
    if (candidate.version !== DENY_COOLDOWN_STATE_VERSION ||
        !candidate.denials ||
        typeof candidate.denials !== "object" ||
        Array.isArray(candidate.denials)) {
        return emptyState();
    }
    const denials = {};
    for (const [key, raw] of Object.entries(candidate.denials)) {
        if (!raw || typeof raw !== "object" || Array.isArray(raw))
            continue;
        const entry = raw;
        if (entry.scopeKey !== key || typeof entry.scopeKey !== "string" || entry.scopeKey.length === 0 ||
            typeof entry.deniedAt !== "number" || !Number.isFinite(entry.deniedAt) || entry.deniedAt < 0 ||
            typeof entry.expiresAt !== "number" || !Number.isFinite(entry.expiresAt) ||
            entry.expiresAt <= entry.deniedAt) {
            continue;
        }
        denials[key] = { scopeKey: key, deniedAt: entry.deniedAt, expiresAt: entry.expiresAt };
    }
    return { version: DENY_COOLDOWN_STATE_VERSION, denials };
}
export class DenyCooldownStore {
    read;
    update;
    cooldownMs;
    constructor(read, update, cooldownMs) {
        this.read = read;
        this.update = update;
        this.cooldownMs = cooldownMs;
    }
    /** True when a recent explicit deny covers this scope key. */
    isCoolingDown(sessionKey, scopeKey, now) {
        if (!scopeKey || !this.cooldownMs || !Number.isFinite(now) || now < 0)
            return false;
        const state = normalizeDenyCooldownState(this.read(sessionKey));
        const entry = state.denials[scopeKey];
        if (!entry)
            return false;
        // Clock rollback must not extend a cooldown into the past.
        if (now < entry.deniedAt)
            return false;
        return now < entry.expiresAt;
    }
    /** Record an explicit deny. Best-effort: store failure simply means the
     *  next matching call asks again (fail toward asking). */
    async recordDeny(sessionKey, scopeKey, now) {
        if (!scopeKey || !this.cooldownMs || !Number.isFinite(now) || now < 0)
            return;
        const entry = {
            scopeKey,
            deniedAt: now,
            expiresAt: now + this.cooldownMs,
        };
        await this.update(sessionKey, (current) => {
            const next = normalizeDenyCooldownState(current);
            for (const [key, existing] of Object.entries(next.denials)) {
                if (existing.expiresAt <= now)
                    delete next.denials[key];
            }
            next.denials[scopeKey] = entry;
            const entries = Object.entries(next.denials);
            if (entries.length > MAX_DENIALS) {
                entries.sort(([, a], [, b]) => a.deniedAt - b.deniedAt);
                for (const [key] of entries.slice(0, entries.length - MAX_DENIALS)) {
                    delete next.denials[key];
                }
            }
            return next;
        });
    }
    snapshot(sessionKey) {
        return normalizeDenyCooldownState(this.read(sessionKey));
    }
}
//# sourceMappingURL=deny-cooldown.js.map