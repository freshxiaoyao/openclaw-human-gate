/** Owner-issued, session-scoped temporary lease for ordinary shell exec calls. */
export const EXEC_LEASE_STATE_VERSION = 1;
export const EXEC_LEASE_POLICY_VERSION = "ordinary-exec-v1";
export const MIN_EXEC_LEASE_MS = 60_000;
export const MAX_EXEC_LEASE_MS = 3_600_000;
export const DEFAULT_EXEC_LEASE_MS = 900_000;
function validIso(value) {
    return typeof value === "string" && Number.isFinite(Date.parse(value));
}
export function normalizeExecLeaseState(value) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
        return { version: EXEC_LEASE_STATE_VERSION };
    }
    const raw = value;
    if (raw.version !== EXEC_LEASE_STATE_VERSION || !raw.lease ||
        typeof raw.lease !== "object" || Array.isArray(raw.lease)) {
        return { version: EXEC_LEASE_STATE_VERSION };
    }
    const lease = raw.lease;
    if (lease.policyVersion !== EXEC_LEASE_POLICY_VERSION ||
        !validIso(lease.grantedAt) || !validIso(lease.expiresAt) ||
        !Number.isInteger(lease.issuedTtlMs) ||
        lease.issuedTtlMs < MIN_EXEC_LEASE_MS || lease.issuedTtlMs > MAX_EXEC_LEASE_MS) {
        return { version: EXEC_LEASE_STATE_VERSION };
    }
    const grantedAt = Date.parse(lease.grantedAt);
    const expiresAt = Date.parse(lease.expiresAt);
    if (expiresAt - grantedAt !== lease.issuedTtlMs) {
        return { version: EXEC_LEASE_STATE_VERSION };
    }
    return {
        version: EXEC_LEASE_STATE_VERSION,
        lease: {
            policyVersion: EXEC_LEASE_POLICY_VERSION,
            grantedAt: lease.grantedAt,
            expiresAt: lease.expiresAt,
            issuedTtlMs: lease.issuedTtlMs,
        },
    };
}
export class ExecLeaseStore {
    read;
    update;
    constructor(read, update) {
        this.read = read;
        this.update = update;
    }
    status(sessionKey, now = Date.now()) {
        if (!sessionKey || !Number.isFinite(now))
            return { active: false };
        const lease = normalizeExecLeaseState(this.read(sessionKey)).lease;
        if (!lease)
            return { active: false };
        const grantedAt = Date.parse(lease.grantedAt);
        const expiresAt = Date.parse(lease.expiresAt);
        if (now < grantedAt || expiresAt <= now)
            return { active: false };
        return { active: true, expiresAt: lease.expiresAt, remainingMs: expiresAt - now };
    }
    isActive(sessionKey, now = Date.now()) {
        return this.status(sessionKey, now).active;
    }
    async grant(sessionKey, ttlMs, now = Date.now()) {
        if (!sessionKey || !Number.isFinite(now) || !Number.isInteger(ttlMs) ||
            ttlMs < MIN_EXEC_LEASE_MS || ttlMs > MAX_EXEC_LEASE_MS) {
            return { active: false };
        }
        const lease = {
            policyVersion: EXEC_LEASE_POLICY_VERSION,
            grantedAt: new Date(now).toISOString(),
            expiresAt: new Date(now + ttlMs).toISOString(),
            issuedTtlMs: ttlMs,
        };
        await this.update(sessionKey, () => ({
            version: EXEC_LEASE_STATE_VERSION,
            lease,
        }));
        return { active: true, expiresAt: lease.expiresAt, remainingMs: ttlMs };
    }
    async revoke(sessionKey) {
        if (!sessionKey)
            return;
        await this.update(sessionKey, () => ({ version: EXEC_LEASE_STATE_VERSION }));
    }
}
/** Parse `15m`, `1h`, or a bare minute count. */
export function parseExecLeaseDuration(raw) {
    const match = raw.trim().toLowerCase().match(/^(\d+)(m|h)?$/);
    if (!match)
        return undefined;
    const value = Number(match[1]);
    if (!Number.isSafeInteger(value) || value <= 0)
        return undefined;
    const ttlMs = value * (match[2] === "h" ? 3_600_000 : 60_000);
    return ttlMs >= MIN_EXEC_LEASE_MS && ttlMs <= MAX_EXEC_LEASE_MS ? ttlMs : undefined;
}
export function isOrdinaryExec(toolName, toolKind, toolInputKind) {
    return toolName.toLowerCase() === "exec" && toolKind !== "code_mode_exec" && toolInputKind === undefined;
}
//# sourceMappingURL=exec-lease.js.map