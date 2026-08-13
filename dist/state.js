/** Per-session, semantically scoped allow-always state. */
export const ALLOW_ALWAYS_STATE_VERSION = 2;
const MAX_GRANTS = 128;
function normalizeState(value) {
    if (!value ||
        typeof value !== "object" || Array.isArray(value) ||
        value.version !== ALLOW_ALWAYS_STATE_VERSION ||
        !value.grants ||
        typeof value.grants !== "object" || Array.isArray(value.grants)) {
        return { version: ALLOW_ALWAYS_STATE_VERSION, grants: {} };
    }
    const grants = {};
    for (const [key, raw] of Object.entries(value.grants)) {
        if (!/^grant2:[0-9a-f]{64}$/.test(key) || !raw || typeof raw !== "object" || Array.isArray(raw) ||
            raw.fingerprintKey !== key || raw.fingerprintVersion !== 2 ||
            typeof raw.rulesetVersion !== "string" || raw.rulesetVersion.length === 0 ||
            raw.rulesetVersion.trim() !== raw.rulesetVersion ||
            typeof raw.grantedAt !== "string" || !Number.isFinite(Date.parse(raw.grantedAt))) {
            continue;
        }
        grants[key] = { ...raw, fingerprintKey: key };
    }
    return { version: ALLOW_ALWAYS_STATE_VERSION, grants };
}
/** Strict v2 parser. Legacy/unversioned grants intentionally become empty. */
export function normalizeAllowAlwaysState(value) {
    return normalizeState(value);
}
export class AllowAlwaysStore {
    read;
    update;
    constructor(read, update) {
        this.read = read;
        this.update = update;
    }
    isGranted(sessionKey, fingerprint) {
        if (!fingerprint.grantKey)
            return false;
        const state = normalizeState(this.read(sessionKey));
        const grant = state.grants[fingerprint.grantKey];
        return Boolean(grant &&
            grant.fingerprintKey === fingerprint.grantKey &&
            grant.fingerprintVersion === fingerprint.fingerprintVersion &&
            grant.rulesetVersion === fingerprint.rulesetVersion);
    }
    async grant(sessionKey, fingerprint) {
        if (!fingerprint.grantKey)
            return;
        const grant = {
            fingerprintKey: fingerprint.grantKey,
            fingerprintVersion: fingerprint.fingerprintVersion,
            rulesetVersion: fingerprint.rulesetVersion,
            grantedAt: new Date().toISOString(),
        };
        await this.update(sessionKey, (current) => {
            const next = normalizeState(current);
            next.grants[fingerprint.grantKey] = grant;
            const entries = Object.entries(next.grants);
            if (entries.length > MAX_GRANTS) {
                entries.sort(([, a], [, b]) => a.grantedAt.localeCompare(b.grantedAt));
                for (const [key] of entries.slice(0, entries.length - MAX_GRANTS)) {
                    delete next.grants[key];
                }
            }
            return next;
        });
    }
    async revoke(sessionKey, fingerprint) {
        if (!fingerprint.grantKey)
            return;
        await this.update(sessionKey, (current) => {
            const next = normalizeState(current);
            delete next.grants[fingerprint.grantKey];
            return next;
        });
    }
    snapshot(sessionKey) {
        return normalizeState(this.read(sessionKey));
    }
}
//# sourceMappingURL=state.js.map