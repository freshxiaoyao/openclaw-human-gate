import { isAuthorizationFingerprint, } from "../scope.js";
import { ADAPTIVE_ELIGIBILITY_VERSION } from "./eligibility.js";
export const ADAPTIVE_STATE_VERSION = 2;
const MAX_ADAPTIVE_ENTRIES = 128;
/** Permanent replay receipts retained per fingerprint. Reaching capacity is
 * fail-closed (a new grant is refused) rather than FIFO-evicting an older
 * receipt and reopening a replay window. */
const MAX_RECEIPT_IDS = 128;
const GRANT_KEY = /^grant2:[0-9a-f]{64}$/;
function emptyState() {
    return { version: ADAPTIVE_STATE_VERSION, observations: {}, receipts: {}, leases: {} };
}
function finiteTime(value) {
    return typeof value === "string" && Number.isFinite(Date.parse(value));
}
function usableNow(now, additionalMs = 0) {
    return Number.isFinite(now) && now >= 0 &&
        Number.isFinite(now + additionalMs) && now + additionalMs <= 8.64e15;
}
function validObservation(key, raw) {
    if (!GRANT_KEY.test(key) || !raw || typeof raw !== "object" || Array.isArray(raw))
        return undefined;
    const item = raw;
    if (item.fingerprintKey !== key ||
        typeof item.approvalCount !== "number" || !Number.isInteger(item.approvalCount) ||
        item.approvalCount < 1 || item.approvalCount > 1_000_000 ||
        !finiteTime(item.lastApprovedAt)) {
        return undefined;
    }
    return {
        fingerprintKey: key,
        approvalCount: item.approvalCount,
        lastApprovedAt: item.lastApprovedAt,
    };
}
function validReceipt(key, raw) {
    if (!GRANT_KEY.test(key) || !raw || typeof raw !== "object" || Array.isArray(raw))
        return undefined;
    const item = raw;
    if (item.fingerprintKey !== key ||
        !Array.isArray(item.originToolCallIds) || item.originToolCallIds.length === 0 ||
        item.originToolCallIds.length > MAX_RECEIPT_IDS ||
        item.originToolCallIds.some((id) => typeof id !== "string" || id.length === 0 || id.length > 256) ||
        new Set(item.originToolCallIds).size !== item.originToolCallIds.length ||
        !finiteTime(item.lastGrantedAt)) {
        return undefined;
    }
    return {
        fingerprintKey: key,
        originToolCallIds: [...item.originToolCallIds],
        lastGrantedAt: item.lastGrantedAt,
    };
}
function validLease(key, raw) {
    if (!GRANT_KEY.test(key) || !raw || typeof raw !== "object" || Array.isArray(raw))
        return undefined;
    const item = raw;
    if (item.fingerprintKey !== key ||
        typeof item.fingerprintVersion !== "number" || !Number.isInteger(item.fingerprintVersion) ||
        typeof item.rulesetVersion !== "string" || item.rulesetVersion.length === 0 ||
        item.rulesetVersion.trim() !== item.rulesetVersion ||
        item.eligibilityVersion !== ADAPTIVE_ELIGIBILITY_VERSION ||
        item.origin !== "explicit-allow-always" ||
        typeof item.originToolCallId !== "string" || item.originToolCallId.length === 0 ||
        item.originToolCallId.length > 256 ||
        !finiteTime(item.grantedAt) || !finiteTime(item.expiresAt) ||
        Date.parse(item.expiresAt) <= Date.parse(item.grantedAt) ||
        typeof item.issuedTtlMs !== "number" || !Number.isInteger(item.issuedTtlMs) ||
        item.issuedTtlMs < 60_000 || item.issuedTtlMs > 3_600_000 ||
        Date.parse(item.expiresAt) - Date.parse(item.grantedAt) !== item.issuedTtlMs ||
        typeof item.maxUses !== "number" || !Number.isInteger(item.maxUses) ||
        item.maxUses < 1 || item.maxUses > 100 ||
        typeof item.remainingUses !== "number" || !Number.isInteger(item.remainingUses) ||
        item.remainingUses < 0 || item.remainingUses > item.maxUses) {
        return undefined;
    }
    return {
        fingerprintKey: key,
        fingerprintVersion: item.fingerprintVersion,
        rulesetVersion: item.rulesetVersion,
        eligibilityVersion: ADAPTIVE_ELIGIBILITY_VERSION,
        origin: "explicit-allow-always",
        originToolCallId: item.originToolCallId,
        grantedAt: item.grantedAt,
        expiresAt: item.expiresAt,
        issuedTtlMs: item.issuedTtlMs,
        maxUses: item.maxUses,
        remainingUses: item.remainingUses,
    };
}
/** Strict parser. Unknown/legacy/future state becomes empty. */
export function normalizeAdaptiveState(value) {
    if (!value || typeof value !== "object" || Array.isArray(value))
        return emptyState();
    const candidate = value;
    if (candidate.version !== ADAPTIVE_STATE_VERSION ||
        !candidate.observations || typeof candidate.observations !== "object" || Array.isArray(candidate.observations) ||
        !candidate.receipts || typeof candidate.receipts !== "object" || Array.isArray(candidate.receipts) ||
        !candidate.leases || typeof candidate.leases !== "object" || Array.isArray(candidate.leases)) {
        return emptyState();
    }
    const observations = {};
    const receipts = {};
    const leases = {};
    for (const [key, raw] of Object.entries(candidate.observations)) {
        const item = validObservation(key, raw);
        if (item)
            observations[key] = item;
    }
    for (const [key, raw] of Object.entries(candidate.receipts)) {
        const item = validReceipt(key, raw);
        if (item)
            receipts[key] = item;
    }
    for (const [key, raw] of Object.entries(candidate.leases)) {
        const item = validLease(key, raw);
        if (item)
            leases[key] = item;
    }
    // Receipts are replay tombstones: never prune them FIFO-style. An oversized
    // receipt map is a corruption/DoS signal and is rejected wholesale instead.
    if (Object.keys(receipts).length > MAX_ADAPTIVE_ENTRIES)
        return emptyState();
    return boundEntries({ version: ADAPTIVE_STATE_VERSION, observations, receipts, leases });
}
function boundEntries(state) {
    const prune = (record, timestamp) => {
        const entries = Object.entries(record);
        if (entries.length <= MAX_ADAPTIVE_ENTRIES)
            return;
        entries.sort(([, left], [, right]) => timestamp(left).localeCompare(timestamp(right)));
        for (const [key] of entries.slice(0, entries.length - MAX_ADAPTIVE_ENTRIES))
            delete record[key];
    };
    prune(state.observations, (value) => value.lastApprovedAt);
    prune(state.leases, (value) => value.grantedAt);
    return state;
}
function matches(lease, fingerprint, config) {
    return Boolean(fingerprint.grantKey &&
        lease.fingerprintKey === fingerprint.grantKey &&
        lease.fingerprintVersion === fingerprint.fingerprintVersion &&
        lease.rulesetVersion === fingerprint.rulesetVersion &&
        lease.eligibilityVersion === ADAPTIVE_ELIGIBILITY_VERSION &&
        lease.issuedTtlMs === config.ttlMs &&
        lease.maxUses === config.maxUses);
}
export class AdaptiveLeaseStore {
    read;
    update;
    config;
    constructor(read, update, config) {
        this.read = read;
        this.update = update;
        this.config = config;
    }
    approvalCount(sessionKey, fingerprint) {
        if (!isAuthorizationFingerprint(fingerprint) || !fingerprint.grantKey)
            return 0;
        return normalizeAdaptiveState(this.read(sessionKey)).observations[fingerprint.grantKey]?.approvalCount ?? 0;
    }
    async observeApproval(sessionKey, fingerprint, decision, now) {
        if (!isAuthorizationFingerprint(fingerprint) || !fingerprint.grantKey || !usableNow(now))
            return;
        if (decision !== "allow-once")
            return;
        await this.update(sessionKey, (current) => {
            const next = normalizeAdaptiveState(current);
            const prior = next.observations[fingerprint.grantKey];
            next.observations[fingerprint.grantKey] = {
                fingerprintKey: fingerprint.grantKey,
                approvalCount: Math.min(1_000_000, (prior?.approvalCount ?? 0) + 1),
                lastApprovedAt: new Date(now).toISOString(),
            };
            return boundEntries(next);
        });
    }
    async grant(sessionKey, fingerprint, now, originToolCallId) {
        if (!isAuthorizationFingerprint(fingerprint) || !fingerprint.grantKey ||
            !originToolCallId || originToolCallId.length > 256 ||
            !Number.isFinite(this.config.ttlMs) || this.config.ttlMs <= 0 ||
            !Number.isInteger(this.config.maxUses) || this.config.maxUses <= 0) {
            return false;
        }
        if (!usableNow(now, this.config.ttlMs))
            return false;
        let granted = false;
        await this.update(sessionKey, (current) => {
            const next = normalizeAdaptiveState(current);
            const key = fingerprint.grantKey;
            const receipt = next.receipts[key];
            const originIds = receipt?.originToolCallIds ?? [];
            // Callback replay must never refill or extend a lease, including after
            // the lease was exhausted or expired.
            if (originIds.includes(originToolCallId))
                return next;
            // Receipt capacity is fail-closed, never FIFO-evicted: refuse a new
            // grant rather than dropping an older receipt and reopening replay.
            if (originIds.length >= MAX_RECEIPT_IDS)
                return next;
            if (!receipt && Object.keys(next.receipts).length >= MAX_ADAPTIVE_ENTRIES)
                return next;
            const grantedAt = new Date(now).toISOString();
            next.receipts[key] = {
                fingerprintKey: key,
                originToolCallIds: [...originIds, originToolCallId],
                lastGrantedAt: grantedAt,
            };
            const observation = next.observations[key];
            const existing = next.leases[key];
            if (existing && matches(existing, fingerprint, this.config) &&
                Date.parse(existing.expiresAt) > now && existing.remainingUses > 0) {
                next.observations[key] = {
                    fingerprintKey: key,
                    approvalCount: Math.min(1_000_000, (observation?.approvalCount ?? 0) + 1),
                    lastApprovedAt: grantedAt,
                };
                return boundEntries(next);
            }
            next.leases[key] = {
                fingerprintKey: key,
                fingerprintVersion: fingerprint.fingerprintVersion,
                rulesetVersion: fingerprint.rulesetVersion,
                eligibilityVersion: ADAPTIVE_ELIGIBILITY_VERSION,
                origin: "explicit-allow-always",
                originToolCallId,
                grantedAt,
                expiresAt: new Date(now + this.config.ttlMs).toISOString(),
                issuedTtlMs: this.config.ttlMs,
                maxUses: this.config.maxUses,
                remainingUses: this.config.maxUses,
            };
            next.observations[key] = {
                fingerprintKey: key,
                approvalCount: Math.min(1_000_000, (observation?.approvalCount ?? 0) + 1),
                lastApprovedAt: grantedAt,
            };
            granted = true;
            return boundEntries(next);
        });
        return granted;
    }
    async consume(sessionKey, fingerprint, now) {
        if (!isAuthorizationFingerprint(fingerprint) || !fingerprint.grantKey || !usableNow(now)) {
            return { outcome: "missing" };
        }
        let result = { outcome: "missing" };
        await this.update(sessionKey, (current) => {
            const next = normalizeAdaptiveState(current);
            const lease = next.leases[fingerprint.grantKey];
            if (!lease)
                return next;
            if (!matches(lease, fingerprint, this.config)) {
                result = { outcome: "mismatch" };
                delete next.leases[fingerprint.grantKey];
                return next;
            }
            const grantedAt = Date.parse(lease.grantedAt);
            const expiresAt = Date.parse(lease.expiresAt);
            if (now < grantedAt) {
                result = { outcome: "clock-rollback", expiresAt: lease.expiresAt };
                return next;
            }
            if (now >= expiresAt) {
                result = { outcome: "expired", expiresAt: lease.expiresAt };
                return next;
            }
            if (lease.remainingUses <= 0) {
                result = { outcome: "exhausted", remainingBefore: 0, remainingAfter: 0, expiresAt: lease.expiresAt };
                return next;
            }
            const before = lease.remainingUses;
            lease.remainingUses -= 1;
            result = {
                outcome: "consumed",
                remainingBefore: before,
                remainingAfter: lease.remainingUses,
                expiresAt: lease.expiresAt,
            };
            return next;
        });
        return result;
    }
    async deny(sessionKey, fingerprint) {
        if (!isAuthorizationFingerprint(fingerprint) || !fingerprint.grantKey)
            return;
        await this.update(sessionKey, (current) => {
            const next = normalizeAdaptiveState(current);
            delete next.leases[fingerprint.grantKey];
            delete next.observations[fingerprint.grantKey];
            // Keep the receipt (replay tombstones) permanently so a replayed
            // allow-always callback cannot re-mint a lease after denial.
            return next;
        });
    }
    snapshot(sessionKey) {
        return normalizeAdaptiveState(this.read(sessionKey));
    }
}
//# sourceMappingURL=state.js.map