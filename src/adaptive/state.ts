import type { ApprovalDecision, AdaptiveAutoPassConfig } from "../types.js";
import {
  isAuthorizationFingerprint,
  type AuthorizationFingerprint,
} from "../scope.js";
import { ADAPTIVE_ELIGIBILITY_VERSION } from "./eligibility.js";

export const ADAPTIVE_STATE_VERSION = 2 as const;
const MAX_ADAPTIVE_ENTRIES = 128;
/** Permanent replay receipts retained per fingerprint. Reaching capacity is
 * fail-closed (a new grant is refused) rather than FIFO-evicting an older
 * receipt and reopening a replay window. */
const MAX_RECEIPT_IDS = 128;
const GRANT_KEY = /^grant2:[0-9a-f]{64}$/;

export interface AdaptiveObservation {
  fingerprintKey: string;
  approvalCount: number;
  lastApprovedAt: string;
}

/** Permanent replay receipts. Never evicted FIFO-style; capacity is fail-closed. */
export interface AdaptiveReceipt {
  fingerprintKey: string;
  originToolCallIds: string[];
  lastGrantedAt: string;
}

export interface AdaptiveLease {
  fingerprintKey: string;
  fingerprintVersion: number;
  rulesetVersion: string;
  eligibilityVersion: typeof ADAPTIVE_ELIGIBILITY_VERSION;
  origin: "explicit-allow-always";
  originToolCallId: string;
  grantedAt: string;
  expiresAt: string;
  issuedTtlMs: number;
  maxUses: number;
  remainingUses: number;
}

export interface AdaptiveState {
  version: typeof ADAPTIVE_STATE_VERSION;
  observations: Record<string, AdaptiveObservation>;
  receipts: Record<string, AdaptiveReceipt>;
  leases: Record<string, AdaptiveLease>;
}

export type AdaptiveStateReader = (sessionKey: string) => AdaptiveState | undefined;
export type AdaptiveStateUpdater = (
  sessionKey: string,
  update: (current: AdaptiveState) => AdaptiveState,
) => Promise<void>;

export type AdaptiveConsumeOutcome =
  | "consumed"
  | "missing"
  | "expired"
  | "exhausted"
  | "mismatch"
  | "clock-rollback";

export interface AdaptiveConsumeResult {
  outcome: AdaptiveConsumeOutcome;
  remainingBefore?: number;
  remainingAfter?: number;
  expiresAt?: string;
}

function emptyState(): AdaptiveState {
  return { version: ADAPTIVE_STATE_VERSION, observations: {}, receipts: {}, leases: {} };
}

function finiteTime(value: unknown): value is string {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}

function usableNow(now: number, additionalMs = 0): boolean {
  return Number.isFinite(now) && now >= 0 &&
    Number.isFinite(now + additionalMs) && now + additionalMs <= 8.64e15;
}

function validObservation(key: string, raw: unknown): AdaptiveObservation | undefined {
  if (!GRANT_KEY.test(key) || !raw || typeof raw !== "object" || Array.isArray(raw)) return undefined;
  const item = raw as Partial<AdaptiveObservation>;
  if (
    item.fingerprintKey !== key ||
    typeof item.approvalCount !== "number" || !Number.isInteger(item.approvalCount) ||
    item.approvalCount < 1 || item.approvalCount > 1_000_000 ||
    !finiteTime(item.lastApprovedAt)
  ) {
    return undefined;
  }
  return {
    fingerprintKey: key,
    approvalCount: item.approvalCount,
    lastApprovedAt: item.lastApprovedAt,
  };
}

function validReceipt(key: string, raw: unknown): AdaptiveReceipt | undefined {
  if (!GRANT_KEY.test(key) || !raw || typeof raw !== "object" || Array.isArray(raw)) return undefined;
  const item = raw as Partial<AdaptiveReceipt>;
  if (
    item.fingerprintKey !== key ||
    !Array.isArray(item.originToolCallIds) || item.originToolCallIds.length === 0 ||
    item.originToolCallIds.length > MAX_RECEIPT_IDS ||
    item.originToolCallIds.some((id) =>
      typeof id !== "string" || id.length === 0 || id.length > 256) ||
    new Set(item.originToolCallIds).size !== item.originToolCallIds.length ||
    !finiteTime(item.lastGrantedAt)
  ) {
    return undefined;
  }
  return {
    fingerprintKey: key,
    originToolCallIds: [...item.originToolCallIds],
    lastGrantedAt: item.lastGrantedAt,
  };
}

function validLease(key: string, raw: unknown): AdaptiveLease | undefined {
  if (!GRANT_KEY.test(key) || !raw || typeof raw !== "object" || Array.isArray(raw)) return undefined;
  const item = raw as Partial<AdaptiveLease>;
  if (
    item.fingerprintKey !== key ||
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
    item.remainingUses < 0 || item.remainingUses > item.maxUses
  ) {
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
export function normalizeAdaptiveState(value: unknown): AdaptiveState {
  if (!value || typeof value !== "object" || Array.isArray(value)) return emptyState();
  const candidate = value as Partial<AdaptiveState>;
  if (
    candidate.version !== ADAPTIVE_STATE_VERSION ||
    !candidate.observations || typeof candidate.observations !== "object" || Array.isArray(candidate.observations) ||
    !candidate.receipts || typeof candidate.receipts !== "object" || Array.isArray(candidate.receipts) ||
    !candidate.leases || typeof candidate.leases !== "object" || Array.isArray(candidate.leases)
  ) {
    return emptyState();
  }
  const observations: Record<string, AdaptiveObservation> = {};
  const receipts: Record<string, AdaptiveReceipt> = {};
  const leases: Record<string, AdaptiveLease> = {};
  for (const [key, raw] of Object.entries(candidate.observations)) {
    const item = validObservation(key, raw);
    if (item) observations[key] = item;
  }
  for (const [key, raw] of Object.entries(candidate.receipts)) {
    const item = validReceipt(key, raw);
    if (item) receipts[key] = item;
  }
  for (const [key, raw] of Object.entries(candidate.leases)) {
    const item = validLease(key, raw);
    if (item) leases[key] = item;
  }
  // Receipts are replay tombstones: never prune them FIFO-style. An oversized
  // receipt map is a corruption/DoS signal and is rejected wholesale instead.
  if (Object.keys(receipts).length > MAX_ADAPTIVE_ENTRIES) return emptyState();
  return boundEntries({ version: ADAPTIVE_STATE_VERSION, observations, receipts, leases });
}

function boundEntries(state: AdaptiveState): AdaptiveState {
  const prune = <T>(record: Record<string, T>, timestamp: (value: T) => string): void => {
    const entries = Object.entries(record);
    if (entries.length <= MAX_ADAPTIVE_ENTRIES) return;
    entries.sort(([, left], [, right]) => timestamp(left).localeCompare(timestamp(right)));
    for (const [key] of entries.slice(0, entries.length - MAX_ADAPTIVE_ENTRIES)) delete record[key];
  };
  prune(state.observations, (value) => value.lastApprovedAt);
  prune(state.leases, (value) => value.grantedAt);
  return state;
}

function matches(
  lease: AdaptiveLease,
  fingerprint: AuthorizationFingerprint,
  config: Pick<AdaptiveAutoPassConfig, "ttlMs" | "maxUses">,
): boolean {
  return Boolean(
    fingerprint.grantKey &&
    lease.fingerprintKey === fingerprint.grantKey &&
    lease.fingerprintVersion === fingerprint.fingerprintVersion &&
    lease.rulesetVersion === fingerprint.rulesetVersion &&
    lease.eligibilityVersion === ADAPTIVE_ELIGIBILITY_VERSION &&
    lease.issuedTtlMs === config.ttlMs &&
    lease.maxUses === config.maxUses,
  );
}

export class AdaptiveLeaseStore {
  constructor(
    private readonly read: AdaptiveStateReader,
    private readonly update: AdaptiveStateUpdater,
    private readonly config: Pick<AdaptiveAutoPassConfig, "ttlMs" | "maxUses">,
  ) {}

  approvalCount(sessionKey: string, fingerprint: AuthorizationFingerprint): number {
    if (!isAuthorizationFingerprint(fingerprint) || !fingerprint.grantKey) return 0;
    return normalizeAdaptiveState(this.read(sessionKey)).observations[fingerprint.grantKey]?.approvalCount ?? 0;
  }

  async observeApproval(
    sessionKey: string,
    fingerprint: AuthorizationFingerprint,
    decision: ApprovalDecision,
    now: number,
  ): Promise<void> {
    if (!isAuthorizationFingerprint(fingerprint) || !fingerprint.grantKey || !usableNow(now)) return;
    if (decision !== "allow-once") return;
    await this.update(sessionKey, (current) => {
      const next = normalizeAdaptiveState(current);
      const prior = next.observations[fingerprint.grantKey!];
      next.observations[fingerprint.grantKey!] = {
        fingerprintKey: fingerprint.grantKey!,
        approvalCount: Math.min(1_000_000, (prior?.approvalCount ?? 0) + 1),
        lastApprovedAt: new Date(now).toISOString(),
      };
      return boundEntries(next);
    });
  }

  async grant(
    sessionKey: string,
    fingerprint: AuthorizationFingerprint,
    now: number,
    originToolCallId: string | undefined,
  ): Promise<boolean> {
    if (
      !isAuthorizationFingerprint(fingerprint) || !fingerprint.grantKey ||
      !originToolCallId || originToolCallId.length > 256 ||
      !Number.isFinite(this.config.ttlMs) || this.config.ttlMs <= 0 ||
      !Number.isInteger(this.config.maxUses) || this.config.maxUses <= 0
    ) {
      return false;
    }
    if (!usableNow(now, this.config.ttlMs)) return false;
    let granted = false;
    await this.update(sessionKey, (current) => {
      const next = normalizeAdaptiveState(current);
      const key = fingerprint.grantKey!;
      const receipt = next.receipts[key];
      const originIds = receipt?.originToolCallIds ?? [];
      // Callback replay must never refill or extend a lease, including after
      // the lease was exhausted or expired.
      if (originIds.includes(originToolCallId)) return next;
      // Receipt capacity is fail-closed, never FIFO-evicted: refuse a new
      // grant rather than dropping an older receipt and reopening replay.
      if (originIds.length >= MAX_RECEIPT_IDS) return next;
      if (!receipt && Object.keys(next.receipts).length >= MAX_ADAPTIVE_ENTRIES) return next;
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

  async consume(
    sessionKey: string,
    fingerprint: AuthorizationFingerprint,
    now: number,
  ): Promise<AdaptiveConsumeResult> {
    if (!isAuthorizationFingerprint(fingerprint) || !fingerprint.grantKey || !usableNow(now)) {
      return { outcome: "missing" };
    }
    let result: AdaptiveConsumeResult = { outcome: "missing" };
    await this.update(sessionKey, (current) => {
      const next = normalizeAdaptiveState(current);
      const lease = next.leases[fingerprint.grantKey!];
      if (!lease) return next;
      if (!matches(lease, fingerprint, this.config)) {
        result = { outcome: "mismatch" };
        delete next.leases[fingerprint.grantKey!];
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

  async deny(sessionKey: string, fingerprint: AuthorizationFingerprint): Promise<void> {
    if (!isAuthorizationFingerprint(fingerprint) || !fingerprint.grantKey) return;
    await this.update(sessionKey, (current) => {
      const next = normalizeAdaptiveState(current);
      delete next.leases[fingerprint.grantKey!];
      delete next.observations[fingerprint.grantKey!];
      // Keep the receipt (replay tombstones) permanently so a replayed
      // allow-always callback cannot re-mint a lease after denial.
      return next;
    });
  }

  snapshot(sessionKey: string): AdaptiveState {
    return normalizeAdaptiveState(this.read(sessionKey));
  }
}
