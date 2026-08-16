/** Owner-issued, session-scoped temporary lease for ordinary shell exec calls. */

import type { SessionStateReader, SessionStateUpdater } from "./state.js";

export const EXEC_LEASE_STATE_VERSION = 1 as const;
export const EXEC_LEASE_POLICY_VERSION = "ordinary-exec-v1" as const;
export const MIN_EXEC_LEASE_MS = 60_000;
export const MAX_EXEC_LEASE_MS = 3_600_000;
export const DEFAULT_EXEC_LEASE_MS = 900_000;

export interface ExecLease {
  policyVersion: typeof EXEC_LEASE_POLICY_VERSION;
  grantedAt: string;
  expiresAt: string;
  issuedTtlMs: number;
}

export interface ExecLeaseState {
  version: typeof EXEC_LEASE_STATE_VERSION;
  lease?: ExecLease;
}

function validIso(value: unknown): value is string {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}

export function normalizeExecLeaseState(value: unknown): ExecLeaseState {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return { version: EXEC_LEASE_STATE_VERSION };
  }
  const raw = value as Partial<ExecLeaseState>;
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

export type ExecLeaseStatus =
  | { active: false }
  | { active: true; expiresAt: string; remainingMs: number };

export class ExecLeaseStore {
  constructor(
    private readonly read: SessionStateReader<ExecLeaseState>,
    private readonly update: SessionStateUpdater<ExecLeaseState>,
  ) {}

  status(sessionKey: string, now = Date.now()): ExecLeaseStatus {
    if (!sessionKey || !Number.isFinite(now)) return { active: false };
    const lease = normalizeExecLeaseState(this.read(sessionKey)).lease;
    if (!lease) return { active: false };
    const grantedAt = Date.parse(lease.grantedAt);
    const expiresAt = Date.parse(lease.expiresAt);
    if (now < grantedAt || expiresAt <= now) return { active: false };
    return { active: true, expiresAt: lease.expiresAt, remainingMs: expiresAt - now };
  }

  isActive(sessionKey: string, now = Date.now()): boolean {
    return this.status(sessionKey, now).active;
  }

  async grant(sessionKey: string, ttlMs: number, now = Date.now()): Promise<ExecLeaseStatus> {
    if (!sessionKey || !Number.isFinite(now) || !Number.isInteger(ttlMs) ||
      ttlMs < MIN_EXEC_LEASE_MS || ttlMs > MAX_EXEC_LEASE_MS) {
      return { active: false };
    }
    const lease: ExecLease = {
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

  async revoke(sessionKey: string): Promise<void> {
    if (!sessionKey) return;
    await this.update(sessionKey, () => ({ version: EXEC_LEASE_STATE_VERSION }));
  }
}

/** Parse `15m`, `1h`, or a bare minute count. */
export function parseExecLeaseDuration(raw: string): number | undefined {
  const match = raw.trim().toLowerCase().match(/^(\d+)(m|h)?$/);
  if (!match) return undefined;
  const value = Number(match[1]);
  if (!Number.isSafeInteger(value) || value <= 0) return undefined;
  const ttlMs = value * (match[2] === "h" ? 3_600_000 : 60_000);
  return ttlMs >= MIN_EXEC_LEASE_MS && ttlMs <= MAX_EXEC_LEASE_MS ? ttlMs : undefined;
}

export function isOrdinaryExec(toolName: string, toolKind?: string, toolInputKind?: string): boolean {
  return toolName.toLowerCase() === "exec" && toolKind !== "code_mode_exec" && toolInputKind === undefined;
}
