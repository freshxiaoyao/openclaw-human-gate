/** Versioned, semantic per-session approval windows. */

import type { PolicyDecision } from "./types.js";
import {
  AUTHORIZATION_FINGERPRINT_VERSION,
  isAuthorizationFingerprint,
  type AuthorizationFingerprint,
  type SemanticApprovalScope,
} from "./scope.js";

export const WINDOW_STATE_VERSION = 2 as const;
export const MAX_WINDOW_ENTRIES = 128;

export interface ApprovalWindowRuntimeConfig {
  mode: "off" | "turn" | "time";
  ttlMs: number;
  bypassCritical: boolean;
}

export interface WindowEntry {
  scopeKey: string;
  scope: SemanticApprovalScope;
  fingerprintVersion: typeof AUTHORIZATION_FINGERPRINT_VERSION;
  rulesetVersion: string;
  mode: "turn" | "time";
  openedAt: number;
  expiresAt?: number;
  runId?: string;
}

export interface WindowState {
  version: typeof WINDOW_STATE_VERSION;
  windows: Record<string, WindowEntry>;
}

export type WindowStateReader = (sessionKey: string) => WindowState | undefined;
export type WindowStateUpdater = (
  sessionKey: string,
  update: (current: WindowState) => WindowState,
) => Promise<void>;

function emptyState(): WindowState {
  return { version: WINDOW_STATE_VERSION, windows: {} };
}

function isScope(value: unknown): value is SemanticApprovalScope {
  return value === "destructive" || value === "same-tool" || value === "effect" ||
    value === "category" || value === "path";
}

function normalizeEntry(key: string, value: unknown): WindowEntry | undefined {
  if (!/^win2:[0-9a-f]{64}$/.test(key) || !value || typeof value !== "object" || Array.isArray(value)) {
    return undefined;
  }
  const entry = value as Partial<WindowEntry>;
  if (
    entry.scopeKey !== key || !isScope(entry.scope) ||
    entry.fingerprintVersion !== AUTHORIZATION_FINGERPRINT_VERSION ||
    typeof entry.rulesetVersion !== "string" || entry.rulesetVersion.length === 0 ||
    entry.rulesetVersion.trim() !== entry.rulesetVersion ||
    (entry.mode !== "turn" && entry.mode !== "time") ||
    typeof entry.openedAt !== "number" || !Number.isFinite(entry.openedAt) || entry.openedAt < 0
  ) {
    return undefined;
  }
  if (entry.mode === "turn") {
    if (typeof entry.runId !== "string" || entry.runId.length === 0) return undefined;
    return {
      scopeKey: key,
      scope: entry.scope,
      fingerprintVersion: AUTHORIZATION_FINGERPRINT_VERSION,
      rulesetVersion: entry.rulesetVersion,
      mode: "turn",
      openedAt: entry.openedAt,
      runId: entry.runId,
    };
  }
  if (
    typeof entry.expiresAt !== "number" || !Number.isFinite(entry.expiresAt) ||
    entry.expiresAt <= entry.openedAt
  ) {
    return undefined;
  }
  return {
    scopeKey: key,
    scope: entry.scope,
    fingerprintVersion: AUTHORIZATION_FINGERPRINT_VERSION,
    rulesetVersion: entry.rulesetVersion,
    mode: "time",
    openedAt: entry.openedAt,
    expiresAt: entry.expiresAt,
    ...(typeof entry.runId === "string" && entry.runId.length > 0 ? { runId: entry.runId } : {}),
  };
}

/** Strictly parse v2 state. Legacy/unversioned state is intentionally lost. */
export function normalizeWindowState(value: unknown): WindowState {
  if (!value || typeof value !== "object" || Array.isArray(value)) return emptyState();
  const candidate = value as Partial<WindowState>;
  if (
    candidate.version !== WINDOW_STATE_VERSION || !candidate.windows ||
    typeof candidate.windows !== "object" || Array.isArray(candidate.windows)
  ) {
    return emptyState();
  }
  const windows: Record<string, WindowEntry> = {};
  for (const [key, rawEntry] of Object.entries(candidate.windows)) {
    const entry = normalizeEntry(key, rawEntry);
    if (entry) windows[key] = entry;
  }
  return { version: WINDOW_STATE_VERSION, windows };
}

function matchesFingerprint(entry: WindowEntry, fingerprint: AuthorizationFingerprint): boolean {
  return (
    entry.scopeKey === fingerprint.windowKey &&
    entry.scope === fingerprint.resolvedScope &&
    entry.fingerprintVersion === fingerprint.fingerprintVersion &&
    entry.rulesetVersion === fingerprint.rulesetVersion
  );
}

function cleanAndBound(state: WindowState, now: number, incomingKey: string): WindowState {
  const windows: Record<string, WindowEntry> = {};
  for (const [key, entry] of Object.entries(state.windows)) {
    if (entry.mode === "time" && entry.expiresAt! <= now) continue;
    windows[key] = entry;
  }

  // Reserve one slot for a new key and deterministically evict oldest entries.
  const targetSize = Object.prototype.hasOwnProperty.call(windows, incomingKey)
    ? MAX_WINDOW_ENTRIES
    : MAX_WINDOW_ENTRIES - 1;
  const ordered = Object.entries(windows).sort(
    ([keyA, a], [keyB, b]) => a.openedAt - b.openedAt || keyA.localeCompare(keyB, "en"),
  );
  while (ordered.length > targetSize) {
    const [key] = ordered.shift()!;
    delete windows[key];
  }
  return { version: WINDOW_STATE_VERSION, windows };
}

export class ApprovalWindowStore {
  constructor(
    private readonly read: WindowStateReader,
    private readonly update: WindowStateUpdater,
  ) {}

  bypasses(cfg: Pick<ApprovalWindowRuntimeConfig, "bypassCritical">, decision: PolicyDecision): boolean {
    return cfg.bypassCritical && decision.severity === "critical";
  }

  isOpen(
    cfg: ApprovalWindowRuntimeConfig,
    sessionKey: string,
    fingerprint: AuthorizationFingerprint | undefined,
    runId: string | undefined,
    now: number,
  ): boolean {
    if (
      cfg.mode === "off" || !isAuthorizationFingerprint(fingerprint) ||
      !Number.isFinite(now) || now < 0
    ) {
      return false;
    }
    const entry = normalizeWindowState(this.read(sessionKey)).windows[fingerprint.windowKey];
    if (!entry || !matchesFingerprint(entry, fingerprint) || entry.mode !== cfg.mode) return false;
    // Clock rollback must not extend a grant into time before it was opened.
    if (now < entry.openedAt) return false;
    if (cfg.mode === "turn") {
      return runId !== undefined && runId.length > 0 && entry.runId === runId;
    }
    return entry.expiresAt !== undefined && now < entry.expiresAt;
  }

  async open(
    cfg: ApprovalWindowRuntimeConfig,
    sessionKey: string,
    fingerprint: AuthorizationFingerprint | undefined,
    runId: string | undefined,
    now: number,
  ): Promise<boolean> {
    if (
      cfg.mode === "off" || !isAuthorizationFingerprint(fingerprint) ||
      !Number.isFinite(now) || now < 0
    ) {
      return false;
    }
    if (cfg.mode === "turn" && (!runId || runId.length === 0)) return false;
    if (
      cfg.mode === "time" &&
      (!Number.isFinite(cfg.ttlMs) || cfg.ttlMs <= 0 || !Number.isFinite(now + cfg.ttlMs))
    ) {
      return false;
    }

    const entry: WindowEntry = {
      scopeKey: fingerprint.windowKey,
      scope: fingerprint.resolvedScope,
      fingerprintVersion: fingerprint.fingerprintVersion,
      rulesetVersion: fingerprint.rulesetVersion,
      mode: cfg.mode,
      openedAt: now,
      ...(runId ? { runId } : {}),
      ...(cfg.mode === "time" ? { expiresAt: now + cfg.ttlMs } : {}),
    };
    await this.update(sessionKey, (current) => {
      const next = cleanAndBound(normalizeWindowState(current), now, fingerprint.windowKey);
      next.windows[fingerprint.windowKey] = entry;
      return next;
    });
    return true;
  }

  snapshot(sessionKey: string): WindowState {
    return normalizeWindowState(this.read(sessionKey));
  }
}
