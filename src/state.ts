/** Per-session allow-always state backed by OpenClaw session extensions. */

import { allowAlwaysKey } from "./types.js";

export interface AllowAlwaysState {
  /** Map of `${ruleId}::${toolName}` -> ISO timestamp granted. */
  grants: Record<string, string>;
}

export type SessionStateReader<T> = (sessionKey: string) => T | undefined;
export type SessionStateUpdater<T> = (
  sessionKey: string,
  update: (current: T) => T,
) => Promise<void>;

function normalizeState(value: AllowAlwaysState | undefined): AllowAlwaysState {
  if (!value || typeof value !== "object" || !value.grants || typeof value.grants !== "object") {
    return { grants: {} };
  }
  return { grants: { ...value.grants } };
}

export class AllowAlwaysStore {
  constructor(
    private readonly read: SessionStateReader<AllowAlwaysState>,
    private readonly update: SessionStateUpdater<AllowAlwaysState>,
  ) {}

  isGranted(sessionKey: string, ruleId: string, toolName: string): boolean {
    const state = normalizeState(this.read(sessionKey));
    return Boolean(state.grants[allowAlwaysKey(ruleId, toolName)]);
  }

  async grant(sessionKey: string, ruleId: string, toolName: string): Promise<void> {
    await this.update(sessionKey, (current) => {
      const next = normalizeState(current);
      next.grants[allowAlwaysKey(ruleId, toolName)] = new Date().toISOString();
      return next;
    });
  }

  async revoke(sessionKey: string, ruleId: string, toolName: string): Promise<void> {
    await this.update(sessionKey, (current) => {
      const next = normalizeState(current);
      delete next.grants[allowAlwaysKey(ruleId, toolName)];
      return next;
    });
  }

  snapshot(sessionKey: string): AllowAlwaysState {
    return normalizeState(this.read(sessionKey));
  }
}
