/**
 * Per-session allow-always memory.
 *
 * When a human picks "allow-always" for a (rule, tool) pair, we record it in a
 * plugin-owned session extension so the same combination is auto-approved for
 * the rest of the session. Falls back to pure in-memory storage when the
 * session extension is unavailable (e.g. older OpenClaw runtimes).
 */

import type { SessionExtensionHandle } from "openclaw/plugin-sdk/plugin-entry";
import { allowAlwaysKey } from "./types.js";

export interface AllowAlwaysState {
  /** Map of `${ruleId}::${toolName}` -> ISO timestamp granted. */
  grants: Record<string, string>;
}

export class AllowAlwaysStore {
  private readonly handle: SessionExtensionHandle<AllowAlwaysState> | null;
  /** In-memory fallback when session extension is unavailable. */
  private readonly memory: AllowAlwaysState = { grants: {} };

  constructor(handle: SessionExtensionHandle<AllowAlwaysState> | null) {
    this.handle = handle ?? null;
  }

  private state(): AllowAlwaysState {
    if (!this.handle) return this.memory;
    try {
      return this.handle.get() ?? this.memory;
    } catch {
      return this.memory;
    }
  }

  private write(state: AllowAlwaysState): void {
    if (!this.handle) {
      this.memory.grants = state.grants;
      return;
    }
    try {
      this.handle.set(state);
    } catch {
      this.memory.grants = state.grants;
    }
  }

  isGranted(ruleId: string, toolName: string): boolean {
    const state = this.state();
    return Boolean(state.grants[allowAlwaysKey(ruleId, toolName)]);
  }

  grant(ruleId: string, toolName: string): void {
    const current = this.state();
    const next: AllowAlwaysState = { grants: { ...current.grants } };
    next.grants[allowAlwaysKey(ruleId, toolName)] = new Date().toISOString();
    this.write(next);
  }

  revoke(ruleId: string, toolName: string): void {
    const current = this.state();
    const next: AllowAlwaysState = { grants: { ...current.grants } };
    delete next.grants[allowAlwaysKey(ruleId, toolName)];
    this.write(next);
  }

  snapshot(): AllowAlwaysState {
    return this.state();
  }
}
