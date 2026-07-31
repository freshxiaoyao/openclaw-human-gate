/**
 * Per-session approval windows.
 *
 * After one destructive call is approved, subsequent matching calls can
 * auto-pass for the same run or a bounded time. State is stored per match key,
 * rather than as one global slot, so approving an `exec` call does not evict an
 * existing `apply_patch` window (and vice versa).
 *
 * The store is defensive: if the host session extension throws after
 * registration, it transparently falls back to process memory.
 */

import type { SessionExtensionHandle } from "openclaw/plugin-sdk/plugin-entry";
import type { ApprovalWindowConfig, PolicyDecision } from "./types.js";

const DESTRUCTIVE_KEY = "__destructive__";

export interface WindowEntry {
  runId?: string;
  openedAt: number;
}

export interface WindowState {
  windows: Record<string, WindowEntry>;
}

export class ApprovalWindowStore {
  private readonly memory: WindowState = { windows: {} };

  constructor(
    private readonly handle: SessionExtensionHandle<WindowState> | null,
  ) {}

  private keyFor(cfg: ApprovalWindowConfig, toolName: string): string {
    return cfg.match === "same-tool" ? toolName : DESTRUCTIVE_KEY;
  }

  private state(): WindowState {
    if (!this.handle) return this.memory;
    try {
      const current = this.handle.get();
      // Migrate the original single-window shape without trusting it for an
      // auto-pass: a fresh approval will repopulate the new keyed shape.
      if (current && current.windows && typeof current.windows === "object") {
        return current;
      }
    } catch {
      // Fall through to process memory.
    }
    return this.memory;
  }

  private write(next: WindowState): void {
    this.memory.windows = next.windows;
    if (!this.handle) return;
    try {
      this.handle.set(next);
    } catch {
      // Process-memory copy above remains authoritative for this runtime.
    }
  }

  bypasses(cfg: ApprovalWindowConfig, decision: PolicyDecision): boolean {
    return cfg.bypassCritical && decision.severity === "critical";
  }

  isOpen(
    cfg: ApprovalWindowConfig,
    toolName: string,
    runId: string | undefined,
    now: number,
  ): boolean {
    if (cfg.mode === "off") return false;
    const entry = this.state().windows[this.keyFor(cfg, toolName)];
    if (!entry) return false;
    if (cfg.mode === "turn") {
      // Missing runId is not a safe turn boundary, so fail closed.
      return runId !== undefined && entry.runId === runId;
    }
    return now >= entry.openedAt && now - entry.openedAt < cfg.ttlMs;
  }

  open(
    cfg: ApprovalWindowConfig,
    toolName: string,
    runId: string | undefined,
    now: number,
  ): void {
    if (cfg.mode === "off") return;
    // A turn-scoped window cannot be bounded safely without a run id.
    if (cfg.mode === "turn" && !runId) return;
    const current = this.state();
    const next: WindowState = { windows: { ...current.windows } };
    next.windows[this.keyFor(cfg, toolName)] = { runId, openedAt: now };
    this.write(next);
  }

  snapshot(): WindowState {
    const current = this.state();
    return { windows: { ...current.windows } };
  }
}
