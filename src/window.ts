/** Per-session approval windows backed by OpenClaw session extensions. */

import type { ApprovalWindowConfig, PolicyDecision } from "./types.js";

const DESTRUCTIVE_KEY = "__destructive__";

export interface WindowEntry {
  runId?: string;
  openedAt: number;
}

export interface WindowState {
  windows: Record<string, WindowEntry>;
}

export type WindowStateReader = (sessionKey: string) => WindowState | undefined;
export type WindowStateUpdater = (
  sessionKey: string,
  update: (current: WindowState) => WindowState,
) => Promise<void>;

function normalizeState(value: WindowState | undefined): WindowState {
  if (!value || typeof value !== "object" || !value.windows || typeof value.windows !== "object") {
    return { windows: {} };
  }
  return { windows: { ...value.windows } };
}

export class ApprovalWindowStore {
  constructor(
    private readonly read: WindowStateReader,
    private readonly update: WindowStateUpdater,
  ) {}

  private keyFor(cfg: ApprovalWindowConfig, toolName: string): string {
    return cfg.match === "same-tool" ? toolName : DESTRUCTIVE_KEY;
  }

  bypasses(cfg: ApprovalWindowConfig, decision: PolicyDecision): boolean {
    return cfg.bypassCritical && decision.severity === "critical";
  }

  isOpen(
    cfg: ApprovalWindowConfig,
    sessionKey: string,
    toolName: string,
    runId: string | undefined,
    now: number,
  ): boolean {
    if (cfg.mode === "off") return false;
    const entry = normalizeState(this.read(sessionKey)).windows[this.keyFor(cfg, toolName)];
    if (!entry) return false;
    if (cfg.mode === "turn") {
      // Missing runId is not a safe turn boundary, so fail closed.
      return runId !== undefined && entry.runId === runId;
    }
    return now >= entry.openedAt && now - entry.openedAt < cfg.ttlMs;
  }

  async open(
    cfg: ApprovalWindowConfig,
    sessionKey: string,
    toolName: string,
    runId: string | undefined,
    now: number,
  ): Promise<void> {
    if (cfg.mode === "off") return;
    // A turn-scoped window cannot be bounded safely without a run id.
    if (cfg.mode === "turn" && !runId) return;
    await this.update(sessionKey, (current) => {
      const next = normalizeState(current);
      next.windows[this.keyFor(cfg, toolName)] = { runId, openedAt: now };
      return next;
    });
  }

  snapshot(sessionKey: string): WindowState {
    return normalizeState(this.read(sessionKey));
  }
}
