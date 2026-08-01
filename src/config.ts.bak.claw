import type { ApprovalWindowConfig, HumanGateConfig } from "./types.js";
import { DEFAULT_CONFIG } from "./types.js";

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null;
}

function resolveWindowConfig(raw: unknown): ApprovalWindowConfig {
  const d = DEFAULT_CONFIG.approvalWindow;
  if (!isObject(raw)) return { ...d };
  const mode = raw.mode === "off" || raw.mode === "turn" || raw.mode === "time" ? raw.mode : d.mode;
  const match = raw.match === "same-tool" || raw.match === "destructive" ? raw.match : d.match;
  const ttlMs = typeof raw.ttlMs === "number"
    ? Math.min(Math.max(raw.ttlMs, 1000), 3_600_000)
    : d.ttlMs;
  const bypassCritical = typeof raw.bypassCritical === "boolean"
    ? raw.bypassCritical
    : d.bypassCritical;
  return { mode, match, ttlMs, bypassCritical };
}

/** Merge validated plugin configuration over the built-in defaults. */
export function resolveConfig(pluginConfig: unknown): HumanGateConfig {
  if (!isObject(pluginConfig)) {
    return {
      ...DEFAULT_CONFIG,
      approvalWindow: { ...DEFAULT_CONFIG.approvalWindow },
      rules: [...DEFAULT_CONFIG.rules],
      autoPassSessionKeys: [...DEFAULT_CONFIG.autoPassSessionKeys],
    };
  }
  return {
    defaultMode:
      pluginConfig.defaultMode === "auto" ||
      pluginConfig.defaultMode === "require-approval" ||
      pluginConfig.defaultMode === "block"
        ? pluginConfig.defaultMode
        : DEFAULT_CONFIG.defaultMode,
    defaultSeverity:
      pluginConfig.defaultSeverity === "info" ||
      pluginConfig.defaultSeverity === "warning" ||
      pluginConfig.defaultSeverity === "critical"
        ? pluginConfig.defaultSeverity
        : DEFAULT_CONFIG.defaultSeverity,
    defaultTimeoutMs: typeof pluginConfig.defaultTimeoutMs === "number"
      ? pluginConfig.defaultTimeoutMs
      : DEFAULT_CONFIG.defaultTimeoutMs,
    rememberAllowAlways: typeof pluginConfig.rememberAllowAlways === "boolean"
      ? pluginConfig.rememberAllowAlways
      : DEFAULT_CONFIG.rememberAllowAlways,
    useClassifiers: typeof pluginConfig.useClassifiers === "boolean"
      ? pluginConfig.useClassifiers
      : DEFAULT_CONFIG.useClassifiers,
    approvalWindow: resolveWindowConfig(pluginConfig.approvalWindow),
    rules: Array.isArray(pluginConfig.rules)
      ? (pluginConfig.rules as HumanGateConfig["rules"])
      : [],
    autoPassSessionKeys: Array.isArray(pluginConfig.autoPassSessionKeys)
      ? (pluginConfig.autoPassSessionKeys as unknown[]).map(String)
      : [...DEFAULT_CONFIG.autoPassSessionKeys],
  };
}
