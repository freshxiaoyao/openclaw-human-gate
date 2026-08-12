import type {
  ApprovalPreviewConfig,
  ApprovalWindowConfig,
  GateRule,
  HumanGateConfig,
  ParamCondition,
  ParamScalar,
  RuleParamMatcher,
  SemanticAnalysisConfig,
  UnattendedPolicyConfig,
} from "./types.js";
import { DEFAULT_CONFIG } from "./types.js";
import { isValidRuleParamMatcher } from "./policy.js";

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null;
}

function ownDataValue(object: object, key: PropertyKey): unknown | undefined {
  const descriptor = Object.getOwnPropertyDescriptor(object, key);
  return descriptor && "value" in descriptor ? descriptor.value : undefined;
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

function clampInteger(value: unknown, fallback: number, min: number, max: number): number {
  if (typeof value !== "number" || !Number.isFinite(value)) return fallback;
  return Math.min(Math.max(Math.trunc(value), min), max);
}

function resolveSemanticAnalysis(raw: unknown): SemanticAnalysisConfig {
  const d = DEFAULT_CONFIG.semanticAnalysis;
  if (!isObject(raw)) return { ...d };
  return {
    enabled: typeof raw.enabled === "boolean" ? raw.enabled : d.enabled,
    maxCommandLength: clampInteger(raw.maxCommandLength, d.maxCommandLength, 1_024, 65_536),
    maxWrapperDepth: clampInteger(raw.maxWrapperDepth, d.maxWrapperDepth, 0, 5),
    maxFindings: clampInteger(raw.maxFindings, d.maxFindings, 1, 32),
  };
}

function resolvePreviews(raw: unknown): ApprovalPreviewConfig {
  const d = DEFAULT_CONFIG.previews;
  if (!isObject(raw)) return { ...d };
  return {
    enabled: typeof raw.enabled === "boolean" ? raw.enabled : d.enabled,
    // The host contract caps this at 512. Accept smaller budgets, never larger.
    maxDescriptionChars: clampInteger(raw.maxDescriptionChars, d.maxDescriptionChars, 256, 512),
    maxSectionChars: clampInteger(raw.maxSectionChars, d.maxSectionChars, 80, 360),
    maxLines: clampInteger(raw.maxLines, d.maxLines, 1, 40),
    maxFiles: clampInteger(raw.maxFiles, d.maxFiles, 1, 10),
    redactSecrets: typeof raw.redactSecrets === "boolean" ? raw.redactSecrets : d.redactSecrets,
  };
}

function resolveUnattendedPolicy(raw: unknown): UnattendedPolicyConfig {
  const d = DEFAULT_CONFIG.unattendedPolicy;
  if (!isObject(raw)) return { ...d };
  return {
    critical: raw.critical === "auto" || raw.critical === "block"
      ? raw.critical
      : d.critical,
  };
}

function cloneParamCondition(condition: ParamCondition): ParamCondition {
  const key = ownDataValue(condition, "key") as string;
  if (Object.prototype.hasOwnProperty.call(condition, "equals")) {
    return { key, equals: ownDataValue(condition, "equals") as ParamScalar };
  }
  if (Object.prototype.hasOwnProperty.call(condition, "in")) {
    return { key, in: [...(ownDataValue(condition, "in") as Array<string | number | boolean | null>)] };
  }
  return { key, missing: true };
}

function cloneRuleParamMatcher(matcher: RuleParamMatcher): RuleParamMatcher {
  if (Object.prototype.hasOwnProperty.call(matcher, "all")) {
    const all = ownDataValue(matcher, "all") as ParamCondition[];
    return { all: all.map(cloneParamCondition) };
  }
  const any = ownDataValue(matcher, "any") as ParamCondition[];
  return { any: any.map(cloneParamCondition) };
}

/** Preserve the behavior of existing rules without `paramMatcher`. A rule that
 * supplies malformed parameter constraints is removed, which is equivalent
 * to that rule never matching and therefore fails closed into later policy. */
function resolveRules(raw: unknown): GateRule[] {
  if (!Array.isArray(raw)) return [];
  const resolved: GateRule[] = [];
  for (const candidate of raw) {
    if (!isObject(candidate) || Array.isArray(candidate)) continue;
    const matcherDescriptor = Object.getOwnPropertyDescriptor(candidate, "paramMatcher");
    if (!matcherDescriptor) {
      resolved.push(candidate as unknown as GateRule);
      continue;
    }
    if (
      !("value" in matcherDescriptor) ||
      !matcherDescriptor.enumerable ||
      !isValidRuleParamMatcher(matcherDescriptor.value)
    ) {
      continue;
    }
    resolved.push({
      ...(candidate as unknown as GateRule),
      paramMatcher: cloneRuleParamMatcher(matcherDescriptor.value),
    });
  }
  return resolved;
}

/** Merge validated plugin configuration over the built-in defaults. */
export function resolveConfig(pluginConfig: unknown): HumanGateConfig {
  if (!isObject(pluginConfig)) {
    return {
      ...DEFAULT_CONFIG,
      approvalWindow: { ...DEFAULT_CONFIG.approvalWindow },
      semanticAnalysis: { ...DEFAULT_CONFIG.semanticAnalysis },
      previews: { ...DEFAULT_CONFIG.previews },
      unattendedPolicy: { ...DEFAULT_CONFIG.unattendedPolicy },
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
    semanticAnalysis: resolveSemanticAnalysis(pluginConfig.semanticAnalysis),
    previews: resolvePreviews(pluginConfig.previews),
    unattendedPolicy: resolveUnattendedPolicy(pluginConfig.unattendedPolicy),
    approvalWindow: resolveWindowConfig(pluginConfig.approvalWindow),
    rules: resolveRules(pluginConfig.rules),
    autoPassSessionKeys: Array.isArray(pluginConfig.autoPassSessionKeys)
      ? (pluginConfig.autoPassSessionKeys as unknown[]).map(String)
      : [...DEFAULT_CONFIG.autoPassSessionKeys],
  };
}
