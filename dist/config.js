import { DEFAULT_CONFIG } from "./types.js";
import { isValidRuleParamMatcher } from "./policy.js";
function isObject(v) {
    return typeof v === "object" && v !== null;
}
function ownDataValue(object, key) {
    const descriptor = Object.getOwnPropertyDescriptor(object, key);
    return descriptor && "value" in descriptor ? descriptor.value : undefined;
}
function resolveWindowConfig(raw) {
    const d = DEFAULT_CONFIG.approvalWindow;
    if (!isObject(raw))
        return { ...d };
    const mode = raw.mode === "off" || raw.mode === "turn" || raw.mode === "time" ? raw.mode : d.mode;
    const explicitScope = raw.scope === "destructive" ||
        raw.scope === "same-tool" ||
        raw.scope === "effect" ||
        raw.scope === "category" ||
        raw.scope === "path"
        ? raw.scope
        : undefined;
    const legacyMatch = raw.match === "same-tool" || raw.match === "destructive"
        ? raw.match
        : undefined;
    const scope = explicitScope ?? legacyMatch ?? d.scope;
    const pathFallback = raw.pathFallback === "none" ||
        raw.pathFallback === "category" ||
        raw.pathFallback === "effect"
        ? raw.pathFallback
        : d.pathFallback;
    const ttlMs = typeof raw.ttlMs === "number" && Number.isFinite(raw.ttlMs)
        ? Math.min(Math.max(Math.trunc(raw.ttlMs), 1000), 3_600_000)
        : d.ttlMs;
    const bypassCritical = typeof raw.bypassCritical === "boolean"
        ? raw.bypassCritical
        : d.bypassCritical;
    const pathMode = raw.pathMode === "root" || raw.pathMode === "directory"
        ? raw.pathMode
        : d.pathMode;
    return {
        mode,
        scope,
        pathFallback,
        bypassCritical,
        ttlMs,
        pathMode,
    };
}
function resolveAdaptiveAutoPass(raw) {
    const d = DEFAULT_CONFIG.adaptiveAutoPass;
    if (!isObject(raw) || Array.isArray(raw))
        return { ...d };
    const rawMode = ownDataValue(raw, "mode");
    const mode = rawMode === "off" ||
        rawMode === "shadow" ||
        rawMode === "suggest" ||
        rawMode === "enforce"
        ? rawMode
        : d.mode;
    return {
        mode,
        ttlMs: clampInteger(ownDataValue(raw, "ttlMs"), d.ttlMs, 60_000, 3_600_000),
        maxUses: clampInteger(ownDataValue(raw, "maxUses"), d.maxUses, 1, 100),
        suggestAfterApprovals: clampInteger(ownDataValue(raw, "suggestAfterApprovals"), d.suggestAfterApprovals, 1, 10),
    };
}
function clampInteger(value, fallback, min, max) {
    if (typeof value !== "number" || !Number.isFinite(value))
        return fallback;
    return Math.min(Math.max(Math.trunc(value), min), max);
}
function resolveSemanticAnalysis(raw) {
    const d = DEFAULT_CONFIG.semanticAnalysis;
    if (!isObject(raw))
        return { ...d };
    return {
        enabled: typeof raw.enabled === "boolean" ? raw.enabled : d.enabled,
        maxCommandLength: clampInteger(raw.maxCommandLength, d.maxCommandLength, 1_024, 65_536),
        maxWrapperDepth: clampInteger(raw.maxWrapperDepth, d.maxWrapperDepth, 0, 5),
        maxFindings: clampInteger(raw.maxFindings, d.maxFindings, 1, 32),
    };
}
function resolvePreviews(raw) {
    const d = DEFAULT_CONFIG.previews;
    if (!isObject(raw))
        return { ...d };
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
function resolveUnattendedPolicy(raw) {
    const d = DEFAULT_CONFIG.unattendedPolicy;
    if (!isObject(raw))
        return { ...d };
    return {
        critical: raw.critical === "auto" || raw.critical === "block"
            ? raw.critical
            : d.critical,
    };
}
function resolveSelfProtection(raw) {
    const d = DEFAULT_CONFIG.selfProtection;
    if (!isObject(raw))
        return { ...d };
    return {
        enabled: typeof raw.enabled === "boolean" ? raw.enabled : d.enabled,
    };
}
function resolveDecisionLog(raw) {
    const d = DEFAULT_CONFIG.decisionLog;
    if (!isObject(raw))
        return { ...d };
    const filePath = ownDataValue(raw, "filePath");
    return {
        enabled: typeof raw.enabled === "boolean" ? raw.enabled : d.enabled,
        maxEntries: clampInteger(raw.maxEntries, d.maxEntries, 16, 8192),
        ...(typeof filePath === "string" && filePath.trim().length > 0
            ? { filePath: filePath.trim() }
            : {}),
    };
}
function resolveFloodDetector(raw) {
    const d = DEFAULT_CONFIG.floodDetector;
    if (!isObject(raw))
        return { ...d };
    return {
        enabled: typeof raw.enabled === "boolean" ? raw.enabled : d.enabled,
        windowMs: clampInteger(raw.windowMs, d.windowMs, 1_000, 600_000),
        threshold: clampInteger(raw.threshold, d.threshold, 2, 1_000),
    };
}
function cloneParamCondition(condition) {
    const key = ownDataValue(condition, "key");
    if (Object.prototype.hasOwnProperty.call(condition, "equals")) {
        return { key, equals: ownDataValue(condition, "equals") };
    }
    if (Object.prototype.hasOwnProperty.call(condition, "in")) {
        return { key, in: [...ownDataValue(condition, "in")] };
    }
    if (Object.prototype.hasOwnProperty.call(condition, "matches")) {
        return { key, matches: ownDataValue(condition, "matches") };
    }
    return { key, missing: true };
}
function cloneRuleParamMatcher(matcher) {
    if (Object.prototype.hasOwnProperty.call(matcher, "all")) {
        const all = ownDataValue(matcher, "all");
        return { all: all.map(cloneParamCondition) };
    }
    const any = ownDataValue(matcher, "any");
    return { any: any.map(cloneParamCondition) };
}
/** Preserve the behavior of existing rules without `paramMatcher`. A rule that
 * supplies malformed parameter constraints is removed, which is equivalent
 * to that rule never matching and therefore fails closed into later policy. */
function resolveRules(raw) {
    if (!Array.isArray(raw))
        return [];
    const resolved = [];
    for (const candidate of raw) {
        if (!isObject(candidate) || Array.isArray(candidate))
            continue;
        const matcherDescriptor = Object.getOwnPropertyDescriptor(candidate, "paramMatcher");
        if (!matcherDescriptor) {
            resolved.push(candidate);
            continue;
        }
        if (!("value" in matcherDescriptor) ||
            !matcherDescriptor.enumerable ||
            !isValidRuleParamMatcher(matcherDescriptor.value)) {
            continue;
        }
        resolved.push({
            ...candidate,
            paramMatcher: cloneRuleParamMatcher(matcherDescriptor.value),
        });
    }
    return resolved;
}
/** Merge validated plugin configuration over the built-in defaults. */
export function resolveConfig(pluginConfig) {
    if (!isObject(pluginConfig)) {
        return {
            ...DEFAULT_CONFIG,
            approvalWindow: { ...DEFAULT_CONFIG.approvalWindow },
            adaptiveAutoPass: { ...DEFAULT_CONFIG.adaptiveAutoPass },
            semanticAnalysis: { ...DEFAULT_CONFIG.semanticAnalysis },
            previews: { ...DEFAULT_CONFIG.previews },
            unattendedPolicy: { ...DEFAULT_CONFIG.unattendedPolicy },
            selfProtection: { ...DEFAULT_CONFIG.selfProtection },
            decisionLog: { ...DEFAULT_CONFIG.decisionLog },
            floodDetector: { ...DEFAULT_CONFIG.floodDetector },
            rules: [...DEFAULT_CONFIG.rules],
            autoPassSessionKeys: [...DEFAULT_CONFIG.autoPassSessionKeys],
            writeRoots: [...DEFAULT_CONFIG.writeRoots],
        };
    }
    return {
        defaultMode: pluginConfig.defaultMode === "auto" ||
            pluginConfig.defaultMode === "require-approval" ||
            pluginConfig.defaultMode === "block"
            ? pluginConfig.defaultMode
            : DEFAULT_CONFIG.defaultMode,
        defaultSeverity: pluginConfig.defaultSeverity === "info" ||
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
        allowAlwaysTtlMs: clampInteger(pluginConfig.allowAlwaysTtlMs, DEFAULT_CONFIG.allowAlwaysTtlMs, 60_000, 86_400_000),
        useClassifiers: typeof pluginConfig.useClassifiers === "boolean"
            ? pluginConfig.useClassifiers
            : DEFAULT_CONFIG.useClassifiers,
        semanticAnalysis: resolveSemanticAnalysis(pluginConfig.semanticAnalysis),
        previews: resolvePreviews(pluginConfig.previews),
        unattendedPolicy: resolveUnattendedPolicy(pluginConfig.unattendedPolicy),
        approvalWindow: resolveWindowConfig(pluginConfig.approvalWindow),
        adaptiveAutoPass: resolveAdaptiveAutoPass(ownDataValue(pluginConfig, "adaptiveAutoPass")),
        denyCooldownMs: clampInteger(pluginConfig.denyCooldownMs, DEFAULT_CONFIG.denyCooldownMs, 0, 3_600_000),
        selfProtection: resolveSelfProtection(pluginConfig.selfProtection),
        decisionLog: resolveDecisionLog(pluginConfig.decisionLog),
        floodDetector: resolveFloodDetector(pluginConfig.floodDetector),
        rules: resolveRules(pluginConfig.rules),
        autoPassSessionKeys: Array.isArray(pluginConfig.autoPassSessionKeys)
            ? pluginConfig.autoPassSessionKeys.map(String)
            : [...DEFAULT_CONFIG.autoPassSessionKeys],
        writeRoots: Array.isArray(pluginConfig.writeRoots)
            ? pluginConfig.writeRoots.map(String).filter((s) => s.trim().length > 0)
            : [...DEFAULT_CONFIG.writeRoots],
    };
}
//# sourceMappingURL=config.js.map