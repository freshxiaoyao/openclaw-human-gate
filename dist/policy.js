/**
 * Policy engine: given a tool call and the resolved config, pick a decision.
 *
 * Evaluation order (first match wins):
 *  1. User rules           — explicit override (highest authority)
 *  2. Built-in destructive toolKind rules (exec / apply_patch / code_mode_exec)
 *  3. Name-token classifier (when useClassifiers)
 *     - destructive token in name  → require-approval (checked FIRST, so
 *       composite names like `readWriteFile` never slip through as reads)
 *     - read-only token / kind     → auto (pass through)
 *     - neither                    → unknown
 *  4. config.defaultMode    — fallback for unknowns (defaults to
 *     `require-approval`: fail-closed; unrecognized tools must be approved).
 *
 * Design intent: reads pass through; anything with side-effect vocabulary is
 * gated; anything unrecognized is gated unless the operator opts into
 * fail-open (`defaultMode: "auto"`).
 */
import { BUILTIN_DESTRUCTIVE_RULES, DESTRUCTIVE_NAME_TOKENS, DESTRUCTIVE_TOOL_KINDS, READONLY_NAME_TOKENS, READONLY_TOOL_KINDS, } from "./types.js";
/** Split a tool name into lowercase segments.
 *
 * Handles camelCase (`readWriteFile` -> read, write, file), snake_case
 * (`remove_old_files` -> remove, old, files), kebab-case, and digit
 * boundaries (`list2` -> list, 2). Names that cannot be segmented reliably
 * (e.g. all-lowercase run-together words like `frobnicate` or `scatter`)
 * yield their whole lowercase form as a single segment — they will only hit
 * a token if the entire name is a vocabulary word (`cat`, `exec`).
 */
export function tokenizeName(name) {
    const parts = name
        // split camelCase / kebab / snake / digit boundaries
        .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
        .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
        .replace(/[_-]+/g, " ")
        .replace(/([a-zA-Z])([0-9])/g, "$1 $2")
        .replace(/([0-9])([a-zA-Z])/g, "$1 $2")
        .toLowerCase()
        .split(/\s+/)
        .filter(Boolean);
    return parts.length > 0 ? parts : [name.toLowerCase()];
}
function containsToken(name, tokens) {
    const segments = tokenizeName(name);
    return segments.some((seg) => tokens.includes(seg));
}
function compilePattern(source) {
    if (!source)
        return undefined;
    try {
        return new RegExp(source);
    }
    catch {
        return undefined;
    }
}
const MAX_PARAM_CONDITIONS = 16;
const MAX_PARAM_IN_VALUES = 32;
const SAFE_DIRECT_PARAM_KEY = /^[A-Za-z_][A-Za-z0-9_-]{0,127}$/;
const FORBIDDEN_PARAM_KEYS = new Set(["__proto__", "prototype", "constructor"]);
function isObject(value) {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}
function isParamScalar(value) {
    return value === null ||
        typeof value === "string" ||
        typeof value === "boolean" ||
        (typeof value === "number" && Number.isFinite(value));
}
/** Only simple top-level names are supported. Dotted/bracketed paths and
 * prototype-control names are rejected instead of being interpreted. */
export function isSafeDirectParamKey(key) {
    return SAFE_DIRECT_PARAM_KEY.test(key) && !FORBIDDEN_PARAM_KEYS.has(key.toLowerCase());
}
function ownDataValue(object, key) {
    const descriptor = Object.getOwnPropertyDescriptor(object, key);
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable)
        return undefined;
    return descriptor.value;
}
function isScalarArray(value) {
    if (!Array.isArray(value) || value.length < 1 || value.length > MAX_PARAM_IN_VALUES) {
        return false;
    }
    const allowedKeys = new Set(["length"]);
    for (let index = 0; index < value.length; index += 1) {
        const key = String(index);
        allowedKeys.add(key);
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        if (!descriptor || !("value" in descriptor) || !descriptor.enumerable)
            return false;
        if (!isParamScalar(descriptor.value))
            return false;
    }
    return Reflect.ownKeys(value).every((key) => allowedKeys.has(key));
}
function isValidParamCondition(value) {
    if (!isObject(value))
        return false;
    const keys = Reflect.ownKeys(value);
    if (keys.length !== 2 || !keys.every((key) => typeof key === "string"))
        return false;
    const key = ownDataValue(value, "key");
    if (typeof key !== "string" || !isSafeDirectParamKey(key))
        return false;
    const operators = ["equals", "in", "missing", "matches"].filter((operator) => Object.prototype.hasOwnProperty.call(value, operator));
    if (operators.length !== 1)
        return false;
    const operator = operators[0];
    if (!operator || !keys.includes(operator))
        return false;
    const operand = ownDataValue(value, operator);
    if (operator === "equals")
        return isParamScalar(operand);
    if (operator === "in")
        return isScalarArray(operand);
    if (operator === "matches") {
        return typeof operand === "string" && operand.length >= 1 && operand.length <= 256 &&
            compilePattern(operand) !== undefined;
    }
    return operand === true;
}
function isConditionArray(value) {
    if (!Array.isArray(value) || value.length < 1 || value.length > MAX_PARAM_CONDITIONS) {
        return false;
    }
    const allowedKeys = new Set(["length"]);
    for (let index = 0; index < value.length; index += 1) {
        const key = String(index);
        allowedKeys.add(key);
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        if (!descriptor || !("value" in descriptor) || !descriptor.enumerable)
            return false;
        if (!isValidParamCondition(descriptor.value))
            return false;
    }
    return Reflect.ownKeys(value).every((key) => allowedKeys.has(key));
}
/** Runtime validation mirrors the manifest schema. A matcher has exactly one
 * top-level `all` or `any` array and cannot contain nested boolean groups. */
export function isValidRuleParamMatcher(value) {
    if (!isObject(value))
        return false;
    const keys = Reflect.ownKeys(value);
    if (keys.length !== 1 || (keys[0] !== "all" && keys[0] !== "any"))
        return false;
    return isConditionArray(ownDataValue(value, keys[0]));
}
function conditionMatches(condition, toolParams) {
    const key = ownDataValue(condition, "key");
    if (typeof key !== "string")
        return false;
    const descriptor = Object.getOwnPropertyDescriptor(toolParams, key);
    if (Object.prototype.hasOwnProperty.call(condition, "missing"))
        return descriptor === undefined;
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable)
        return false;
    if (Object.prototype.hasOwnProperty.call(condition, "equals")) {
        return descriptor.value === ownDataValue(condition, "equals");
    }
    if (Object.prototype.hasOwnProperty.call(condition, "matches")) {
        if (typeof descriptor.value !== "string")
            return false;
        const source = ownDataValue(condition, "matches");
        try {
            // Command matching is case-insensitive (PowerShell cmdlets, exes).
            return new RegExp(source, "i").test(descriptor.value);
        }
        catch {
            return false;
        }
    }
    const candidates = ownDataValue(condition, "in");
    return Array.isArray(candidates) &&
        candidates.some((candidate) => candidate === descriptor.value);
}
/** Match direct-own parameter constraints without invoking accessors or
 * traversing prototypes. Invalid matchers and missing required values fail. */
export function matchRuleParamMatcher(matcher, toolParams) {
    if (!isValidRuleParamMatcher(matcher) || !toolParams || typeof toolParams !== "object") {
        return false;
    }
    if (Object.prototype.hasOwnProperty.call(matcher, "all")) {
        const all = ownDataValue(matcher, "all");
        return all.every((condition) => conditionMatches(condition, toolParams));
    }
    const any = ownDataValue(matcher, "any");
    return any.some((condition) => conditionMatches(condition, toolParams));
}
function hasInheritedParamMatcher(rule) {
    let prototype = Object.getPrototypeOf(rule);
    while (prototype) {
        if (Object.getOwnPropertyDescriptor(prototype, "paramMatcher"))
            return true;
        prototype = Object.getPrototypeOf(prototype);
    }
    return false;
}
function ruleMatches(rule, toolName, toolKind, toolParams) {
    if (rule.toolName && rule.toolName !== toolName)
        return false;
    if (rule.toolKind && rule.toolKind !== toolKind)
        return false;
    if (rule.toolNamePattern) {
        const re = compilePattern(rule.toolNamePattern);
        // Invalid configured regexes must never become match-all rules. Treat the
        // rule as non-matching; manifest JSON Schema cannot validate regex syntax.
        if (!re || !re.test(toolName))
            return false;
    }
    const matcherDescriptor = Object.getOwnPropertyDescriptor(rule, "paramMatcher");
    if (matcherDescriptor) {
        if (!("value" in matcherDescriptor) || !matcherDescriptor.enumerable)
            return false;
        if (!matchRuleParamMatcher(matcherDescriptor.value, toolParams))
            return false;
    }
    else if (hasInheritedParamMatcher(rule)) {
        // Never let a prototype-supplied matcher silently turn into a broad rule.
        return false;
    }
    return true;
}
function resolveDecision(rule, config, source) {
    const severity = rule.severity ?? config.defaultSeverity;
    const timeoutMs = rule.timeoutMs ?? config.defaultTimeoutMs;
    const allowedDecisions = rule.allowedDecisions ?? [
        "allow-once",
        "allow-always",
        "deny",
    ];
    return {
        mode: rule.mode,
        source,
        rule,
        severity,
        timeoutMs: clampTimeout(timeoutMs),
        allowedDecisions,
        reason: rule.reason ?? `Tool "${rule.id}" gated by Human Gate`,
    };
}
function clampTimeout(ms) {
    return Math.min(Math.max(ms, 1000), 600_000);
}
/** Name-token classifier. Returns a synthesised decision, or undefined to
 *  defer to defaultMode (fail-closed by default).
 *
 *  Order matters: destructive tokens are scanned FIRST so composite names
 *  that mix read-only and destructive vocabulary (`readWriteFile`) are
 *  gated, never auto-passed. Read-only tokens then pass through, and names
 *  with neither are unknown -> undefined -> defaultMode.
 */
function classifyByName(toolName, toolKind, config, toolParams) {
    // `session_status` normally observes state, but an explicit model parameter
    // persists a model override. Presence is checked without reading a getter.
    if (toolName === "session_status" &&
        toolParams &&
        Object.getOwnPropertyDescriptor(toolParams, "model") !== undefined) {
        return requireApprovalDecision("builtin:session-status-model-change", "session_status with model changes persistent session configuration", config);
    }
    // host toolKind is authoritative when present.
    if (toolKind) {
        if (READONLY_TOOL_KINDS.has(toolKind)) {
            return autoDecision("builtin:readonly-kind", "Read-only tool kind");
        }
        if (DESTRUCTIVE_TOOL_KINDS.has(toolKind)) {
            // Already covered by BUILTIN_DESTRUCTIVE_RULES, but keep as safety net.
            return requireApprovalDecision("builtin:destructive-kind", `Destructive tool kind "${toolKind}"`, config);
        }
    }
    // Fall back to name tokens for tools without a recognised kind.
    // Destructive vocabulary wins over read-only vocabulary in composite names.
    if (containsToken(toolName, DESTRUCTIVE_NAME_TOKENS)) {
        return requireApprovalDecision("builtin:destructive-name", `Destructive name token in "${toolName}"`, config);
    }
    if (containsToken(toolName, READONLY_NAME_TOKENS)) {
        return autoDecision("builtin:readonly-name", "Read-only name token");
    }
    return undefined;
}
function autoDecision(ruleId, reason) {
    return {
        mode: "auto",
        source: "classifier",
        severity: "info",
        timeoutMs: 0,
        allowedDecisions: [],
        reason,
        rule: { id: ruleId, mode: "auto", reason },
    };
}
function requireApprovalDecision(ruleId, reason, config) {
    return {
        mode: "require-approval",
        source: "classifier",
        severity: config.defaultSeverity,
        timeoutMs: clampTimeout(config.defaultTimeoutMs),
        allowedDecisions: ["allow-once", "allow-always", "deny"],
        reason,
        rule: { id: ruleId, mode: "require-approval", reason },
    };
}
export function evaluatePolicy(toolName, toolKind, config, toolParams) {
    // 1. User rules (explicit override).
    for (const rule of config.rules) {
        if (ruleMatches(rule, toolName, toolKind, toolParams)) {
            return resolveDecision(rule, config, "user");
        }
    }
    // 2. Built-in destructive toolKind rules.
    for (const rule of BUILTIN_DESTRUCTIVE_RULES) {
        if (ruleMatches(rule, toolName, toolKind, toolParams)) {
            return resolveDecision(rule, config, "builtin");
        }
    }
    // 3. Name-token classifier.
    if (config.useClassifiers) {
        const classified = classifyByName(toolName, toolKind, config, toolParams);
        if (classified)
            return classified;
    }
    // 4. Fallback. The decision carries a synthesised rule so that
    //    allow-always can be persisted keyed on ("builtin:default-mode",
    //    toolName) instead of silently failing to remember.
    return {
        mode: config.defaultMode,
        source: "default",
        severity: config.defaultSeverity,
        timeoutMs: clampTimeout(config.defaultTimeoutMs),
        allowedDecisions: ["allow-once", "allow-always", "deny"],
        reason: `No rule or classifier matched; default mode "${config.defaultMode}"`,
        rule: {
            id: "builtin:default-mode",
            mode: config.defaultMode,
            reason: `No rule or classifier matched; default mode "${config.defaultMode}"`,
        },
    };
}
/** True when a session key belongs to an unattended context (cron isolated
 *  runs, heartbeat runs, subagents) that must not stall on an approval
 *  popup nobody can see.
 *
 *  Matching is exact per `:`-delimited segment — NOT a loose substring match —
 *  so `:cron:` never matches a key like `cronx:` or `x:cronology`. Configured
 *  keys may be written with or without surrounding colons (`":cron:"`,
 *  `":heartbeat"`, `"subagent"` all work); a bare value matches only a
 *  standalone segment.
 */
export function isAutoPassContext(sessionKey, keys) {
    const segments = new Set(sessionKey.split(":"));
    return keys.some((key) => {
        const cleaned = key.replace(/^:+|:+$/g, "");
        return cleaned !== "" && segments.has(cleaned);
    });
}
//# sourceMappingURL=policy.js.map