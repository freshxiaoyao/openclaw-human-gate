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
function ruleMatches(rule, toolName, toolKind) {
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
    return true;
}
function resolveDecision(rule, config) {
    const severity = rule.severity ?? config.defaultSeverity;
    const timeoutMs = rule.timeoutMs ?? config.defaultTimeoutMs;
    const allowedDecisions = rule.allowedDecisions ?? [
        "allow-once",
        "allow-always",
        "deny",
    ];
    return {
        mode: rule.mode,
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
function classifyByName(toolName, toolKind, config) {
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
        severity: config.defaultSeverity,
        timeoutMs: clampTimeout(config.defaultTimeoutMs),
        allowedDecisions: ["allow-once", "allow-always", "deny"],
        reason,
        rule: { id: ruleId, mode: "require-approval", reason },
    };
}
export function evaluatePolicy(toolName, toolKind, config) {
    // 1. User rules (explicit override).
    for (const rule of config.rules) {
        if (ruleMatches(rule, toolName, toolKind)) {
            return resolveDecision(rule, config);
        }
    }
    // 2. Built-in destructive toolKind rules.
    for (const rule of BUILTIN_DESTRUCTIVE_RULES) {
        if (ruleMatches(rule, toolName, toolKind)) {
            return resolveDecision(rule, config);
        }
    }
    // 3. Name-token classifier.
    if (config.useClassifiers) {
        const classified = classifyByName(toolName, toolKind, config);
        if (classified)
            return classified;
    }
    // 4. Fallback. The decision carries a synthesised rule so that
    //    allow-always can be persisted keyed on ("builtin:default-mode",
    //    toolName) instead of silently failing to remember.
    return {
        mode: config.defaultMode,
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