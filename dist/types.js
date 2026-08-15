/**
 * Plugin-owned types for openclaw-human-gate.
 *
 * These describe the plugin's configuration shape and policy model. They are
 * independent of the OpenClaw SDK surface (see `sdk-shim.d.ts` for the SDK
 * contract this plugin relies on).
 */
export const DEFAULT_CONFIG = {
    defaultMode: "require-approval",
    defaultSeverity: "warning",
    defaultTimeoutMs: 300_000,
    rememberAllowAlways: true,
    allowAlwaysTtlMs: 14_400_000,
    useClassifiers: true,
    semanticAnalysis: {
        enabled: true,
        maxCommandLength: 16_384,
        maxWrapperDepth: 3,
        maxFindings: 8,
    },
    previews: {
        enabled: true,
        maxDescriptionChars: 512,
        maxSectionChars: 220,
        maxLines: 12,
        maxFiles: 4,
        redactSecrets: true,
    },
    unattendedPolicy: {
        critical: "block",
    },
    approvalWindow: {
        mode: "turn",
        ttlMs: 300_000,
        scope: "path",
        pathFallback: "none",
        bypassCritical: true,
        pathMode: "directory",
    },
    adaptiveAutoPass: {
        mode: "off",
        ttlMs: 900_000,
        maxUses: 20,
        suggestAfterApprovals: 2,
    },
    denyCooldownMs: 120_000,
    selfProtection: {
        enabled: true,
    },
    decisionLog: {
        enabled: true,
        maxEntries: 512,
    },
    floodDetector: {
        enabled: true,
        windowMs: 60_000,
        threshold: 8,
    },
    rules: [],
    autoPassSessionKeys: [":cron:", ":heartbeat"],
    writeRoots: [],
};
/** host toolKind values that always have side effects → require approval. */
export const DESTRUCTIVE_TOOL_KINDS = new Set([
    "exec",
    "code_mode_exec",
    "apply_patch",
]);
/** host toolKind values that are pure observation → auto. Keep conservative:
 *  only kinds we know are read-only. Unknown kinds are NOT assumed read-only. */
export const READONLY_TOOL_KINDS = new Set([
    "read",
    "search",
    "glob",
    "grep",
    "fetch",
]);
/** Destructive / read-only vocabulary for the name classifier.
 *
 * Tokens are matched against the *whole* tool name after splitting it into
 * segments (camelCase, snake_case, kebab-case, digits). Destructive tokens are
 * checked FIRST, so a composite name like `readWriteFile` or `getDeleteUser`
 * is gated even though it also contains a read-only token. A name that
 * contains neither a destructive nor a read-only token is unknown and falls
 * through to `defaultMode` (which defaults to `require-approval`). */
export const DESTRUCTIVE_NAME_TOKENS = [
    "write", "edit", "delete", "remove", "rm", "rmdir", "mkdir",
    "move", "rename", "deploy", "publish", "install", "uninstall",
    "exec", "run", "apply", "patch", "create", "update", "kill",
    "send", "post", "put", "push", "commit", "flush", "drop",
    "truncate", "grant", "revoke",
];
export const READONLY_NAME_TOKENS = [
    "read", "get", "list", "search", "glob", "grep", "view", "show",
    "status", "ping", "fetch", "head", "cat", "ls", "find", "whoami",
    "echo", "inspect", "describe", "explain", "query", "count",
];
/** Explicit built-in rules for known destructive toolKinds, applied after user
 *  rules. These carry severity / allowedDecisions defaults; the name-token
 *  classifier synthesises a lighter-weight decision for matched names. */
export const BUILTIN_DESTRUCTIVE_RULES = [
    {
        id: "builtin:exec",
        toolKind: "exec",
        mode: "require-approval",
        severity: "warning",
        allowedDecisions: ["allow-once", "allow-always", "deny"],
        reason: "Shell command execution",
    },
    {
        id: "builtin:apply-patch",
        toolName: "apply_patch",
        mode: "require-approval",
        severity: "warning",
        allowedDecisions: ["allow-once", "allow-always", "deny"],
        reason: "Filesystem write via apply_patch",
    },
    {
        id: "builtin:code-mode-exec",
        toolKind: "code_mode_exec",
        mode: "require-approval",
        severity: "warning",
        allowedDecisions: ["allow-once", "deny"],
        reason: "Code Mode execution",
    },
];
/** Key used to remember an allow-always decision for a rule. */
export function allowAlwaysKey(ruleId, toolName) {
    return `${ruleId}::${toolName}`;
}
/** Parse + validate raw tool params into AskToolInput. Throws on missing
 *  question. Strips non-string choices. */
export function parseAskInput(params) {
    const o = typeof params === "object" && params !== null
        ? params
        : {};
    const question = typeof o.question === "string" ? o.question.trim() : "";
    if (!question) {
        throw new Error("human_gate_ask: 'question' (string) is required");
    }
    const rawChoices = Array.isArray(o.choices) ? o.choices : [];
    const choices = rawChoices
        .filter((c) => typeof c === "string")
        .map((c) => c.trim())
        .filter(Boolean)
        .slice(0, 8);
    const context = typeof o.context === "string" ? o.context.trim() : "";
    return {
        question: question.slice(0, 2000),
        choices: choices.length > 0 ? choices.map((c) => c.slice(0, 500)) : undefined,
        allowFreeText: typeof o.allowFreeText === "boolean" ? o.allowFreeText : undefined,
        context: context ? context.slice(0, 2000) : undefined,
    };
}
/** Format the question + choices as text for the tool result `content`,
 *  which the agent presents in chat. The agent is instructed to wait. */
export function formatAskForChat(p) {
    const lines = [
        "The AI needs your input before continuing.",
    ];
    if (p.context)
        lines.push("", `Context: ${p.context}`);
    lines.push("", `Q: ${p.question}`);
    const choices = p.choices ?? [];
    const allowFree = p.allowFreeText ?? choices.length === 0;
    if (choices.length > 0) {
        lines.push("", "Options:");
        for (let i = 0; i < choices.length; i++) {
            lines.push(`  ${i + 1}. ${choices[i]}`);
        }
        if (allowFree) {
            lines.push("  (or reply with your own answer)");
        }
    }
    else {
        lines.push("", "(reply with your answer)");
    }
    lines.push("", "Reply in chat — the AI will wait for your response before taking any further action.");
    // Tool result text has no documented hard cap, but keep it reasonable.
    return lines.join("\n");
}
/** Resolve the structured details value for the tool result. */
export function askDetails(p) {
    const choices = p.choices ?? [];
    return {
        question: p.question,
        choices,
        allowFreeText: p.allowFreeText ?? choices.length === 0,
        context: p.context,
    };
}
//# sourceMappingURL=types.js.map