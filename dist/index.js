/**
 * openclaw-human-gate — Human-in-the-loop approval middleware.
 *
 * Strategy:
 *  - Register a `before_tool_call` hook (priority 60, after host-trusted
 *    policies but before most observation hooks).
 *  - For each tool call, evaluate the policy (user rules → built-in destructive
 *    toolKinds → name-pattern classifier → defaultMode).
 *  - auto -> pass through; block -> block with reason; require-approval
 *    -> return requireApproval, which pauses the agent run and pushes the
 *    request to every approval surface (TUI / Control UI / chat /approve).
 *  - On allow-always resolution, record a per-session grant so subsequent
 *    matching calls skip the prompt.
 *
 * Ask User tool (Claude Code-style chat prompt):
 *  - Registers `human_gate_ask` so the model can ask a structured question when
 *    information is missing or the task is ambiguous.
 *  - `execute` returns a standard `{ content, details }` tool result whose text
 *    is the question + numbered choices; the agent presents it in chat and
 *    waits for the human's reply in the next turn.
 *  - No TUI popup: OpenClaw's plugin API has no generic selector-prompt surface
 *    (requireApproval is allow/deny only). Chat is the selector.
 *
 * The pause / TUI render / Web UI push / timeout for the *approval gate* are
 * handled by OpenClaw's Gateway plugin.approval.* flow. This plugin never
 * talks to the TUI directly.
 */
import { Type } from "typebox";
import { definePluginEntry, } from "openclaw/plugin-sdk/plugin-entry";
import { allowAlwaysKey, parseAskInput, formatAskForChat, askDetails, } from "./types.js";
import { resolveConfig } from "./config.js";
import { evaluatePolicy, isAutoPassContext } from "./policy.js";
import { AllowAlwaysStore } from "./state.js";
import { ApprovalWindowStore } from "./window.js";
const PLUGIN_ID = "human-gate";
const ASK_TOOL_NAME = "human_gate_ask";
const ALLOW_ALWAYS_NAMESPACE = "allow-always";
const WINDOW_NAMESPACE = "approval-window";
const HOOK_PRIORITY = 60;
function parseAllowAlwaysState(value) {
    if (!value || typeof value !== "object" || Array.isArray(value))
        return undefined;
    const grants = value.grants;
    if (!grants || typeof grants !== "object" || Array.isArray(grants))
        return undefined;
    const normalized = {};
    for (const [key, timestamp] of Object.entries(grants)) {
        if (typeof timestamp === "string")
            normalized[key] = timestamp;
    }
    return { grants: normalized };
}
function parseWindowState(value) {
    if (!value || typeof value !== "object" || Array.isArray(value))
        return undefined;
    const windows = value.windows;
    if (!windows || typeof windows !== "object" || Array.isArray(windows))
        return undefined;
    const normalized = {};
    for (const [key, entry] of Object.entries(windows)) {
        if (!entry || typeof entry !== "object" || Array.isArray(entry))
            continue;
        const openedAt = entry.openedAt;
        const runId = entry.runId;
        if (typeof openedAt !== "number" || !Number.isFinite(openedAt))
            continue;
        normalized[key] = {
            openedAt,
            ...(typeof runId === "string" ? { runId } : {}),
        };
    }
    return { windows: normalized };
}
function extensionValue(api, sessionKey, namespace) {
    const entry = api.runtime.agent.session.getSessionEntry({
        sessionKey,
        readConsistency: "latest",
    });
    return entry?.pluginExtensions?.[PLUGIN_ID]?.[namespace];
}
async function patchExtension(api, sessionKey, namespace, fallback, parse, update) {
    const patched = await api.runtime.agent.session.patchSessionEntry({
        cfg: api.config,
        sessionKey,
        readConsistency: "latest",
        preserveActivity: true,
        update: (entry) => {
            const pluginExtensions = { ...entry.pluginExtensions };
            const pluginState = { ...pluginExtensions[PLUGIN_ID] };
            const current = parse(pluginState[namespace]) ?? fallback;
            pluginState[namespace] = update(current);
            pluginExtensions[PLUGIN_ID] = pluginState;
            return { pluginExtensions };
        },
    });
    if (!patched) {
        throw new Error(`human-gate: unknown session key: ${sessionKey}`);
    }
}
function truncate(text, max) {
    return text.length <= max ? text : `${text.slice(0, Math.max(0, max - 1))}…`;
}
function compactValue(value) {
    if (typeof value === "string") {
        const oneLine = value.replace(/\s+/g, " ").trim();
        return oneLine ? truncate(oneLine, 160) : undefined;
    }
    if (typeof value === "number" || typeof value === "boolean") {
        return String(value);
    }
    return undefined;
}
/** Best-effort, bounded summary for the approval UI. Never dumps the entire
 * params object, which could expose secrets or produce unreadable popups. */
function summarizeParams(params) {
    const preferred = [
        "command",
        "filePath",
        "file_path",
        "path",
        "url",
        "environment",
        "target",
        "name",
    ];
    const parts = [];
    for (const key of preferred) {
        const value = compactValue(params[key]);
        if (value)
            parts.push(`${key}=${value}`);
        if (parts.length >= 3)
            break;
    }
    return parts.length > 0 ? truncate(parts.join("; "), 240) : undefined;
}
function describeToolCall(event, decisionReason, ruleId) {
    const lines = [
        `Tool: ${event.toolName}${event.toolKind ? ` [${event.toolKind}]` : ""}`,
    ];
    if (event.derivedPaths?.length) {
        lines.push(`Paths: ${truncate(event.derivedPaths.slice(0, 4).join(", "), 180)}`);
    }
    const paramSummary = summarizeParams(event.params);
    if (paramSummary)
        lines.push(`Input: ${paramSummary}`);
    lines.push(`Reason: ${decisionReason}`, `Rule: ${ruleId}`);
    return truncate(lines.join("\n"), 512);
}
export default definePluginEntry({
    id: PLUGIN_ID,
    name: "Human Gate",
    description: "Human-in-the-loop approval middleware. Routes selected tool calls through OpenClaw's built-in approval flow before execution. Also adds Claude Code-style interactive ask prompts when the AI needs clarification.",
    register(api) {
        const log = api.logger;
        const config = resolveConfig(api.pluginConfig);
        api.session.state.registerSessionExtension({
            namespace: ALLOW_ALWAYS_NAMESPACE,
            description: "Per-session allow-always grants for Human Gate",
        });
        api.session.state.registerSessionExtension({
            namespace: WINDOW_NAMESPACE,
            description: "Per-session approval windows for Human Gate",
        });
        const allowAlways = new AllowAlwaysStore((sessionKey) => parseAllowAlwaysState(extensionValue(api, sessionKey, ALLOW_ALWAYS_NAMESPACE)), (sessionKey, update) => patchExtension(api, sessionKey, ALLOW_ALWAYS_NAMESPACE, { grants: {} }, parseAllowAlwaysState, update));
        const approvalWindow = new ApprovalWindowStore((sessionKey) => parseWindowState(extensionValue(api, sessionKey, WINDOW_NAMESPACE)), (sessionKey, update) => patchExtension(api, sessionKey, WINDOW_NAMESPACE, { windows: {} }, parseWindowState, update));
        // ── Primary approval gate (priority 60) ──
        api.on("before_tool_call", (event, ctx) => {
            // Skip the ask tool — it has its own dedicated hook below
            if (event.toolName === ASK_TOOL_NAME)
                return undefined;
            const sessionKey = ctx.sessionKey ?? "";
            const decision = evaluatePolicy(event.toolName, event.toolKind, config);
            log.debug("human-gate: evaluated", {
                tool: event.toolName,
                toolKind: event.toolKind,
                mode: decision.mode,
                rule: decision.rule?.id,
                sessionId: ctx.sessionId,
            });
            if (decision.mode === "auto") {
                return undefined;
            }
            // block is unconditional: a tool the operator explicitly banned must
            // never run, even in an unattended cron/heartbeat context.
            if (decision.mode === "block") {
                const blockReason = decision.reason;
                log.warn("human-gate: blocking tool call", {
                    tool: event.toolName,
                    rule: decision.rule?.id,
                    blockReason,
                });
                return {
                    block: true,
                    blockReason,
                };
            }
            // decision.mode === "require-approval"
            // Unattended contexts (cron / heartbeat / subagent) have no human at
            // the popup, so skip the approval prompt — but ONLY the prompt.
            // `block` above still applies: autoPass exempts require-approval,
            // never user-forbidden tools.
            if (sessionKey &&
                isAutoPassContext(sessionKey, config.autoPassSessionKeys)) {
                log.debug("human-gate: auto-pass system context", {
                    tool: event.toolName,
                    sessionKey,
                });
                return undefined;
            }
            // 1) permanent allow-always grant
            if (sessionKey &&
                config.rememberAllowAlways &&
                decision.rule &&
                allowAlways.isGranted(sessionKey, decision.rule.id, event.toolName)) {
                log.debug("human-gate: allow-always grant hit", {
                    rule: decision.rule.id,
                    tool: event.toolName,
                });
                return undefined;
            }
            // 2) approval window (turn / time scoped) — suppresses popup fatigue
            const win = config.approvalWindow;
            const now = Date.now();
            if (sessionKey &&
                !approvalWindow.bypasses(win, decision) &&
                approvalWindow.isOpen(win, sessionKey, event.toolName, ctx.runId, now)) {
                log.debug("human-gate: approval-window auto-pass", {
                    tool: event.toolName,
                    mode: win.mode,
                    match: win.match,
                    runId: ctx.runId,
                });
                return undefined;
            }
            const title = truncate(`Approve ${event.toolName}`, 80);
            const description = describeToolCall(event, decision.reason, decision.rule?.id ?? "default");
            return {
                requireApproval: {
                    title,
                    description,
                    severity: decision.severity,
                    timeoutMs: decision.timeoutMs,
                    allowedDecisions: decision.allowedDecisions,
                    pluginId: PLUGIN_ID,
                    onResolution: async (res) => {
                        try {
                            // Session state is never shared or remembered without a trusted
                            // session key. The approved current call still proceeds.
                            if (!sessionKey) {
                                log.warn("human-gate: approval resolved without sessionKey; not persisting state", {
                                    decision: res,
                                    tool: event.toolName,
                                });
                                return;
                            }
                            // Any approval opens the per-session window for subsequent
                            // matching calls.
                            if ((res === "allow-once" || res === "allow-always") &&
                                !approvalWindow.bypasses(win, decision)) {
                                await approvalWindow.open(win, sessionKey, event.toolName, ctx.runId, Date.now());
                                log.info("human-gate: approval window opened", {
                                    mode: win.mode,
                                    match: win.match,
                                    runId: ctx.runId,
                                    sessionId: ctx.sessionId,
                                });
                            }
                            if (res === "allow-always" && decision.rule && config.rememberAllowAlways) {
                                await allowAlways.grant(sessionKey, decision.rule.id, event.toolName);
                                log.info("human-gate: allow-always granted", {
                                    key: allowAlwaysKey(decision.rule.id, event.toolName),
                                    sessionId: ctx.sessionId,
                                });
                            }
                            else {
                                log.info("human-gate: approval resolved", {
                                    decision: res,
                                    tool: event.toolName,
                                    rule: decision.rule?.id,
                                });
                            }
                        }
                        catch (err) {
                            // State persistence failure must not create a wider grant. The
                            // approved current call may continue, but subsequent calls will
                            // prompt again because no state was recorded.
                            log.error("human-gate: failed to persist approval state", {
                                error: String(err),
                                decision: res,
                                tool: event.toolName,
                                sessionId: ctx.sessionId,
                            });
                        }
                    },
                },
            };
        }, { priority: HOOK_PRIORITY, timeoutMs: 60_000 });
        // ── Observation hook ──
        api.on("after_tool_call", (event) => {
            if (event.error) {
                log.warn("human-gate: tool errored after gate", {
                    tool: event.toolName,
                    toolCallId: event.toolCallId,
                    error: String(event.error),
                });
            }
        }, { priority: 40, timeoutMs: 10_000 });
        // ── Ask tool (chat-based; no TUI popup) ──
        // OpenClaw's requireApproval is allow/deny only and cannot capture a
        // choice or free-text answer, so the ask tool returns a standard tool
        // result whose text the agent presents in chat, then waits for the human's
        // reply in the next turn. This is the Claude Code ask pattern.
        const askTool = {
            name: ASK_TOOL_NAME,
            description: "Ask the human operator a structured question when you need " +
                "clarification, a decision, or more context. Use this when the " +
                "task is ambiguous, the user's request is too broad, there are " +
                "multiple valid approaches, or you're missing critical information. " +
                "You MUST use this instead of guessing or proceeding with " +
                "assumptions. After calling, present the returned question and " +
                "choices to the user in chat, then WAIT for their reply before " +
                "taking any further action.",
            parameters: Type.Object({
                question: Type.String({
                    minLength: 1,
                    maxLength: 2000,
                    description: "The question to ask the human. Be specific, concise, and " +
                        "actionable. Include relevant details so they can make an " +
                        "informed decision.",
                }),
                choices: Type.Optional(Type.Array(Type.String({ maxLength: 500 }), {
                    maxItems: 8,
                    description: "Optional labeled choices for structured decisions, e.g. " +
                        '["A: Deploy to production now", ' +
                        '"B: Wait for code review first", ' +
                        '"C: Cancel deployment"]. ' +
                        "If omitted, a free-text answer is expected.",
                })),
                allowFreeText: Type.Optional(Type.Boolean({
                    description: "Allow the human to type a free-form answer even when " +
                        "choices are provided. Defaults to true when no choices are " +
                        "given, false when choices are present.",
                })),
                context: Type.Optional(Type.String({
                    maxLength: 2000,
                    description: "Optional additional context to help the human understand " +
                        "why this question is being asked. Shown alongside the question.",
                })),
            }, { additionalProperties: false }),
            outputSchema: Type.Object({
                question: Type.String(),
                choices: Type.Array(Type.String()),
                allowFreeText: Type.Boolean(),
                context: Type.Optional(Type.String()),
            }, { additionalProperties: false }),
            async execute(_callId, params) {
                const p = parseAskInput(params);
                const details = askDetails(p);
                log.info("human-gate: ask tool executed", {
                    question: p.question.slice(0, 120),
                    choiceCount: details.choices.length,
                    allowFreeText: details.allowFreeText,
                });
                return {
                    content: [{ type: "text", text: formatAskForChat(p) }],
                    details,
                };
            },
        };
        api.registerTool(askTool, { optional: true });
        log.info("human-gate: registered approval gate + ask tool", {
            hookPriority: HOOK_PRIORITY,
            askTool: ASK_TOOL_NAME,
        });
    },
});
//# sourceMappingURL=index.js.map