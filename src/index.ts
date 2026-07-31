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
import {
  definePluginEntry,
  type BeforeToolCallEvent,
  type OpenClawPluginApi,
  type ToolCallHookContext,
  type ApprovalResolution,
  type AnyAgentTool,
} from "openclaw/plugin-sdk/plugin-entry";
import {
  type HumanGateConfig,
  type ApprovalWindowConfig,
  DEFAULT_CONFIG,
  allowAlwaysKey,
  parseAskInput,
  formatAskForChat,
  askDetails,
} from "./types.js";
import { evaluatePolicy } from "./policy.js";
import { AllowAlwaysStore } from "./state.js";
import { ApprovalWindowStore } from "./window.js";
import { createInMemoryHandle } from "./in-memory-handle.js";

const PLUGIN_ID = "human-gate";
const ASK_TOOL_NAME = "human_gate_ask";
const SESSION_EXT_ID = "human-gate:allow-always";
const WINDOW_EXT_ID = "human-gate:approval-window";
const HOOK_PRIORITY = 60;

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null;
}

/** Merge validated pluginConfig (from manifest configSchema) over defaults. */
function resolveConfig(pluginConfig: unknown): HumanGateConfig {
  if (!isObject(pluginConfig)) return { ...DEFAULT_CONFIG };
  const cfg: HumanGateConfig = {
    defaultMode: (pluginConfig.defaultMode as HumanGateConfig["defaultMode"]) ?? DEFAULT_CONFIG.defaultMode,
    defaultSeverity: (pluginConfig.defaultSeverity as HumanGateConfig["defaultSeverity"]) ?? DEFAULT_CONFIG.defaultSeverity,
    defaultTimeoutMs: typeof pluginConfig.defaultTimeoutMs === "number" ? pluginConfig.defaultTimeoutMs : DEFAULT_CONFIG.defaultTimeoutMs,
    rememberAllowAlways: typeof pluginConfig.rememberAllowAlways === "boolean" ? pluginConfig.rememberAllowAlways : DEFAULT_CONFIG.rememberAllowAlways,
    useClassifiers: typeof pluginConfig.useClassifiers === "boolean" ? pluginConfig.useClassifiers : DEFAULT_CONFIG.useClassifiers,
    approvalWindow: resolveWindowConfig(pluginConfig.approvalWindow),
    rules: Array.isArray(pluginConfig.rules) ? (pluginConfig.rules as HumanGateConfig["rules"]) : [],
    autoPassSessionKeys: Array.isArray(pluginConfig.autoPassSessionKeys)
      ? (pluginConfig.autoPassSessionKeys as unknown[]).map(String)
      : DEFAULT_CONFIG.autoPassSessionKeys,
  };
  return cfg;
}

function resolveWindowConfig(raw: unknown): ApprovalWindowConfig {
  const d = DEFAULT_CONFIG.approvalWindow;
  if (typeof raw !== "object" || raw === null) return { ...d };
  const o = raw as Record<string, unknown>;
  const mode = o.mode === "off" || o.mode === "turn" || o.mode === "time" ? o.mode : d.mode;
  const match = o.match === "same-tool" || o.match === "destructive" ? o.match : d.match;
  const ttlMs = typeof o.ttlMs === "number" ? Math.min(Math.max(o.ttlMs, 1000), 3_600_000) : d.ttlMs;
  const bypassCritical = typeof o.bypassCritical === "boolean" ? o.bypassCritical : d.bypassCritical;
  return { mode, match, ttlMs, bypassCritical };
}

function truncate(text: string, max: number): string {
  return text.length <= max ? text : `${text.slice(0, Math.max(0, max - 1))}…`;
}

function compactValue(value: unknown): string | undefined {
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
function summarizeParams(params: Record<string, unknown>): string | undefined {
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
  const parts: string[] = [];
  for (const key of preferred) {
    const value = compactValue(params[key]);
    if (value) parts.push(`${key}=${value}`);
    if (parts.length >= 3) break;
  }
  return parts.length > 0 ? truncate(parts.join("; "), 240) : undefined;
}

function describeToolCall(event: BeforeToolCallEvent, decisionReason: string, ruleId: string): string {
  const lines = [
    `Tool: ${event.toolName}${event.toolKind ? ` [${event.toolKind}]` : ""}`,
  ];
  if (event.derivedPaths?.length) {
    lines.push(`Paths: ${truncate(event.derivedPaths.slice(0, 4).join(", "), 180)}`);
  }
  const paramSummary = summarizeParams(event.params);
  if (paramSummary) lines.push(`Input: ${paramSummary}`);
  lines.push(`Reason: ${decisionReason}`, `Rule: ${ruleId}`);
  return truncate(lines.join("\n"), 512);
}

export default definePluginEntry({
  id: PLUGIN_ID,
  name: "Human Gate",
  description:
    "Human-in-the-loop approval middleware. Routes selected tool calls through OpenClaw's built-in approval flow before execution. Also adds Claude Code-style interactive ask prompts when the AI needs clarification.",
  register(api: OpenClawPluginApi) {
    const log = api.logger;

    // Session extension for allow-always grants. Falls back to in-memory if the
    // host runtime does not support session extensions.
    let allowAlwaysHandle;
    try {
      const h = api.session.state.registerSessionExtension<
        ReturnType<AllowAlwaysStore["snapshot"]>
      >({ id: SESSION_EXT_ID, defaultValue: { grants: {} } });
      allowAlwaysHandle =
        h && typeof h.get === "function"
          ? h
          : createInMemoryHandle({ grants: {} });
      if (h && typeof h.get !== "function") {
        log.warn("human-gate: session extension handle missing .get(); using in-memory fallback");
      }
    } catch (err) {
      log.warn("human-gate: session extension registration failed; using in-memory fallback", {
        error: String(err),
      });
      allowAlwaysHandle = createInMemoryHandle({ grants: {} });
    }
    const allowAlways = new AllowAlwaysStore(allowAlwaysHandle);

    // Session extension for the approval window (same defensive pattern).
    let windowHandle;
    try {
      const h = api.session.state.registerSessionExtension<ReturnType<ApprovalWindowStore["snapshot"]>>(
        { id: WINDOW_EXT_ID, defaultValue: { windows: {} } },
      );
      windowHandle =
        h && typeof h.get === "function" ? h : createInMemoryHandle({ windows: {} });
      if (h && typeof h.get !== "function") {
        log.warn("human-gate: window extension handle missing .get(); using in-memory fallback");
      }
    } catch (err) {
      log.warn("human-gate: window extension registration failed; using in-memory fallback", {
        error: String(err),
      });
      windowHandle = createInMemoryHandle({ windows: {} });
    }
    const approvalWindow = new ApprovalWindowStore(windowHandle);

    // ── Primary approval gate (priority 60) ──
    api.on<BeforeToolCallEvent, ToolCallHookContext>(
      "before_tool_call",
      (event, ctx) => {
        // Skip the ask tool — it has its own dedicated hook below
        if (event.toolName === ASK_TOOL_NAME) return undefined;

        const pluginConfig = (event.context?.pluginConfig ?? {}) as unknown;
        const config = resolveConfig(pluginConfig);

        // System contexts (cron isolated runs, heartbeat isolated runs) have
        // no human at the keyboard; auto-pass so scheduled maintenance and
        // heartbeat fixes are never blocked on an approval nobody can see.
        const sessionKey = ctx.sessionKey ?? "";
        if (config.autoPassSessionKeys.some((p) => p && sessionKey.includes(p))) {
          log.debug("human-gate: auto-pass system context", {
            tool: event.toolName,
            sessionKey,
          });
          return undefined;
        }

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
        // 1) permanent allow-always grant
        if (
          config.rememberAllowAlways &&
          decision.rule &&
          allowAlways.isGranted(decision.rule.id, event.toolName)
        ) {
          log.debug("human-gate: allow-always grant hit", {
            rule: decision.rule.id,
            tool: event.toolName,
          });
          return undefined;
        }

        // 2) approval window (turn / time scoped) — suppresses popup fatigue
        const win = config.approvalWindow;
        const now = Date.now();
        if (
          !approvalWindow.bypasses(win, decision) &&
          approvalWindow.isOpen(win, event.toolName, ctx.runId, now)
        ) {
          log.debug("human-gate: approval-window auto-pass", {
            tool: event.toolName,
            mode: win.mode,
            match: win.match,
            runId: ctx.runId,
          });
          return undefined;
        }

        const title = truncate(`Approve ${event.toolName}`, 80);
        const description = describeToolCall(
          event,
          decision.reason,
          decision.rule?.id ?? "default",
        );

        return {
          requireApproval: {
            title,
            description,
            severity: decision.severity,
            timeoutMs: decision.timeoutMs,
            allowedDecisions: decision.allowedDecisions,
            pluginId: PLUGIN_ID,
            onResolution: (res: ApprovalResolution) => {
              // Any approval opens the window for subsequent same-class calls.
              if (
                (res === "allow-once" || res === "allow-always") &&
                !approvalWindow.bypasses(win, decision)
              ) {
                approvalWindow.open(win, event.toolName, ctx.runId, Date.now());
                log.info("human-gate: approval window opened", {
                  mode: win.mode,
                  match: win.match,
                  runId: ctx.runId,
                });
              }
              if (res === "allow-always" && decision.rule && config.rememberAllowAlways) {
                allowAlways.grant(decision.rule.id, event.toolName);
                log.info("human-gate: allow-always granted", {
                  key: allowAlwaysKey(decision.rule.id, event.toolName),
                  sessionId: ctx.sessionId,
                });
              } else {
                log.info("human-gate: approval resolved", {
                  decision: res,
                  tool: event.toolName,
                  rule: decision.rule?.id,
                });
              }
            },
          },
        };
      },
      { priority: HOOK_PRIORITY, timeoutMs: 60_000 },
    );

    // ── Observation hook ──
    api.on<
      {
        toolName: string;
        toolCallId?: string;
        error?: unknown;
        durationMs?: number;
      },
      ToolCallHookContext
    >(
      "after_tool_call",
      (event) => {
        if (event.error) {
          log.warn("human-gate: tool errored after gate", {
            tool: event.toolName,
            toolCallId: event.toolCallId,
            error: String(event.error),
          });
        }
      },
      { priority: 40, timeoutMs: 10_000 },
    );

    // ── Ask tool (chat-based; no TUI popup) ──
    // OpenClaw's requireApproval is allow/deny only and cannot capture a
    // choice or free-text answer, so the ask tool returns a standard tool
    // result whose text the agent presents in chat, then waits for the human's
    // reply in the next turn. This is the Claude Code ask pattern.
    const askTool: AnyAgentTool = {
      name: ASK_TOOL_NAME,
      description:
        "Ask the human operator a structured question when you need " +
        "clarification, a decision, or more context. Use this when the " +
        "task is ambiguous, the user's request is too broad, there are " +
        "multiple valid approaches, or you're missing critical information. " +
        "You MUST use this instead of guessing or proceeding with " +
        "assumptions. After calling, present the returned question and " +
        "choices to the user in chat, then WAIT for their reply before " +
        "taking any further action.",
      parameters: Type.Object(
        {
          question: Type.String({
            minLength: 1,
            maxLength: 2000,
            description:
              "The question to ask the human. Be specific, concise, and " +
              "actionable. Include relevant details so they can make an " +
              "informed decision.",
          }),
          choices: Type.Optional(Type.Array(Type.String({ maxLength: 500 }), {
            maxItems: 8,
            description:
              "Optional labeled choices for structured decisions, e.g. " +
              '["A: Deploy to production now", ' +
              '"B: Wait for code review first", ' +
              '"C: Cancel deployment"]. ' +
              "If omitted, a free-text answer is expected.",
          })),
          allowFreeText: Type.Optional(Type.Boolean({
            description:
              "Allow the human to type a free-form answer even when " +
              "choices are provided. Defaults to true when no choices are " +
              "given, false when choices are present.",
          })),
          context: Type.Optional(Type.String({
            maxLength: 2000,
            description:
              "Optional additional context to help the human understand " +
              "why this question is being asked. Shown alongside the question.",
          })),
        },
        { additionalProperties: false },
      ),
      outputSchema: Type.Object(
        {
          question: Type.String(),
          choices: Type.Array(Type.String()),
          allowFreeText: Type.Boolean(),
          context: Type.Optional(Type.String()),
        },
        { additionalProperties: false },
      ),
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
