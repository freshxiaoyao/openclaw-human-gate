/**
 * openclaw-human-gate — Human-in-the-loop approval middleware.
 *
 * Strategy:
 *  - Register a `before_tool_call` hook (priority 60, after host-trusted
 *    policies but before most observation hooks).
 *  - Snapshot params, evaluate the base policy, then run upgrade-only semantic
 *    analyzers before any auto/grant/window decision.
 *  - auto -> pass through; block -> block with reason; require-approval
 *    -> return requireApproval, which pauses the agent run and pushes the
 *    request to every approval surface (TUI / Control UI / chat /approve).
 *  - On allow-always resolution, record a per-session grant so subsequent
 *    matching non-critical calls skip the prompt.
 *  - Build bounded, redacted previews through provider + presenter layers.
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
  type OpenClawPluginApi,
  type OpenClawPluginDefinition,
  type AnyAgentTool,
  type PluginJsonValue,
} from "openclaw/plugin-sdk/plugin-entry";
import {
  type HumanGateConfig,
  allowAlwaysKey,
  parseAskInput,
  formatAskForChat,
  askDetails,
} from "./types.js";
import { resolveConfig } from "./config.js";
import { evaluatePolicy, isAutoPassContext } from "./policy.js";
import { type AllowAlwaysState, AllowAlwaysStore } from "./state.js";
import { type WindowState, ApprovalWindowStore } from "./window.js";
import { CommandAnalyzer } from "./analysis/command.js";
import { CodeModeAnalyzer } from "./analysis/code.js";
import { reduceDecision } from "./analysis/decision.js";
import { AnalyzerRegistry } from "./analysis/registry.js";
import { EMPTY_SEMANTIC_REPORT, type ToolCallContext } from "./analysis/types.js";
import { ApprovalPresenter } from "./preview/presenter.js";

const PLUGIN_ID = "human-gate";
const ASK_TOOL_NAME = "human_gate_ask";
const ALLOW_ALWAYS_NAMESPACE = "allow-always";
const WINDOW_NAMESPACE = "approval-window";
const HOOK_PRIORITY = 60;

function logPayload(message: string, details: Record<string, unknown>): string {
  return `${message} ${JSON.stringify(details)}`;
}

type ApprovalResolution =
  | "allow-once"
  | "allow-always"
  | "deny"
  | "timeout"
  | "cancelled";

type BeforeToolCallEvent = {
  toolName: string;
  params: Record<string, unknown>;
  toolKind?: string;
  toolInputKind?: string;
  derivedPaths?: readonly string[];
  runId?: string;
  toolCallId?: string;
};

type ToolCallHookContext = {
  agentId?: string;
  sessionKey?: string;
  sessionId?: string;
  runId?: string;
  toolKind?: string;
  toolInputKind?: string;
  trace?: unknown;
  getSessionExtension?: (namespace: string) => PluginJsonValue | undefined;
  requester?: {
    channel?: string;
    accountId?: string;
    senderId?: string;
    senderIsOwner?: boolean;
    roleIds?: readonly string[];
  };
};

function parseAllowAlwaysState(value: unknown): AllowAlwaysState | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const grants = (value as { grants?: unknown }).grants;
  if (!grants || typeof grants !== "object" || Array.isArray(grants)) return undefined;
  const normalized: Record<string, string> = {};
  for (const [key, timestamp] of Object.entries(grants)) {
    if (typeof timestamp === "string") normalized[key] = timestamp;
  }
  return { grants: normalized };
}

function parseWindowState(value: unknown): WindowState | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const windows = (value as { windows?: unknown }).windows;
  if (!windows || typeof windows !== "object" || Array.isArray(windows)) return undefined;
  const normalized: WindowState["windows"] = {};
  for (const [key, entry] of Object.entries(windows)) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) continue;
    const openedAt = (entry as { openedAt?: unknown }).openedAt;
    const runId = (entry as { runId?: unknown }).runId;
    if (typeof openedAt !== "number" || !Number.isFinite(openedAt)) continue;
    normalized[key] = {
      openedAt,
      ...(typeof runId === "string" ? { runId } : {}),
    };
  }
  return { windows: normalized };
}

function extensionValue(
  api: OpenClawPluginApi,
  sessionKey: string,
  namespace: string,
): unknown {
  const entry = api.runtime.agent.session.getSessionEntry({
    sessionKey,
    readConsistency: "latest",
  });
  return entry?.pluginExtensions?.[PLUGIN_ID]?.[namespace];
}

async function patchExtension<T extends object>(
  api: OpenClawPluginApi,
  sessionKey: string,
  namespace: string,
  fallback: T,
  parse: (value: unknown) => T | undefined,
  update: (current: T) => T,
): Promise<void> {
  const patched = await api.runtime.agent.session.patchSessionEntry({
    sessionKey,
    readConsistency: "latest",
    preserveActivity: true,
    update: (entry: {
      pluginExtensions?: Record<string, Record<string, PluginJsonValue>>;
    }) => {
      const pluginExtensions = { ...entry.pluginExtensions };
      const pluginState = { ...pluginExtensions[PLUGIN_ID] };
      const current = parse(pluginState[namespace]) ?? fallback;
      pluginState[namespace] = update(current) as PluginJsonValue;
      pluginExtensions[PLUGIN_ID] = pluginState;
      return { pluginExtensions };
    },
  });
  if (!patched) {
    throw new Error(`human-gate: unknown session key: ${sessionKey}`);
  }
}

function truncate(text: string, max: number): string {
  return text.length <= max ? text : `${text.slice(0, Math.max(0, max - 1))}…`;
}

function snapshotParams(params: Record<string, unknown>): Record<string, unknown> | undefined {
  try {
    const cloned = structuredClone(params);
    return cloned && typeof cloned === "object" && !Array.isArray(cloned)
      ? cloned
      : undefined;
  } catch {
    return undefined;
  }
}

const pluginEntry: OpenClawPluginDefinition = definePluginEntry({
  id: PLUGIN_ID,
  name: "Human Gate",
  description:
    "Human-in-the-loop approval middleware. Routes selected tool calls through OpenClaw's built-in approval flow before execution. Also adds Claude Code-style interactive ask prompts when the AI needs clarification.",
  register(api: OpenClawPluginApi) {
    const log = api.logger;

    const config: HumanGateConfig = resolveConfig(api.pluginConfig);
    const analyzerRegistry = new AnalyzerRegistry(
      [
        new CodeModeAnalyzer(config.semanticAnalysis),
        new CommandAnalyzer(config.semanticAnalysis),
      ],
      config.semanticAnalysis.maxFindings,
    );
    const presenter = new ApprovalPresenter(config.previews);

    api.session.state.registerSessionExtension({
      namespace: ALLOW_ALWAYS_NAMESPACE,
      description: "Per-session allow-always grants for Human Gate",
    });
    api.session.state.registerSessionExtension({
      namespace: WINDOW_NAMESPACE,
      description: "Per-session approval windows for Human Gate",
    });

    const allowAlways = new AllowAlwaysStore(
      (sessionKey) =>
        parseAllowAlwaysState(
          extensionValue(api, sessionKey, ALLOW_ALWAYS_NAMESPACE),
        ),
      (sessionKey, update) =>
        patchExtension(
          api,
          sessionKey,
          ALLOW_ALWAYS_NAMESPACE,
          { grants: {} },
          parseAllowAlwaysState,
          update,
        ),
    );
    const approvalWindow = new ApprovalWindowStore(
      (sessionKey) =>
        parseWindowState(extensionValue(api, sessionKey, WINDOW_NAMESPACE)),
      (sessionKey, update) =>
        patchExtension(
          api,
          sessionKey,
          WINDOW_NAMESPACE,
          { windows: {} },
          parseWindowState,
          update,
        ),
    );

    // ── Primary approval gate (priority 60) ──
    api.on(
      "before_tool_call",
      (event: BeforeToolCallEvent, ctx: ToolCallHookContext) => {
        // Skip the ask tool — it has its own dedicated hook below
        if (event.toolName === ASK_TOOL_NAME) return undefined;

        const sessionKey = ctx.sessionKey ?? "";
        const baseDecision = evaluatePolicy(
          event.toolName,
          event.toolKind,
          config,
          event.params,
        );
        // An explicit base block is terminal and needs neither parameter
        // inspection nor preview generation.
        if (baseDecision.mode === "block") {
          const blockReason = baseDecision.reason;
          log.warn(logPayload("human-gate: blocking tool call", {
            tool: event.toolName,
            rule: baseDecision.rule?.id,
            blockReason,
          }));
          return { block: true, blockReason };
        }
        const paramsSnapshot = snapshotParams(event.params);
        if (!paramsSnapshot) {
          const blockReason = "Human Gate could not safely snapshot tool parameters";
          log.warn(logPayload("human-gate: blocking unsnapshotable tool params", {
            tool: event.toolName,
            sessionId: ctx.sessionId,
          }));
          return { block: true, blockReason };
        }
        const analysisContext: ToolCallContext = {
          toolName: event.toolName,
          toolKind: event.toolKind,
          toolInputKind: event.toolInputKind,
          params: paramsSnapshot,
          derivedPaths: event.derivedPaths ?? [],
        };
        const semanticReport = config.semanticAnalysis.enabled
          ? analyzerRegistry.analyze(analysisContext)
          : EMPTY_SEMANTIC_REPORT;
        const decision = reduceDecision(baseDecision, semanticReport);
        const isParamScopedRule = decision.source === "user" &&
          decision.rule !== undefined &&
          Object.prototype.hasOwnProperty.call(decision.rule, "paramMatcher");

        log.debug?.(logPayload("human-gate: evaluated", {
          tool: event.toolName,
          toolKind: event.toolKind,
          mode: decision.mode,
          rule: decision.rule?.id,
          findings: decision.semanticReport.findings.map((finding) => finding.id),
          sessionId: ctx.sessionId,
        }));

        if (decision.mode === "auto") {
          // A parameter-scoped auto decision is bound to the exact JSON-safe
          // snapshot that matched. This prevents the host from executing a
          // subsequently mutated action under an earlier narrow decision.
          return isParamScopedRule ? { params: paramsSnapshot } : undefined;
        }

        // block is unconditional: a tool the operator explicitly banned must
        // never run, even in an unattended cron/heartbeat context.
        if (decision.mode === "block") {
          const blockReason = decision.reason;
          log.warn(logPayload("human-gate: blocking tool call", {
            tool: event.toolName,
            rule: decision.rule?.id,
            blockReason,
          }));
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
        if (
          sessionKey &&
          isAutoPassContext(sessionKey, config.autoPassSessionKeys)
        ) {
          if (
            decision.severity === "critical" &&
            config.unattendedPolicy.critical === "block"
          ) {
            const blockReason = `Critical unattended tool call blocked: ${decision.reason}`;
            log.warn(logPayload("human-gate: blocking critical unattended call", {
              tool: event.toolName,
              findings: decision.semanticReport.findings.map((finding) => finding.id),
              sessionKey,
            }));
            return { block: true, blockReason };
          }
          log.debug?.(logPayload("human-gate: auto-pass system context", {
            tool: event.toolName,
            sessionKey,
          }));
          return undefined;
        }
        // 1) permanent allow-always grant
        if (
          sessionKey &&
          decision.windowEligible &&
          config.rememberAllowAlways &&
          decision.rule &&
          allowAlways.isGranted(sessionKey, decision.rule.id, event.toolName)
        ) {
          log.debug?.(logPayload("human-gate: allow-always grant hit", {
            rule: decision.rule.id,
            tool: event.toolName,
          }));
          return undefined;
        }

        // 2) approval window (turn / time scoped) — suppresses popup fatigue
        const win = config.approvalWindow;
        const now = Date.now();
        if (
          sessionKey &&
          decision.windowEligible &&
          !isParamScopedRule &&
          !approvalWindow.bypasses(win, decision) &&
          approvalWindow.isOpen(win, sessionKey, event.toolName, ctx.runId, now)
        ) {
          log.debug?.(logPayload("human-gate: approval-window auto-pass", {
            tool: event.toolName,
            mode: win.mode,
            match: win.match,
            runId: ctx.runId,
          }));
          return undefined;
        }

        const title = truncate(`Approve ${event.toolName}`, 80);
        const description = presenter.describe(analysisContext, decision);

        return {
          // Bind the approval to the exact params that were analyzed and shown.
          params: paramsSnapshot,
          requireApproval: {
            title,
            description,
            severity: decision.severity,
            timeoutMs: decision.timeoutMs,
            timeoutBehavior: "deny" as const,
            timeoutReason: "Human Gate approval timed out",
            allowedDecisions: decision.allowedDecisions,
            pluginId: PLUGIN_ID,
            onResolution: async (res: ApprovalResolution) => {
              try {
                // Session state is never shared or remembered without a trusted
                // session key. The approved current call still proceeds.
                if (!sessionKey) {
                  log.warn(logPayload("human-gate: approval resolved without sessionKey; not persisting state", {
                    decision: res,
                    tool: event.toolName,
                  }));
                  return;
                }
                // Any approval opens the per-session window for subsequent
                // matching calls.
                if (
                  (res === "allow-once" || res === "allow-always") &&
                  decision.windowEligible &&
                  !isParamScopedRule &&
                  !approvalWindow.bypasses(win, decision)
                ) {
                  await approvalWindow.open(
                    win,
                    sessionKey,
                    event.toolName,
                    ctx.runId,
                    Date.now(),
                  );
                  log.info(logPayload("human-gate: approval window opened", {
                    mode: win.mode,
                    match: win.match,
                    runId: ctx.runId,
                    sessionId: ctx.sessionId,
                  }));
                }
                if (
                  res === "allow-always" &&
                  decision.windowEligible &&
                  decision.rule &&
                  config.rememberAllowAlways
                ) {
                  await allowAlways.grant(
                    sessionKey,
                    decision.rule.id,
                    event.toolName,
                  );
                  log.info(logPayload("human-gate: allow-always granted", {
                    key: allowAlwaysKey(decision.rule.id, event.toolName),
                    sessionId: ctx.sessionId,
                  }));
                } else {
                  log.info(logPayload("human-gate: approval resolved", {
                    decision: res,
                    tool: event.toolName,
                    rule: decision.rule?.id,
                  }));
                }
              } catch (err) {
                // State persistence failure must not create a wider grant. The
                // approved current call may continue, but subsequent calls will
                // prompt again because no state was recorded.
                log.error(logPayload("human-gate: failed to persist approval state", {
                  error: String(err),
                  decision: res,
                  tool: event.toolName,
                  sessionId: ctx.sessionId,
                }));
              }
            },
          },
        };
      },
      { priority: HOOK_PRIORITY, timeoutMs: 60_000 },
    );

    // ── Observation hook ──
    api.on(
      "after_tool_call",
      (event: {
        toolName: string;
        toolCallId?: string;
        error?: unknown;
        durationMs?: number;
      }) => {
        if (event.error) {
          log.warn(logPayload("human-gate: tool errored after gate", {
            tool: event.toolName,
            toolCallId: event.toolCallId,
            error: String(event.error),
          }));
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
      label: "Ask Human",
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
      async execute(_callId: string, params: Record<string, unknown>) {
        const p = parseAskInput(params);
        const details = askDetails(p);

        log.info(logPayload("human-gate: ask tool executed", {
          questionLength: p.question.length,
          choiceCount: details.choices.length,
          allowFreeText: details.allowFreeText,
        }));

        return {
          content: [{ type: "text", text: formatAskForChat(p) }],
          details,
        };
      },
    };
    api.registerTool(askTool, { optional: true });

    log.info(logPayload("human-gate: registered approval gate + ask tool", {
      hookPriority: HOOK_PRIORITY,
      askTool: ASK_TOOL_NAME,
    }));
  },
});

export default pluginEntry;
