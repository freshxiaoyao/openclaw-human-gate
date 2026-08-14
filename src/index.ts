/**
 * openclaw-human-gate — Human-in-the-loop approval middleware.
 *
 * Strategy:
 *  - Register a `before_tool_call` gate (priority 60) plus a final parameter
 *    sealer. The sealer restores the exact host params inspected by the gate
 *    after ordinary lower-priority plugin rewrites.
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
  parseAskInput,
  formatAskForChat,
  askDetails,
} from "./types.js";
import { resolveConfig } from "./config.js";
import { evaluatePolicy, isAutoPassContext } from "./policy.js";
import {
  ALLOW_ALWAYS_STATE_VERSION,
  AllowAlwaysStore,
  normalizeAllowAlwaysState,
} from "./state.js";
import {
  WINDOW_STATE_VERSION,
  ApprovalWindowStore,
  normalizeWindowState,
} from "./window.js";
import { CommandAnalyzer } from "./analysis/command.js";
import { CodeModeAnalyzer } from "./analysis/code.js";
import { FileMutationAnalyzer } from "./analysis/file-mutation.js";
import { reduceDecision, type EffectiveDecision } from "./analysis/decision.js";
import { AnalyzerRegistry } from "./analysis/registry.js";
import { EMPTY_SEMANTIC_REPORT, type ToolCallContext } from "./analysis/types.js";
import { ApprovalPresenter } from "./preview/presenter.js";
import {
  createAuthorizationFingerprint,
  createPolicyIdentity,
  type AuthorizationFingerprint,
} from "./scope.js";
import {
  ADAPTIVE_STATE_VERSION,
  AdaptiveLeaseStore,
  normalizeAdaptiveState,
} from "./adaptive/state.js";
import { evaluateAdaptiveEligibility } from "./adaptive/eligibility.js";

const PLUGIN_ID = "human-gate";
const ASK_TOOL_NAME = "human_gate_ask";
const ALLOW_ALWAYS_NAMESPACE = "allow-always-v2";
const WINDOW_NAMESPACE = "approval-window-v2";
const ADAPTIVE_NAMESPACE = "adaptive-auto-pass-v1";
const HOOK_PRIORITY = 60;
// OpenClaw runs typed hooks in descending numeric priority. There is no public
// finalizer hook, so this ordinary-hook compatibility seal deliberately sorts
// after every finite-priority handler. Installed plugins remain trusted code;
// the SDK cannot reserve an absolute final slot against another -Infinity hook.
const PARAM_SEAL_PRIORITY = Number.NEGATIVE_INFINITY;
/** Bump whenever semantic effects/categories/target derivation changes. */
const SEMANTIC_RULESET_VERSION = "2026-08-14.3";

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
  /** Host-authoritative working directory for this tool execution. */
  cwd?: string;
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

function appendDescriptionHint(description: string, hint: string, max: number): string {
  const combined = `${description}\n${hint}`;
  return combined.length <= max ? combined : description;
}

function adaptiveLeaseLabel(ttlMs: number, maxUses: number): string {
  const minutes = Math.max(1, Math.round(ttlMs / 60_000));
  return `${maxUses}-use/${minutes}-minute`;
}

interface SnapshotBudget {
  nodes: number;
  stringChars: number;
}

type SnapshotResult = { ok: true; value: unknown } | { ok: false };

function cloneJsonLike(
  value: unknown,
  seen: Set<object>,
  budget: SnapshotBudget,
  depth: number,
): SnapshotResult {
  budget.nodes += 1;
  if (budget.nodes > 100_000 || depth > 64) return { ok: false };
  if (value === undefined || value === null || typeof value === "boolean") {
    return { ok: true, value };
  }
  if (typeof value === "string") {
    budget.stringChars += value.length;
    return budget.stringChars <= 16 * 1024 * 1024
      ? { ok: true, value }
      : { ok: false };
  }
  if (typeof value === "number") {
    return Number.isFinite(value) ? { ok: true, value } : { ok: false };
  }
  if (typeof value !== "object" || seen.has(value)) return { ok: false };

  let prototype: object | null;
  let keys: PropertyKey[];
  try {
    prototype = Object.getPrototypeOf(value) as object | null;
    keys = Reflect.ownKeys(value);
  } catch {
    return { ok: false };
  }
  const array = Array.isArray(value);
  if (array ? prototype !== Array.prototype : prototype !== Object.prototype && prototype !== null) {
    return { ok: false };
  }
  seen.add(value);
  try {
    if (array) {
      if (keys.some((key) => typeof key !== "string" || (key !== "length" && !/^(?:0|[1-9][0-9]*)$/.test(key)))) {
        return { ok: false };
      }
      const output: unknown[] = [];
      for (let index = 0; index < value.length; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
        if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) return { ok: false };
        const cloned = cloneJsonLike(descriptor.value, seen, budget, depth + 1);
        if (!cloned.ok) return cloned;
        output.push(cloned.value);
      }
      return { ok: true, value: output };
    }

    const output: Record<string, unknown> = {};
    for (const key of keys) {
      if (typeof key !== "string") return { ok: false };
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) return { ok: false };
      const cloned = cloneJsonLike(descriptor.value, seen, budget, depth + 1);
      if (!cloned.ok) return cloned;
      Object.defineProperty(output, key, {
        value: cloned.value,
        enumerable: true,
        configurable: true,
        writable: true,
      });
    }
    return { ok: true, value: output };
  } finally {
    seen.delete(value);
  }
}

function snapshotParams(params: Record<string, unknown>): Record<string, unknown> | undefined {
  try {
    const cloned = cloneJsonLike(params, new Set<object>(), { nodes: 0, stringChars: 0 }, 0);
    return cloned.ok && cloned.value && typeof cloned.value === "object" && !Array.isArray(cloned.value)
      ? cloned.value as Record<string, unknown>
      : undefined;
  } catch {
    return undefined;
  }
}

function policyIdentityFor(
  decision: EffectiveDecision,
  config: HumanGateConfig,
): string | undefined {
  const rule = decision.rule;
  return createPolicyIdentity({
    source: decision.source,
    rule: {
      id: rule?.id ?? null,
      toolName: rule?.toolName ?? null,
      toolNamePattern: rule?.toolNamePattern ?? null,
      toolKind: rule?.toolKind ?? null,
      paramMatcher: rule?.paramMatcher ?? null,
      mode: rule?.mode ?? null,
      severity: rule?.severity ?? null,
      allowedDecisions: rule?.allowedDecisions
        ? [...rule.allowedDecisions].sort()
        : null,
      timeoutMs: rule?.timeoutMs ?? null,
    },
    effective: {
      mode: decision.mode,
      severity: decision.severity,
      timeoutMs: decision.timeoutMs,
      allowedDecisions: [...decision.allowedDecisions].sort(),
    },
    semanticAnalysis: {
      enabled: config.semanticAnalysis.enabled,
      maxCommandLength: config.semanticAnalysis.maxCommandLength,
      maxWrapperDepth: config.semanticAnalysis.maxWrapperDepth,
    },
  });
}

function fingerprintFor(
  config: HumanGateConfig,
  event: BeforeToolCallEvent,
  ctx: ToolCallHookContext,
  decision: EffectiveDecision,
  isParamScopedRule: boolean,
): AuthorizationFingerprint | undefined {
  if (!decision.windowEligible || isParamScopedRule || !decision.rule) return undefined;
  const policyIdentity = policyIdentityFor(decision, config);
  if (!policyIdentity) return undefined;
  return createAuthorizationFingerprint({
    toolName: event.toolName,
    toolKind: event.toolKind ?? "unspecified",
    toolInputKind: event.toolInputKind ?? "unspecified",
    ruleId: decision.rule.id,
    policyIdentity,
    effects: decision.semanticReport.effects,
    categories: decision.semanticReport.categories,
    verifiedTargets: decision.semanticReport.verifiedTargets.map(({ path, targetKind }) => ({
      path,
      targetKind,
    })),
    // workspaceDir/resolveAgentWorkspaceDir are diagnostic locations, not the
    // authoritative execution cwd. Without ctx.cwd, relative paths fail closed.
    executionCwd: typeof ctx.cwd === "string" ? ctx.cwd : undefined,
    analysisComplete: decision.semanticReport.complete,
  }, {
    scope: config.approvalWindow.scope,
    pathFallback: config.approvalWindow.pathFallback,
    rulesetVersion: SEMANTIC_RULESET_VERSION,
  });
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
        new FileMutationAnalyzer(config.semanticAnalysis),
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
    api.session.state.registerSessionExtension({
      namespace: ADAPTIVE_NAMESPACE,
      description: "Bounded adaptive safe-file leases and non-authorizing approval evidence",
    });

    const allowAlways = new AllowAlwaysStore(
      (sessionKey) =>
        normalizeAllowAlwaysState(
          extensionValue(api, sessionKey, ALLOW_ALWAYS_NAMESPACE),
        ),
      (sessionKey, update) =>
        patchExtension(
          api,
          sessionKey,
          ALLOW_ALWAYS_NAMESPACE,
          { version: ALLOW_ALWAYS_STATE_VERSION, grants: {} },
          normalizeAllowAlwaysState,
          update,
        ),
      config.allowAlwaysTtlMs,
    );
    const approvalWindow = new ApprovalWindowStore(
      (sessionKey) =>
        normalizeWindowState(extensionValue(api, sessionKey, WINDOW_NAMESPACE)),
      (sessionKey, update) =>
        patchExtension(
          api,
          sessionKey,
          WINDOW_NAMESPACE,
          { version: WINDOW_STATE_VERSION, windows: {} },
          normalizeWindowState,
          update,
        ),
    );
    const adaptiveLease = new AdaptiveLeaseStore(
      (sessionKey) =>
        normalizeAdaptiveState(extensionValue(api, sessionKey, ADAPTIVE_NAMESPACE)),
      (sessionKey, update) =>
        patchExtension(
          api,
          sessionKey,
          ADAPTIVE_NAMESPACE,
          { version: ADAPTIVE_STATE_VERSION, observations: {}, receipts: {}, leases: {} },
          normalizeAdaptiveState,
          update,
        ),
      config.adaptiveAutoPass,
    );
    // The same event object is passed to every ordinary hook. Capture the
    // gate-time snapshot by object identity so an intervening handler cannot
    // defeat the final seal by mutating event.params in place.
    const parameterSeals = new WeakMap<BeforeToolCallEvent, Record<string, unknown>>();

    // ── Primary approval gate (priority 60) ──
    api.on(
      "before_tool_call",
      async (event: BeforeToolCallEvent, ctx: ToolCallHookContext) => {
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
        parameterSeals.set(event, paramsSnapshot);
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
        const fingerprint = fingerprintFor(
          config,
          event,
          ctx,
          decision,
          isParamScopedRule,
        );
        const adaptiveMode = config.adaptiveAutoPass.mode;
        const adaptiveEligibility = adaptiveMode === "off"
          ? undefined
          : evaluateAdaptiveEligibility({
              decision,
              fingerprint,
              isParamScopedRule,
              sessionKey: sessionKey || undefined,
              toolCallId: event.toolCallId,
              rememberAllowAlways: config.rememberAllowAlways,
            });
        // Freeze ownership at gate time. Once enforce owns a semantically
        // safe-file call, a lease miss/error must never fall through to a
        // legacy grant/window, even when no lease can be minted right now.
        const adaptiveOwns = adaptiveMode === "enforce" && adaptiveEligibility?.semanticEligible === true;

        log.debug?.(logPayload("human-gate: evaluated", {
          tool: event.toolName,
          toolKind: event.toolKind,
          mode: decision.mode,
          rule: decision.rule?.id,
          findings: decision.semanticReport.findings.map((finding) => finding.id),
          semanticComplete: decision.semanticReport.complete,
          reusableScope: fingerprint?.resolvedScope,
          adaptiveMode,
          adaptiveEligible: adaptiveEligibility?.eligible,
          adaptiveReasons: adaptiveEligibility?.reasonCodes,
          sessionId: ctx.sessionId,
        }));

        if (decision.mode === "auto") {
          // Every pass is bound to the exact JSON-safe snapshot that was
          // classified. The final sealer below restores this snapshot after
          // ordinary lower-priority plugin parameter rewrites.
          return { params: paramsSnapshot };
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
          return { params: paramsSnapshot };
        }
        const win = config.approvalWindow;
        const now = Date.now();
        if (adaptiveOwns) {
          // Semantically adaptive-owned calls never fall back to legacy
          // grants/windows, even when no lease can be minted right now
          // (missing toolCallId, session, or durable grant key).
          if (fingerprint && sessionKey) {
            try {
              const consumed = await adaptiveLease.consume(sessionKey, fingerprint, now);
              log.debug?.(logPayload("human-gate: adaptive lease consume", {
                tool: event.toolName,
                outcome: consumed.outcome,
                scopeDigest: fingerprint.grantKey?.slice(0, 19),
                remainingBefore: consumed.remainingBefore,
                remainingAfter: consumed.remainingAfter,
                legacySuppressed: true,
              }));
              if (consumed.outcome === "consumed") return { params: paramsSnapshot };
            } catch {
              // Store failure is an authorization miss. Do not expose exception
              // text (which may contain host paths/state); continue to approval.
              log.error(logPayload("human-gate: adaptive lease consume failed", {
                tool: event.toolName,
                outcome: "store-error",
                legacySuppressed: true,
              }));
            }
          }
        } else {
          // Legacy remembered grants/windows remain unchanged for
          // off/shadow/suggest and calls outside the safe-file MVP.
          if (
            sessionKey &&
            config.rememberAllowAlways &&
            fingerprint?.grantKey &&
            allowAlways.isGranted(sessionKey, fingerprint, now)
          ) {
            log.debug?.(logPayload("human-gate: allow-always grant hit", {
              rule: decision.rule?.id,
              tool: event.toolName,
              scope: fingerprint.resolvedScope,
            }));
            return { params: paramsSnapshot };
          }
          if (
            sessionKey &&
            fingerprint &&
            !approvalWindow.bypasses(win, decision) &&
            approvalWindow.isOpen(win, sessionKey, fingerprint, ctx.runId, now)
          ) {
            log.debug?.(logPayload("human-gate: approval-window auto-pass", {
              tool: event.toolName,
              mode: win.mode,
              requestedScope: fingerprint.requestedScope,
              resolvedScope: fingerprint.resolvedScope,
              runId: ctx.runId,
            }));
            return { params: paramsSnapshot };
          }
        }

        const title = truncate(`Approve ${event.toolName}`, 80);
        let description = presenter.describe(analysisContext, decision);
        const canRemember = Boolean(
          sessionKey && config.rememberAllowAlways && fingerprint?.grantKey,
        );
        const allowedDecisions = canRemember
          ? [...decision.allowedDecisions]
          : decision.allowedDecisions.filter((item) => item !== "allow-always");
        let approvalCount = 0;
        if (
          adaptiveMode === "suggest" &&
          adaptiveEligibility?.eligible && sessionKey && fingerprint
        ) {
          try {
            approvalCount = adaptiveLease.approvalCount(sessionKey, fingerprint);
          } catch {
            // Suggestions are non-authorizing UX only. State-read failure must
            // neither fail the gate nor suppress the ordinary approval.
            log.warn(logPayload("human-gate: adaptive evidence read failed", {
              tool: event.toolName,
              outcome: "store-error",
            }));
          }
        }
        if (adaptiveEligibility?.eligible && allowedDecisions.includes("allow-always")) {
          const leaseLabel = adaptiveLeaseLabel(
            config.adaptiveAutoPass.ttlMs,
            config.adaptiveAutoPass.maxUses,
          );
          if (adaptiveMode === "enforce") {
            description = appendDescriptionHint(
              description,
              `Adaptive: allow-always creates a bounded ${leaseLabel} path lease.`,
              config.previews.maxDescriptionChars,
            );
          } else if (
            adaptiveMode === "suggest" &&
            approvalCount >= config.adaptiveAutoPass.suggestAfterApprovals
          ) {
            description = appendDescriptionHint(
              description,
              `Adaptive preview: eligible for a ${leaseLabel} lease in enforce mode.`,
              config.previews.maxDescriptionChars,
            );
          }
        }

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
            allowedDecisions,
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
                // Enforce-owned safe-file calls use exactly one authorization
                // system. They never mint a legacy window/grant that could
                // bypass the adaptive use budget or revive after exhaustion.
                if (
                  !adaptiveOwns &&
                  (res === "allow-once" || res === "allow-always") &&
                  fingerprint &&
                  !approvalWindow.bypasses(win, decision)
                ) {
                  const opened = await approvalWindow.open(
                    win,
                    sessionKey,
                    fingerprint,
                    ctx.runId,
                    Date.now(),
                  );
                  if (opened) {
                    log.info(logPayload("human-gate: approval window opened", {
                      mode: win.mode,
                      requestedScope: fingerprint.requestedScope,
                      resolvedScope: fingerprint.resolvedScope,
                      scopeDigest: fingerprint.windowKey.slice(0, 17),
                      runId: ctx.runId,
                      sessionId: ctx.sessionId,
                    }));
                  }
                }
                if (
                  adaptiveOwns &&
                  res === "allow-always" &&
                  fingerprint
                ) {
                  const granted = await adaptiveLease.grant(
                    sessionKey,
                    fingerprint,
                    Date.now(),
                    event.toolCallId,
                  );
                  log.info(logPayload("human-gate: adaptive lease resolution", {
                    decision: res,
                    granted,
                    tool: event.toolName,
                    scopeDigest: fingerprint.grantKey?.slice(0, 19),
                    maxUses: config.adaptiveAutoPass.maxUses,
                    ttlMs: config.adaptiveAutoPass.ttlMs,
                  }));
                } else if (
                  adaptiveOwns &&
                  res === "deny" &&
                  fingerprint
                ) {
                  await adaptiveLease.deny(sessionKey, fingerprint);
                  log.info(logPayload("human-gate: adaptive lease revoked", {
                    decision: res,
                    tool: event.toolName,
                    scopeDigest: fingerprint.grantKey?.slice(0, 19),
                  }));
                } else if (
                  !adaptiveOwns &&
                  res === "allow-always" &&
                  canRemember &&
                  fingerprint?.grantKey
                ) {
                  await allowAlways.grant(sessionKey, fingerprint, Date.now());
                  log.info(logPayload("human-gate: allow-always granted", {
                    rule: decision.rule?.id,
                    scopeDigest: fingerprint.grantKey.slice(0, 19),
                    sessionId: ctx.sessionId,
                  }));
                } else {
                  log.info(logPayload("human-gate: approval resolved", {
                    decision: res,
                    tool: event.toolName,
                    rule: decision.rule?.id,
                  }));
                }
                if (
                  adaptiveMode === "suggest" &&
                  adaptiveEligibility?.eligible &&
                  fingerprint &&
                  res === "allow-once"
                ) {
                  await adaptiveLease.observeApproval(
                    sessionKey,
                    fingerprint,
                    res,
                    Date.now(),
                  );
                } else if (
                  adaptiveMode === "suggest" &&
                  adaptiveEligibility?.eligible &&
                  fingerprint &&
                  res === "deny"
                ) {
                  await adaptiveLease.deny(sessionKey, fingerprint);
                }
              } catch (err) {
                // Reuse begins only after the session-extension update
                // succeeds, so persistence failure creates no authorization.
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

    // OpenClaw currently has no public final-params/finalizer hook. Ordinary
    // before_tool_call handlers all receive the same host-adjusted event, and
    // later handler results can otherwise replace params after a window/grant
    // hit. Re-snapshotting the original event at the final numeric priority
    // makes the analyzed payload the last ordinary params decision. A prior
    // requireApproval from another plugin remains authoritative by host design.
    api.on(
      "before_tool_call",
      (event: BeforeToolCallEvent) => {
        if (event.toolName === ASK_TOOL_NAME) return undefined;
        const paramsSnapshot = parameterSeals.get(event);
        parameterSeals.delete(event);
        if (!paramsSnapshot) {
          const blockReason = "Human Gate parameter seal is missing";
          log.warn(logPayload("human-gate: blocking tool call without a parameter seal", {
            tool: event.toolName,
          }));
          return { block: true, blockReason };
        }
        return { params: paramsSnapshot };
      },
      { priority: PARAM_SEAL_PRIORITY, timeoutMs: 10_000 },
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
      parameterSealPriority: String(PARAM_SEAL_PRIORITY),
      askTool: ASK_TOOL_NAME,
    }));
  },
});

export default pluginEntry;
