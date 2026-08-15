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
import { definePluginEntry, } from "openclaw/plugin-sdk/plugin-entry";
import { parseAskInput, formatAskForChat, askDetails, allowAlwaysKey, } from "./types.js";
import { resolveConfig } from "./config.js";
import { evaluatePolicy, isAutoPassContext } from "./policy.js";
import { ALLOW_ALWAYS_STATE_VERSION, AllowAlwaysStore, normalizeAllowAlwaysState, } from "./state.js";
import { DENY_COOLDOWN_STATE_VERSION, DenyCooldownStore, normalizeDenyCooldownState, } from "./deny-cooldown.js";
import { DecisionLog, digestSessionKey } from "./decision-log.js";
import { classifySensitiveEscalation } from "./self-protection.js";
import { WINDOW_STATE_VERSION, ApprovalWindowStore, normalizeWindowState, } from "./window.js";
import { CommandAnalyzer } from "./analysis/command.js";
import { CodeModeAnalyzer } from "./analysis/code.js";
import { FileMutationAnalyzer } from "./analysis/file-mutation.js";
import { reduceDecision } from "./analysis/decision.js";
import { AnalyzerRegistry } from "./analysis/registry.js";
import { EMPTY_SEMANTIC_REPORT } from "./analysis/types.js";
import { ApprovalPresenter } from "./preview/presenter.js";
import { createAuthorizationFingerprint, createPolicyIdentity, } from "./scope.js";
import { ADAPTIVE_STATE_VERSION, AdaptiveLeaseStore, normalizeAdaptiveState, } from "./adaptive/state.js";
import { evaluateAdaptiveEligibility } from "./adaptive/eligibility.js";
const PLUGIN_ID = "human-gate";
const ASK_TOOL_NAME = "human_gate_ask";
const ALLOW_ALWAYS_NAMESPACE = "allow-always-v2";
const WINDOW_NAMESPACE = "approval-window-v2";
const ADAPTIVE_NAMESPACE = "adaptive-auto-pass-v1";
const DENY_COOLDOWN_NAMESPACE = "deny-cooldown-v1";
const HOOK_PRIORITY = 60;
// OpenClaw runs typed hooks in descending numeric priority. There is no public
// finalizer hook, so this ordinary-hook compatibility seal deliberately sorts
// after every finite-priority handler. Installed plugins remain trusted code;
// the SDK cannot reserve an absolute final slot against another -Infinity hook.
const PARAM_SEAL_PRIORITY = Number.NEGATIVE_INFINITY;
/** Bump whenever semantic effects/categories/target derivation changes. */
const SEMANTIC_RULESET_VERSION = "2026-08-14.3";
function logPayload(message, details) {
    return `${message} ${JSON.stringify(details)}`;
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
function appendDescriptionHint(description, hint, max) {
    const combined = `${description}\n${hint}`;
    return combined.length <= max ? combined : description;
}
function adaptiveLeaseLabel(ttlMs, maxUses) {
    const minutes = Math.max(1, Math.round(ttlMs / 60_000));
    return `${maxUses}-use/${minutes}-minute`;
}
function cloneJsonLike(value, seen, budget, depth) {
    budget.nodes += 1;
    if (budget.nodes > 100_000 || depth > 64)
        return { ok: false };
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
    if (typeof value !== "object" || seen.has(value))
        return { ok: false };
    let prototype;
    let keys;
    try {
        prototype = Object.getPrototypeOf(value);
        keys = Reflect.ownKeys(value);
    }
    catch {
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
            const output = [];
            for (let index = 0; index < value.length; index += 1) {
                const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
                if (!descriptor || !("value" in descriptor) || !descriptor.enumerable)
                    return { ok: false };
                const cloned = cloneJsonLike(descriptor.value, seen, budget, depth + 1);
                if (!cloned.ok)
                    return cloned;
                output.push(cloned.value);
            }
            return { ok: true, value: output };
        }
        const output = {};
        for (const key of keys) {
            if (typeof key !== "string")
                return { ok: false };
            const descriptor = Object.getOwnPropertyDescriptor(value, key);
            if (!descriptor || !("value" in descriptor) || !descriptor.enumerable)
                return { ok: false };
            const cloned = cloneJsonLike(descriptor.value, seen, budget, depth + 1);
            if (!cloned.ok)
                return cloned;
            Object.defineProperty(output, key, {
                value: cloned.value,
                enumerable: true,
                configurable: true,
                writable: true,
            });
        }
        return { ok: true, value: output };
    }
    finally {
        seen.delete(value);
    }
}
function snapshotParams(params) {
    try {
        const cloned = cloneJsonLike(params, new Set(), { nodes: 0, stringChars: 0 }, 0);
        return cloned.ok && cloned.value && typeof cloned.value === "object" && !Array.isArray(cloned.value)
            ? cloned.value
            : undefined;
    }
    catch {
        return undefined;
    }
}
function policyIdentityFor(decision, config) {
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
function fingerprintFor(config, event, ctx, decision, isParamScopedRule) {
    if (!decision.windowEligible || isParamScopedRule || !decision.rule)
        return undefined;
    const policyIdentity = policyIdentityFor(decision, config);
    if (!policyIdentity)
        return undefined;
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
const pluginEntry = definePluginEntry({
    id: PLUGIN_ID,
    name: "Human Gate",
    description: "Human-in-the-loop approval middleware. Routes selected tool calls through OpenClaw's built-in approval flow before execution. Also adds Claude Code-style interactive ask prompts when the AI needs clarification.",
    register(api) {
        const log = api.logger;
        const config = resolveConfig(api.pluginConfig);
        const analyzerRegistry = new AnalyzerRegistry([
            new CodeModeAnalyzer(config.semanticAnalysis),
            new FileMutationAnalyzer(config.semanticAnalysis),
            new CommandAnalyzer(config.semanticAnalysis),
        ], config.semanticAnalysis.maxFindings);
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
        api.session.state.registerSessionExtension({
            namespace: DENY_COOLDOWN_NAMESPACE,
            description: "Per-session deny cooldowns for Human Gate",
        });
        const allowAlways = new AllowAlwaysStore((sessionKey) => normalizeAllowAlwaysState(extensionValue(api, sessionKey, ALLOW_ALWAYS_NAMESPACE)), (sessionKey, update) => patchExtension(api, sessionKey, ALLOW_ALWAYS_NAMESPACE, { version: ALLOW_ALWAYS_STATE_VERSION, grants: {} }, normalizeAllowAlwaysState, update), config.allowAlwaysTtlMs);
        const approvalWindow = new ApprovalWindowStore((sessionKey) => normalizeWindowState(extensionValue(api, sessionKey, WINDOW_NAMESPACE)), (sessionKey, update) => patchExtension(api, sessionKey, WINDOW_NAMESPACE, { version: WINDOW_STATE_VERSION, windows: {} }, normalizeWindowState, update));
        const adaptiveLease = new AdaptiveLeaseStore((sessionKey) => normalizeAdaptiveState(extensionValue(api, sessionKey, ADAPTIVE_NAMESPACE)), (sessionKey, update) => patchExtension(api, sessionKey, ADAPTIVE_NAMESPACE, { version: ADAPTIVE_STATE_VERSION, observations: {}, receipts: {}, leases: {} }, normalizeAdaptiveState, update), config.adaptiveAutoPass);
        const denyCooldown = new DenyCooldownStore((sessionKey) => normalizeDenyCooldownState(extensionValue(api, sessionKey, DENY_COOLDOWN_NAMESPACE)), (sessionKey, update) => patchExtension(api, sessionKey, DENY_COOLDOWN_NAMESPACE, { version: DENY_COOLDOWN_STATE_VERSION, denials: {} }, normalizeDenyCooldownState, update), config.denyCooldownMs);
        const decisionLog = new DecisionLog(config.decisionLog);
        // The same event object is passed to every ordinary hook. Capture the
        // gate-time snapshot by object identity so an intervening handler cannot
        // defeat the final seal by mutating event.params in place.
        const parameterSeals = new WeakMap();
        // ── Primary approval gate (priority 60) ──
        api.on("before_tool_call", async (event, ctx) => {
            // Skip the ask tool — it has its own dedicated hook below
            if (event.toolName === ASK_TOOL_NAME)
                return undefined;
            const sessionKey = ctx.sessionKey ?? "";
            const baseDecision = evaluatePolicy(event.toolName, event.toolKind, config, event.params);
            // An explicit base block is terminal and needs neither parameter
            // inspection nor preview generation.
            if (baseDecision.mode === "block") {
                const blockReason = baseDecision.reason;
                log.warn(logPayload("human-gate: blocking tool call", {
                    tool: event.toolName,
                    rule: baseDecision.rule?.id,
                    blockReason,
                }));
                decisionLog.record({
                    ts: Date.now(),
                    sessionDigest: digestSessionKey(sessionKey),
                    sessionId: ctx.sessionId,
                    toolName: event.toolName,
                    ruleId: baseDecision.rule?.id,
                    decision: "block",
                    severity: baseDecision.severity,
                    reason: blockReason,
                });
                return { block: true, blockReason };
            }
            const paramsSnapshot = snapshotParams(event.params);
            if (!paramsSnapshot) {
                const blockReason = "Human Gate could not safely snapshot tool parameters";
                log.warn(logPayload("human-gate: blocking unsnapshotable tool params", {
                    tool: event.toolName,
                    sessionId: ctx.sessionId,
                }));
                decisionLog.record({
                    ts: Date.now(),
                    sessionDigest: digestSessionKey(sessionKey),
                    sessionId: ctx.sessionId,
                    toolName: event.toolName,
                    decision: "block",
                    severity: "critical",
                    reason: blockReason,
                });
                return { block: true, blockReason };
            }
            parameterSeals.set(event, paramsSnapshot);
            // Structural self-protection: file-write / shell-command calls that
            // reference the authority surface (openclaw.json, paths under a
            // .openclaw directory) are blocked before any analyzer, grant, or
            // window runs. Escalation-only — pure reads pass through untouched.
            if (config.selfProtection.enabled) {
                const sensitive = classifySensitiveEscalation(event.toolName, event.toolKind, paramsSnapshot);
                if (sensitive.escalate) {
                    const blockReason = `Human Gate self-protection: call touches the authority surface (${sensitive.hits.map((hit) => hit.marker).join(", ")})`;
                    log.warn(logPayload("human-gate: self-protection block", {
                        tool: event.toolName,
                        markers: sensitive.hits.map((hit) => hit.marker),
                        sessionId: ctx.sessionId,
                    }));
                    decisionLog.record({
                        ts: Date.now(),
                        sessionDigest: digestSessionKey(sessionKey),
                        sessionId: ctx.sessionId,
                        toolName: event.toolName,
                        ruleId: "builtin:self-protection",
                        decision: "block",
                        severity: "critical",
                        reason: blockReason,
                    });
                    return { block: true, blockReason };
                }
            }
            const analysisContext = {
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
            const fingerprint = fingerprintFor(config, event, ctx, decision, isParamScopedRule);
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
                decisionLog.record({
                    ts: Date.now(),
                    sessionDigest: digestSessionKey(sessionKey),
                    sessionId: ctx.sessionId,
                    toolName: event.toolName,
                    ruleId: decision.rule?.id,
                    decision: "auto",
                    severity: decision.severity,
                    scopeDigest: fingerprint?.windowKey?.slice(0, 19),
                });
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
                decisionLog.record({
                    ts: Date.now(),
                    sessionDigest: digestSessionKey(sessionKey),
                    sessionId: ctx.sessionId,
                    toolName: event.toolName,
                    ruleId: decision.rule?.id,
                    decision: "block",
                    severity: decision.severity,
                    scopeDigest: fingerprint?.windowKey?.slice(0, 19),
                    reason: blockReason,
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
                if (decision.severity === "critical" &&
                    config.unattendedPolicy.critical === "block") {
                    const blockReason = `Critical unattended tool call blocked: ${decision.reason}`;
                    log.warn(logPayload("human-gate: blocking critical unattended call", {
                        tool: event.toolName,
                        findings: decision.semanticReport.findings.map((finding) => finding.id),
                        sessionKey,
                    }));
                    decisionLog.record({
                        ts: Date.now(),
                        sessionDigest: digestSessionKey(sessionKey),
                        sessionId: ctx.sessionId,
                        toolName: event.toolName,
                        ruleId: decision.rule?.id,
                        decision: "block",
                        severity: decision.severity,
                        scopeDigest: fingerprint?.windowKey?.slice(0, 19),
                        reason: blockReason,
                    });
                    return { block: true, blockReason };
                }
                log.debug?.(logPayload("human-gate: auto-pass system context", {
                    tool: event.toolName,
                    sessionKey,
                }));
                decisionLog.record({
                    ts: Date.now(),
                    sessionDigest: digestSessionKey(sessionKey),
                    sessionId: ctx.sessionId,
                    toolName: event.toolName,
                    ruleId: decision.rule?.id,
                    decision: "auto",
                    severity: decision.severity,
                    scopeDigest: fingerprint?.windowKey?.slice(0, 19),
                    reason: "unattended auto-pass",
                });
                return { params: paramsSnapshot };
            }
            const win = config.approvalWindow;
            const now = Date.now();
            // Deny cooldown: after an explicit deny, matching calls auto-block for
            // denyCooldownMs instead of asking the same question again. Keyed by
            // the semantic scope when available, else ruleId::toolName. This runs
            // before grants/windows so a recent explicit deny wins over an older
            // standing authorization; it only ever turns ask into block.
            const cooldownKey = fingerprint?.windowKey ??
                (decision.rule ? allowAlwaysKey(decision.rule.id, event.toolName) : event.toolName);
            if (sessionKey && denyCooldown.isCoolingDown(sessionKey, cooldownKey, now)) {
                const blockReason = `Human Gate deny cooldown: this call was recently denied and repeats are blocked for ${Math.max(1, Math.round(config.denyCooldownMs / 1000))}s`;
                log.info(logPayload("human-gate: deny cooldown block", {
                    tool: event.toolName,
                    sessionId: ctx.sessionId,
                }));
                decisionLog.record({
                    ts: now,
                    sessionDigest: digestSessionKey(sessionKey),
                    sessionId: ctx.sessionId,
                    toolName: event.toolName,
                    ruleId: decision.rule?.id,
                    decision: "block",
                    severity: decision.severity,
                    scopeDigest: fingerprint?.windowKey?.slice(0, 19),
                    reason: blockReason,
                });
                return { block: true, blockReason };
            }
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
                        if (consumed.outcome === "consumed") {
                            decisionLog.record({
                                ts: now,
                                sessionDigest: digestSessionKey(sessionKey),
                                sessionId: ctx.sessionId,
                                toolName: event.toolName,
                                ruleId: decision.rule?.id,
                                decision: "auto",
                                severity: decision.severity,
                                scopeDigest: fingerprint?.grantKey?.slice(0, 19),
                                reason: "adaptive lease",
                            });
                            return { params: paramsSnapshot };
                        }
                    }
                    catch {
                        // Store failure is an authorization miss. Do not expose exception
                        // text (which may contain host paths/state); continue to approval.
                        log.error(logPayload("human-gate: adaptive lease consume failed", {
                            tool: event.toolName,
                            outcome: "store-error",
                            legacySuppressed: true,
                        }));
                    }
                }
            }
            else {
                // Legacy remembered grants/windows remain unchanged for
                // off/shadow/suggest and calls outside the safe-file MVP.
                if (sessionKey &&
                    config.rememberAllowAlways &&
                    fingerprint?.grantKey &&
                    allowAlways.isGranted(sessionKey, fingerprint, now)) {
                    log.debug?.(logPayload("human-gate: allow-always grant hit", {
                        rule: decision.rule?.id,
                        tool: event.toolName,
                        scope: fingerprint.resolvedScope,
                    }));
                    decisionLog.record({
                        ts: now,
                        sessionDigest: digestSessionKey(sessionKey),
                        sessionId: ctx.sessionId,
                        toolName: event.toolName,
                        ruleId: decision.rule?.id,
                        decision: "auto",
                        severity: decision.severity,
                        scopeDigest: fingerprint.grantKey.slice(0, 19),
                        reason: "allow-always grant",
                    });
                    return { params: paramsSnapshot };
                }
                if (sessionKey &&
                    fingerprint &&
                    !approvalWindow.bypasses(win, decision) &&
                    approvalWindow.isOpen(win, sessionKey, fingerprint, ctx.runId, now)) {
                    log.debug?.(logPayload("human-gate: approval-window auto-pass", {
                        tool: event.toolName,
                        mode: win.mode,
                        requestedScope: fingerprint.requestedScope,
                        resolvedScope: fingerprint.resolvedScope,
                        runId: ctx.runId,
                    }));
                    decisionLog.record({
                        ts: now,
                        sessionDigest: digestSessionKey(sessionKey),
                        sessionId: ctx.sessionId,
                        toolName: event.toolName,
                        ruleId: decision.rule?.id,
                        decision: "auto",
                        severity: decision.severity,
                        scopeDigest: fingerprint.windowKey.slice(0, 19),
                        reason: "approval window",
                    });
                    return { params: paramsSnapshot };
                }
            }
            const title = truncate(`Approve ${event.toolName}`, 80);
            let description = presenter.describe(analysisContext, decision);
            const canRemember = Boolean(sessionKey && config.rememberAllowAlways && fingerprint?.grantKey);
            const allowedDecisions = canRemember
                ? [...decision.allowedDecisions]
                : decision.allowedDecisions.filter((item) => item !== "allow-always");
            let approvalCount = 0;
            if (adaptiveMode === "suggest" &&
                adaptiveEligibility?.eligible && sessionKey && fingerprint) {
                try {
                    approvalCount = adaptiveLease.approvalCount(sessionKey, fingerprint);
                }
                catch {
                    // Suggestions are non-authorizing UX only. State-read failure must
                    // neither fail the gate nor suppress the ordinary approval.
                    log.warn(logPayload("human-gate: adaptive evidence read failed", {
                        tool: event.toolName,
                        outcome: "store-error",
                    }));
                }
            }
            if (adaptiveEligibility?.eligible && allowedDecisions.includes("allow-always")) {
                const leaseLabel = adaptiveLeaseLabel(config.adaptiveAutoPass.ttlMs, config.adaptiveAutoPass.maxUses);
                if (adaptiveMode === "enforce") {
                    description = appendDescriptionHint(description, `Adaptive: allow-always creates a bounded ${leaseLabel} path lease.`, config.previews.maxDescriptionChars);
                }
                else if (adaptiveMode === "suggest" &&
                    approvalCount >= config.adaptiveAutoPass.suggestAfterApprovals) {
                    description = appendDescriptionHint(description, `Adaptive preview: eligible for a ${leaseLabel} lease in enforce mode.`, config.previews.maxDescriptionChars);
                }
            }
            // Approval-flood detector: non-authorizing UX only. When asks are
            // arriving at a high rate (the rubber-stamping failure mode), surface
            // a hint to open a grant or narrow rules — never auto-pass anything.
            if (config.floodDetector.enabled) {
                const askRate = decisionLog.askRate(config.floodDetector.windowMs);
                if (askRate >= config.floodDetector.threshold) {
                    description = appendDescriptionHint(description, `High approval rate detected (${askRate} prompts in the last ${Math.round(config.floodDetector.windowMs / 1000)}s) — consider allow-always on this rule or narrowing your rules to reduce repeated prompts.`, config.previews.maxDescriptionChars);
                }
            }
            const askedAt = Date.now();
            decisionLog.record({
                ts: askedAt,
                sessionDigest: digestSessionKey(sessionKey),
                sessionId: ctx.sessionId,
                toolName: event.toolName,
                ruleId: decision.rule?.id,
                decision: "ask",
                severity: decision.severity,
                scopeDigest: fingerprint?.windowKey?.slice(0, 19),
                reason: decision.reason,
            });
            return {
                // Bind the approval to the exact params that were analyzed and shown.
                params: paramsSnapshot,
                requireApproval: {
                    title,
                    description,
                    severity: decision.severity,
                    timeoutMs: decision.timeoutMs,
                    timeoutBehavior: "deny",
                    timeoutReason: "Human Gate approval timed out",
                    allowedDecisions,
                    pluginId: PLUGIN_ID,
                    onResolution: async (res) => {
                        try {
                            decisionLog.record({
                                ts: Date.now(),
                                sessionDigest: digestSessionKey(sessionKey),
                                sessionId: ctx.sessionId,
                                toolName: event.toolName,
                                ruleId: decision.rule?.id,
                                decision: res,
                                severity: decision.severity,
                                scopeDigest: fingerprint?.windowKey?.slice(0, 19),
                                latencyMs: Date.now() - askedAt,
                            });
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
                            if (!adaptiveOwns &&
                                (res === "allow-once" || res === "allow-always") &&
                                fingerprint &&
                                !approvalWindow.bypasses(win, decision)) {
                                const opened = await approvalWindow.open(win, sessionKey, fingerprint, ctx.runId, Date.now());
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
                            if (adaptiveOwns &&
                                res === "allow-always" &&
                                fingerprint) {
                                const granted = await adaptiveLease.grant(sessionKey, fingerprint, Date.now(), event.toolCallId);
                                log.info(logPayload("human-gate: adaptive lease resolution", {
                                    decision: res,
                                    granted,
                                    tool: event.toolName,
                                    scopeDigest: fingerprint.grantKey?.slice(0, 19),
                                    maxUses: config.adaptiveAutoPass.maxUses,
                                    ttlMs: config.adaptiveAutoPass.ttlMs,
                                }));
                            }
                            else if (adaptiveOwns &&
                                res === "deny" &&
                                fingerprint) {
                                await adaptiveLease.deny(sessionKey, fingerprint);
                                log.info(logPayload("human-gate: adaptive lease revoked", {
                                    decision: res,
                                    tool: event.toolName,
                                    scopeDigest: fingerprint.grantKey?.slice(0, 19),
                                }));
                            }
                            else if (!adaptiveOwns &&
                                res === "allow-always" &&
                                canRemember &&
                                fingerprint?.grantKey) {
                                await allowAlways.grant(sessionKey, fingerprint, Date.now());
                                log.info(logPayload("human-gate: allow-always granted", {
                                    rule: decision.rule?.id,
                                    scopeDigest: fingerprint.grantKey.slice(0, 19),
                                    sessionId: ctx.sessionId,
                                }));
                            }
                            else {
                                log.info(logPayload("human-gate: approval resolved", {
                                    decision: res,
                                    tool: event.toolName,
                                    rule: decision.rule?.id,
                                }));
                            }
                            if (adaptiveMode === "suggest" &&
                                adaptiveEligibility?.eligible &&
                                fingerprint &&
                                res === "allow-once") {
                                await adaptiveLease.observeApproval(sessionKey, fingerprint, res, Date.now());
                            }
                            else if (adaptiveMode === "suggest" &&
                                adaptiveEligibility?.eligible &&
                                fingerprint &&
                                res === "deny") {
                                await adaptiveLease.deny(sessionKey, fingerprint);
                            }
                            // Best-effort deny cooldown, deliberately LAST and isolated:
                            // lease/grant revocation above is the authorization teardown
                            // and must never be interrupted by a cooldown persistence
                            // failure. On failure the next matching call simply asks
                            // again (fail toward asking).
                            if (res === "deny" && sessionKey) {
                                try {
                                    await denyCooldown.recordDeny(sessionKey, cooldownKey, Date.now());
                                }
                                catch (err) {
                                    log.warn(logPayload("human-gate: deny cooldown record failed; next call will ask again", {
                                        error: String(err),
                                        tool: event.toolName,
                                        sessionId: ctx.sessionId,
                                    }));
                                }
                            }
                        }
                        catch (err) {
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
        }, { priority: HOOK_PRIORITY, timeoutMs: 60_000 });
        // OpenClaw currently has no public final-params/finalizer hook. Ordinary
        // before_tool_call handlers all receive the same host-adjusted event, and
        // later handler results can otherwise replace params after a window/grant
        // hit. Re-snapshotting the original event at the final numeric priority
        // makes the analyzed payload the last ordinary params decision. A prior
        // requireApproval from another plugin remains authoritative by host design.
        api.on("before_tool_call", (event) => {
            if (event.toolName === ASK_TOOL_NAME)
                return undefined;
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
        }, { priority: PARAM_SEAL_PRIORITY, timeoutMs: 10_000 });
        // ── Observation hook ──
        api.on("after_tool_call", (event) => {
            if (event.error) {
                log.warn(logPayload("human-gate: tool errored after gate", {
                    tool: event.toolName,
                    toolCallId: event.toolCallId,
                    error: String(event.error),
                }));
            }
        }, { priority: 40, timeoutMs: 10_000 });
        // ── Ask tool (chat-based; no TUI popup) ──
        // OpenClaw's requireApproval is allow/deny only and cannot capture a
        // choice or free-text answer, so the ask tool returns a standard tool
        // result whose text the agent presents in chat, then waits for the human's
        // reply in the next turn. This is the Claude Code ask pattern.
        const askTool = {
            name: ASK_TOOL_NAME,
            label: "Ask Human",
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
            async execute(_callId, params) {
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
//# sourceMappingURL=index.js.map