/**
 * Policy engine: given a tool call and the resolved config, pick a decision.
 *
 * Evaluation order (first match wins):
 *  1. User rules           — explicit override (highest authority)
 *  2. Built-in destructive toolKind rules (exec / apply_patch / code_mode_exec)
 *  3. Read-only / destructive name-pattern classifier (when useClassifiers)
 *     - read-only name/kind  → auto (fail-open for reads)
 *     - destructive name     → require-approval (fail-closed for writes)
 *  4. config.defaultMode    — fallback for everything else
 *
 * Design intent: do NOT gate everything by default. Reads pass through; only
 * side-effecting operations prompt the human. Unknown tools fall to
 * `defaultMode` (which defaults to `auto` for low friction; set to
 * `require-approval` for a strict shop).
 */

import {
  type GateRule,
  type HumanGateConfig,
  type PolicyDecision,
  type GateSeverity,
} from "./types.js";
import {
  BUILTIN_DESTRUCTIVE_RULES,
  DESTRUCTIVE_NAME_PATTERN,
  DESTRUCTIVE_TOOL_KINDS,
  READONLY_NAME_PATTERN,
  READONLY_TOOL_KINDS,
} from "./types.js";

function compilePattern(source: string | undefined): RegExp | undefined {
  if (!source) return undefined;
  try {
    return new RegExp(source);
  } catch {
    return undefined;
  }
}

function ruleMatches(
  rule: GateRule,
  toolName: string,
  toolKind: string | undefined,
): boolean {
  if (rule.toolName && rule.toolName !== toolName) return false;
  if (rule.toolKind && rule.toolKind !== toolKind) return false;
  if (rule.toolNamePattern) {
    const re = compilePattern(rule.toolNamePattern);
    // Invalid configured regexes must never become match-all rules. Treat the
    // rule as non-matching; manifest JSON Schema cannot validate regex syntax.
    if (!re || !re.test(toolName)) return false;
  }
  return true;
}

function resolveDecision(
  rule: GateRule,
  config: HumanGateConfig,
): PolicyDecision {
  const severity: GateSeverity = rule.severity ?? config.defaultSeverity;
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

function clampTimeout(ms: number): number {
  return Math.min(Math.max(ms, 1000), 600_000);
}

/** Name-pattern classifier. Returns a synthesised decision, or undefined to
 *  defer to defaultMode. Conservative: unknown → undefined (not auto). */
function classifyByName(
  toolName: string,
  toolKind: string | undefined,
  config: HumanGateConfig,
): PolicyDecision | undefined {
  // host toolKind is authoritative when present.
  if (toolKind) {
    if (READONLY_TOOL_KINDS.has(toolKind)) {
      return autoDecision("builtin:readonly-kind", "Read-only tool kind");
    }
    if (DESTRUCTIVE_TOOL_KINDS.has(toolKind)) {
      // Already covered by BUILTIN_DESTRUCTIVE_RULES, but keep as safety net.
      return requireApprovalDecision(
        "builtin:destructive-kind",
        `Destructive tool kind "${toolKind}"`,
        config,
      );
    }
  }
  // Fall back to name pattern for tools without a recognised kind.
  if (READONLY_NAME_PATTERN.test(toolName)) {
    return autoDecision("builtin:readonly-name", "Read-only tool name");
  }
  if (DESTRUCTIVE_NAME_PATTERN.test(toolName)) {
    return requireApprovalDecision(
      "builtin:destructive-name",
      `Destructive tool name "${toolName}"`,
      config,
    );
  }
  return undefined;
}

function autoDecision(ruleId: string, reason: string): PolicyDecision {
  return {
    mode: "auto",
    severity: "info",
    timeoutMs: 0,
    allowedDecisions: [],
    reason,
    rule: { id: ruleId, mode: "auto", reason },
  };
}

function requireApprovalDecision(
  ruleId: string,
  reason: string,
  config: HumanGateConfig,
): PolicyDecision {
  return {
    mode: "require-approval",
    severity: config.defaultSeverity,
    timeoutMs: clampTimeout(config.defaultTimeoutMs),
    allowedDecisions: ["allow-once", "allow-always", "deny"],
    reason,
    rule: { id: ruleId, mode: "require-approval", reason },
  };
}

export function evaluatePolicy(
  toolName: string,
  toolKind: string | undefined,
  config: HumanGateConfig,
): PolicyDecision {
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

  // 3. Name-pattern classifier.
  if (config.useClassifiers) {
    const classified = classifyByName(toolName, toolKind, config);
    if (classified) return classified;
  }

  // 4. Fallback.
  return {
    mode: config.defaultMode,
    severity: config.defaultSeverity,
    timeoutMs: clampTimeout(config.defaultTimeoutMs),
    allowedDecisions: ["allow-once", "allow-always", "deny"],
    reason: `No rule or classifier matched; default mode "${config.defaultMode}"`,
  };
}
