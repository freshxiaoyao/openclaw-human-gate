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
import { type HumanGateConfig, type PolicyDecision } from "./types.js";
export declare function evaluatePolicy(toolName: string, toolKind: string | undefined, config: HumanGateConfig): PolicyDecision;
//# sourceMappingURL=policy.d.ts.map