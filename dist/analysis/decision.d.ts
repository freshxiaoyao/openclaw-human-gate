import type { PolicyDecision } from "../types.js";
import type { SemanticReport } from "./types.js";
export interface EffectiveDecision extends PolicyDecision {
    semanticReport: SemanticReport;
    windowEligible: boolean;
}
/** Semantic analysis is upgrade-only across every policy source, including an
 * explicit broad auto rule. Operators can disable semantic analysis globally,
 * but an `auto` rule cannot accidentally whitelist dangerous parameters. */
export declare function reduceDecision(base: PolicyDecision, report: SemanticReport): EffectiveDecision;
//# sourceMappingURL=decision.d.ts.map