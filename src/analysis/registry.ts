import type {
  AnalysisResult,
  RiskCategory,
  RiskFinding,
  SemanticReport,
  ToolCallAnalyzer,
  ToolCallContext,
  ToolEffect,
  VerifiedTarget,
} from "./types.js";
import type { GateMode, GateSeverity } from "../types.js";

const MODE_RANK: Record<GateMode, number> = {
  auto: 0,
  "require-approval": 1,
  block: 2,
};

const SEVERITY_RANK: Record<GateSeverity, number> = {
  info: 0,
  warning: 1,
  critical: 2,
};

function higherMode(a: GateMode | undefined, b: GateMode | undefined): GateMode | undefined {
  if (!a) return b;
  if (!b) return a;
  return MODE_RANK[a] >= MODE_RANK[b] ? a : b;
}

function higherSeverity(
  a: GateSeverity | undefined,
  b: GateSeverity | undefined,
): GateSeverity | undefined {
  if (!a) return b;
  if (!b) return a;
  return SEVERITY_RANK[a] >= SEVERITY_RANK[b] ? a : b;
}

function analyzerFailure(analyzerId: string): AnalysisResult {
  const finding: RiskFinding = {
    id: "analysis.failed",
    category: "unknown",
    severity: "warning",
    confidence: "low",
    title: "Semantic analysis failed",
    explanation: `Analyzer ${analyzerId} could not classify this call; approval is required.`,
  };
  return {
    analyzerId,
    findings: [finding],
    effects: ["unknown"],
    categories: ["unknown"],
    verifiedTargets: [],
    complete: false,
    minimumMode: "require-approval",
    minimumSeverity: "warning",
    windowEligible: false,
  };
}

/** Runs matching analyzers and monotonically combines their safety constraints. */
export class AnalyzerRegistry {
  private readonly analyzers: ToolCallAnalyzer[];

  constructor(
    analyzers: readonly ToolCallAnalyzer[],
    private readonly maxFindings: number,
  ) {
    this.analyzers = [...analyzers].sort((a, b) => b.priority - a.priority);
  }

  analyze(context: ToolCallContext): SemanticReport {
    const findings: RiskFinding[] = [];
    const effects = new Set<ToolEffect>();
    const categories = new Set<RiskCategory>();
    const targets = new Map<string, VerifiedTarget>();
    const analyzerIds: string[] = [];
    let minimumMode: GateMode | undefined;
    let minimumSeverity: GateSeverity | undefined;
    let windowEligible = true;
    let complete = true;

    for (const analyzer of this.analyzers) {
      let result: AnalysisResult;
      try {
        if (!analyzer.supports(context)) continue;
        result = analyzer.analyze(context);
      } catch {
        result = analyzerFailure(analyzer.id);
      }

      analyzerIds.push(analyzer.id);
      findings.push(...result.findings);
      for (const effect of result.effects) effects.add(effect);
      for (const category of result.categories ?? []) categories.add(category);
      for (const target of result.verifiedTargets ?? []) {
        const key = `${target.source}\u0000${target.parameter ?? ""}\u0000${target.path}`;
        targets.set(key, target);
      }
      minimumMode = higherMode(minimumMode, result.minimumMode);
      minimumSeverity = higherSeverity(minimumSeverity, result.minimumSeverity);
      windowEligible = windowEligible && result.windowEligible;
      // Older/custom analyzers that omit completeness cannot authorize reuse.
      complete = complete && result.complete === true;
    }

    const uniqueFindings = [...new Map(
      findings.map((finding) => [finding.id, finding] as const),
    ).values()].sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]);

    return {
      findings: uniqueFindings.slice(0, Math.max(1, this.maxFindings)),
      effects: [...effects],
      categories: [...categories],
      verifiedTargets: [...targets.values()],
      complete: analyzerIds.length > 0 && complete,
      minimumMode,
      minimumSeverity,
      windowEligible: analyzerIds.length > 0 && complete && windowEligible,
      analyzerIds,
    };
  }
}
