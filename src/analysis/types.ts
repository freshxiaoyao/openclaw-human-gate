import type { GateMode, GateSeverity } from "../types.js";

/** Immutable, host-derived input shared by semantic analyzers and previews. */
export interface ToolCallContext {
  toolName: string;
  toolKind?: string;
  toolInputKind?: string;
  params: Readonly<Record<string, unknown>>;
  derivedPaths: readonly string[];
}

export type ToolEffect =
  | "read-only"
  | "local-write"
  | "network-write"
  | "code-execution"
  | "privilege-change"
  | "destructive"
  | "unknown";

export type RiskCategory =
  | "filesystem"
  | "network"
  | "execution"
  | "credentials"
  | "privilege"
  | "source-control"
  | "deployment"
  | "obfuscation"
  | "dev-build"
  | "dev-test"
  | "dev-format"
  | "read-only"
  | "unknown";

export interface RiskFinding {
  id: string;
  category: RiskCategory;
  severity: GateSeverity;
  confidence: "high" | "medium" | "low";
  title: string;
  explanation: string;
  evidence?: {
    source: "command" | "argument" | "operator" | "path" | "content";
    excerpt?: string;
  };
}

/** A target extracted from an authoritative tool parameter or the complete
 * patch payload. Host-derived paths are intentionally excluded: they are
 * useful hints, but are not an authorization boundary. */
export interface VerifiedTarget {
  path: string;
  targetKind: "file" | "directory";
  source: "params" | "patch";
  parameter?: string;
}

export interface AnalysisResult {
  analyzerId: string;
  findings: RiskFinding[];
  effects: ToolEffect[];
  /** Complete category set; unlike findings, this is never presentation-capped. */
  categories: RiskCategory[];
  /** Targets parsed from authoritative input, never inferred from derivedPaths. */
  verifiedTargets: VerifiedTarget[];
  /** True only when the analyzer consumed all input needed for its result. */
  complete: boolean;
  minimumMode?: GateMode;
  minimumSeverity?: GateSeverity;
  /** False means an earlier approval must never suppress this call. */
  windowEligible: boolean;
}

/** Small, pure extension point. An analyzer must never execute the input. */
export interface ToolCallAnalyzer {
  readonly id: string;
  readonly priority: number;
  supports(context: ToolCallContext): boolean;
  analyze(context: ToolCallContext): AnalysisResult;
}

export interface SemanticReport {
  findings: RiskFinding[];
  effects: ToolEffect[];
  categories: RiskCategory[];
  verifiedTargets: VerifiedTarget[];
  /** False for an empty report or if any matching analyzer is incomplete. */
  complete: boolean;
  minimumMode?: GateMode;
  minimumSeverity?: GateSeverity;
  windowEligible: boolean;
  analyzerIds: string[];
}

export const EMPTY_SEMANTIC_REPORT: SemanticReport = {
  findings: [],
  effects: [],
  categories: [],
  verifiedTargets: [],
  complete: false,
  windowEligible: false,
  analyzerIds: [],
};
