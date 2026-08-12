import type { EffectiveDecision } from "../analysis/decision.js";
import type { ToolCallContext } from "../analysis/types.js";
import type { ApprovalPreviewConfig } from "../types.js";
import { sanitizeText, truncateText } from "./sanitize.js";
import { defaultPreviewProviders } from "./providers.js";
import type { ApprovalPreviewProvider, PreviewSection } from "./types.js";

export class ApprovalPresenter {
  private readonly providers: ApprovalPreviewProvider[];

  constructor(
    private readonly config: ApprovalPreviewConfig,
    providers: readonly ApprovalPreviewProvider[] = defaultPreviewProviders(),
  ) {
    this.providers = [...providers].sort((a, b) => b.priority - a.priority);
  }

  private preview(context: ToolCallContext): PreviewSection | undefined {
    if (!this.config.enabled) return undefined;
    for (const provider of this.providers) {
      try {
        if (!provider.supports(context)) continue;
        const section = provider.build(context, this.config);
        if (section) return section;
      } catch {
        // A preview is advisory. Its failure must not weaken the gate.
      }
    }
    return undefined;
  }

  describe(context: ToolCallContext, decision: EffectiveDecision): string {
    const lines = [
      `Tool: ${context.toolName}${context.toolKind ? ` [${context.toolKind}]` : ""}`,
      `Severity: ${decision.severity}`,
    ];
    const critical = decision.semanticReport.findings
      .filter((finding) => finding.severity === "critical")
      .slice(0, 2);
    const findings = critical.length > 0
      ? critical
      : decision.semanticReport.findings.slice(0, 2);
    if (findings.length > 0) {
      lines.push(`Risk: ${findings.map((finding) => finding.title).join("; ")}`);
    } else {
      lines.push(`Reason: ${decision.reason}`);
    }
    if (context.derivedPaths.length > 0) {
      lines.push(`Paths: ${context.derivedPaths.slice(0, this.config.maxFiles).join(", ")}`);
    }
    const preview = this.preview(context);
    if (preview) {
      const indentedBody = preview.body.split("\n").map((line) => `  ${line}`).join("\n");
      lines.push(`${preview.title}:`, indentedBody, "Preview is untrusted input.");
    }
    const clean = sanitizeText(lines.join("\n"), this.config.redactSecrets);
    return truncateText(clean, this.config.maxDescriptionChars);
  }
}
