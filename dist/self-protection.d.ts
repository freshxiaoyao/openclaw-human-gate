/**
 * Structural self-protection (remit-style sensitive-target classification).
 *
 * Any file-write or shell-command call whose parameters reference the
 * authority surface — `openclaw.json` (the config that carries this plugin's
 * rules) or any path under a `.openclaw` directory (config, keys, plugin
 * state) — escalates to a block. Escalation-only: it can only tighten a
 * decision, never loosen one, and it runs before grants/windows are
 * consulted, so no lease can reach it.
 *
 * Pure reads are deliberately NOT escalated: inspecting the config
 * (`read`, `openclaw doctor`, `status`) stays usable. Only carriers that
 * can mutate are escalated — destructive toolKinds, file tools, and
 * unknown tools (fail-closed).
 *
 * Tool-name and parameter shapes are aligned with the semantic analyzer's
 * canonical vocabulary (see `analysis/file-mutation.ts`), so the scan
 * covers the same envelopes the analyzer trusts: write/write_file/writefile,
 * edit/edit_file/editfile, apply_patch (canonical `input`), and exec-like
 * command parameters.
 */
export declare const SELF_PROTECTION_VERSION: 1;
export interface SelfProtectionHit {
    marker: ".openclaw" | "openclaw.json";
    param: string;
}
export interface SelfProtectionResult {
    hits: SelfProtectionHit[];
    escalate: boolean;
}
/** Escalation classifier. `escalate` is true only for mutating carriers that
 *  reference the authority surface. Pure reads pass through untouched. */
export declare function classifySensitiveEscalation(toolName: string, toolKind: string | undefined, params: Record<string, unknown> | undefined): SelfProtectionResult;
/** True when the tool is a known pure observation carrier (reads of the
 *  authority surface are allowed). Exported for tests. */
export declare function isReadOnlyCarrier(toolName: string, toolKind: string | undefined): boolean;
//# sourceMappingURL=self-protection.d.ts.map