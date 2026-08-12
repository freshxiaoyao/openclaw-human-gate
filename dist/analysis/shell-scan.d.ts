/**
 * A small, deterministic shell scanner for approval-time inspection.
 *
 * This is deliberately a scanner rather than a shell parser. It never
 * expands variables, resolves aliases, reads files, or executes input. Its
 * only job is to expose quote-aware words, command boundaries, and output
 * redirections so semantic rules do not mistake text inside a string literal
 * for another command.
 */
export type ShellDialect = "posix" | "powershell" | "cmd";
export type ShellControlOperator = "|" | "&&" | "||" | ";" | "&" | "\n";
export type ShellRedirectionOperator = ">" | ">>";
export type ShellQuoteKind = "none" | "single" | "double" | "mixed";
export type ShellTokenRole = "command" | "argument" | "redirection-target";
export interface ShellToken {
    /** Value with quote delimiters and escaping syntax removed. */
    value: string;
    /** Exact source slice for display and evidence. */
    raw: string;
    start: number;
    end: number;
    quote: ShellQuoteKind;
    /** True when the token contains shell expansion syntax outside a literal. */
    dynamic: boolean;
    role: ShellTokenRole;
    invocationIndex: number;
}
export interface ShellRedirection {
    operator: ShellRedirectionOperator;
    start: number;
    end: number;
    /** Explicit descriptor in forms such as `2>errors.log`. */
    fd?: number;
    target?: ShellToken;
    invocationIndex: number;
}
export interface ShellInvocation {
    index: number;
    start: number;
    end: number;
    /** Command and argument words. Redirection targets are kept separately. */
    tokens: readonly ShellToken[];
    redirections: readonly ShellRedirection[];
}
export interface ShellOperator {
    operator: ShellControlOperator;
    start: number;
    end: number;
    leftInvocationIndex?: number;
    rightInvocationIndex?: number;
}
export type ShellScanIssueCode = "unterminated-single-quote" | "unterminated-double-quote" | "trailing-escape" | "missing-redirection-target" | "missing-command-before-operator" | "missing-command-after-operator";
export interface ShellScanIssue {
    code: ShellScanIssueCode;
    offset: number;
}
export interface ShellScanResult {
    dialect: ShellDialect;
    source: string;
    invocations: readonly ShellInvocation[];
    /** All words, including redirection targets, in source order. */
    tokens: readonly ShellToken[];
    operators: readonly ShellOperator[];
    redirections: readonly ShellRedirection[];
    complete: boolean;
    issues: readonly ShellScanIssue[];
}
/**
 * Scan one shell command without performing expansion or execution.
 *
 * The result is conservative metadata only. It must not be used by itself to
 * auto-authorize a command: aliases, functions, variables, and nested shell
 * wrappers can change runtime meaning after this scan.
 */
export declare function scanShell(source: string, dialect: ShellDialect): ShellScanResult;
//# sourceMappingURL=shell-scan.d.ts.map