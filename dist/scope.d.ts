/** Semantic authorization fingerprints used by approval windows and grants. */
export declare const AUTHORIZATION_FINGERPRINT_VERSION: 2;
/** Bound path fingerprints so a single approval cannot create unbounded state. */
export declare const MAX_PATH_SCOPE_DIRECTORIES = 64;
export type ApprovalScope = "destructive" | "same-tool" | "effect" | "category" | "path";
export type SemanticApprovalScope = ApprovalScope;
export type PathScopeFallback = "none" | "effect" | "category";
export interface VerifiedScopeTarget {
    /** Analyzer-verified target; host-derived preview hints must not be used. */
    path: string;
    targetKind: "file" | "directory";
}
/** Complete, immutable facts about the call being authorized. */
export interface ScopeContext {
    toolName: string;
    toolKind: string;
    toolInputKind: string;
    ruleId: string;
    /** Canonical digest of the full matched policy rule, not merely its id. */
    policyIdentity: string;
    effects: readonly string[];
    categories: readonly string[];
    verifiedTargets: readonly VerifiedScopeTarget[];
    /** Host-authoritative tool execution cwd used to resolve relative targets. */
    executionCwd?: string;
    /** False when analysis failed, was disabled, or emitted a partial result. */
    analysisComplete: boolean;
}
export interface FingerprintOptions {
    scope: ApprovalScope;
    /** Explicit fail-closed behavior when a path scope cannot be constructed. */
    pathFallback?: PathScopeFallback;
    /** Bump whenever analyzer semantics change to invalidate earlier grants. */
    rulesetVersion: string;
}
export interface FingerprintIdentity {
    toolName: string;
    toolKind: string;
    toolInputKind: string;
    ruleId: string;
    policyIdentity: string;
}
export interface AuthorizationFingerprint {
    /** Key projected according to the configured temporary-window scope. */
    windowKey: string;
    /**
     * Permanent grants are always path-bound and include full policy identity.
     * Missing means allow-always must not be offered or persisted.
     */
    grantKey?: string;
    /** Compatibility name used by WindowEntry; always identical to windowKey. */
    scopeKey: string;
    requestedScope: ApprovalScope;
    resolvedScope: ApprovalScope;
    fingerprintVersion: typeof AUTHORIZATION_FINGERPRINT_VERSION;
    rulesetVersion: string;
    identity: FingerprintIdentity;
}
export interface NormalizedPathDirectory {
    kind: "posix" | "windows-drive" | "unc";
    /** Canonical filesystem volume. */
    volume: string;
    /** Exact canonical parent directory, never a filesystem root. */
    path: string;
}
export interface NormalizedPathScope {
    /** Sorted, de-duplicated exact directories; never a common ancestor. */
    directories: NormalizedPathDirectory[];
}
/** Return a bounded exact set of canonical parent directories. */
export declare function normalizePathScope(targets: readonly VerifiedScopeTarget[], executionCwd?: string): NormalizedPathScope | undefined;
/** Stable digest of every authorization-relevant policy field. */
export declare function createPolicyIdentity(policy: unknown): string | undefined;
/**
 * Build stable temporary-window and permanent-grant keys. Returning undefined
 * is the expected fail-closed result for missing/unknown/partial semantics.
 */
export declare function createAuthorizationFingerprint(context: ScopeContext, options: FingerprintOptions): AuthorizationFingerprint | undefined;
export declare function isAuthorizationFingerprint(value: unknown): value is AuthorizationFingerprint;
//# sourceMappingURL=scope.d.ts.map