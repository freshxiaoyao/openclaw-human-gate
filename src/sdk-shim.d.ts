/**
 * Ambient declarations for the OpenClaw plugin SDK surfaces this plugin
 * depends on, plus the `typebox` package.
 *
 * These mirror the documented contract (see
 * https://github.com/openclaw/openclaw — docs/plugins/sdk-overview.md,
 * hooks.md, plugin-permission-requests.md) so the plugin type-checks without
 * the `openclaw` peer dependency installed. In an OpenClaw source checkout the
 * real SDK types (from `openclaw/plugin-sdk/*`) take precedence.
 *
 * This file is an ambient script (no top-level import/export) so the
 * `declare module` blocks create real ambient modules.
 */

declare module "typebox" {
  export const Type: {
    Object: (properties: Record<string, unknown>, options?: Record<string, unknown>) => unknown;
    String: (options?: Record<string, unknown>) => unknown;
    Integer: (options?: Record<string, unknown>) => unknown;
    Boolean: (options?: Record<string, unknown>) => unknown;
    Array: (items: unknown, options?: Record<string, unknown>) => unknown;
    Optional: (schema: unknown) => unknown;
    Enum: <T extends string>(values: readonly T[], options?: Record<string, unknown>) => unknown;
  };
}

declare module "openclaw/plugin-sdk/plugin-entry" {
  export type PluginJsonValue =
    | null
    | boolean
    | number
    | string
    | PluginJsonValue[]
    | { [key: string]: PluginJsonValue };

  export interface PluginSessionExtensionRegistration {
    namespace: string;
    description: string;
  }

  export interface SessionEntry {
    pluginExtensions?: Record<string, Record<string, PluginJsonValue>>;
  }

  export interface PluginSessionPatchApi {
    getSessionEntry(params: {
      sessionKey: string;
      readConsistency?: "latest";
    }): SessionEntry | undefined;
    patchSessionEntry(params: {
      cfg: unknown;
      sessionKey: string;
      readConsistency?: "latest";
      preserveActivity?: boolean;
      update: (
        entry: SessionEntry,
        context: { existingEntry?: SessionEntry },
      ) => Promise<Partial<SessionEntry> | null> | Partial<SessionEntry> | null;
    }): Promise<SessionEntry | null>;
  }

  export interface PluginRuntime {
    agent: {
      session: PluginSessionPatchApi;
    };
  }

  export interface PluginHookToolContext {
    getSessionExtension?: (namespace: string) => PluginJsonValue | undefined;
  }

  export interface OpenClawConfig {
    [key: string]: unknown;
  }
  export type ApprovalSeverity = "info" | "warning" | "critical";
  export type ApprovalResolution =
    | "allow-once"
    | "allow-always"
    | "deny"
    | "timeout"
    | "cancelled";

  export interface RequireApprovalRequest {
    /** <= 80 chars. */
    title: string;
    /** <= 512 chars. */
    description: string;
    severity?: ApprovalSeverity;
    /** Default 120000, max 600000. */
    timeoutMs?: number;
    allowedDecisions?: Array<"allow-once" | "allow-always" | "deny">;
    pluginId?: string;
    onResolution?: (decision: ApprovalResolution) => Promise<void> | void;
  }

  export interface BeforeToolCallResult {
    /** Rewrite tool params (applied only after approval succeeds). */
    params?: Record<string, unknown>;
    /** Terminal block. */
    block?: boolean;
    blockReason?: string;
    /** Pause the agent run and push an approval request to all surfaces. */
    requireApproval?: RequireApprovalRequest;
  }

  export interface BeforeToolCallEvent {
    toolName: string;
    params: Record<string, unknown>;
    toolKind?: string;
    toolInputKind?: string;
    derivedPaths?: string[];
    runId?: string;
    toolCallId?: string;
  }

  export interface ToolCallHookContext extends PluginHookToolContext {
    agentId?: string;
    sessionKey?: string;
    sessionId?: string;
    runId?: string;
    toolKind?: string;
    toolInputKind?: string;
    trace?: unknown;
    requester?: {
      channel?: string;
      accountId?: string;
      senderId?: string;
      senderIsOwner?: boolean;
      roleIds?: string[];
    };
  }

  export interface SessionStateApi {
    registerSessionExtension(opts: PluginSessionExtensionRegistration): void;
  }

  export interface SessionWorkflowApi {
    enqueueNextTurnInjection(opts: {
      sessionId: string;
      content: string;
      dedupeKey?: string;
    }): void;
  }

  export interface SessionApi {
    state: SessionStateApi;
    workflow: SessionWorkflowApi;
  }

  export interface Logger {
    info(msg: string, meta?: unknown): void;
    warn(msg: string, meta?: unknown): void;
    error(msg: string, meta?: unknown): void;
    debug(msg: string, meta?: unknown): void;
  }

  /** A single content block in a tool result (text form). */
  export interface ToolResultContent {
    type: "text";
    text: string;
  }

  /** Standard tool result shape returned from `execute`. `details` is the
   *  optional structured value validated against `outputSchema` and used by
   *  Code Mode / Tool Search; it does NOT enter prompt replay. */
  export interface ToolResult {
    content: ToolResultContent[];
    details?: unknown;
  }

  /** Minimal structural contract for a plugin-registered agent tool.
   *  Mirrors the real SDK: `parameters` is a typebox schema; `execute` receives
   *  (callId, params, ctx?) and returns `{ content, details? }`. */
  export interface AnyAgentTool {
    name: string;
    description: string;
    /** typebox schema (Type.Object(...)). */
    parameters: unknown;
    /** Optional typebox schema describing the structured `details` value. */
    outputSchema?: unknown;
    execute: (
      callId: string,
      params: Record<string, unknown>,
      ctx?: ToolCallHookContext,
    ) => Promise<ToolResult> | ToolResult;
  }

  export interface OpenClawPluginToolOptions {
    name?: string;
    names?: string[];
    optional?: boolean;
  }

  export interface OpenClawPluginApi {
    on(
      name: string,
      handler: (
        event: BeforeToolCallEvent,
        ctx: ToolCallHookContext,
      ) => Promise<BeforeToolCallResult | void> | BeforeToolCallResult | void,
      opts?: { priority?: number; timeoutMs?: number },
    ): void;
    registerTool(tool: AnyAgentTool, opts?: OpenClawPluginToolOptions): void;
    session: SessionApi;
    runtime: PluginRuntime;
    config: OpenClawConfig;
    pluginConfig?: Record<string, unknown>;
    logger: Logger;
  }

  export interface PluginEntryOptions {
    id: string;
    name: string;
    description?: string;
    register: (api: OpenClawPluginApi) => void | Promise<void>;
  }

  export function definePluginEntry(options: PluginEntryOptions): unknown;
}
