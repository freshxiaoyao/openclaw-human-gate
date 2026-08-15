/**
 * Optional Clawd on Desk desktop-pet notification.
 *
 * When an approval is raised, POST a `notification` state to the local Clawd
 * server so the desktop pet shows a visual reminder without the operator
 * watching the web/TUI. Local-only (127.0.0.1), fire-and-forget, best-effort:
 * a notification failure never affects the approval flow.
 *
 * Clawd's server validates only that the state is a known animation state and
 * that the agent is enabled — it does not gate on the agent's permission
 * capability — so human-gate can drive the `notification` animation directly,
 * exactly like Clawd's own OpenClaw plugin (hooks/openclaw-plugin/index.js).
 */
export interface ClawdNotifyPayload {
    state: string;
    event: string;
    sessionId?: string;
    toolName?: string;
}
/** Fire-and-forget POST to the first reachable local Clawd server. Never throws. */
export declare function notifyClawd(payload: ClawdNotifyPayload): void;
//# sourceMappingURL=clawd-notify.d.ts.map