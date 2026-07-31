/**
 * openclaw-human-gate — Human-in-the-loop approval middleware.
 *
 * Strategy:
 *  - Register a `before_tool_call` hook (priority 60, after host-trusted
 *    policies but before most observation hooks).
 *  - For each tool call, evaluate the policy (user rules → built-in destructive
 *    toolKinds → name-pattern classifier → defaultMode).
 *  - auto -> pass through; block -> block with reason; require-approval
 *    -> return requireApproval, which pauses the agent run and pushes the
 *    request to every approval surface (TUI / Control UI / chat /approve).
 *  - On allow-always resolution, record a per-session grant so subsequent
 *    matching calls skip the prompt.
 *
 * Ask User tool (Claude Code-style chat prompt):
 *  - Registers `human_gate_ask` so the model can ask a structured question when
 *    information is missing or the task is ambiguous.
 *  - `execute` returns a standard `{ content, details }` tool result whose text
 *    is the question + numbered choices; the agent presents it in chat and
 *    waits for the human's reply in the next turn.
 *  - No TUI popup: OpenClaw's plugin API has no generic selector-prompt surface
 *    (requireApproval is allow/deny only). Chat is the selector.
 *
 * The pause / TUI render / Web UI push / timeout for the *approval gate* are
 * handled by OpenClaw's Gateway plugin.approval.* flow. This plugin never
 * talks to the TUI directly.
 */
declare const _default: unknown;
export default _default;
//# sourceMappingURL=index.d.ts.map