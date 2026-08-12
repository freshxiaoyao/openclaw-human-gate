/**
 * openclaw-human-gate — Human-in-the-loop approval middleware.
 *
 * Strategy:
 *  - Register a `before_tool_call` hook (priority 60, after host-trusted
 *    policies but before most observation hooks).
 *  - Snapshot params, evaluate the base policy, then run upgrade-only semantic
 *    analyzers before any auto/grant/window decision.
 *  - auto -> pass through; block -> block with reason; require-approval
 *    -> return requireApproval, which pauses the agent run and pushes the
 *    request to every approval surface (TUI / Control UI / chat /approve).
 *  - On allow-always resolution, record a per-session grant so subsequent
 *    matching non-critical calls skip the prompt.
 *  - Build bounded, redacted previews through provider + presenter layers.
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
import { type OpenClawPluginDefinition } from "openclaw/plugin-sdk/plugin-entry";
declare const pluginEntry: OpenClawPluginDefinition;
export default pluginEntry;
//# sourceMappingURL=index.d.ts.map