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

import { request } from "node:http";

const CLAWD_PORTS = [23333, 23334, 23335, 23336, 23337];
const POST_TIMEOUT_MS = 1000;
const CLAWD_SERVER_HEADER = "x-clawd-server";

export interface ClawdNotifyPayload {
  state: string;
  event: string;
  sessionId?: string;
  toolName?: string;
}

/** Fire-and-forget POST to the first reachable local Clawd server. Never throws. */
export function notifyClawd(payload: ClawdNotifyPayload): void {
  const body = JSON.stringify({
    agent_id: "openclaw",
    hook_source: "human-gate",
    state: payload.state,
    event: payload.event,
    ...(payload.sessionId ? { session_id: payload.sessionId } : {}),
    ...(payload.toolName ? { tool_name: payload.toolName } : {}),
  });
  void (async () => {
    for (const port of CLAWD_PORTS) {
      if (await postJson(port, body)) return;
    }
  })().catch(() => {});
}

function postJson(port: number, payload: string): Promise<boolean> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (ok: boolean) => {
      if (settled) return;
      settled = true;
      resolve(ok);
    };
    const req = request(
      {
        hostname: "127.0.0.1",
        port,
        path: "/state",
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(payload),
        },
        timeout: POST_TIMEOUT_MS,
      },
      (res) => {
        const isClawd = res.headers[CLAWD_SERVER_HEADER] === "clawd-on-desk";
        res.resume();
        res.on("end", () => finish(isClawd));
      },
    );
    req.on("timeout", () => {
      req.destroy();
      finish(false);
    });
    req.on("error", () => finish(false));
    req.write(payload);
    req.end();
  });
}
