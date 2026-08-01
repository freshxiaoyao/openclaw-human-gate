/**
 * Runtime load + hook end-to-end tests.
 *
 * Loads the built plugin (dist/index.js) and drives `register()` against a
 * mock OpenClaw API, then exercises the actual `before_tool_call` handler:
 * approval requests, blocks, auto-pass contexts, and allow-always persistence
 * through the session-extension backend.
 *
 * This validates the plugin entry surface (`definePluginEntry` default
 * export, `register` signature) against a real module load — the thing a
 * static typecheck cannot see.
 */

import assert from "node:assert/strict";
import test from "node:test";

const PLUGIN_ID = "human-gate";

/** Minimal in-memory session backend mimicking
 *  runtime.agent.session.{getSessionEntry,patchSessionEntry}. */
function createSessionBackend() {
  const store = new Map();
  return {
    getSessionEntry({ sessionKey }) {
      return store.get(sessionKey);
    },
    async patchSessionEntry({ sessionKey, update }) {
      const current = store.get(sessionKey) ?? {};
      const merged = { ...current, ...update(current) };
      store.set(sessionKey, merged);
      return merged;
    },
  };
}

/** Build a mock OpenClawPluginApi and record all registration calls. */
function createMockApi({ pluginConfig = {}, backend } = {}) {
  const calls = { on: [], registerTool: [], extensions: [] };
  const api = {
    logger: {
      info() {},
      warn() {},
      error() {},
      debug() {},
    },
    config: {},
    pluginConfig,
    session: {
      state: {
        registerSessionExtension(opts) {
          calls.extensions.push(opts);
        },
      },
      workflow: {},
    },
    runtime: {
      agent: {
        session: backend ?? createSessionBackend(),
      },
    },
    on(name, handler, opts) {
      calls.on.push({ name, handler, opts });
    },
    registerTool(tool, opts) {
      calls.registerTool.push({ tool, opts });
    },
  };
  return { api, calls };
}

async function loadPlugin() {
  const mod = await import("../dist/index.js");
  assert.ok(mod.default, "dist/index.js must have a default export");
  assert.equal(
    typeof mod.default.register,
    "function",
    "default export must be a plugin entry with register()",
  );
  return mod.default;
}

function hookFor(calls, name) {
  const reg = calls.on.find((r) => r.name === name);
  assert.ok(reg, `expected a '${name}' hook registration`);
  return reg.handler;
}

test("plugin entry loads and registers against the mock API", async () => {
  const entry = await loadPlugin();
  const { api, calls } = createMockApi();
  await entry.register(api);

  assert.ok(calls.on.length >= 2, "before_tool_call + after_tool_call hooks");
  assert.ok(calls.on.some((r) => r.name === "before_tool_call"));
  assert.ok(calls.on.some((r) => r.name === "after_tool_call"));
  assert.equal(calls.registerTool.length, 1);
  assert.equal(calls.registerTool[0].tool.name, "human_gate_ask");
  assert.deepEqual(
    calls.extensions.map((e) => e.namespace).sort(),
    ["allow-always", "approval-window"],
  );
});

test("destructive call requests approval; allow-once opens the window", async () => {
  const entry = await loadPlugin();
  const backend = createSessionBackend();
  const { api, calls } = createMockApi({
    pluginConfig: { defaultMode: "auto", rememberAllowAlways: true },
    backend,
  });
  await entry.register(api);
  const handler = hookFor(calls, "before_tool_call");

  const res = await handler(
    { toolName: "writeFile", params: { path: "x" } },
    { sessionKey: "agent:main:webchat", runId: "run-1" },
  );
  assert.ok(res?.requireApproval, "writeFile must require approval");
  assert.equal(res.requireApproval.pluginId, PLUGIN_ID);

  // resolve with allow-once -> window recorded in the session extension
  await res.requireApproval.onResolution("allow-once");
  const entry_ = backend.getSessionEntry({ sessionKey: "agent:main:webchat" });
  const windows = entry_.pluginExtensions?.[PLUGIN_ID]?.["approval-window"];
  assert.ok(windows?.windows?.writeFile, "approval window must be stored");
});

test("read-only call passes through", async () => {
  const entry = await loadPlugin();
  const { api, calls } = createMockApi();
  await entry.register(api);
  const handler = hookFor(calls, "before_tool_call");

  const res = await handler(
    { toolName: "readFile", params: { path: "x" } },
    { sessionKey: "agent:main:webchat", runId: "run-1" },
  );
  assert.equal(res, undefined);
});

test("explicit block rule is enforced even in cron auto-pass context", async () => {
  const entry = await loadPlugin();
  const { api, calls } = createMockApi({
    pluginConfig: {
      defaultMode: "require-approval",
      rules: [{ id: "no-exec", toolName: "exec", mode: "block" }],
      autoPassSessionKeys: [":cron:"],
    },
  });
  await entry.register(api);
  const handler = hookFor(calls, "before_tool_call");

  const res = await handler(
    { toolName: "exec", params: { command: "rm -rf /" } },
    { sessionKey: "agent:main:cron:job-1", runId: "run-1" },
  );
  assert.deepEqual(res, { block: true, blockReason: 'Tool "no-exec" gated by Human Gate' });
});

test("cron auto-pass skips the approval prompt for gated writes", async () => {
  const entry = await loadPlugin();
  const { api, calls } = createMockApi({
    pluginConfig: {
      defaultMode: "require-approval",
      autoPassSessionKeys: [":cron:"],
    },
  });
  await entry.register(api);
  const handler = hookFor(calls, "before_tool_call");

  const res = await handler(
    { toolName: "writeFile", params: { path: "x" } },
    { sessionKey: "agent:main:cron:job-1", runId: "run-1" },
  );
  assert.equal(res, undefined, "cron context must not stall on a popup");
});

test("allow-always persists and suppresses later prompts", async () => {
  const entry = await loadPlugin();
  const backend = createSessionBackend();
  const { api, calls } = createMockApi({
    pluginConfig: { defaultMode: "require-approval", rememberAllowAlways: true },
    backend,
  });
  await entry.register(api);
  const handler = hookFor(calls, "before_tool_call");
  const sessionKey = "agent:main:webchat";

  // first call -> approval with allow-always option
  const first = await handler(
    { toolName: "writeFile", params: { path: "x" } },
    { sessionKey, runId: "run-1" },
  );
  assert.ok(first?.requireApproval);
  await first.requireApproval.onResolution("allow-always");

  // second call in the same session -> grant hit, no prompt
  const second = await handler(
    { toolName: "writeFile", params: { path: "y" } },
    { sessionKey, runId: "run-2" },
  );
  assert.equal(second, undefined, "allow-always grant must suppress the prompt");

  // a different session still prompts
  const other = await handler(
    { toolName: "writeFile", params: { path: "z" } },
    { sessionKey: "agent:main:telegram", runId: "run-1" },
  );
  assert.ok(other?.requireApproval, "grant must be session-scoped");
});
