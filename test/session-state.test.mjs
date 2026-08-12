import assert from "node:assert/strict";
import test from "node:test";

import { resolveConfig } from "../dist/config.js";
import { AllowAlwaysStore } from "../dist/state.js";
import { ApprovalWindowStore } from "../dist/window.js";

function createSessionBackend(defaultValue) {
  const state = new Map();
  return {
    read(sessionKey) {
      return state.get(sessionKey);
    },
    async update(sessionKey, update) {
      state.set(sessionKey, update(state.get(sessionKey) ?? structuredClone(defaultValue)));
    },
  };
}

test("resolveConfig honors api.pluginConfig values", () => {
  const cfg = resolveConfig({
    defaultMode: "block",
    rememberAllowAlways: false,
    useClassifiers: false,
    semanticAnalysis: { enabled: false, maxCommandLength: 999999, maxWrapperDepth: 99, maxFindings: 0 },
    previews: { maxDescriptionChars: 9999, maxLines: 0, redactSecrets: false },
    unattendedPolicy: { critical: "auto" },
    approvalWindow: { mode: "off", match: "destructive", ttlMs: 1234 },
    autoPassSessionKeys: [],
    rules: [{ id: "deny-all", mode: "block" }],
  });

  assert.equal(cfg.defaultMode, "block");
  assert.equal(cfg.rememberAllowAlways, false);
  assert.equal(cfg.useClassifiers, false);
  assert.equal(cfg.semanticAnalysis.enabled, false);
  assert.equal(cfg.semanticAnalysis.maxCommandLength, 65536);
  assert.equal(cfg.semanticAnalysis.maxWrapperDepth, 5);
  assert.equal(cfg.semanticAnalysis.maxFindings, 1);
  assert.equal(cfg.previews.maxDescriptionChars, 512);
  assert.equal(cfg.previews.maxLines, 1);
  assert.equal(cfg.previews.redactSecrets, false);
  assert.equal(cfg.unattendedPolicy.critical, "auto");
  assert.equal(cfg.approvalWindow.mode, "off");
  assert.equal(cfg.approvalWindow.match, "destructive");
  assert.equal(cfg.approvalWindow.ttlMs, 1234);
  assert.deepEqual(cfg.autoPassSessionKeys, []);
  assert.equal(cfg.rules[0]?.id, "deny-all");
});

test("allow-always grants are isolated by sessionKey", async () => {
  const backend = createSessionBackend({ grants: {} });
  const store = new AllowAlwaysStore(backend.read, backend.update);

  await store.grant("session-a", "rule", "write_file");

  assert.equal(store.isGranted("session-a", "rule", "write_file"), true);
  assert.equal(store.isGranted("session-b", "rule", "write_file"), false);
});

test("time approval windows are isolated by sessionKey", async () => {
  const backend = createSessionBackend({ windows: {} });
  const store = new ApprovalWindowStore(backend.read, backend.update);
  const cfg = {
    mode: "time",
    ttlMs: 300_000,
    match: "same-tool",
    bypassCritical: true,
  };

  await store.open(cfg, "session-a", "write_file", "run-a", 1000);

  assert.equal(store.isOpen(cfg, "session-a", "write_file", "run-a", 1001), true);
  assert.equal(store.isOpen(cfg, "session-b", "write_file", "run-b", 1001), false);
});

test("turn windows require the same run within the same session", async () => {
  const backend = createSessionBackend({ windows: {} });
  const store = new ApprovalWindowStore(backend.read, backend.update);
  const cfg = {
    mode: "turn",
    ttlMs: 300_000,
    match: "same-tool",
    bypassCritical: true,
  };

  await store.open(cfg, "session-a", "apply_patch", "run-a", 1000);

  assert.equal(store.isOpen(cfg, "session-a", "apply_patch", "run-a", 1001), true);
  assert.equal(store.isOpen(cfg, "session-a", "apply_patch", "run-b", 1001), false);
  assert.equal(store.isOpen(cfg, "session-b", "apply_patch", "run-a", 1001), false);
  assert.equal(store.isOpen(cfg, "session-a", "apply_patch", undefined, 1001), false);
});
