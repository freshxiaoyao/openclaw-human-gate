import assert from "node:assert/strict";
import test from "node:test";

import { resolveConfig } from "../dist/config.js";
import { AllowAlwaysStore } from "../dist/state.js";
import { ApprovalWindowStore } from "../dist/window.js";
import { createAuthorizationFingerprint } from "../dist/scope.js";

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

function windowFingerprint(path = "C:\\repo\\src\\file.ts") {
  return createAuthorizationFingerprint({
    toolName: "write_file",
    toolKind: "write",
    toolInputKind: "write",
    ruleId: "builtin:write",
    policyIdentity: "policy-v1",
    effects: ["local-write"],
    categories: ["filesystem"],
    verifiedTargets: [{ path, targetKind: "file" }],
    analysisComplete: true,
  }, {
    scope: "path",
    pathFallback: "none",
    rulesetVersion: "rules-v1",
  });
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
  assert.equal(cfg.approvalWindow.scope, "destructive");
  assert.equal(cfg.approvalWindow.pathFallback, "none");
  assert.equal(Object.hasOwn(cfg.approvalWindow, "match"), false);
  assert.equal(cfg.approvalWindow.ttlMs, 1234);
  assert.deepEqual(cfg.autoPassSessionKeys, []);
  assert.equal(cfg.rules[0]?.id, "deny-all");
});

test("allow-always grants are isolated by sessionKey", async () => {
  const backend = createSessionBackend({ version: 2, grants: {} });
  const store = new AllowAlwaysStore(backend.read, backend.update);
  const fp = windowFingerprint();

  await store.grant("session-a", fp);

  assert.equal(store.isGranted("session-a", fp), true);
  assert.equal(store.isGranted("session-b", fp), false);
});

test("time approval windows are isolated by sessionKey", async () => {
  const backend = createSessionBackend({ version: 2, windows: {} });
  const store = new ApprovalWindowStore(backend.read, backend.update);
  const fp = windowFingerprint();
  const cfg = {
    mode: "time",
    ttlMs: 300_000,
    bypassCritical: true,
  };

  await store.open(cfg, "session-a", fp, "run-a", 1000);

  assert.equal(store.isOpen(cfg, "session-a", fp, "run-a", 1001), true);
  assert.equal(store.isOpen(cfg, "session-b", fp, "run-b", 1001), false);
});

test("turn windows require the same run within the same session", async () => {
  const backend = createSessionBackend({ version: 2, windows: {} });
  const store = new ApprovalWindowStore(backend.read, backend.update);
  const fp = windowFingerprint();
  const cfg = {
    mode: "turn",
    ttlMs: 300_000,
    bypassCritical: true,
  };

  await store.open(cfg, "session-a", fp, "run-a", 1000);

  assert.equal(store.isOpen(cfg, "session-a", fp, "run-a", 1001), true);
  assert.equal(store.isOpen(cfg, "session-a", fp, "run-b", 1001), false);
  assert.equal(store.isOpen(cfg, "session-b", fp, "run-a", 1001), false);
  assert.equal(store.isOpen(cfg, "session-a", fp, undefined, 1001), false);
});
