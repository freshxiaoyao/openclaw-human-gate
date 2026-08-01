/**
 * Regression tests for the two hardening fixes:
 *
 * 1. Fallback allow-always: a decision that falls through to `defaultMode`
 *    must carry a synthesised rule, so the allow-always button actually
 *    persists (previously `decision.rule` was undefined and the grant was
 *    silently dropped while the UI offered the option).
 *
 * 2. Tightened cron/heartbeat bypass: auto-pass contexts are matched per
 *    `:`-delimited segment (not loose substring), and `block` decisions are
 *    evaluated before any auto-pass so user-forbidden tools never run in
 *    unattended contexts.
 */

import assert from "node:assert/strict";
import test from "node:test";

import { evaluatePolicy, isAutoPassContext } from "../dist/policy.js";
import { DEFAULT_CONFIG, allowAlwaysKey } from "../dist/types.js";

function config(overrides = {}) {
  return {
    ...DEFAULT_CONFIG,
    rules: [],
    autoPassSessionKeys: [],
    ...overrides,
    approvalWindow: { ...DEFAULT_CONFIG.approvalWindow },
  };
}

// ── 1. fallback allow-always ──
test("fallback decisions carry a synthesised rule for allow-always", () => {
  const cfg = config(); // defaultMode: "require-approval"
  const decision = evaluatePolicy("frobnicate", undefined, cfg);

  assert.equal(decision.mode, "require-approval");
  assert.ok(decision.rule, "fallback decision must have a rule");
  assert.equal(decision.rule.id, "builtin:default-mode");
  assert.equal(decision.rule.mode, "require-approval");

  // the persistence key is stable and tool-scoped: granting "frobnicate"
  // never leaks to other unknown tools
  const key = allowAlwaysKey(decision.rule.id, "frobnicate");
  assert.equal(key, "builtin:default-mode::frobnicate");
  assert.notEqual(key, allowAlwaysKey(decision.rule.id, "zorp"));
});

test("fallback with defaultMode: auto still carries a rule", () => {
  const cfg = config({ defaultMode: "auto" });
  const decision = evaluatePolicy("frobnicate", undefined, cfg);
  assert.equal(decision.mode, "auto");
  assert.equal(decision.rule?.id, "builtin:default-mode");
});

// ── 2. isAutoPassContext: exact segment matching ──
test("auto-pass keys match standalone segments only", () => {
  const keys = [":cron:", ":heartbeat", "subagent"];

  assert.equal(isAutoPassContext("agent:main:cron:run-1", keys), true);
  assert.equal(isAutoPassContext("agent:main:heartbeat", keys), true);
  assert.equal(isAutoPassContext("agent:subagent:xyz", keys), true);
  assert.equal(isAutoPassContext(":cron:", keys), true);

  // loose-substring false positives are rejected
  assert.equal(isAutoPassContext("agent:x:cronx:", keys), false);
  assert.equal(isAutoPassContext("agent:cronology", keys), false);
  assert.equal(isAutoPassContext("agent:main", keys), false);
  assert.equal(isAutoPassContext("agent:subagents:x", keys), false);
});

test("empty auto-pass list matches nothing", () => {
  assert.equal(isAutoPassContext("agent:main:cron:run-1", []), false);
  assert.equal(isAutoPassContext("", [":cron:"]), false);
});

// ── 3. policy-level contract the hook relies on ──
test("block rules stay block even for unknown toolKind in cron sessions", () => {
  const cfg = config({
    rules: [{ id: "no-exec", toolName: "exec", mode: "block" }],
  });
  const decision = evaluatePolicy("exec", undefined, cfg);
  assert.equal(decision.mode, "block");
  // the hook evaluates policy BEFORE auto-pass, so this block is enforced
  // even when isAutoPassContext would be true
  assert.equal(isAutoPassContext("agent:main:cron:run-1", [":cron:"]), true);
});
