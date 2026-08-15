import assert from "node:assert/strict";
import test from "node:test";

import { resolveConfig } from "../dist/config.js";
import { DEFAULT_CONFIG } from "../dist/types.js";

test("approval windows default to fail-closed path scope", () => {
  for (const raw of [undefined, null, {}, { approvalWindow: null }]) {
    const resolved = resolveConfig(raw);
    assert.deepEqual(resolved.approvalWindow, DEFAULT_CONFIG.approvalWindow);
    assert.equal(resolved.approvalWindow.scope, "path");
    assert.equal(resolved.approvalWindow.pathFallback, "none");
    assert.equal(Object.hasOwn(resolved.approvalWindow, "match"), false);
  }
});

test("all five approval scopes and explicit path fallbacks resolve", () => {
  for (const scope of ["destructive", "same-tool", "effect", "category", "path"]) {
    assert.equal(resolveConfig({ approvalWindow: { scope } }).approvalWindow.scope, scope);
  }
  for (const pathFallback of ["none", "category", "effect"]) {
    assert.equal(
      resolveConfig({ approvalWindow: { scope: "path", pathFallback } }).approvalWindow.pathFallback,
      pathFallback,
    );
  }

  const invalid = resolveConfig({
    approvalWindow: { scope: "everything", pathFallback: "destructive" },
  }).approvalWindow;
  assert.equal(invalid.scope, "path");
  assert.equal(invalid.pathFallback, "none");
});

test("legacy match migrates without surviving in resolved configuration", () => {
  for (const match of ["same-tool", "destructive"]) {
    const resolved = resolveConfig({ approvalWindow: { match } }).approvalWindow;
    assert.equal(resolved.scope, match);
    assert.equal(Object.hasOwn(resolved, "match"), false);
  }

  const explicitWins = resolveConfig({
    approvalWindow: {
      match: "destructive",
      scope: "path",
      pathFallback: "none",
    },
  }).approvalWindow;
  assert.equal(explicitWins.scope, "path");
  assert.equal(explicitWins.pathFallback, "none");
  assert.equal(Object.hasOwn(explicitWins, "match"), false);
});

test("approval window numeric and boolean controls remain bounded", () => {
  assert.deepEqual(
    resolveConfig({
      approvalWindow: {
        mode: "time",
        scope: "effect",
        pathFallback: "category",
        ttlMs: 999_999_999,
        bypassCritical: false,
      },
    }).approvalWindow,
    {
      mode: "time",
      scope: "effect",
      pathFallback: "category",
      ttlMs: 3_600_000,
      bypassCritical: false,
      pathMode: "directory",
    },
  );
  assert.equal(resolveConfig({ approvalWindow: { ttlMs: -1 } }).approvalWindow.ttlMs, 1000);
  assert.equal(resolveConfig({ approvalWindow: { ttlMs: 1234.9 } }).approvalWindow.ttlMs, 1234);
  assert.equal(
    resolveConfig({ approvalWindow: { ttlMs: Number.NaN } }).approvalWindow.ttlMs,
    DEFAULT_CONFIG.approvalWindow.ttlMs,
  );
});
