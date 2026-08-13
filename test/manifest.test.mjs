import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { validateJsonSchemaValue } from "openclaw/plugin-sdk/json-schema-runtime";
import { resolveConfig } from "../dist/config.js";
import { DEFAULT_CONFIG } from "../dist/types.js";

test("manifest security defaults match runtime defaults", async () => {
  const manifest = JSON.parse(await readFile(new URL("../openclaw.plugin.json", import.meta.url), "utf8"));
  const properties = manifest.configSchema.properties;
  assert.equal(properties.defaultMode.default, DEFAULT_CONFIG.defaultMode);
  assert.equal(properties.semanticAnalysis.properties.enabled.default, DEFAULT_CONFIG.semanticAnalysis.enabled);
  assert.equal(properties.semanticAnalysis.properties.maxWrapperDepth.default, DEFAULT_CONFIG.semanticAnalysis.maxWrapperDepth);
  assert.equal(properties.previews.properties.maxDescriptionChars.default, DEFAULT_CONFIG.previews.maxDescriptionChars);
  assert.equal(properties.unattendedPolicy.properties.critical.default, DEFAULT_CONFIG.unattendedPolicy.critical);
  const window = properties.approvalWindow.properties;
  assert.equal(window.mode.default, DEFAULT_CONFIG.approvalWindow.mode);
  assert.equal(window.ttlMs.default, DEFAULT_CONFIG.approvalWindow.ttlMs);
  assert.equal(window.pathFallback.default, DEFAULT_CONFIG.approvalWindow.pathFallback);
  assert.equal(window.bypassCritical.default, DEFAULT_CONFIG.approvalWindow.bypassCritical);
  // OpenClaw's schema default application must not inject a legacy alias and
  // override the safer runtime default.
  assert.equal(Object.hasOwn(window.scope, "default"), false);
  assert.equal(Object.hasOwn(window.match, "default"), false);
  assert.deepEqual(window.scope.enum, ["destructive", "same-tool", "effect", "category", "path"]);
  assert.deepEqual(window.pathFallback.enum, ["none", "category", "effect"]);
  assert.match(window.match.description, /deprecated/i);
});

test("OpenClaw schema default application remains fail-closed", async () => {
  const manifest = JSON.parse(await readFile(new URL("../openclaw.plugin.json", import.meta.url), "utf8"));
  const result = validateJsonSchemaValue({
    schema: manifest.configSchema,
    cacheKey: "human-gate-manifest-test",
    value: {},
    applyDefaults: true,
    cache: false,
  });
  assert.equal(result.ok, true);
  const resolved = resolveConfig(result.value);
  assert.equal(resolved.defaultMode, "require-approval");
  assert.equal(resolved.semanticAnalysis.enabled, true);
  assert.equal(resolved.unattendedPolicy.critical, "block");
  assert.equal(resolved.approvalWindow.scope, "path");
  assert.equal(resolved.approvalWindow.pathFallback, "none");
  assert.equal(Object.hasOwn(resolved.approvalWindow, "match"), false);
});

test("manifest accepts all semantic scopes and rejects unknown scope controls", async () => {
  const manifest = JSON.parse(await readFile(new URL("../openclaw.plugin.json", import.meta.url), "utf8"));
  const validate = (approvalWindow) => validateJsonSchemaValue({
    schema: manifest.configSchema,
    cacheKey: `human-gate-window-${JSON.stringify(approvalWindow)}`,
    value: { approvalWindow },
    applyDefaults: false,
    cache: false,
  });

  for (const scope of ["destructive", "same-tool", "effect", "category", "path"]) {
    assert.equal(validate({ scope }).ok, true, scope);
  }
  for (const pathFallback of ["none", "category", "effect"]) {
    assert.equal(validate({ scope: "path", pathFallback }).ok, true, pathFallback);
  }
  assert.equal(validate({ match: "same-tool" }).ok, true);
  assert.equal(validate({ match: "destructive" }).ok, true);
  assert.equal(validate({ scope: "tool-and-path" }).ok, false);
  assert.equal(validate({ scope: "path", pathFallback: "destructive" }).ok, false);
  assert.equal(validate({ match: "path" }).ok, false);
});

test("manifest accepts the documented parameter matcher and rejects malformed forms", async () => {
  const manifest = JSON.parse(await readFile(new URL("../openclaw.plugin.json", import.meta.url), "utf8"));
  const validate = (paramMatcher) => validateJsonSchemaValue({
    schema: manifest.configSchema,
    cacheKey: `human-gate-param-matcher-${JSON.stringify(paramMatcher)}`,
    value: {
      rules: [{ id: "process-read", toolName: "process", paramMatcher, mode: "auto" }],
    },
    applyDefaults: false,
    cache: false,
  });

  const documentedRules = validateJsonSchemaValue({
    schema: manifest.configSchema,
    cacheKey: "human-gate-documented-param-rules",
    value: {
      rules: [
        {
          id: "process-observation-auto",
          toolName: "process",
          paramMatcher: {
            all: [{ key: "action", in: ["list", "poll", "log"] }],
          },
          mode: "auto",
        },
        {
          id: "session-observation-auto",
          toolNamePattern: "^(?:sessions_list|sessions_history|subagents)$",
          paramMatcher: {
            any: [
              { key: "action", missing: true },
              { key: "action", equals: "list" },
            ],
          },
          mode: "auto",
        },
      ],
    },
    applyDefaults: false,
    cache: false,
  });
  assert.equal(documentedRules.ok, true);

  for (const matcher of [
    { all: [] },
    { any: [] },
    { all: [{ key: "action.value", equals: "list" }] },
    { all: [{ key: "constructor", equals: "list" }] },
    { all: [{ key: "action", equals: "list", missing: true }] },
    { all: [{ key: "action", in: [] }] },
    { all: [{ key: "action", missing: false }] },
    {
      all: [{ key: "action", equals: "list" }],
      any: [{ key: "action", equals: "list" }],
    },
  ]) {
    assert.equal(validate(matcher).ok, false, JSON.stringify(matcher));
  }
});
