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
});
