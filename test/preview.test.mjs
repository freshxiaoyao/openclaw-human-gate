import assert from "node:assert/strict";
import test from "node:test";

import { ApprovalPresenter } from "../dist/preview/presenter.js";
import { DEFAULT_CONFIG } from "../dist/types.js";

const decision = {
  mode: "require-approval",
  source: "builtin",
  severity: "warning",
  timeoutMs: 300000,
  allowedDecisions: ["allow-once", "allow-always", "deny"],
  reason: "test",
  semanticReport: { findings: [], effects: [], windowEligible: true, analyzerIds: [] },
  windowEligible: true,
};

function describe(context) {
  return new ApprovalPresenter(DEFAULT_CONFIG.previews).describe(
    { derivedPaths: [], ...context },
    decision,
  );
}

test("write, edit, patch, command and code previews are bounded", () => {
  const contexts = [
    { toolName: "writeFile", params: { path: "x", content: "hello\nworld" } },
    { toolName: "edit", params: { path: "x", edits: [{ oldText: "old", newText: "new" }] } },
    { toolName: "apply_patch", params: { input: "*** Begin Patch\n*** Update File: x\n-old\n+new\n*** End Patch" } },
    { toolName: "exec", params: { command: "echo hello" } },
    { toolName: "exec", toolKind: "code_mode_exec", toolInputKind: "typescript", params: { code: "return 1;" } },
  ];
  for (const context of contexts) {
    const output = describe(context);
    assert.ok(output.length <= 512, context.toolName);
    assert.match(output, /preview/i);
  }
});

test("preview sanitizes secrets, ANSI and bidi controls", () => {
  const output = describe({
    toolName: "writeFile",
    params: { content: "\u001b[31mAPI_KEY=abcdef123456\u001b[0m\nBearer abcdefghijklmnop\u202E" },
  });
  assert.doesNotMatch(output, /abcdef123456|abcdefghijklmnop|\u001b|\u202e/);
  assert.match(output, /\[REDACTED\]/);
  assert.match(output, /\[BIDI\]/);
});

test("description truncation never leaves a lone UTF-16 surrogate", () => {
  const output = describe({
    toolName: "writeFile",
    params: { content: `${"x".repeat(215)}😀${"y".repeat(1000)}` },
  });
  assert.ok(output.length <= 512);
  assert.equal(/[\uD800-\uDBFF]$/.test(output), false);
});

test("command preview shows environment keys but never values", () => {
  const output = describe({
    toolName: "exec",
    params: {
      command: "echo hello",
      workdir: "C:/workspace",
      env: { API_TOKEN: "must-not-leak", SAFE_NAME: "also-hidden" },
    },
  });
  assert.match(output, /env keys: API_TOKEN, SAFE_NAME/);
  assert.doesNotMatch(output, /must-not-leak|also-hidden/);
});

test("legacy JSON-string edit arrays still produce a replacement preview", () => {
  const output = describe({
    toolName: "edit",
    params: {
      path: "src/example.ts",
      edits: JSON.stringify([{ oldText: "before", newText: "after" }]),
    },
  });
  assert.match(output, /Edit src\/example\.ts \(1 replacement/);
  assert.match(output, /- before/);
  assert.match(output, /\+ after/);
});

test("preview redacts flag, basic-auth, provider-token, and partial private-key forms", () => {
  const output = describe({
    toolName: "exec",
    params: {
      command: [
        "curl --token topsecret123 https://example.test",
        "Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
        "sk-abcdefghijklmnopqrstu",
        "-----BEGIN PRIVATE KEY----- abcdef",
      ].join("\n"),
    },
  });
  assert.doesNotMatch(output, /topsecret123|QWxhZGRpb|sk-abcdef|PRIVATE KEY----- abcdef/);
  assert.match(output, /\[REDACTED/);
});

test("long command previews preserve both the beginning and dangerous tail", () => {
  const output = describe({
    toolName: "exec",
    params: { command: `begin-marker ${"x".repeat(1000)} tail-marker --force` },
  });
  assert.match(output, /begin-marker/);
  assert.match(output, /tail-marker --force/);
  assert.ok(output.length <= 512);
});
