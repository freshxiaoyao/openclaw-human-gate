/**
 * Classifier regression matrix — composite tool names.
 *
 * The classifier must:
 *  1. Gate any name containing a destructive token, EVEN IF it also contains
 *     a read-only token (`readWriteFile` must never auto-pass).
 *  2. Auto-pass names with only read-only tokens.
 *  3. Treat names with neither as unknown -> defaultMode (fail-closed default:
 *     `require-approval`).
 *
 * The bug this guards against: the old implementation matched only the first
 * name segment, so `readWriteFile` / `getDeleteUser` matched the read-only
 * prefix and auto-passed past the gate.
 */

import assert from "node:assert/strict";
import test from "node:test";

import { evaluatePolicy, tokenizeName } from "../dist/policy.js";
import { DEFAULT_CONFIG } from "../dist/types.js";

function config(overrides = {}) {
  return {
    ...DEFAULT_CONFIG,
    rules: [],
    autoPassSessionKeys: [],
    ...overrides,
    approvalWindow: { ...DEFAULT_CONFIG.approvalWindow },
  };
}

const APPROVAL = "require-approval";

// ── tokenizer unit checks ──
test("tokenizeName splits camelCase / snake / kebab / digits", () => {
  assert.deepEqual(tokenizeName("readWriteFile"), ["read", "write", "file"]);
  assert.deepEqual(tokenizeName("remove_old_files"), ["remove", "old", "files"]);
  assert.deepEqual(tokenizeName("list-files"), ["list", "files"]);
  assert.deepEqual(tokenizeName("list2"), ["list", "2"]);
  assert.deepEqual(tokenizeName("getUser2"), ["get", "user", "2"]);
  assert.deepEqual(tokenizeName("cat"), ["cat"]);
  assert.deepEqual(tokenizeName("scatter"), ["scatter"]);
  assert.deepEqual(tokenizeName("exec"), ["exec"]);
});

// ── 1. composite names: destructive token must win ──
test("composite names with a destructive token are gated (never auto)", () => {
  const cfg = config();
  const cases = [
    "readWriteFile",
    "getDeleteUser",
    "listAndRemove",
    "view_edit",
    "showCreate",
    "queryUpdate",
    "fetchAndPost",
    "head_rmdir",
    "readAndWrite",
    "searchDelete",
    "statusUpdate",
    "describeCommit",
  ];
  for (const name of cases) {
    assert.equal(
      evaluatePolicy(name, undefined, cfg).mode,
      APPROVAL,
      `expected ${name} to require approval (destructive token present)`,
    );
  }
});

// ── 2. pure read-only names pass through ──
test("pure read-only names auto-pass", () => {
  const cfg = config();
  const cases = [
    "readFile",
    "getUser",
    "listFiles",
    "search_users",
    "fetchPage",
    "cat",
    "glob",
    "grep",
    "describeThing",
    "showStatus",
    "countRows",
    "view_logs",
  ];
  for (const name of cases) {
    assert.equal(
      evaluatePolicy(name, undefined, cfg).mode,
      "auto",
      `expected ${name} to auto-pass`,
    );
  }
});

// ── 3. pure destructive names are gated ──
test("pure destructive names require approval", () => {
  const cfg = config();
  const cases = [
    "writeFile",
    "deleteUser",
    "remove_old",
    "mkdir_p",
    "exec",
    "apply_patch",
    "updateRecord",
    "createThing",
    "runTask",
    "pushBranch",
    "installPackage",
  ];
  for (const name of cases) {
    assert.equal(
      evaluatePolicy(name, undefined, cfg).mode,
      APPROVAL,
      `expected ${name} to require approval`,
    );
  }
});

// ── 4. unknown names -> defaultMode (fail-closed by default) ──
test("unknown names fall to defaultMode = require-approval (fail-closed)", () => {
  const cfg = config(); // DEFAULT_CONFIG.defaultMode === "require-approval"
  const cases = ["frobnicate", "scatter", "randomTool", "blob_store", "zorp"];
  for (const name of cases) {
    assert.equal(
      evaluatePolicy(name, undefined, cfg).mode,
      APPROVAL,
      `expected unknown ${name} to require approval by default`,
    );
  }
});

test("unknown names respect explicit defaultMode: auto (opt-in fail-open)", () => {
  const cfg = config({ defaultMode: "auto" });
  for (const name of ["frobnicate", "scatter", "randomTool"]) {
    assert.equal(
      evaluatePolicy(name, undefined, cfg).mode,
      "auto",
      `expected unknown ${name} to auto-pass when defaultMode: auto`,
    );
  }
});

// ── 5. user rules stay highest authority ──
test("user rules override the classifier", () => {
  const cfg = config({
    rules: [
      { id: "r1", toolNamePattern: "^readWrite.*", mode: "auto" },
      { id: "r2", toolName: "writeFile", mode: "block" },
    ],
  });
  assert.equal(evaluatePolicy("readWriteFile", undefined, cfg).mode, "auto");
  assert.equal(evaluatePolicy("writeFile", undefined, cfg).mode, "block");
  // unrelated destructive name still gated by classifier
  assert.equal(evaluatePolicy("deleteUser", undefined, cfg).mode, APPROVAL);
});

// ── 6. host toolKind is authoritative ──
test("host toolKind overrides name tokens", () => {
  const cfg = config();
  // host says read-only -> auto even though the name is destructive-looking
  assert.equal(evaluatePolicy("writeFile", "read", cfg).mode, "auto");
  // host says exec -> gated even though the name is read-only-looking
  assert.equal(evaluatePolicy("readFile", "exec", cfg).mode, APPROVAL);
  // unknown host kind falls back to name tokens
  assert.equal(evaluatePolicy("readFile", "custom-kind", cfg).mode, "auto");
  assert.equal(evaluatePolicy("writeFile", "custom-kind", cfg).mode, APPROVAL);
});

// ── 7. classifiers can be disabled ──
test("useClassifiers: false disables name classification", () => {
  const cfg = config({ useClassifiers: false });
  // name tokens ignored -> falls to defaultMode
  assert.equal(evaluatePolicy("writeFile", undefined, cfg).mode, APPROVAL);
  assert.equal(evaluatePolicy("readFile", undefined, cfg).mode, APPROVAL);
  const cfgOpen = config({ useClassifiers: false, defaultMode: "auto" });
  assert.equal(evaluatePolicy("writeFile", undefined, cfgOpen).mode, "auto");
});

test("parameter matcher auto-passes only approved process observation actions", () => {
  const cfg = config({
    rules: [{
      id: "process-observation",
      toolName: "process",
      paramMatcher: {
        all: [{ key: "action", in: ["list", "poll", "log"] }],
      },
      mode: "auto",
    }],
  });

  for (const action of ["list", "poll", "log"]) {
    const decision = evaluatePolicy("process", undefined, cfg, { action });
    assert.equal(decision.mode, "auto", action);
    assert.equal(decision.rule?.id, "process-observation");
  }
  for (const params of [{}, { action: "write" }, { action: "kill" }, { action: "LIST" }]) {
    assert.equal(evaluatePolicy("process", undefined, cfg, params).mode, APPROVAL);
  }
});

test("one-level any supports missing or exact own values for session observation", () => {
  const cfg = config({
    rules: [{
      id: "session-observation",
      toolNamePattern: "^(?:sessions_list|sessions_history|subagents)$",
      paramMatcher: {
        any: [
          { key: "action", missing: true },
          { key: "action", equals: "list" },
        ],
      },
      mode: "auto",
    }],
  });

  assert.equal(evaluatePolicy("subagents", undefined, cfg, {}).mode, "auto");
  assert.equal(evaluatePolicy("subagents", undefined, cfg, { action: "list" }).mode, "auto");
  assert.equal(evaluatePolicy("subagents", undefined, cfg, { action: "kill" }).mode, APPROVAL);
  assert.equal(evaluatePolicy("sessions_delete", undefined, cfg, {}).mode, APPROVAL);

  const inherited = Object.create({ action: "list" });
  assert.equal(evaluatePolicy("subagents", undefined, cfg, inherited).mode, "auto");
  const exactOnly = config({
    rules: [{
      id: "exact-only",
      toolName: "process",
      paramMatcher: { all: [{ key: "action", equals: "list" }] },
      mode: "auto",
    }],
  });
  assert.equal(evaluatePolicy("process", undefined, exactOnly, inherited).mode, APPROVAL);
});

test("matches regex operator matches string parameters only", () => {
  const cfg = config({
    rules: [{
      id: "readonly-git",
      toolName: "exec",
      paramMatcher: {
        all: [{ key: "command", matches: "^git (status|diff|log)\\b" }],
      },
      mode: "auto",
    }],
  });

  assert.equal(evaluatePolicy("exec", undefined, cfg, { command: "git status" }).mode, "auto");
  assert.equal(evaluatePolicy("exec", undefined, cfg, { command: "git diff --stat" }).mode, "auto");
  assert.equal(evaluatePolicy("exec", undefined, cfg, { command: "git commit -m x" }).mode, APPROVAL);
  assert.equal(evaluatePolicy("exec", undefined, cfg, { command: 123 }).mode, APPROVAL);
});

test("matches regex operator is case-insensitive (PowerShell cmdlets, exes)", () => {
  const cfg = config({
    rules: [{
      id: "readonly-case",
      toolName: "exec",
      paramMatcher: {
        all: [{ key: "command", matches: "^(cat|get-childitem)$" }],
      },
      mode: "auto",
    }],
  });

  assert.equal(evaluatePolicy("exec", undefined, cfg, { command: "cat" }).mode, "auto");
  assert.equal(evaluatePolicy("exec", undefined, cfg, { command: "CAT" }).mode, "auto");
  assert.equal(evaluatePolicy("exec", undefined, cfg, { command: "Get-ChildItem" }).mode, "auto");
  assert.equal(evaluatePolicy("exec", undefined, cfg, { command: "get-childitem" }).mode, "auto");
  assert.equal(evaluatePolicy("exec", undefined, cfg, { command: "rm" }).mode, APPROVAL);
});

test("invalid, accessor, inherited, and prototype-injected matchers never match", () => {
  const invalidMatchers = [
    {},
    { all: [] },
    { all: [{ key: "action", equals: "list", in: ["list"] }] },
    { all: [{ key: "action.value", equals: "list" }] },
    { all: [{ key: "constructor", equals: "list" }] },
    { all: [{ key: "action", in: [] }] },
    { all: [{ key: "action", missing: false }] },
    { all: [{ key: "action", equals: { nested: true } }] },
    { all: [{ key: "action", equals: "list" }], any: [{ key: "action", equals: "list" }] },
  ];
  for (const paramMatcher of invalidMatchers) {
    const cfg = config({
      rules: [{ id: "invalid", toolName: "process", paramMatcher, mode: "auto" }],
    });
    assert.equal(evaluatePolicy("process", undefined, cfg, { action: "list" }).mode, APPROVAL);
  }

  let getterRead = false;
  const params = {};
  Object.defineProperty(params, "action", {
    enumerable: true,
    get() {
      getterRead = true;
      return "list";
    },
  });
  const safeCfg = config({
    rules: [{
      id: "safe",
      toolName: "process",
      paramMatcher: { all: [{ key: "action", equals: "list" }] },
      mode: "auto",
    }],
  });
  assert.equal(evaluatePolicy("process", undefined, safeCfg, params).mode, APPROVAL);
  assert.equal(getterRead, false);

  const inheritedMatcherRule = Object.create({
    paramMatcher: { all: [{ key: "action", equals: "list" }] },
  });
  Object.assign(inheritedMatcherRule, { id: "inherited", toolName: "process", mode: "auto" });
  assert.equal(
    evaluatePolicy("process", undefined, config({ rules: [inheritedMatcherRule] }), { action: "list" }).mode,
    APPROVAL,
  );

  const inheritedGroup = Object.create({ all: [{ key: "action", equals: "list" }] });
  const inheritedOperator = Object.create({ equals: "list" });
  Object.assign(inheritedOperator, { key: "action" });
  for (const paramMatcher of [inheritedGroup, { all: [inheritedOperator] }]) {
    assert.equal(
      evaluatePolicy(
        "process",
        undefined,
        config({ rules: [{ id: "proto", toolName: "process", paramMatcher, mode: "auto" }] }),
        { action: "list" },
      ).mode,
      APPROVAL,
    );
  }

  const injectedMissing = Object.assign(
    Object.create({ missing: true }),
    { key: "action", in: ["list"] },
  );
  assert.equal(
    evaluatePolicy(
      "process",
      undefined,
      config({
        rules: [{
          id: "injected-missing",
          toolName: "process",
          paramMatcher: { any: [injectedMissing] },
          mode: "auto",
        }],
      }),
      {},
    ).mode,
    APPROVAL,
  );

  const ownEquals = { key: "action", equals: "list" };
  const ownAnyWithInheritedAll = Object.assign(
    Object.create({ all: [{ key: "action", missing: true }] }),
    { any: [ownEquals] },
  );
  const ownAnyCfg = config({
    rules: [{
      id: "own-any",
      toolName: "process",
      paramMatcher: ownAnyWithInheritedAll,
      mode: "auto",
    }],
  });
  assert.equal(evaluatePolicy("process", undefined, ownAnyCfg, {}).mode, APPROVAL);
  assert.equal(evaluatePolicy("process", undefined, ownAnyCfg, { action: "list" }).mode, "auto");
});

test("session_status with an own model parameter requires approval", () => {
  const cfg = config();
  assert.equal(evaluatePolicy("session_status", undefined, cfg, {}).mode, "auto");
  const decision = evaluatePolicy("session_status", undefined, cfg, { model: "openai/gpt" });
  assert.equal(decision.mode, APPROVAL);
  assert.equal(decision.rule?.id, "builtin:session-status-model-change");

  const inherited = Object.create({ model: "openai/gpt" });
  assert.equal(evaluatePolicy("session_status", undefined, cfg, inherited).mode, "auto");
});
