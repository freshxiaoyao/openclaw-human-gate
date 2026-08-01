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
