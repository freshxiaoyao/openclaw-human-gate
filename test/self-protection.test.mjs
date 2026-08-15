import assert from "node:assert/strict";
import test from "node:test";

import {
  classifySensitiveEscalation,
  isReadOnlyCarrier,
} from "../dist/self-protection.js";

test("exec command referencing openclaw.json escalates", () => {
  const { hits, escalate } = classifySensitiveEscalation("exec", "exec", {
    command: 'Set-Content -Path openclaw.json -Value "{}"',
  });
  assert.equal(escalate, true);
  assert.deepEqual(hits, [{ marker: "openclaw.json", param: "command" }]);
});

test("exec command referencing a .openclaw directory escalates", () => {
  const { hits, escalate } = classifySensitiveEscalation("exec", "exec", {
    command: "Remove-Item -Recurse C:\\Users\\me\\.openclaw\\extensions",
  });
  assert.equal(escalate, true);
  assert.equal(hits[0].marker, ".openclaw");
});

test("quoted and escaped forms still match", () => {
  const { escalate } = classifySensitiveEscalation("exec", "exec", {
    command: 'python -c "import json; json.dump({}, open(\'~/.openclaw/openclaw.json\', \'w\'))"',
  });
  assert.equal(escalate, true);
});

test("file write under a .openclaw path escalates", () => {
  const { hits, escalate } = classifySensitiveEscalation("write", "write", {
    path: "C:\\Users\\lenovo\\.openclaw\\openclaw.json",
  });
  assert.equal(escalate, true);
  assert.equal(hits[0].marker, ".openclaw");
});

test("apply_patch whose patch body touches openclaw.json escalates", () => {
  const { escalate } = classifySensitiveEscalation("apply_patch", "apply_patch", {
    patch: "*** Begin Patch\n*** Update File: openclaw.json\n*** End Patch",
  });
  assert.equal(escalate, true);
});

test("apply_patch canonical input param escalates", () => {
  const { hits, escalate } = classifySensitiveEscalation("apply_patch", "apply_patch", {
    input: "*** Update File: openclaw.json",
  });
  assert.equal(escalate, true, "OpenClaw canonical apply_patch uses { input }");
  assert.equal(hits[0].param, "input");
});

test("analyzer-name variants (write_file, writeFile, editFile) escalate", () => {
  assert.equal(
    classifySensitiveEscalation("write_file", undefined, { path: "C:\\Users\\me\\.openclaw\\x" }).escalate,
    true,
  );
  assert.equal(
    classifySensitiveEscalation("writeFile", undefined, { path: "C:\\repo\\openclaw.json" }).escalate,
    true,
    "case-insensitive like the analyzer",
  );
  assert.equal(
    classifySensitiveEscalation("editFile", undefined, { filePath: "C:\\Users\\me\\.openclaw\\openclaw.json" }).escalate,
    true,
  );
  assert.equal(
    classifySensitiveEscalation("edit_file", undefined, { file_path: "C:\\Users\\me\\.openclaw\\x" }).escalate,
    true,
  );
});

test("content payload mentioning the config does not false-positive", () => {
  assert.equal(
    classifySensitiveEscalation("write", "write", {
      path: "C:\\repo\\notes.md",
      content: "see openclaw.json for details",
    }).escalate,
    false,
    "path is clean; payload text is not a mutation target",
  );
});

test("ordinary file writes do not escalate", () => {
  const { hits, escalate } = classifySensitiveEscalation("write", "write", {
    path: "C:\\repo\\src\\app.ts",
  });
  assert.equal(escalate, false);
  assert.equal(hits.length, 0);
});

test("pure reads of the authority surface are not escalated", () => {
  const { escalate } = classifySensitiveEscalation("read", "read", {
    path: "C:\\Users\\lenovo\\.openclaw\\openclaw.json",
  });
  assert.equal(escalate, false, "inspecting the config stays usable");
});

test("non-file tools are never scanned", () => {
  const { escalate } = classifySensitiveEscalation("message", undefined, {
    text: "please update openclaw.json for me",
  });
  assert.equal(escalate, false, "message text mentioning the config is not a mutation");
});

test("unknown params or non-object params never escalate", () => {
  assert.equal(classifySensitiveEscalation("exec", "exec", undefined).escalate, false);
  assert.equal(classifySensitiveEscalation("write", "write", null).escalate, false);
  assert.equal(classifySensitiveEscalation("write", "write", { path: 42 }).escalate, false);
});

test("oversized values are skipped", () => {
  const { escalate } = classifySensitiveEscalation("exec", "exec", {
    command: "x".repeat(20_000) + " openclaw.json",
  });
  assert.equal(escalate, false);
});

test("isReadOnlyCarrier classifies carriers conservatively", () => {
  assert.equal(isReadOnlyCarrier("read", "read"), true);
  assert.equal(isReadOnlyCarrier("memory_search", undefined), true);
  assert.equal(isReadOnlyCarrier("write", "write"), false);
  assert.equal(isReadOnlyCarrier("exec", "exec"), false);
  assert.equal(isReadOnlyCarrier("frobnicate", undefined), false, "unknown → can mutate");
});
