import assert from "node:assert/strict";
import test from "node:test";

import {
  AUTHORIZATION_FINGERPRINT_VERSION,
  MAX_PATH_SCOPE_DIRECTORIES,
  createAuthorizationFingerprint,
  createPolicyIdentity,
  normalizePathScope,
  normalizeTrustedRoot,
} from "../dist/scope.js";
import {
  ApprovalWindowStore,
  MAX_WINDOW_ENTRIES,
  WINDOW_STATE_VERSION,
} from "../dist/window.js";

const baseContext = {
  toolName: "write",
  toolKind: "apply_patch",
  toolInputKind: "apply_patch",
  ruleId: "builtin:apply-patch",
  policyIdentity: "sha256:policy-identity",
  effects: ["local-write"],
  categories: ["filesystem"],
  verifiedTargets: [{ path: "C:\\repo\\src\\foo.ts", targetKind: "file" }],
  analysisComplete: true,
};

function fingerprint(context = {}, options = {}) {
  return createAuthorizationFingerprint(
    { ...baseContext, ...context },
    { scope: "path", pathFallback: "none", rulesetVersion: "rules-2026-08-14", ...options },
  );
}

function createBackend(initial) {
  const state = new Map(initial === undefined ? [] : [["session", structuredClone(initial)]]);
  return {
    state,
    read(sessionKey) {
      return state.get(sessionKey);
    },
    async update(sessionKey, update) {
      state.set(sessionKey, update(state.get(sessionKey)));
    },
  };
}

test("policy identity is canonical and rejects accessor-backed input", () => {
  const left = createPolicyIdentity({
    mode: "require-approval",
    matcher: { all: [{ key: "action", equals: "write" }] },
  });
  const reordered = createPolicyIdentity({
    matcher: { all: [{ equals: "write", key: "action" }] },
    mode: "require-approval",
  });
  const changed = createPolicyIdentity({
    matcher: { all: [{ equals: "kill", key: "action" }] },
    mode: "require-approval",
  });
  assert.match(left, /^policy2:[0-9a-f]{64}$/);
  assert.equal(left, reordered);
  assert.notEqual(left, changed);

  let getterRead = false;
  const hostile = {};
  Object.defineProperty(hostile, "mode", {
    enumerable: true,
    get() {
      getterRead = true;
      return "auto";
    },
  });
  assert.equal(createPolicyIdentity(hostile), undefined);
  assert.equal(getterRead, false);
});

test("fingerprints are stable over complete semantic sets and retain full identity", () => {
  const a = fingerprint({
    effects: ["network-write", "local-write", "local-write"],
    categories: ["source-control", "filesystem", "filesystem"],
  }, { scope: "category" });
  const reordered = fingerprint({
    effects: ["local-write", "network-write"],
    categories: ["filesystem", "source-control"],
  }, { scope: "category" });

  assert.ok(a);
  assert.equal(a.scopeKey, reordered?.scopeKey);
  assert.match(a.windowKey, /^win2:[0-9a-f]{64}$/);
  assert.match(a.grantKey, /^grant2:[0-9a-f]{64}$/);
  assert.equal(a.fingerprintVersion, AUTHORIZATION_FINGERPRINT_VERSION);

  for (const change of [
    { toolName: "edit" },
    { toolKind: "exec" },
    { toolInputKind: "shell" },
    { ruleId: "user:write" },
    { policyIdentity: "sha256:other-policy" },
    { effects: ["local-write"] },
    { categories: ["deployment"] },
  ]) {
    assert.notEqual(fingerprint(change, { scope: "category" })?.scopeKey, a.scopeKey);
  }
});

test("missing, unknown, or incomplete semantics never produce a key", () => {
  for (const change of [
    { analysisComplete: false },
    { toolName: "" },
    { toolKind: "" },
    { toolInputKind: "" },
    { ruleId: "" },
    { policyIdentity: "" },
    { effects: [] },
    { categories: [] },
    { effects: ["unknown"] },
    { categories: ["unknown"] },
    { effects: ["UNKNOWN"] },
  ]) {
    assert.equal(fingerprint(change, { scope: "effect" }), undefined);
  }
  assert.equal(fingerprint({}, { scope: "effect", rulesetVersion: "" }), undefined);
});

test("path scopes normalize component prefixes for POSIX, DOS, and UNC paths", () => {
  const win = process.platform === "win32";

  const posix = normalizePathScope([
    { path: "/srv/app/src/a.ts", targetKind: "file" },
    { path: "/srv/app/src/lib/b.ts", targetKind: "file" },
  ]);
  if (win) {
    assert.equal(posix, undefined);
  } else {
    assert.deepEqual(posix, {
      directories: [
        { kind: "posix", volume: "posix:/", path: "/srv/app/src" },
        { kind: "posix", volume: "posix:/", path: "/srv/app/src/lib" },
      ],
    });
  }

  const dos = normalizePathScope([
    { path: "C:\\Repo\\SRC\\a.ts", targetKind: "file" },
    { path: "c:/repo/src/lib/b.ts", targetKind: "file" },
  ]);
  if (win) {
    assert.deepEqual(dos, {
      directories: [
        { kind: "windows-drive", volume: "drive:c", path: "c:\\repo\\src" },
        { kind: "windows-drive", volume: "drive:c", path: "c:\\repo\\src\\lib" },
      ],
    });
  } else {
    assert.equal(dos, undefined);
  }

  const unc = normalizePathScope([
    { path: "\\\\Server\\Share\\Repo\\a", targetKind: "file" },
    { path: "//server/share/repo/b", targetKind: "file" },
  ]);
  if (win) {
    assert.deepEqual(unc, {
      directories: [
        { kind: "unc", volume: "unc:server/share", path: "\\\\server\\share\\repo" },
      ],
    });
  } else {
    assert.equal(unc, undefined);
  }
});

test("path scopes reject ambiguous, broad, relative, and traversal paths", () => {
  for (const paths of [
    [],
    ["relative/file"],
    ["~/secret"],
    ["/"],
    ["C:\\"],
    ["\\\\server\\share"],
    ["/safe/../secret"],
    ["C:\\safe\\..\\secret"],
    ["\\\\?\\C:\\repo\\a"],
  ]) {
    assert.equal(
      normalizePathScope(paths.map((path) => ({ path, targetKind: "directory" }))),
      undefined,
      JSON.stringify(paths),
    );
  }
});

test("relative verified targets require an authoritative execution cwd", () => {
  assert.equal(
    normalizePathScope([{ path: "src/foo.ts", targetKind: "file" }]),
    undefined,
  );
  assert.deepEqual(
    normalizePathScope(
      [
        { path: "src/foo.ts", targetKind: "file" },
        { path: "src/lib/bar.ts", targetKind: "file" },
      ],
      "C:\\repo",
    ),
    {
      directories: [
        { kind: "windows-drive", volume: "drive:c", path: "c:\\repo\\src" },
        { kind: "windows-drive", volume: "drive:c", path: "c:\\repo\\src\\lib" },
      ],
    },
  );
  assert.equal(
    normalizePathScope([{ path: "src/../secret", targetKind: "file" }], "C:\\repo"),
    undefined,
  );
  assert.equal(
    normalizePathScope([{ path: "src/", targetKind: "file" }], "C:\\repo"),
    undefined,
  );
});

test("path scopes use a bounded, sorted, de-duplicated exact directory set", () => {
  assert.deepEqual(
    normalizePathScope([
      { path: "docs/readme.md", targetKind: "file" },
      { path: "src/a.ts", targetKind: "file" },
      { path: "SRC/b.ts", targetKind: "file" },
      { path: "D:\\other\\file.ts", targetKind: "file" },
    ], "C:\\repo"),
    {
      directories: [
        { kind: "windows-drive", volume: "drive:c", path: "c:\\repo\\docs" },
        { kind: "windows-drive", volume: "drive:c", path: "c:\\repo\\src" },
        { kind: "windows-drive", volume: "drive:d", path: "d:\\other" },
      ],
    },
  );

  assert.equal(
    normalizePathScope(Array.from(
      { length: MAX_PATH_SCOPE_DIRECTORIES + 1 },
      (_, index) => ({ path: `C:\\repo\\dir-${index}\\file.ts`, targetKind: "file" }),
    )),
    undefined,
  );
});

test("multi-target fingerprints never collapse to a common ancestor", () => {
  const approved = fingerprint({
    verifiedTargets: [
      { path: "project/src/a.ts", targetKind: "file" },
      { path: "project/docs/readme.md", targetKind: "file" },
    ],
    executionCwd: "C:\\repo",
  });
  const reordered = fingerprint({
    verifiedTargets: [
      { path: "project/docs/other.md", targetKind: "file" },
      { path: "project/src/b.ts", targetKind: "file" },
      { path: "project/src/c.ts", targetKind: "file" },
    ],
    executionCwd: "C:\\repo",
  });
  const ancestorCollisionAttempt = fingerprint({
    verifiedTargets: [
      { path: "project/.git/config", targetKind: "file" },
      { path: "project/docs/readme.md", targetKind: "file" },
    ],
    executionCwd: "C:\\repo",
  });

  assert.ok(approved);
  assert.equal(approved.windowKey, reordered?.windowKey);
  assert.equal(approved.grantKey, reordered?.grantKey);
  assert.notEqual(approved.windowKey, ancestorCollisionAttempt?.windowKey);
  assert.notEqual(approved.grantKey, ancestorCollisionAttempt?.grantKey);
});

test("relative fingerprints require execution cwd while absolute targets remain reusable", () => {
  assert.equal(fingerprint({
    verifiedTargets: [{ path: "src/a.ts", targetKind: "file" }],
  }), undefined);
  assert.equal(fingerprint(
    { verifiedTargets: [{ path: "src/a.ts", targetKind: "file" }] },
    { pathFallback: "effect" },
  ), undefined, "fallback must not broaden an unresolved supplied target");
  assert.ok(fingerprint({
    verifiedTargets: [{ path: "C:\\repo\\src\\a.ts", targetKind: "file" }],
  }));
});

test("path fallback is explicit, visible, and cannot collide with direct effect scope", () => {
  const noFallback = fingerprint({ verifiedTargets: [] });
  const fallback = fingerprint(
    { verifiedTargets: [] },
    { scope: "path", pathFallback: "effect" },
  );
  const direct = fingerprint({ verifiedTargets: [] }, { scope: "effect" });

  assert.equal(noFallback, undefined);
  assert.equal(fallback?.requestedScope, "path");
  assert.equal(fallback?.resolvedScope, "effect");
  assert.notEqual(fallback?.scopeKey, direct?.scopeKey);
  assert.equal(fallback?.grantKey, undefined);
});

test("legacy state and malformed v2 entries are discarded", () => {
  const legacyBackend = createBackend({ windows: { write: { openedAt: 1, runId: "run" } } });
  const legacyStore = new ApprovalWindowStore(legacyBackend.read, legacyBackend.update);
  assert.deepEqual(legacyStore.snapshot("session"), { version: WINDOW_STATE_VERSION, windows: {} });

  const malformedBackend = createBackend({
    version: WINDOW_STATE_VERSION,
    windows: {
      [`win2:${"a".repeat(64)}`]: {
        scopeKey: "win2:" + "b".repeat(64),
        scope: "path",
        fingerprintVersion: 2,
        rulesetVersion: "rules",
        mode: "turn",
        openedAt: 1,
        runId: "run",
      },
    },
  });
  const malformedStore = new ApprovalWindowStore(malformedBackend.read, malformedBackend.update);
  assert.deepEqual(malformedStore.snapshot("session").windows, {});
});

test("legacy destructive windows never broaden permanent grant keys", () => {
  const first = fingerprint({}, { scope: "destructive" });
  const otherPolicy = fingerprint(
    { ruleId: "other", policyIdentity: "sha256:other" },
    { scope: "destructive" },
  );
  assert.equal(first?.windowKey, otherPolicy?.windowKey);
  assert.notEqual(first?.grantKey, otherPolicy?.grantKey);
});

test("time windows store fixed expiry and do not inherit later TTL changes", async () => {
  const backend = createBackend();
  const store = new ApprovalWindowStore(backend.read, backend.update);
  const fp = fingerprint({}, { scope: "effect" });
  const cfg = { mode: "time", ttlMs: 100, bypassCritical: true };

  assert.equal(await store.open(cfg, "session", fp, "run-a", 1000), true);
  const entry = store.snapshot("session").windows[fp.scopeKey];
  assert.deepEqual(entry, {
    scopeKey: fp.scopeKey,
    scope: "effect",
    fingerprintVersion: 2,
    rulesetVersion: "rules-2026-08-14",
    mode: "time",
    openedAt: 1000,
    expiresAt: 1100,
    runId: "run-a",
  });
  assert.equal(store.isOpen({ ...cfg, ttlMs: 999999 }, "session", fp, "run-a", 1099), true);
  assert.equal(store.isOpen({ ...cfg, ttlMs: 999999 }, "session", fp, "run-a", 1100), false);
  assert.equal(store.isOpen(cfg, "session", fp, "run-a", 999), false);
});

test("turn windows require exact fingerprint, mode, session, and run", async () => {
  const backend = createBackend();
  const store = new ApprovalWindowStore(backend.read, backend.update);
  const fp = fingerprint();
  const cfg = { mode: "turn", ttlMs: 300_000, bypassCritical: true };

  assert.equal(await store.open(cfg, "session", fp, undefined, 1000), false);
  assert.equal(await store.open(cfg, "session", fp, "run-a", 1000), true);
  assert.equal(store.isOpen(cfg, "session", fp, "run-a", 1001), true);
  assert.equal(store.isOpen(cfg, "session", fp, "run-b", 1001), false);
  assert.equal(store.isOpen(cfg, "other", fp, "run-a", 1001), false);
  assert.equal(store.isOpen({ ...cfg, mode: "time" }, "session", fp, "run-a", 1001), false);
  assert.equal(store.isOpen(cfg, "session", fingerprint({
    verifiedTargets: [{ path: "C:\\Windows\\System32\\x", targetKind: "file" }],
  }), "run-a", 1001), false);
});

test("opening windows removes expired entries and enforces a hard capacity", async () => {
  const backend = createBackend();
  const store = new ApprovalWindowStore(backend.read, backend.update);
  const cfg = { mode: "time", ttlMs: 10_000, bypassCritical: true };

  for (let i = 0; i < MAX_WINDOW_ENTRIES + 2; i += 1) {
    const fp = fingerprint({ ruleId: `rule:${i}` }, { scope: "effect" });
    await store.open(cfg, "session", fp, undefined, 1000 + i);
  }
  const state = store.snapshot("session");
  assert.equal(Object.keys(state.windows).length, MAX_WINDOW_ENTRIES);
  assert.equal(state.windows[fingerprint({ ruleId: "rule:0" }, { scope: "effect" }).scopeKey], undefined);
  assert.ok(state.windows[fingerprint({ ruleId: `rule:${MAX_WINDOW_ENTRIES + 1}` }, { scope: "effect" }).scopeKey]);

  const replacement = fingerprint({ ruleId: "after-expiry" }, { scope: "effect" });
  await store.open(cfg, "session", replacement, undefined, 20_000);
  assert.equal(Object.keys(store.snapshot("session").windows).length, 1);
});

test("root path mode remaps a scope to its nearest trusted root", () => {
  const root = normalizeTrustedRoot("C:\\repo");
  assert.ok(root, "C:\\repo normalizes to a trusted root");
  const opts = { pathMode: "root", writeRoots: [root] };

  const a = fingerprint(
    { verifiedTargets: [{ path: "C:\\repo\\src\\a.ts", targetKind: "file" }] },
    opts,
  );
  const b = fingerprint(
    { verifiedTargets: [{ path: "C:\\repo\\lib\\b.ts", targetKind: "file" }] },
    opts,
  );
  assert.ok(a?.windowKey && b?.windowKey, "both under the root must produce keys");
  assert.equal(a.windowKey, b.windowKey, "sibling subdirs share the recursive root scope");
});

test("root path mode keeps outside-root writes exact (no high-level broadening)", () => {
  const root = normalizeTrustedRoot("C:\\repo");
  const opts = { pathMode: "root", writeRoots: [root] };

  const inside = fingerprint(
    { verifiedTargets: [{ path: "C:\\repo\\src\\a.ts", targetKind: "file" }] },
    opts,
  );
  const outside = fingerprint(
    { verifiedTargets: [{ path: "C:\\Users\\me\\Desktop\\x.txt", targetKind: "file" }] },
    opts,
  );
  assert.ok(inside?.windowKey && outside?.windowKey);
  assert.notEqual(inside.windowKey, outside.windowKey, "outside a root stays exact → no volume-wide grant");
});

test("directory path mode (default) keeps different directories distinct", () => {
  const a = fingerprint({ verifiedTargets: [{ path: "C:\\repo\\src\\a.ts", targetKind: "file" }] });
  const b = fingerprint({ verifiedTargets: [{ path: "C:\\repo\\lib\\b.ts", targetKind: "file" }] });
  assert.ok(a?.windowKey && b?.windowKey);
  assert.notEqual(a.windowKey, b.windowKey, "without root mode, sibling dirs are separate scopes");
});
