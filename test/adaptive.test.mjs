import assert from "node:assert/strict";
import test from "node:test";

import { createAuthorizationFingerprint } from "../dist/scope.js";
import {
  evaluateAdaptiveEligibility,
  isStrictAbsoluteTarget,
} from "../dist/adaptive/eligibility.js";
import {
  AdaptiveLeaseStore,
  normalizeAdaptiveState,
  ADAPTIVE_STATE_VERSION,
} from "../dist/adaptive/state.js";
import { resolveConfig } from "../dist/config.js";

/** A narrow, path-bound fingerprint with a real grantKey (absolute path). */
function fp(path = "C:\\repo\\src\\a.ts") {
  const fingerprint = createAuthorizationFingerprint({
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
  assert.ok(fingerprint?.grantKey, "expected a grantKey for an absolute path");
  return fingerprint;
}

function report(overrides = {}) {
  return {
    complete: true,
    windowEligible: true,
    analyzerIds: ["builtin.file-mutation-semantics"],
    effects: ["local-write"],
    categories: ["filesystem"],
    verifiedTargets: [{ path: "C:\\repo\\src\\a.ts", targetKind: "file" }],
    findings: [],
    ...overrides,
  };
}

function decision(overrides = {}) {
  return {
    mode: "require-approval",
    source: "classifier",
    severity: "warning",
    windowEligible: true,
    semanticReport: report(),
    ...overrides,
  };
}

function input(overrides = {}) {
  return {
    decision: decision(),
    fingerprint: fp(),
    isParamScopedRule: false,
    sessionKey: "agent:main:test",
    toolCallId: "call-1",
    rememberAllowAlways: true,
    ...overrides,
  };
}

// ── isStrictAbsoluteTarget ────────────────────────────────────────────────

test("isStrictAbsoluteTarget accepts POSIX, Windows drive, and UNC, rejects rooted-relative", () => {
  assert.equal(isStrictAbsoluteTarget("/tmp/a.ts"), true);
  assert.equal(isStrictAbsoluteTarget("C:\\repo\\a.ts"), true);
  assert.equal(isStrictAbsoluteTarget("C:/repo/a.ts"), true);
  assert.equal(isStrictAbsoluteTarget("\\\\server\\share\\a.ts"), true);
  assert.equal(isStrictAbsoluteTarget("//server/share/a.ts"), true);

  assert.equal(isStrictAbsoluteTarget("src/a.ts"), false);
  assert.equal(isStrictAbsoluteTarget("C:foo"), false); // drive-relative
  assert.equal(isStrictAbsoluteTarget("\\foo"), false); // root-relative
  assert.equal(isStrictAbsoluteTarget(""), false);
  assert.equal(isStrictAbsoluteTarget("  "), false);
  assert.equal(isStrictAbsoluteTarget("a\nb"), false);
});

// ── evaluateAdaptiveEligibility ───────────────────────────────────────────

test("adaptive eligibility accepts canonical absolute-path local file writes", () => {
  const e = evaluateAdaptiveEligibility(input());
  assert.equal(e.eligible, true);
  assert.deepEqual(e.reasonCodes, []);
  assert.equal(e.targetCount, 1);
});

test("adaptive eligibility rejects every non-safe-file shape", () => {
  const cases = [
    [input({ decision: decision({ mode: "auto" }) }), "not-require-approval"],
    [input({ decision: decision({ source: "user" }) }), "explicit-user-policy"],
    [input({ isParamScopedRule: true }), "param-scoped-policy"],
    [input({ decision: decision({ severity: "critical" }) }), "critical"],
    [input({ decision: decision({ semanticReport: report({ complete: false }) }) }), "analysis-incomplete"],
    [input({ decision: decision({ windowEligible: false }) }), "not-reusable"],
    [input({ decision: decision({ semanticReport: report({ analyzerIds: ["builtin.command-semantics"] }) }) }), "wrong-analyzer-family"],
    [input({ decision: decision({ semanticReport: report({ effects: ["local-write", "destructive"] }) }) }), "unsupported-effects"],
    [input({ decision: decision({ semanticReport: report({ categories: ["filesystem", "network"] }) }) }), "unsupported-categories"],
    [input({ decision: decision({ semanticReport: report({ verifiedTargets: [] }) }) }), "missing-target"],
    [input({ decision: decision({ semanticReport: report({ verifiedTargets: [{ path: "src/a.ts", targetKind: "file" }] }) }) }), "non-absolute-target"],
    [input({ fingerprint: undefined }), "missing-path-fingerprint"],
    [input({ sessionKey: undefined }), "missing-session"],
    [input({ rememberAllowAlways: false }), "remember-disabled"],
    [input({ toolCallId: undefined }), "missing-tool-call-id"],
  ];
  for (const [inp, code] of cases) {
    const e = evaluateAdaptiveEligibility(inp);
    assert.equal(e.eligible, false, code);
    assert.ok(e.reasonCodes.includes(code), `expected ${code}, got ${JSON.stringify(e.reasonCodes)}`);
  }
});

test("adaptive eligibility rejects delete/move patch effects", () => {
  const e = evaluateAdaptiveEligibility(input({
    decision: decision({
      semanticReport: report({ effects: ["local-write", "destructive"] }),
    }),
  }));
  assert.equal(e.eligible, false);
  assert.ok(e.reasonCodes.includes("unsupported-effects"));
});

// ── AdaptiveLeaseStore ────────────────────────────────────────────────────

function createBackend(defaultValue) {
  const state = new Map();
  return {
    store: state,
    read(sessionKey) {
      return state.get(sessionKey);
    },
    async update(sessionKey, update) {
      state.set(sessionKey, update(state.get(sessionKey) ?? structuredClone(defaultValue)));
    },
  };
}

const EMPTY = { version: ADAPTIVE_STATE_VERSION, observations: {}, leases: {} };
const CFG = { ttlMs: 900_000, maxUses: 20 };

test("grant creates a lease and consume deducts exactly one use", async () => {
  const backend = createBackend(EMPTY);
  const store = new AdaptiveLeaseStore(backend.read, backend.update, CFG);
  const key = fp();

  assert.equal(await store.grant("s", key, 1000, "origin-1"), true);
  const first = await store.consume("s", key, 2000);
  assert.equal(first.outcome, "consumed");
  assert.equal(first.remainingBefore, 20);
  assert.equal(first.remainingAfter, 19);

  const snap = store.snapshot("s");
  assert.equal(snap.leases[key.grantKey].remainingUses, 19);
  assert.equal(snap.leases[key.grantKey].origin, "explicit-allow-always");
  assert.equal(snap.leases[key.grantKey].originToolCallId, "origin-1");
});

test("consume exhausts the budget then refuses", async () => {
  const backend = createBackend(EMPTY);
  const store = new AdaptiveLeaseStore(backend.read, backend.update, { ttlMs: 900_000, maxUses: 2 });
  const key = fp();
  await store.grant("s", key, 1000, "origin-1");

  assert.equal((await store.consume("s", key, 1100)).remainingAfter, 1);
  assert.equal((await store.consume("s", key, 1200)).remainingAfter, 0);
  const exhausted = await store.consume("s", key, 1300);
  assert.equal(exhausted.outcome, "exhausted");
  assert.equal(exhausted.remainingAfter, 0);
});

test("expired leases refuse and clock rollback does not consume", async () => {
  const backend = createBackend(EMPTY);
  const store = new AdaptiveLeaseStore(backend.read, backend.update, { ttlMs: 60_000, maxUses: 5 });
  const key = fp();
  await store.grant("s", key, 1000, "origin-1");

  assert.equal((await store.consume("s", key, 1000 + 59_999)).outcome, "consumed");
  assert.equal((await store.consume("s", key, 1000 + 60_000)).outcome, "expired");
  assert.equal((await store.consume("s", key, 999)).outcome, "clock-rollback");
});

test("grant replay with the same originToolCallId never refills", async () => {
  const backend = createBackend(EMPTY);
  const store = new AdaptiveLeaseStore(backend.read, backend.update, { ttlMs: 900_000, maxUses: 3 });
  const key = fp();

  assert.equal(await store.grant("s", key, 1000, "origin-1"), true);
  await store.consume("s", key, 1100);
  await store.consume("s", key, 1200);
  assert.equal(store.snapshot("s").leases[key.grantKey].remainingUses, 1);

  // Replay of the same approval callback must not refill to 3.
  assert.equal(await store.grant("s", key, 1300, "origin-1"), false);
  assert.equal(store.snapshot("s").leases[key.grantKey].remainingUses, 1);
});

test("consume returns missing for another path and mismatch for config drift", async () => {
  const backend = createBackend(EMPTY);
  const key = fp();
  const store = new AdaptiveLeaseStore(backend.read, backend.update, { ttlMs: 900_000, maxUses: 20 });
  await store.grant("s", key, 1000, "origin-1");

  // A different directory produces a different grantKey → missing (no lease).
  const other = fp("C:\\repo\\other\\b.ts");
  assert.equal((await store.consume("s", other, 2000)).outcome, "missing");
  assert.equal(store.snapshot("s").leases[key.grantKey].remainingUses, 20);

  // Same grantKey but a store whose ttlMs/maxUses differ → config mismatch.
  const drifted = new AdaptiveLeaseStore(backend.read, backend.update, { ttlMs: 60_000, maxUses: 20 });
  assert.equal((await drifted.consume("s", key, 2000)).outcome, "mismatch");
  assert.equal(drifted.snapshot("s").leases[key.grantKey], undefined);
});

test("revoke removes both the lease and observation", async () => {
  const backend = createBackend(EMPTY);
  const store = new AdaptiveLeaseStore(backend.read, backend.update, CFG);
  const key = fp();
  await store.observeApproval("s", key, "allow-once", 1000);
  await store.grant("s", key, 1000, "origin-1");
  await store.revoke("s", key);

  const snap = store.snapshot("s");
  assert.equal(snap.leases[key.grantKey], undefined);
  assert.equal(snap.observations[key.grantKey], undefined);
});

test("observeApproval only counts allow-once and is capped", async () => {
  const backend = createBackend(EMPTY);
  const store = new AdaptiveLeaseStore(backend.read, backend.update, CFG);
  const key = fp();

  await store.observeApproval("s", key, "allow-once", 1000);
  await store.observeApproval("s", key, "allow-always", 2000); // ignored
  await store.observeApproval("s", key, "allow-once", 3000);

  assert.equal(store.approvalCount("s", key), 2);
});

test("normalizeAdaptiveState rejects legacy, malformed, and oversized entries", () => {
  assert.deepEqual(normalizeAdaptiveState(undefined), EMPTY);
  assert.deepEqual(normalizeAdaptiveState({ version: 999 }), EMPTY);
  assert.deepEqual(normalizeAdaptiveState({ version: ADAPTIVE_STATE_VERSION }), {
    version: ADAPTIVE_STATE_VERSION,
    observations: {},
    leases: {},
  });

  const key = fp().grantKey;
  // Malformed lease (negative remainingUses) is dropped.
  const malformed = normalizeAdaptiveState({
    version: ADAPTIVE_STATE_VERSION,
    observations: {},
    leases: {
      [key]: {
        fingerprintKey: key,
        fingerprintVersion: 2,
        rulesetVersion: "rules-v1",
        eligibilityVersion: "safe-file-v1",
        origin: "explicit-allow-always",
        originToolCallId: "o",
        grantedAt: "2026-01-01T00:00:00.000Z",
        expiresAt: "2026-01-01T01:00:00.000Z",
        issuedTtlMs: 900_000,
        maxUses: 20,
        remainingUses: -1,
      },
    },
  });
  assert.deepEqual(malformed.leases, {});
});

test("adaptive state contains only opaque digests and counters, never raw paths or params", () => {
  const backend = createBackend(EMPTY);
  const store = new AdaptiveLeaseStore(backend.read, backend.update, CFG);
  const key = fp("C:\\secret\\file.ts");
  store.grant("s", key, 1000, "origin-1");
  const json = JSON.stringify(store.snapshot("s"));
  assert.equal(json.includes("C:\\secret"), false);
  assert.equal(json.includes("secret"), false);
});

// ── resolveConfig adaptive ────────────────────────────────────────────────

test("adaptiveAutoPass parses all modes and falls back to off on invalid", () => {
  for (const mode of ["off", "shadow", "suggest", "enforce"]) {
    assert.equal(resolveConfig({ adaptiveAutoPass: { mode } }).adaptiveAutoPass.mode, mode);
  }
  assert.equal(resolveConfig({ adaptiveAutoPass: { mode: "banana" } }).adaptiveAutoPass.mode, "off");
  assert.equal(resolveConfig({}).adaptiveAutoPass.mode, "off");
});

test("adaptiveAutoPass bounds clamp to documented ranges", () => {
  const cfg = resolveConfig({
    adaptiveAutoPass: { ttlMs: 1, maxUses: 9999, suggestAfterApprovals: -5 },
  });
  assert.equal(cfg.adaptiveAutoPass.ttlMs, 60_000);
  assert.equal(cfg.adaptiveAutoPass.maxUses, 100);
  assert.equal(cfg.adaptiveAutoPass.suggestAfterApprovals, 1);

  const defaults = resolveConfig({}).adaptiveAutoPass;
  assert.equal(defaults.ttlMs, 900_000);
  assert.equal(defaults.maxUses, 20);
  assert.equal(defaults.suggestAfterApprovals, 2);
});

test("adaptiveAutoPass accessor/prototype-backed values fail closed", () => {
  const proto = { mode: "enforce" };
  const raw = Object.create(proto);
  raw.ttlMs = 900_000;
  raw.maxUses = 20;
  raw.suggestAfterApprovals = 2;
  const cfg = resolveConfig({ adaptiveAutoPass: raw });
  assert.equal(cfg.adaptiveAutoPass.mode, "off");
});
