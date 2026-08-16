import test from "node:test";
import assert from "node:assert/strict";

import {
  DEFAULT_EXEC_LEASE_MS,
  EXEC_LEASE_STATE_VERSION,
  ExecLeaseStore,
  isOrdinaryExec,
  normalizeExecLeaseState,
  parseExecLeaseDuration,
} from "../dist/exec-lease.js";

function backend() {
  const states = new Map();
  return {
    read: (key) => states.get(key),
    update: async (key, update) => states.set(key, update(states.get(key))),
    states,
  };
}

test("exec lease duration parser is bounded to one hour", () => {
  assert.equal(parseExecLeaseDuration("15m"), 900_000);
  assert.equal(parseExecLeaseDuration("15"), 900_000);
  assert.equal(parseExecLeaseDuration("1h"), 3_600_000);
  assert.equal(parseExecLeaseDuration("0m"), undefined);
  assert.equal(parseExecLeaseDuration("61m"), undefined);
  assert.equal(parseExecLeaseDuration("2h"), undefined);
  assert.equal(parseExecLeaseDuration("forever"), undefined);
  assert.equal(DEFAULT_EXEC_LEASE_MS, 900_000);
});

test("exec lease is session-scoped, fixed-expiry, and revocable", async () => {
  const state = backend();
  const store = new ExecLeaseStore(state.read, state.update);
  const now = Date.parse("2026-08-17T00:00:00.000Z");

  assert.equal(store.isActive("a", now), false);
  await store.grant("a", 900_000, now);
  assert.equal(store.isActive("a", now), true);
  assert.equal(store.isActive("b", now), false);
  assert.equal(store.isActive("a", now + 899_999), true);
  assert.equal(store.isActive("a", now + 900_000), false);

  await store.revoke("a");
  assert.equal(store.isActive("a", now), false);
});

test("malformed or duration-inconsistent persisted leases fail closed", () => {
  const grantedAt = "2026-08-17T00:00:00.000Z";
  const invalid = normalizeExecLeaseState({
    version: EXEC_LEASE_STATE_VERSION,
    lease: {
      policyVersion: "ordinary-exec-v1",
      grantedAt,
      expiresAt: "2099-01-01T00:00:00.000Z",
      issuedTtlMs: 900_000,
    },
  });
  assert.deepEqual(invalid, { version: EXEC_LEASE_STATE_VERSION });
  assert.deepEqual(normalizeExecLeaseState({ version: 0, lease: {} }), {
    version: EXEC_LEASE_STATE_VERSION,
  });
});

test("ordinary exec classification excludes Code Mode and inconsistent envelopes", () => {
  assert.equal(isOrdinaryExec("exec"), true);
  assert.equal(isOrdinaryExec("EXEC"), true);
  assert.equal(isOrdinaryExec("exec", "code_mode_exec", "javascript"), false);
  assert.equal(isOrdinaryExec("exec", undefined, "javascript"), false);
  assert.equal(isOrdinaryExec("bash"), false);
});
