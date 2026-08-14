import assert from "node:assert/strict";
import test from "node:test";

import {
  DenyCooldownStore,
  normalizeDenyCooldownState,
} from "../dist/deny-cooldown.js";

function createSessionBackend(defaultValue) {
  const state = new Map();
  return {
    read(sessionKey) {
      return state.get(sessionKey);
    },
    async update(sessionKey, update) {
      state.set(sessionKey, update(state.get(sessionKey) ?? structuredClone(defaultValue)));
    },
  };
}

const COOLDOWN_MS = 120_000;

function store(backend, cooldownMs = COOLDOWN_MS) {
  return new DenyCooldownStore(backend.read, backend.update, cooldownMs);
}

test("recordDeny cools down the same scope key within the window", async () => {
  const backend = createSessionBackend({ version: 1, denials: {} });
  const s = store(backend);

  await s.recordDeny("session-a", "scope:write:x", 1000);

  assert.equal(s.isCoolingDown("session-a", "scope:write:x", 1001), true);
  assert.equal(s.isCoolingDown("session-a", "scope:write:x", 1000 + COOLDOWN_MS - 1), true);
  assert.equal(s.isCoolingDown("session-a", "scope:write:x", 1000 + COOLDOWN_MS), false);
  assert.equal(s.isCoolingDown("session-a", "scope:write:y", 1001), false, "different scope unaffected");
  assert.equal(s.isCoolingDown("session-b", "scope:write:x", 1001), false, "other session unaffected");
});

test("cooldown is disabled when cooldownMs is zero", async () => {
  const backend = createSessionBackend({ version: 1, denials: {} });
  const s = store(backend, 0);

  await s.recordDeny("session-a", "scope:x", 1000);

  assert.equal(s.isCoolingDown("session-a", "scope:x", 1001), false);
  assert.deepEqual(s.snapshot("session-a"), { version: 1, denials: {} });
});

test("clock rollback never extends a cooldown", async () => {
  const backend = createSessionBackend({ version: 1, denials: {} });
  const s = store(backend);

  await s.recordDeny("session-a", "scope:x", 5000);

  assert.equal(s.isCoolingDown("session-a", "scope:x", 4000), false, "before deniedAt");
  assert.equal(s.isCoolingDown("session-a", "scope:x", 6000), true);
});

test("normalize discards malformed and legacy state", () => {
  const valid = normalizeDenyCooldownState({
    version: 1,
    denials: {
      "scope:x": { scopeKey: "scope:x", deniedAt: 1000, expiresAt: 2000 },
    },
  });
  assert.equal(valid.denials["scope:x"].expiresAt, 2000);

  const legacy = normalizeDenyCooldownState({ version: 0, denials: { "scope:x": { scopeKey: "scope:x", deniedAt: 1000, expiresAt: 2000 } } });
  assert.deepEqual(legacy, { version: 1, denials: {} });

  const malformed = normalizeDenyCooldownState({
    version: 1,
    denials: {
      "key-mismatch": { scopeKey: "other", deniedAt: 1000, expiresAt: 2000 },
      "no-expiry": { scopeKey: "no-expiry", deniedAt: 1000 },
      "expiry-before": { scopeKey: "expiry-before", deniedAt: 2000, expiresAt: 1000 },
      "nan": { scopeKey: "nan", deniedAt: "1000", expiresAt: 2000 },
    },
  });
  assert.deepEqual(malformed.denials, {});
});

test("denials are bounded to MAX entries with oldest evicted", async () => {
  const backend = createSessionBackend({ version: 1, denials: {} });
  const s = store(backend);

  // Exceed the bound: 128 max; record 130 distinct scopes.
  for (let i = 0; i < 130; i += 1) {
    await s.recordDeny("session-a", `scope:${i}`, 1000 + i);
  }
  const denials = Object.keys(s.snapshot("session-a").denials);
  assert.equal(denials.length, 128);
  assert.equal(denials.includes("scope:0"), false, "oldest evicted");
  assert.equal(denials.includes("scope:129"), true);
});

test("recording prunes expired entries as a side effect", async () => {
  const backend = createSessionBackend({ version: 1, denials: {} });
  const s = store(backend);

  await s.recordDeny("session-a", "scope:old", 1000);
  await s.recordDeny("session-a", "scope:new", 1000 + COOLDOWN_MS + 1000);

  const denials = s.snapshot("session-a").denials;
  assert.equal(Object.hasOwn(denials, "scope:old"), false, "expired pruned");
  assert.equal(Object.hasOwn(denials, "scope:new"), true);
});
