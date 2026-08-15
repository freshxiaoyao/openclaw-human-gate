import assert from "node:assert/strict";
import test from "node:test";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { DecisionLog, digestSessionKey } from "../dist/decision-log.js";
import { resolveConfig } from "../dist/config.js";

function logConfig(overrides = {}) {
  return { enabled: true, maxEntries: 512, ...overrides };
}

test("decision log records and snapshots in order", () => {
  const log = new DecisionLog(logConfig());
  log.record({ ts: 1000, sessionDigest: "a", toolName: "write", decision: "ask" });
  log.record({ ts: 2000, sessionDigest: "a", toolName: "write", decision: "allow-once" });

  const entries = log.snapshot();
  assert.equal(entries.length, 2);
  assert.equal(entries[0].decision, "ask");
  assert.equal(entries[1].decision, "allow-once");
  assert.equal(entries[0].toolName, "write");
});

test("decision log evicts oldest entries beyond maxEntries", () => {
  const log = new DecisionLog(logConfig({ maxEntries: 4 }));
  for (let i = 0; i < 10; i += 1) {
    log.record({ ts: i, sessionDigest: "a", toolName: "t", decision: "auto" });
  }
  const entries = log.snapshot();
  assert.equal(entries.length, 4);
  assert.equal(entries[0].ts, 6, "oldest entries are evicted first");
  assert.equal(entries[3].ts, 9);
});

test("disabled log records nothing", () => {
  const log = new DecisionLog({ enabled: false, maxEntries: 16 });
  log.record({ ts: 1, sessionDigest: "a", toolName: "t", decision: "ask" });
  assert.equal(log.snapshot().length, 0);
  assert.equal(log.askRate(60_000), 0);
});

test("askRate counts asks in the trailing window only", () => {
  const log = new DecisionLog(logConfig());
  log.record({ ts: 1000, sessionDigest: "a", toolName: "t", decision: "ask" });
  log.record({ ts: 2000, sessionDigest: "a", toolName: "t", decision: "ask" });
  log.record({ ts: 2000, sessionDigest: "a", toolName: "t", decision: "auto" });
  assert.equal(log.askRate(60_000, 3000), 2, "only ask decisions count");
  assert.equal(log.askRate(60_000, 4000), 2);
  assert.equal(log.askRate(60_000, 2000 + 60_000 + 1), 0, "window slides forward");
});

test("entries are bounded to safe field lengths", () => {
  const log = new DecisionLog(logConfig());
  log.record({
    ts: -5,
    sessionDigest: "x".repeat(200),
    sessionId: "y".repeat(200),
    toolName: "t".repeat(500),
    ruleId: "r".repeat(500),
    scopeDigest: "s".repeat(200),
    reason: "z".repeat(2000),
    decision: "block",
  });
  const [entry] = log.snapshot();
  assert.equal(entry.sessionDigest.length, 24);
  assert.equal(entry.sessionId.length, 64);
  assert.equal(entry.toolName.length, 200);
  assert.equal(entry.ruleId.length, 200);
  assert.equal(entry.scopeDigest.length, 64);
  assert.equal(entry.reason.length, 500);
});

test("filePath appends JSONL lines best-effort", async () => {
  const dir = mkdtempSync(join(tmpdir(), "hg-decision-"));
  const file = join(dir, "decisions.jsonl");
  const log = new DecisionLog(logConfig({ filePath: file }));
  log.record({ ts: 1000, sessionDigest: "a", toolName: "write", decision: "ask" });
  log.record({ ts: 2000, sessionDigest: "a", toolName: "write", decision: "deny" });
  await log.flush();

  const lines = readFileSync(file, "utf8").trim().split("\n");
  assert.equal(lines.length, 2);
  assert.equal(JSON.parse(lines[0]).decision, "ask");
  assert.equal(JSON.parse(lines[1]).decision, "deny");
  if (process.platform !== "win32") {
    const { statSync } = await import("node:fs");
    assert.equal(statSync(file).mode & 0o777, 0o600, "log file must be owner-only");
  }
});

test("async appends do not block record()", async () => {
  const dir = mkdtempSync(join(tmpdir(), "hg-decision-"));
  const file = join(dir, "decisions.jsonl");
  const log = new DecisionLog(logConfig({ filePath: file }));
  const started = Date.now();
  for (let i = 0; i < 200; i += 1) {
    log.record({ ts: i, sessionDigest: "a", toolName: "t", decision: "ask" });
  }
  const elapsed = Date.now() - started;
  await log.flush();
  const lines = readFileSync(file, "utf8").trim().split("\n");
  assert.equal(lines.length, 200);
  assert.ok(elapsed < 1000, `200 records should not block: took ${elapsed}ms`);
});

test("askWindow is pruned on record even when askRate is never called", () => {
  const log = new DecisionLog(logConfig());
  const retention = 3_600_000;
  log.record({ ts: 1000, sessionDigest: "a", toolName: "t", decision: "ask" });
  // A far-future ask prunes the stale one at record time.
  log.record({ ts: 1000 + retention + 1, sessionDigest: "a", toolName: "t", decision: "ask" });
  assert.equal(
    log.askRate(Number.MAX_SAFE_INTEGER, 1000 + retention + 1),
    1,
    "the stale ask was pruned on record, not only on askRate",
  );
});

test("askRate windows are clamped to the retention", () => {
  const log = new DecisionLog(logConfig());
  log.record({ ts: 1_000_000, sessionDigest: "a", toolName: "t", decision: "ask" });
  // A window larger than the retention must not resurrect pruned entries.
  assert.equal(log.askRate(86_400_000, 1_000_001), 1);
});

test("digestSessionKey is stable and bounded", () => {
  const a = digestSessionKey("agent:main:cron:run-1");
  const b = digestSessionKey("agent:main:cron:run-1");
  const c = digestSessionKey("agent:main:wechat");
  assert.equal(a, b);
  assert.notEqual(a, c);
  assert.equal(a.length, 24);
  assert.match(a, /^[0-9a-f]{24}$/);
});

test("resolveConfig parses the new P0 fields", () => {
  const cfg = resolveConfig({
    denyCooldownMs: 45_000,
    selfProtection: { enabled: false },
    decisionLog: { enabled: false, maxEntries: 64, filePath: "~/logs/hg.jsonl" },
    clawdNotify: { enabled: true },
  });
  assert.equal(cfg.denyCooldownMs, 45_000);
  assert.equal(cfg.selfProtection.enabled, false);
  assert.equal(cfg.decisionLog.enabled, false);
  assert.equal(cfg.decisionLog.maxEntries, 64);
  assert.equal(cfg.decisionLog.filePath, "~/logs/hg.jsonl");
  assert.equal(cfg.clawdNotify.enabled, true);

  const clamped = resolveConfig({ denyCooldownMs: 99_999_999, decisionLog: { maxEntries: 1 } });
  assert.equal(clamped.denyCooldownMs, 3_600_000);
  assert.equal(clamped.decisionLog.maxEntries, 16);

  const defaults = resolveConfig({});
  assert.equal(defaults.denyCooldownMs, 120_000);
  assert.equal(defaults.selfProtection.enabled, true);
  assert.equal(defaults.decisionLog.enabled, true);
  assert.equal(defaults.decisionLog.filePath, undefined);
  assert.equal(defaults.clawdNotify.enabled, false, "clawdNotify is opt-in (default off)");
});
