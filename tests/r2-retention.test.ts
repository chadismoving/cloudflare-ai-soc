import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { convertV4MiniflareOptions, Miniflare } from "miniflare";
import { afterEach, beforeEach, expect, it } from "vitest";
import cleanup from "../apps/ingest/src/r2-retention-worker";

const root = fileURLToPath(new URL("../", import.meta.url));
const past = "2000-01-01T00:00:00.000Z";
const future = "2099-01-01T00:00:00.000Z";
const anchor = (expiry: string) => new Date(Date.parse(expiry) - 90 * 86400000).toISOString();
const content = '{"fixture":true,"source":"synthetic"}';
const hash = (v: string) => createHash("sha256").update(v).digest("hex");
const key = `cases/ingested/${"a".repeat(64)}.json`;
const policy = [
  {
    source_id: "fixture-evidence",
    source_kind: "case",
    object_key: key,
    sha256: hash(content),
    expires_at: past,
    anchor: anchor(past),
  },
];
const vars = {
  APP_ENV: "local",
  DATA_ENVIRONMENT: "simulation",
  RETENTION_PROFILE: "local-r2-retention-v1",
  RETENTION_MODE: "apply",
  LOCAL_R2_POLICY: JSON.stringify(policy),
};
let runtime: Miniflare;
let db: D1Database;
let bucket: R2Bucket;
let outbound = 0;
beforeEach(async () => {
  outbound = 0;
  runtime = new Miniflare({
    ...convertV4MiniflareOptions({
      workers: [
        {
          name: "cleanup",
          modules: true,
          scriptPath: `${root}.local/test-build/r2-retention/cleanup/r2-retention-worker.js`,
          compatibilityDate: "2026-10-27",
          compatibilityFlags: ["nodejs_compat"],
          cf: false,
          bindings: vars,
          d1Databases: { SIMULATION_DB: "r2-retention-fixture" },
          r2Buckets: { SIMULATION_STORE: "r2-retention-fixture" },
          outboundService: async () => {
            outbound++;
            return new Response("Disabled", { status: 503 });
          },
        },
        {
          name: "metadata",
          modules: true,
          scriptPath: `${root}.local/test-build/r2-retention/metadata/retention-outbox-worker.js`,
          compatibilityDate: "2026-10-27",
          compatibilityFlags: ["nodejs_compat"],
          cf: false,
          bindings: {
            APP_ENV: "local",
            DATA_ENVIRONMENT: "simulation",
            RETENTION_PROFILE: "local-retention-outbox-v1",
            RETENTION_MODE: "apply",
          },
          d1Databases: { SIMULATION_DB: "r2-retention-fixture" },
          outboundService: async () => {
            outbound++;
            return new Response("Disabled", { status: 503 });
          },
        },
        {
          name: "ingest",
          modules: true,
          scriptPath: `${root}.local/test-build/r2-retention/ingest/index.js`,
          compatibilityDate: "2026-10-27",
          compatibilityFlags: ["nodejs_compat"],
          cf: false,
          bindings: {
            APP_ENV: "cloud-simulation",
            DATA_ENVIRONMENT: "simulation",
            CLOUD_SIMULATION_PROFILE: "phase2b-retention-v1",
          },
          d1Databases: { SIMULATION_DB: "r2-retention-fixture" },
          r2Buckets: { SIMULATION_STORE: "r2-retention-fixture" },
          outboundService: async () => {
            outbound++;
            return new Response("Disabled", { status: 503 });
          },
        },
      ],
    }),
    host: "127.0.0.1",
    port: 0,
    telemetry: { enabled: false },
  });
  db = (await runtime.getD1Database("SIMULATION_DB")) as unknown as D1Database;
  bucket = (await runtime.getR2Bucket("SIMULATION_STORE")) as unknown as R2Bucket;
  const names = [
    ...[
      "0001_foundation.sql",
      "0002_ingestion.sql",
      "0003_ingestion_metrics.sql",
      "0004_ingestion_observability.sql",
    ].map((n) => `migrations/${n}`),
    "retention-migrations/0005_retention_guard_indexes.sql",
    "r2-retention-migrations/0006_r2_deletion_outbox.sql",
  ];
  for (const name of names)
    for (const statement of (await readFile(`${root}infrastructure/${name}`, "utf8"))
      .split(";")
      .map((s) => s.trim())
      .filter(Boolean))
      await db.prepare(statement).run();
  await db
    .prepare(
      "INSERT INTO zones VALUES ('fixture-zone','fixture-account','demo.fixture.invalid',1,'simulation')",
    )
    .run();
});
afterEach(async () => {
  expect(outbound).toBe(0);
  await runtime?.dispose();
});
const count = async (table: string) =>
  (await db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).first<{ n: number }>())?.n;
const env = () => ({ ...vars, SIMULATION_DB: db, SIMULATION_STORE: bucket });
const controller = (cron: string) => ({ cron, scheduledTime: Date.now(), noRetry() {} });
const runMetadata = async () => {
  const result = await (await runtime.getWorker("metadata")).scheduled({ cron: "17 * * * *" });
  if (result.outcome !== "ok") throw Error("Metadata transaction rejected");
};
const run = () => cleanup.scheduled(controller("37 * * * *"), env());
async function source(expiry = past) {
  await db
    .prepare(
      "INSERT INTO incidents VALUES ('fixture-case','simulation','fixture-zone','Synthetic','waf','info','new',?,?,'Synthetic',NULL,?)",
    )
    .bind(anchor(expiry), anchor(expiry), expiry)
    .run();
  await db
    .prepare(
      "INSERT INTO evidence_objects VALUES ('fixture-evidence','fixture-case','simulation','fixture-zone',?,'cases',?,?,?)",
    )
    .bind(key, hash(content), anchor(expiry), expiry)
    .run();
  await bucket.put(key, content);
}
async function task() {
  await source();
  await runMetadata();
}
async function retryNow() {
  await db
    .prepare("UPDATE r2_deletion_outbox SET lease_until=NULL,next_attempt_at=?")
    .bind(past)
    .run();
}
function storage(override: Partial<R2Bucket>) {
  return new Proxy(bucket, {
    get(target, name) {
      if (name in override) return Reflect.get(override, name);
      const value = Reflect.get(target, name, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}
it("commits deletion intent with metadata removal, or rolls both back when the audit fails", async () => {
  await source();
  await db
    .prepare(
      "CREATE TRIGGER deny_audit BEFORE INSERT ON audit_trail BEGIN SELECT RAISE(ABORT,'fixture audit failure'); END",
    )
    .run();
  await expect(runMetadata()).rejects.toThrow();
  expect(await count("evidence_objects")).toBe(1);
  expect(await count("r2_deletion_outbox")).toBe(0);
  await db.prepare("DROP TRIGGER deny_audit").run();
  await runMetadata();
  expect(await count("evidence_objects")).toBe(0);
  expect(
    await db.prepare("SELECT source_id,expected_sha256,expires_at FROM r2_deletion_outbox").first(),
  ).toEqual({ source_id: "fixture-evidence", expected_sha256: hash(content), expires_at: past });
  expect(await bucket.head(key)).not.toBeNull();
});
it("rolls metadata removal back when an immutable outbox task conflicts", async () => {
  await source();
  await db
    .prepare(
      "INSERT INTO r2_deletion_outbox(id,source_kind,source_id,object_key,expires_at,next_attempt_at) VALUES ('case:fixture-evidence','case','fixture-evidence',?,?,?)",
    )
    .bind(key, future, future)
    .run();
  await expect(runMetadata()).rejects.toThrow();
  expect(await count("evidence_objects")).toBe(1);
  expect(await count("audit_trail")).toBe(0);
});
it("does not use a future scheduledTime to delete unexpired objects", async () => {
  await source(future);
  await runMetadata();
  expect(await count("r2_deletion_outbox")).toBe(0);
  await db
    .prepare(
      "INSERT INTO r2_deletion_outbox(id,source_kind,source_id,object_key,expected_sha256,expires_at,next_attempt_at) VALUES ('case:fixture-evidence','case','fixture-evidence',?,?,?,?)",
    )
    .bind(key, hash(content), future, past)
    .run();
  await cleanup.scheduled(
    { ...controller("37 * * * *"), scheduledTime: Date.parse(future) },
    env(),
  );
  expect(await bucket.head(key)).not.toBeNull();
  expect(await count("evidence_objects")).toBe(1);
});
it("compiled workerd deletes only approved due content, audits before deletion and makes replay a no-op", async () => {
  await task();
  await bucket.put("raw/firewall/leave.ndjson", "Synthetic raw");
  expect((await (await runtime.getWorker()).scheduled({ cron: "37 * * * *" })).outcome).toBe("ok");
  expect(await bucket.head(key)).toBeNull();
  expect(await bucket.head("raw/firewall/leave.ndjson")).not.toBeNull();
  const row = await db.prepare("SELECT state,attempts FROM r2_deletion_outbox").first();
  expect(row).toEqual({ state: "deleted", attempts: 1 });
  const audits = await db
    .prepare(
      "SELECT operation FROM audit_trail WHERE operation IN ('r2.retention.intent','r2.retention.deleted') ORDER BY rowid",
    )
    .all();
  expect(audits.results.map((r) => r.operation)).toEqual([
    "r2.retention.intent",
    "r2.retention.deleted",
  ]);
  await run();
  expect(await db.prepare("SELECT state,attempts FROM r2_deletion_outbox").first()).toEqual(row);
});
it("keeps a recoverable task when R2 fails and retries with a new intent", async () => {
  await task();
  await cleanup.scheduled(controller("37 * * * *"), {
    ...env(),
    SIMULATION_STORE: storage({
      delete: async () => {
        throw Error("fixture failure");
      },
    }),
  });
  expect(await db.prepare("SELECT state,attempts FROM r2_deletion_outbox").first()).toEqual({
    state: "pending",
    attempts: 1,
  });
  expect(await bucket.head(key)).not.toBeNull();
  await retryNow();
  await run();
  expect(await db.prepare("SELECT state,attempts FROM r2_deletion_outbox").first()).toEqual({
    state: "deleted",
    attempts: 2,
  });
});
it("recovers after R2 succeeds but completion audit fails, without deleting twice", async () => {
  await task();
  let deletes = 0;
  const store = storage({
    delete: async (k) => {
      deletes++;
      await bucket.delete(k);
    },
  });
  await db
    .prepare(
      "CREATE TRIGGER deny_result BEFORE INSERT ON audit_trail WHEN NEW.operation='r2.retention.deleted' BEGIN SELECT RAISE(ABORT,'fixture result failure'); END",
    )
    .run();
  await expect(
    cleanup.scheduled(controller("37 * * * *"), { ...env(), SIMULATION_STORE: store }),
  ).rejects.toThrow();
  expect(await bucket.head(key)).toBeNull();
  expect(await db.prepare("SELECT state FROM r2_deletion_outbox").first()).toEqual({
    state: "deleting",
  });
  await db.prepare("DROP TRIGGER deny_result").run();
  await retryNow();
  await cleanup.scheduled(controller("37 * * * *"), { ...env(), SIMULATION_STORE: store });
  expect(deletes).toBe(1);
  expect(await db.prepare("SELECT state,attempts FROM r2_deletion_outbox").first()).toEqual({
    state: "deleted",
    attempts: 2,
  });
});
it("blocks changed content and an unapproved key instead of deleting either", async () => {
  await task();
  await bucket.put(key, "changed");
  await run();
  expect(await db.prepare("SELECT state,last_error FROM r2_deletion_outbox").first()).toEqual({
    state: "blocked",
    last_error: "digest_mismatch",
  });
  expect(await (await bucket.get(key))?.text()).toBe("changed");
  await db
    .prepare(
      "UPDATE r2_deletion_outbox SET state='pending',next_attempt_at=?,object_key='cases/unapproved.json'",
    )
    .bind(past)
    .run();
  await bucket.put("cases/unapproved.json", "other");
  await run();
  expect(await db.prepare("SELECT state,last_error FROM r2_deletion_outbox").first()).toEqual({
    state: "blocked",
    last_error: "policy_mismatch",
  });
  expect(await bucket.head("cases/unapproved.json")).not.toBeNull();
});
it("claims a due task once across concurrent invocations", async () => {
  await task();
  let deletes = 0;
  const store = storage({
    delete: async (k) => {
      deletes++;
      await bucket.delete(k);
    },
  });
  await Promise.all(
    [1, 2].map(() =>
      cleanup.scheduled(controller("37 * * * *"), { ...env(), SIMULATION_STORE: store }),
    ),
  );
  expect(deletes).toBe(1);
  expect(await db.prepare("SELECT attempts FROM r2_deletion_outbox").first()).toEqual({
    attempts: 1,
  });
});
it("stops automatic storage retries after three failed attempts and retains the blocked task", async () => {
  await task();
  let tries = 0;
  const denied = storage({
    delete: async () => {
      tries++;
      throw Error("fixture unavailable");
    },
  });
  for (let i = 0; i < 3; i++) {
    await cleanup.scheduled(controller("37 * * * *"), { ...env(), SIMULATION_STORE: denied });
    await retryNow();
  }
  await cleanup.scheduled(controller("37 * * * *"), { ...env(), SIMULATION_STORE: denied });
  expect(tries).toBe(3);
  expect(await db.prepare("SELECT state,attempts FROM r2_deletion_outbox").first()).toEqual({
    state: "blocked",
    attempts: 3,
  });
  expect(await bucket.head(key)).not.toBeNull();
});
it("prunes only completed ninety-day task tombstones in the same transaction as the run audit", async () => {
  await task();
  await run();
  await db.prepare("UPDATE r2_deletion_outbox SET completed_at=?").bind(past).run();
  await db.prepare("DELETE FROM audit_trail WHERE operation='r2.retention.completed'").run();
  await db
    .prepare(
      "CREATE TRIGGER deny_run BEFORE INSERT ON audit_trail WHEN NEW.operation='r2.retention.completed' BEGIN SELECT RAISE(ABORT,'fixture completion failure'); END",
    )
    .run();
  await expect(run()).rejects.toThrow();
  expect(await count("r2_deletion_outbox")).toBe(1);
  await db.prepare("DROP TRIGGER deny_run").run();
  await run();
  expect(await count("r2_deletion_outbox")).toBe(0);
});
it("preview has no writes or R2 operations; paused and live reject without accessing storage", async () => {
  await task();
  const before = await count("audit_trail");
  const denied = storage({
    get: async () => {
      throw Error("R2 must not be accessed");
    },
  });
  await cleanup.scheduled(controller("37 * * * *"), {
    ...env(),
    RETENTION_MODE: "preview",
    SIMULATION_STORE: denied,
  });
  expect(await count("audit_trail")).toBe(before);
  const noDb = new Proxy(db, {
    get() {
      throw Error("DB must not be accessed");
    },
  });
  await cleanup.scheduled(controller("37 * * * *"), {
    ...env(),
    RETENTION_MODE: "paused",
    SIMULATION_DB: noDb,
    SIMULATION_STORE: denied,
  });
  await expect(
    cleanup.scheduled(controller("37 * * * *"), {
      ...env(),
      DATA_ENVIRONMENT: "live",
      SIMULATION_DB: noDb,
    }),
  ).rejects.toThrow("runtime_rejected");
  expect((await (await runtime.getWorker()).fetch("https://example.invalid/purge")).status).toBe(
    403,
  );
});
it("immutable archive retries preserve upload/version and expired or missing sources cannot recreate an archive", async () => {
  const rawKey = "raw/firewall/phase2b-fixture-partial.ndjson";
  const raw = await bucket.put(rawKey, "{broken");
  if (!raw) throw Error("fixture");
  const ref = {
    account: "00000000000000000000000000000001",
    bucket: "example-cloudflare-ai-soc-simulation",
    action: "PutObject",
    object: { key: rawKey, eTag: raw.etag, size: raw.size },
    eventTime: raw.uploaded.toISOString(),
  };
  const objectId = hash(JSON.stringify([ref.bucket, rawKey, raw.etag]));
  const received = raw.uploaded.toISOString();
  await db
    .prepare(
      "INSERT INTO ingestion_objects(id,object_key,etag,dataset,received_at,raw_expires_at,expires_at,state,last_error) VALUES (?,?,?,'firewall',?,?,?,'partial','invalid_rows')",
    )
    .bind(
      objectId,
      rawKey,
      raw.etag,
      received,
      new Date(Date.parse(received) + 30 * 86400000).toISOString(),
      new Date(Date.parse(received) + 90 * 86400000).toISOString(),
    )
    .run();
  const deliver = async () =>
    (await runtime.getWorker("ingest")).queue("example-soc-ingest-simulation-dlq", [
      { id: crypto.randomUUID(), timestamp: new Date(), attempts: 1, body: ref },
    ]);
  expect((await deliver()).explicitAcks).toHaveLength(1);
  const archiveKey = `tool-snapshots/ingest-failures/${hash(JSON.stringify(ref))}.json`;
  const first = await bucket.head(archiveKey);
  expect((await deliver()).explicitAcks).toHaveLength(1);
  expect(first).not.toBeNull();
  expect((await bucket.head(archiveKey))?.version).toBe(first?.version);
  await bucket.put(archiveKey, "conflict");
  expect((await deliver()).retryMessages).toHaveLength(1);
  await bucket.delete(archiveKey);
  await db
    .prepare("UPDATE ingestion_objects SET raw_expires_at=? WHERE id=?")
    .bind(past, objectId)
    .run();
  expect((await deliver()).explicitAcks).toHaveLength(1);
  expect(await bucket.head(archiveKey)).toBeNull();
  await db.prepare("DELETE FROM ingestion_objects WHERE id=?").bind(objectId).run();
  expect((await deliver()).explicitAcks).toHaveLength(1);
  expect(await bucket.head(archiveKey)).toBeNull();
  expect(
    await db
      .prepare("SELECT operation FROM audit_trail WHERE operation='ingestion.archive.skipped'")
      .first(),
  ).not.toBeNull();
  const rejected = await (await runtime.getWorker("ingest")).queue(
    "example-soc-ingest-simulation-dlq",
    [
      {
        id: crypto.randomUUID(),
        timestamp: new Date(),
        attempts: 1,
        body: { untrusted: "fixture" },
      },
    ],
  );
  expect(rejected.explicitAcks).toHaveLength(1);
  expect((await bucket.list({ prefix: "tool-snapshots/" })).objects).toHaveLength(0);
});
