import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { convertV4MiniflareOptions, Miniflare } from "miniflare";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { retainEvidence } from "../apps/api/src/workbench/evidence-retention";
import maintenance from "../apps/api/src/workbench/maintenance-worker";
import fixedCleanup from "../apps/ingest/src/r2-retention-worker";
import metadata from "../apps/ingest/src/retention-outbox-worker";

const root = fileURLToPath(new URL("../", import.meta.url)),
  past = "2000-01-01T00:00:00.000Z",
  future = "2099-01-01T00:00:00.000Z";
let mf: Miniflare, db: D1Database, bucket: R2Bucket;
const content = JSON.stringify({
  fixture: true,
  environment: "simulation",
  source: "synthetic",
  signals: { requests: 10 },
});
const sha = createHash("sha256").update(content).digest("hex");
beforeEach(async () => {
  mf = new Miniflare({
    ...convertV4MiniflareOptions({
      modules: true,
      script: "export default {fetch(){return new Response('disabled',{status:403})}}",
      compatibilityDate: "2026-10-27",
      cf: false,
      d1Databases: { DB: "wb-retention" },
      r2Buckets: { BUCKET: "wb-retention" },
      outboundService: async () => {
        throw Error("Network forbidden");
      },
    }),
    host: "127.0.0.1",
    port: 0,
    telemetry: { enabled: false },
  });
  db = (await mf.getD1Database("DB")) as unknown as D1Database;
  bucket = (await mf.getR2Bucket("BUCKET")) as unknown as R2Bucket;
  for (const file of [
    "migrations/0001_foundation.sql",
    "migrations/0002_ingestion.sql",
    "migrations/0003_ingestion_metrics.sql",
    "migrations/0004_ingestion_observability.sql",
    "retention-migrations/0005_retention_guard_indexes.sql",
    "r2-retention-migrations/0006_r2_deletion_outbox.sql",
    "functional-migrations/0007_soc_workbench.sql",
    "functional-migrations/0008_workbench_evidence_retention.sql",
  ])
    for (const sql of (await readFile(`${root}infrastructure/${file}`, "utf8"))
      .split(";")
      .map((s) => s.trim())
      .filter(Boolean))
      await db.prepare(sql).run();
  await db
    .prepare(
      "INSERT INTO zones VALUES ('fixture-zone','fixture-account','demo.fixture.invalid',1,'simulation')",
    )
    .run();
});
afterEach(async () => {
  await mf?.dispose();
});
async function fixture(deadline = past, staging = false) {
  const key = "a".repeat(64),
    id = `evidence-${key}`,
    incident = `sim-${key}`,
    object = `cases/workbench/${key}.json`,
    created = new Date(Date.parse(deadline) - 90 * 86400000).toISOString();
  await db
    .prepare(
      "INSERT INTO incidents VALUES (?,'simulation','fixture-zone','Fixture','waf','high','closed',?,?,'Fixture',0.8,?)",
    )
    .bind(incident, created, created, deadline)
    .run();
  await db
    .prepare(
      "INSERT INTO wb_evidence_registry(id,incident_id,zone_id,object_key,sha256,created_at,expires_at,next_attempt_at,state) VALUES (?,?,'fixture-zone',?,?,?,?,?,?)",
    )
    .bind(
      id,
      incident,
      object,
      sha,
      created,
      deadline,
      deadline,
      staging ? "staging" : "registered",
    )
    .run();
  if (!staging) {
    await db
      .prepare(
        "INSERT INTO evidence_objects VALUES (?,?,'simulation','fixture-zone',?,'cases',?,?,?)",
      )
      .bind(id, incident, object, sha, created, deadline)
      .run();
    await bucket.put(object, content);
  }
  return { id, incident, object };
}
const schedule = (cron: string) => ({ cron, scheduledTime: Date.now(), noRetry() {} });
const metadataEnv = () => ({
  APP_ENV: "local",
  DATA_ENVIRONMENT: "simulation",
  RETENTION_PROFILE: "local-retention-workbench-v1",
  RETENTION_MODE: "apply",
  SIMULATION_DB: db,
});
const env = () => ({
  APP_ENV: "local",
  MAINTENANCE_PROFILE: "local-workbench-maintenance-v1",
  MAINTENANCE_MODE: "apply",
  MAINTENANCE_ACCOUNT_ID: "",
  MAINTENANCE_DATABASE_ID: "",
  MAINTENANCE_BUCKET: "",
  SIMULATION_DB: db,
  SIMULATION_EVIDENCE: bucket,
});
it("old metadata stages preserve WB references; the new evidence owner cleans its object before parent removal", async () => {
  const row = await fixture();
  await db
    .prepare(
      "INSERT INTO wb_runs(id,incident_id,zone_id,user_id,kind,provider,model_id,status,started_at,expires_at) VALUES (?,?,'fixture-zone','tester','investigation','fixture','none','completed',?,?)",
    )
    .bind("held-run", row.incident, past, future)
    .run();
  await metadata.scheduled(schedule("17 * * * *"), metadataEnv());
  expect(
    await db.prepare("SELECT id FROM incidents WHERE id=?").bind(row.incident).first(),
  ).toBeTruthy();
  expect(
    await db.prepare("SELECT id FROM r2_deletion_outbox WHERE source_id=?").bind(row.id).first(),
  ).toBeNull();
  await retainEvidence(db, bucket);
  expect(await bucket.head(row.object)).toBeNull();
  expect(
    await db.prepare("SELECT id FROM evidence_objects WHERE id=?").bind(row.id).first(),
  ).toBeNull();
  await db.prepare("UPDATE wb_runs SET expires_at=?").bind(past).run();
  await maintenance.scheduled(schedule("*/5 * * * *"), env());
  const c = schedule("17 * * * *");
  c.scheduledTime += 3600000;
  await metadata.scheduled(c, metadataEnv());
  expect(
    await db.prepare("SELECT id FROM incidents WHERE id=?").bind(row.incident).first(),
  ).toBeNull();
  expect((await db.prepare("PRAGMA foreign_key_check").all()).results).toHaveLength(0);
});
it("changed evidence is blocked without deleting the object or registration", async () => {
  const row = await fixture();
  await bucket.put(row.object, "changed by another actor");
  expect((await retainEvidence(db, bucket)).outcomes.blocked).toBe(1);
  expect(await bucket.head(row.object)).toBeTruthy();
  expect(
    await db.prepare("SELECT id FROM evidence_objects WHERE id=?").bind(row.id).first(),
  ).toBeTruthy();
  expect(await db.prepare("SELECT state,attempts FROM wb_evidence_registry").first()).toEqual({
    state: "blocked",
    attempts: 1,
  });
});
it("staging records recover an absent object; future evidence and raw/legacy objects remain untouched", async () => {
  const row = await fixture(past, true);
  await bucket.put("raw/firewall/keep.ndjson", "raw");
  await bucket.put("cases/fixture/evidence-001.json", "legacy");
  expect((await retainEvidence(db, bucket)).outcomes.already_absent).toBe(1);
  expect(
    await db.prepare("SELECT state FROM wb_evidence_registry WHERE id=?").bind(row.id).first(),
  ).toEqual({ state: "deleted" });
  expect(await bucket.head("raw/firewall/keep.ndjson")).toBeTruthy();
  expect(await bucket.head("cases/fixture/evidence-001.json")).toBeTruthy();
});
it("preview and paused schedules do not write or remove evidence; wrong cloud identity is rejected", async () => {
  const row = await fixture(future),
    before = await db.prepare("SELECT * FROM wb_evidence_registry").all();
  for (const mode of ["preview", "paused"])
    await maintenance.scheduled(schedule("*/5 * * * *"), { ...env(), MAINTENANCE_MODE: mode });
  expect(await db.prepare("SELECT * FROM wb_evidence_registry").all()).toMatchObject({
    results: before.results,
  });
  expect((await retainEvidence(db, bucket)).outcomes).toEqual({});
  expect(await bucket.head(row.object)).toBeTruthy();
  await expect(
    maintenance.scheduled(schedule("*/5 * * * *"), {
      ...env(),
      APP_ENV: "cloud-simulation",
      MAINTENANCE_PROFILE: "simulation-workbench-maintenance-v1",
      MAINTENANCE_ACCOUNT_ID: "wrong",
    }),
  ).rejects.toThrow("runtime_rejected");
});
it("transient failures have at most three attempts and retain the minimal blocked record", async () => {
  await fixture();
  const unavailable = {
    get: vi.fn().mockRejectedValue(Error("storage unavailable")),
  } as unknown as R2Bucket;
  for (let i = 0; i < 4; i++) {
    await db.prepare("UPDATE wb_evidence_registry SET next_attempt_at=?").bind(past).run();
    await retainEvidence(db, unavailable);
  }
  expect(unavailable.get).toHaveBeenCalledTimes(3);
  expect(await db.prepare("SELECT state,attempts FROM wb_evidence_registry").first()).toEqual({
    state: "blocked",
    attempts: 3,
  });
});
it("concurrent cleanup claims one durable deletion intent", async () => {
  await fixture();
  await Promise.all([retainEvidence(db, bucket), retainEvidence(db, bucket)]);
  expect(
    (
      await db
        .prepare(
          "SELECT COUNT(*) AS n FROM audit_trail WHERE operation='workbench.evidence.delete_intent'",
        )
        .first<{ n: number }>()
    )?.n,
  ).toBe(1);
});

it("workbench cleaner variants allow the existing ninety-day audit volume without expanding fixed R2 ownership", async () => {
  await fixture();
  await db
    .prepare(
      "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<4200) INSERT INTO audit_trail SELECT 'old-audit-'||i,NULL,'existing.cleaner','simulation','{}',?,? FROM n",
    )
    .bind(past, future)
    .run();
  await metadata.scheduled(schedule("17 * * * *"), metadataEnv());
  await fixedCleanup.scheduled(schedule("37 * * * *"), {
    APP_ENV: "cloud-simulation",
    DATA_ENVIRONMENT: "simulation",
    RETENTION_PROFILE: "simulation-r2-retention-workbench-v1",
    RETENTION_MODE: "apply",
    RETENTION_DATABASE_ID: "00000000-0000-4000-8000-000000000012",
    RETENTION_ACCOUNT_ID: "00000000000000000000000000000001",
    RETENTION_BUCKET: "example-cloudflare-ai-soc-simulation",
    SIMULATION_DB: db,
    SIMULATION_STORE: bucket,
  });
  expect(
    (await db.prepare("SELECT COUNT(*) AS n FROM audit_trail").first<{ n: number }>())?.n,
  ).toBeGreaterThan(4200);
  expect((await bucket.list({ prefix: "cases/workbench/" })).objects).toHaveLength(1);
});
it("maintenance audit is summarized by day and keeps the original expiry", async () => {
  await maintenance.scheduled(schedule("*/5 * * * *"), env());
  const before = await db
    .prepare("SELECT expires_at FROM audit_trail WHERE operation='workbench.maintenance.completed'")
    .first();
  await maintenance.scheduled(schedule("*/5 * * * *"), env());
  expect(
    (
      await db
        .prepare(
          "SELECT details_json,expires_at FROM audit_trail WHERE operation='workbench.maintenance.completed'",
        )
        .all()
    ).results,
  ).toHaveLength(1);
  expect(
    await db
      .prepare(
        "SELECT expires_at FROM audit_trail WHERE operation='workbench.maintenance.completed'",
      )
      .first(),
  ).toEqual(before);
  expect(
    JSON.parse(
      String(
        (
          await db
            .prepare(
              "SELECT details_json FROM audit_trail WHERE operation='workbench.maintenance.completed'",
            )
            .first()
        )?.details_json,
      ),
    ).runs,
  ).toBe(2);
});
