import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { convertV4MiniflareOptions, Miniflare } from "miniflare";
import { afterEach, beforeEach, expect, it } from "vitest";
import {
  candidateSql,
  inventoryParams,
  inventorySql,
  retentionStages,
} from "../apps/ingest/src/retention-plan";

const root = fileURLToPath(new URL("../", import.meta.url));
const past = "2000-01-01T00:00:00.000Z";
const future = "2099-01-01T00:00:00.000Z";
let runtime: Miniflare;
let db: Awaited<ReturnType<Miniflare["getD1Database"]>>;
let outbound = 0;
const fixtureVars = {
  APP_ENV: "local",
  DATA_ENVIRONMENT: "simulation",
  RETENTION_PROFILE: "local-retention-v1",
};
async function setup(overrides: Record<string, string> = {}) {
  outbound = 0;
  runtime = new Miniflare({
    ...convertV4MiniflareOptions({
      modules: true,
      scriptPath: `${root}.local/retention-dist/retention-worker.js`,
      compatibilityDate: "2026-10-27",
      compatibilityFlags: ["nodejs_compat"],
      cf: false,
      bindings: { ...fixtureVars, ...overrides },
      d1Databases: { SIMULATION_DB: "retention-fixture" },
      outboundService: async () => {
        outbound++;
        return new Response("Disabled", { status: 503 });
      },
    }),
    host: "127.0.0.1",
    port: 0,
    telemetry: { enabled: false },
  });
  db = await runtime.getD1Database("SIMULATION_DB");
  for (const file of [
    "0001_foundation.sql",
    "0002_ingestion.sql",
    "0003_ingestion_metrics.sql",
    "0004_ingestion_observability.sql",
  ])
    for (const statement of (await readFile(`${root}infrastructure/migrations/${file}`, "utf8"))
      .split(";")
      .map((v) => v.trim())
      .filter(Boolean))
      await db.prepare(statement).run();
  for (const statement of (
    await readFile(
      `${root}infrastructure/retention-migrations/0005_retention_guard_indexes.sql`,
      "utf8",
    )
  )
    .split(";")
    .map((v) => v.trim())
    .filter(Boolean))
    await db.prepare(statement).run();
  await db
    .prepare(
      "INSERT INTO zones VALUES ('fixture-zone','fixture-account','demo.fixture.invalid',1,'simulation')",
    )
    .run();
}
async function fixture(suffix: string, eventExpiry = past, caseExpiry = future) {
  const incident = `incident-${suffix}`,
    event = `event-${suffix}`,
    object = `object-${suffix}`;
  await db.batch([
    db
      .prepare(
        "INSERT INTO events VALUES (?,'simulation','fixture-zone','synthetic','waf',?,? ,?, '{\"fixture\":true}',?)",
      )
      .bind(event, past, past, suffix, eventExpiry),
    db
      .prepare(
        "INSERT INTO incidents VALUES (?,'simulation','fixture-zone','Synthetic case','waf','info','new',?,?,'Synthetic',NULL,?)",
      )
      .bind(incident, past, past, caseExpiry),
    db
      .prepare("INSERT INTO incident_events VALUES (?,?,'simulation','fixture-zone')")
      .bind(incident, event),
    db
      .prepare(
        "INSERT INTO evidence_objects VALUES (?,?,'simulation','fixture-zone',?,'cases',?,?,?)",
      )
      .bind(
        `evidence-${suffix}`,
        incident,
        `simulation/cases/fixture/${suffix}.json`,
        "a".repeat(64),
        past,
        caseExpiry,
      ),
    db
      .prepare(
        "INSERT INTO ingestion_objects (id,object_key,etag,dataset,received_at,raw_expires_at,expires_at,state) VALUES (?,?,'etag','firewall',?, ?,?,'complete')",
      )
      .bind(object, `raw/firewall/${suffix}.ndjson`, past, eventExpiry, caseExpiry),
    db.prepare("INSERT INTO ingestion_provenance VALUES (?,?,1)").bind(object, event),
    db
      .prepare("INSERT INTO ingestion_event_keys VALUES (?,?,?,?)")
      .bind(`key-${suffix}`, event, eventExpiry, caseExpiry),
  ]);
  return { incident, event, object };
}
const count = async (table: string) =>
  (await db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).first<{ n: number }>())?.n;
const run = async (scheduledTime = new Date()) =>
  (await runtime.getWorker()).scheduled({ cron: "17 * * * *", scheduledTime });
beforeEach(async () => setup());
afterEach(async () => {
  expect(outbound).toBe(0);
  await runtime?.dispose();
});

it("physically removes expired events/references while retaining 90-day cases, evidence, checkpoints and dedupe tombstones", async () => {
  await fixture("old");
  await fixture("current", future);
  const before = await db.prepare("SELECT * FROM evidence_objects ORDER BY id").all();
  expect((await run(new Date(future))).outcome).toBe("ok");
  expect(await count("events")).toBe(1);
  expect(await count("ingestion_provenance")).toBe(1);
  expect(await count("incident_events")).toBe(1);
  for (const table of [
    "incidents",
    "evidence_objects",
    "ingestion_objects",
    "ingestion_event_keys",
  ])
    expect(await count(table)).toBe(2);
  expect((await db.prepare("SELECT * FROM evidence_objects ORDER BY id").all()).results).toEqual(
    before.results,
  );
  const audit = await db
    .prepare("SELECT details_json,created_at FROM audit_trail")
    .first<{ details_json: string; created_at: string }>();
  expect(JSON.parse(audit?.details_json || "{}")).toMatchObject({
    r2Deletion: false,
    perTableLimit: 10,
  });
  expect(Math.abs(Date.parse(audit?.created_at || "") - Date.now())).toBeLessThan(60000);
  expect((await run()).outcome).toBe("ok");
  expect(await count("events")).toBe(1);
  expect(await count("ingestion_event_keys")).toBe(2);
  expect(
    (
      await runtime.dispatchFetch("http://127.0.0.1:8789/purge", {
        method: "POST",
        body: JSON.stringify({ cutoff: future }),
      })
    ).status,
  ).toBe(403);
});
it("removes expired 90-day metadata without cascading into unexpired children and defers blocked parents", async () => {
  await fixture("expired", past, past);
  const held = await fixture("held", past, past);
  await db
    .prepare("UPDATE evidence_objects SET expires_at=? WHERE incident_id=?")
    .bind(future, held.incident)
    .run();
  await db
    .prepare("INSERT INTO ingestion_replays VALUES ('held-replay',?,'queued',?,?)")
    .bind(held.object, past, future)
    .run();
  await db
    .prepare(
      "INSERT INTO ingestion_failures VALUES ('old-failure',NULL,'synthetic_failure','synthetic-archive',?,?)",
    )
    .bind(past, past)
    .run();
  expect((await run()).outcome).toBe("ok");
  expect(await count("events")).toBe(0);
  expect(await count("ingestion_failures")).toBe(0);
  expect(await count("ingestion_event_keys")).toBe(0);
  expect(await count("incidents")).toBe(1);
  expect(await count("evidence_objects")).toBe(1);
  expect(await count("ingestion_objects")).toBe(1);
  expect(await count("ingestion_replays")).toBe(1);
  await db.batch([
    db
      .prepare("UPDATE evidence_objects SET expires_at=? WHERE incident_id=?")
      .bind(past, held.incident),
    db.prepare("UPDATE ingestion_replays SET expires_at=?").bind(past),
  ]);
  expect((await run()).outcome).toBe("ok");
  for (const table of [
    "events",
    "incidents",
    "evidence_objects",
    "ingestion_objects",
    "ingestion_provenance",
    "incident_events",
    "ingestion_replays",
    "ingestion_failures",
    "ingestion_event_keys",
  ])
    expect(await count(table)).toBe(0);
});
it("bounds fan-out cleanup to ten rows per stage and progresses across repeated scheduled batches", async () => {
  const ids = await fixture("fanout");
  for (let i = 2; i <= 25; i++)
    await db
      .prepare("INSERT INTO ingestion_provenance VALUES (?,?,?)")
      .bind(ids.object, ids.event, i)
      .run();
  for (const remaining of [15, 5, 0]) {
    expect((await run()).outcome).toBe("ok");
    expect(await count("ingestion_provenance")).toBe(remaining);
    expect(await count("events")).toBe(remaining ? 1 : 0);
  }
  expect(await count("incidents")).toBe(1);
  expect(await count("ingestion_event_keys")).toBe(1);
});
it("rolls back all deletion stages when the completion audit fails, then safely retries", async () => {
  await fixture("rollback", past, past);
  await db
    .prepare(
      "CREATE TRIGGER block_retention_audit BEFORE INSERT ON audit_trail BEGIN SELECT RAISE(ABORT,'fixture audit failure'); END",
    )
    .run();
  expect((await run()).outcome).toBe("exception");
  for (const table of [
    "events",
    "incidents",
    "evidence_objects",
    "ingestion_objects",
    "ingestion_provenance",
    "incident_events",
    "ingestion_event_keys",
  ])
    expect(await count(table)).toBe(1);
  expect(await count("audit_trail")).toBe(0);
  await db.prepare("DROP TRIGGER block_retention_audit").run();
  expect((await run()).outcome).toBe("ok");
  expect(await count("events")).toBe(0);
});
it("rejects mixed/live or real-source databases before deleting any row", async () => {
  await fixture("mixed", past, past);
  await db
    .prepare(
      "INSERT INTO zones VALUES ('live-zone','fixture-account','live.fixture.invalid',1,'live')",
    )
    .run();
  expect((await run()).outcome).toBe("exception");
  expect(await count("events")).toBe(1);
  await db.prepare("DELETE FROM zones WHERE id='live-zone'").run();
  await db.prepare("UPDATE events SET metadata_json='{\"fixture\":false}'").run();
  expect((await run()).outcome).toBe("exception");
  expect(await count("events")).toBe(1);
  expect(await count("audit_trail")).toBe(0);
  await db
    .prepare("UPDATE events SET metadata_json='{\"fixture\":true}',expires_at='invalid-expiry'")
    .run();
  expect((await run()).outcome).toBe("exception");
  expect(await count("events")).toBe(1);
  expect(await count("audit_trail")).toBe(0);
});
it.each([
  { APP_ENV: "cloud-simulation" },
  { DATA_ENVIRONMENT: "live" },
  { RETENTION_PROFILE: "wrong" },
])("rejects unapproved runtime configuration: %j", async (bindings) => {
  await runtime.dispose();
  await setup(bindings);
  await fixture("denied", past, past);
  expect((await run()).outcome).toBe("exception");
  expect(await count("events")).toBe(1);
  expect(await count("audit_trail")).toBe(0);
});

const cloudVars = {
  APP_ENV: "cloud-simulation",
  DATA_ENVIRONMENT: "simulation",
  RETENTION_PROFILE: "simulation-retention-v1",
  RETENTION_MODE: "apply",
  RETENTION_ACCOUNT_ID: "00000000000000000000000000000001",
  RETENTION_DATABASE_ID: "00000000-0000-4000-8000-000000000012",
};
async function cloud(mode = "apply", overrides: Record<string, string> = {}) {
  await runtime.dispose();
  await setup({ ...cloudVars, RETENTION_MODE: mode, ...overrides });
}
it("cloud preview is read-only and the shared single-SELECT inventory identifies expired metadata", async () => {
  await cloud("preview");
  await fixture("preview", past, past);
  const result = await db
    .prepare(inventorySql)
    .bind(...inventoryParams(new Date().toISOString()))
    .first<{ inventory_json: string }>();
  const inventory = JSON.parse(result?.inventory_json || "[]") as Array<{
    table_name: string;
    expired: number;
  }>;
  expect(inventory.find((v) => v.table_name === "events")?.expired).toBe(1);
  expect((await run()).outcome).toBe("ok");
  expect(await count("events")).toBe(1);
  expect(await count("audit_trail")).toBe(0);
  expect(await count("retention_guard")).toBe(0);
});
it("cloud apply records exact counts atomically, skips repeated hourly slots and uses the proposed child indexes", async () => {
  await cloud();
  await fixture("apply", past, past);
  const plans = [];
  for (const name of ["events", "ingestion_objects", "incidents"]) {
    const stage = retentionStages.find((v) => v.name === name);
    if (!stage) throw Error("Missing stage");
    const plan = await db
      .prepare(`EXPLAIN QUERY PLAN ${candidateSql(stage)}`)
      .bind(...Array(stage.times).fill(new Date().toISOString()), 10)
      .all<{ detail: string }>();
    plans.push(...plan.results.map((v) => v.detail));
  }
  for (const index of [
    "retention_provenance_event",
    "retention_incident_links_event",
    "retention_evidence_incident",
    "retention_replays_object",
    "retention_failures_object",
  ])
    expect(plans.join("\n")).toContain(index);
  const time = new Date();
  expect((await run(time)).outcome).toBe("ok");
  const audit = await db
    .prepare(
      "SELECT details_json FROM audit_trail WHERE operation='retention.simulation.completed'",
    )
    .first<{ details_json: string }>();
  expect(JSON.parse(audit?.details_json || "{}")).toMatchObject({
    deleted: {
      events: 1,
      incidents: 1,
      evidence_objects: 1,
      ingestion_provenance: 1,
      incident_events: 1,
      ingestion_objects: 1,
      ingestion_event_keys: 1,
    },
    expiredRowsRemain: 0,
    r2Deletion: false,
  });
  await fixture("late", past, past);
  expect((await run(new Date(time.getTime() + 1))).outcome).toBe("ok");
  expect(await count("events")).toBe(1);
  expect(await count("audit_trail")).toBe(1);
  expect((await run(new Date(time.getTime() + 3600000))).outcome).toBe("ok");
  expect(await count("events")).toBe(0);
  expect(await count("audit_trail")).toBe(2);
  expect(await count("retention_guard")).toBe(0);
});
it("cloud paused mode needs no storage capability and cannot mutate data", async () => {
  await runtime.dispose();
  runtime = new Miniflare({
    ...convertV4MiniflareOptions({
      modules: true,
      scriptPath: `${root}.local/retention-dist/retention-worker.js`,
      compatibilityDate: "2026-10-27",
      bindings: { ...cloudVars, RETENTION_MODE: "paused" },
      cf: false,
    }),
    host: "127.0.0.1",
    port: 0,
    telemetry: { enabled: false },
  });
  expect((await run()).outcome).toBe("ok");
});
it("cloud apply refuses tables above the 4096-row ceiling without deleting expired rows", async () => {
  await cloud();
  await fixture("oversized", past, past);
  await db
    .prepare(
      "INSERT INTO audit_trail SELECT 'size-'||value,NULL,'fixture','fixture','{}',?,? FROM json_each(?)",
    )
    .bind(past, future, JSON.stringify(Array.from({ length: 4097 }, (_, i) => i)))
    .run();
  expect((await run()).outcome).toBe("exception");
  expect(await count("events")).toBe(1);
  expect(await count("audit_trail")).toBe(4097);
  expect(await count("retention_guard")).toBe(0);
});
it("cloud apply requires the exact account/database pins and an explicit mode", async () => {
  for (const override of [
    { RETENTION_ACCOUNT_ID: "foreign" },
    { RETENTION_DATABASE_ID: "live-db" },
    { RETENTION_MODE: "" },
  ]) {
    await cloud("apply", override);
    await fixture("pins", past, past);
    expect((await run()).outcome).toBe("exception");
    expect(await count("events")).toBe(1);
    expect(await count("audit_trail")).toBe(0);
  }
});
