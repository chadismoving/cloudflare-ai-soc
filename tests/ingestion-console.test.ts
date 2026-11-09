import { createHash, randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import type { IngestionCoverage } from "@soc/shared";
import { convertV4MiniflareOptions, Miniflare } from "miniflare";
import { afterAll, beforeAll, expect, it } from "vitest";
import { fixtureEnvironment } from "../scripts/fixture-env.mjs";

const root = fileURLToPath(new URL("../", import.meta.url));
const secret = randomBytes(32).toString("hex");
let runtime: Miniflare;
let cookie: string;
let viewerCookie: string;
let incidentId: string;
const origin = "http://127.0.0.1:8787";
async function api(path: string, identity = cookie) {
  return runtime.dispatchFetch(`${origin}${path}`, { headers: { Cookie: identity } });
}
beforeAll(async () => {
  const common = {
    modules: true,
    compatibilityDate: "2026-10-27",
    compatibilityFlags: ["nodejs_compat"],
    cf: false,
  };
  const keys = await fixtureEnvironment();
  runtime = new Miniflare({
    ...convertV4MiniflareOptions({
      workers: [
        {
          name: "api",
          ...common,
          scriptPath: `${root}apps/api/dist/index.js`,
          bindings: {
            APP_ENV: "local",
            AUTH_MODE: "fixture",
            APP_ORIGIN: origin,
            ACCESS_ISSUER: `${origin}/__local/access`,
            ACCESS_AUDIENCE: "soc-local-fixture",
            ...keys,
          },
          d1Databases: { APP_DB: "control", SIMULATION_DB: "simulation" },
          r2Buckets: { SIMULATION_EVIDENCE: "evidence" },
          serviceBindings: { ASSETS: async () => new Response("Fixture") },
          outboundService: async () => new Response("Disabled", { status: 503 }),
        },
        {
          name: "ingest",
          ...common,
          scriptPath: `${root}apps/ingest/dist/index.js`,
          bindings: {
            APP_ENV: "local",
            DATA_ENVIRONMENT: "simulation",
            LOCAL_INGEST_SECRET: secret,
          },
          d1Databases: { SIMULATION_DB: "simulation" },
          r2Buckets: { SIMULATION_STORE: "evidence" },
          queueProducers: { INGEST_QUEUE: "soc-local-ingest" },
          queueConsumers: {
            "soc-local-ingest": {
              maxBatchSize: 1,
              maxBatchTimeout: 0,
              maxRetries: 3,
              retryDelay: 1,
              deadLetterQueue: "soc-local-ingest-dlq",
            },
            "soc-local-ingest-dlq": {
              maxBatchSize: 1,
              maxBatchTimeout: 0,
              maxRetries: 3,
              retryDelay: 1,
            },
          },
          outboundService: async () => new Response("Disabled", { status: 503 }),
        },
      ],
    }),
    host: "127.0.0.1",
    port: 0,
    telemetry: { enabled: false },
  });
  const control = await runtime.getD1Database("APP_DB", "api"),
    simulation = await runtime.getD1Database("SIMULATION_DB", "api");
  const execute = async (db: typeof control, sql: string) => {
    for (const s of sql
      .split(";")
      .map((v) => v.trim())
      .filter(Boolean))
      await db.prepare(s).run();
  };
  for (const db of [control, simulation])
    for (const file of [
      "0001_foundation.sql",
      "0002_ingestion.sql",
      "0003_ingestion_metrics.sql",
      "0004_ingestion_observability.sql",
    ])
      await execute(db, await readFile(`${root}infrastructure/migrations/${file}`, "utf8"));
  await execute(control, await readFile(`${root}infrastructure/seeds/control.sql`, "utf8"));
  const bytes = await readFile(`${root}simulations/fixtures/evidence-001.json`);
  await execute(
    simulation,
    (await readFile(`${root}infrastructure/seeds/simulation.sql`, "utf8")).replace(
      "__EVIDENCE_SHA256__",
      createHash("sha256").update(bytes).digest("hex"),
    ),
  );
  for (const persona of ["admin", "viewer"]) {
    const response = await runtime.dispatchFetch(`${origin}/__local/session`, {
      method: "POST",
      headers: { Origin: origin, "Content-Type": "application/json" },
      body: JSON.stringify({ persona }),
    });
    expect(response.status).toBe(200);
    const value = response.headers.get("Set-Cookie")?.split(";")[0] || "";
    if (persona === "admin") cookie = value;
    else viewerCookie = value;
  }
  const ingest = await runtime.getWorker("ingest");
  const base = Math.floor(Date.now() / 300000) * 300000 - 300000;
  const record = (id: string, offset: number) => ({
    fixture: true,
    RayID: id,
    Datetime: new Date(base + offset).toISOString(),
    Action: "block",
    RuleID: "rule-a",
    Source: "waf",
    ClientRequestHost: "demo.fixture.invalid",
    ClientRequestPath: "/__soc_test/login",
    ClientIP: "client-a",
  });
  expect(
    (
      await ingest.fetch("http://127.0.0.1:8788/__local/object", {
        method: "POST",
        headers: { "cf-webhook-auth": secret, "Content-Type": "application/json" },
        body: JSON.stringify({
          key: "raw/firewall/console.ndjson.gz",
          records: [
            record("ray-late", 20000),
            record("ray-early", 10000),
            record("ray-early", 10000),
          ],
          gzip: true,
        }),
      })
    ).status,
  ).toBe(202);
  const end = Date.now() + 10000;
  for (;;) {
    const list = (await (await api("/api/overview")).json()) as {
      incidents: Array<{ id: string }>;
    };
    const incident = list.incidents.find((v) => v.id.startsWith("ingest-"));
    if (incident) {
      const row = await simulation
        .prepare(
          "SELECT state FROM ingestion_objects WHERE object_key='raw/firewall/console.ndjson.gz'",
        )
        .first<{ state: string }>();
      if (row?.state === "complete") {
        incidentId = incident.id;
        break;
      }
    }
    if (Date.now() > end) throw Error("Console ingestion timeout");
    await new Promise((r) => setTimeout(r, 40));
  }
});
afterAll(async () => {
  await runtime?.dispose();
});
it("shows two unique logical events, ordered provenance and checked evidence through the authenticated console API", async () => {
  const response = await api(`/api/incidents/${incidentId}`);
  expect(response.status).toBe(200);
  const value = (await response.json()) as {
    timeline: Array<{ event_time: string; deliveryReferences: number }>;
    evidence: Array<{ id: string }>;
  };
  expect(value.timeline).toHaveLength(2);
  expect(
    value.timeline[0]?.event_time.localeCompare(value.timeline[1]?.event_time || ""),
  ).toBeLessThan(0);
  expect(value.timeline.map((v) => v.deliveryReferences)).toEqual([2, 1]);
  const evidence = await api(`/api/evidence/${value.evidence[0]?.id}`);
  expect(evidence.status).toBe(200);
  expect(await evidence.json()).toMatchObject({
    environment: "simulation",
    evidence: { fixture: true, source: "synthetic", emulatedSource: "firewall_events" },
  });
  expect((await (await api("/api/ingestion/status")).json()) as unknown).toMatchObject({
    simulation: true,
    cloudDeliveryVerified: false,
    objects: [{ state: "complete", valid_rows: 3 }],
  });
});
it("keeps ingestion diagnostics behind JWT/zone checks and Viewer cannot approve ingested incidents", async () => {
  expect((await runtime.dispatchFetch(`${origin}/api/ingestion/status`)).status).toBe(401);
  expect((await api("/api/overview?environment=live")).status).toBe(403);
  expect((await api(`/api/incidents/${incidentId}`, viewerCookie)).status).toBe(200);
  const session = (await (await api("/api/session", viewerCookie)).json()) as { csrfToken: string };
  expect(
    (
      await runtime.dispatchFetch(`${origin}/api/authorization/approval-check`, {
        method: "POST",
        headers: { Cookie: viewerCookie, Origin: origin, "X-CSRF-Token": session.csrfToken },
      })
    ).status,
  ).toBe(403);
});

it("records processing timestamps separately and reports legacy timing as unknown", async () => {
  const db = await runtime.getD1Database("SIMULATION_DB", "api");
  const bucket = await runtime.getR2Bucket("SIMULATION_EVIDENCE", "api");
  const object = await bucket.head("raw/firewall/console.ndjson.gz");
  const status = (await (await api("/api/ingestion/status")).json()) as {
    objects: Array<{
      id: string;
      received_at: string;
      first_attempt_at: string | null;
      processed_at: string;
      observedWaitSeconds: number | null;
    }>;
  };
  const row = status.objects[0];
  expect(row?.received_at).toBe(object?.uploaded.toISOString());
  expect(Date.parse(row?.first_attempt_at || "")).toBeGreaterThanOrEqual(
    Date.parse(row?.received_at || ""),
  );
  expect(Date.parse(row?.processed_at || "")).toBeGreaterThanOrEqual(
    Date.parse(row?.first_attempt_at || ""),
  );
  expect(row?.observedWaitSeconds).toBeGreaterThanOrEqual(0);
  await db
    .prepare("UPDATE ingestion_objects SET first_attempt_at=NULL WHERE id=?")
    .bind(row?.id)
    .run();
  expect(await (await api("/api/ingestion/status")).json()).toMatchObject({
    objects: [{ first_attempt_at: null, observedWaitSeconds: null }],
  });
});
it("reconciles missing, replaced and expired raw metadata without modifying checkpoints", async () => {
  const db = await runtime.getD1Database("SIMULATION_DB", "api");
  const bucket = await runtime.getR2Bucket("SIMULATION_EVIDENCE", "api");
  await bucket.put("raw/firewall/missing.ndjson", "synthetic");
  const changed = await bucket.put("raw/firewall/changed.ndjson", "synthetic");
  const expired = await bucket.put("raw/firewall/expired.ndjson", "synthetic");
  await bucket.put("raw/unscoped-secret-name", "excluded");
  for (const [id, object, etag, expiry] of [
    ["changed", changed, "different", "2099-01-01T00:00:00.000Z"],
    ["expired", expired, expired.etag, "2000-01-01T00:00:00.000Z"],
  ] as const) {
    await db
      .prepare(
        "INSERT INTO ingestion_objects (id,object_key,etag,dataset,received_at,raw_expires_at,expires_at,state) VALUES (?,?,?,'firewall',?,?,'2099-01-01T00:00:00.000Z','processing')",
      )
      .bind(id, object.key, etag, object.uploaded.toISOString(), expiry)
      .run();
  }
  const before = await db.prepare("SELECT * FROM ingestion_objects ORDER BY id").all();
  const response = await api("/api/ingestion/reconciliation");
  expect(response.status).toBe(200);
  const value = (await response.json()) as IngestionCoverage;
  expect(value.scanComplete).toBe(true);
  expect(value.excludedObjects).toBe(1);
  expect(Object.fromEntries(value.objects.map((v) => [v.key, v.status]))).toEqual({
    "raw/firewall/console.ndjson.gz": "complete",
    "raw/firewall/missing.ndjson": "missing_checkpoint",
    "raw/firewall/changed.ndjson": "etag_changed",
    "raw/firewall/expired.ndjson": "expired",
  });
  expect(value.objects.some((v) => v.key.includes("secret"))).toBe(false);
  expect((await db.prepare("SELECT * FROM ingestion_objects ORDER BY id").all()).results).toEqual(
    before.results,
  );
});
it("denies unauthenticated, live and ungranted coverage reads", async () => {
  expect((await api("/api/ingestion/reconciliation", "")).status).toBe(401);
  expect((await api("/api/ingestion/reconciliation?environment=live")).status).toBe(403);
  const db = await runtime.getD1Database("APP_DB", "api");
  await db.prepare("DELETE FROM zone_access WHERE user_id='user-viewer'").run();
  try {
    expect((await api("/api/ingestion/reconciliation", viewerCookie)).status).toBe(403);
  } finally {
    await db
      .prepare("INSERT INTO zone_access VALUES ('user-viewer','fixture-zone','approve')")
      .run();
  }
});
it("marks a capped raw scan incomplete rather than claiming complete coverage", async () => {
  const bucket = await runtime.getR2Bucket("SIMULATION_EVIDENCE", "api");
  for (let i = 0; i < 21; i++) await bucket.put(`raw/http/bounded-${i}.ndjson`, "synthetic");
  const value = (await (await api("/api/ingestion/reconciliation")).json()) as IngestionCoverage;
  expect(value.scanComplete).toBe(false);
  expect(value.scannedObjects).toBe(20);
  expect(value.objects.length + value.excludedObjects).toBe(20);
});
