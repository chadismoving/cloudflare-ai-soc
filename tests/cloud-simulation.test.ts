import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";
import {
  type IngestionCoverage,
  pilotRawKeys,
  pilotRawPrefix,
  simulationHealthProfile,
} from "@soc/shared";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { convertV4MiniflareOptions, Miniflare } from "miniflare";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { approvedAccess } from "../apps/api/src/env";
import { cloudEnabled, type Env } from "../apps/ingest/src/profile";
import { cloudAccount, cloudBucket } from "../apps/ingest/src/schema";
import { ownerBootstrap, simulationBootstrap } from "../scripts/prepare-console.mjs";

const root = fileURLToPath(new URL("../", import.meta.url));
let runtime: Miniflare;
let db: Awaited<ReturnType<Miniflare["getD1Database"]>>;
let bucket: Awaited<ReturnType<Miniflare["getR2Bucket"]>>;
let queue: Awaited<ReturnType<Miniflare["getQueueProducer"]>>;
let pair: Awaited<ReturnType<typeof generateKeyPair>>;
let token: string;
let unexpected = 0;
const email = "owner@fixture.invalid",
  subject = "cloud-simulation-fixture-owner";
const profileBindings = {
  APP_ENV: "cloud-simulation",
  DATA_ENVIRONMENT: "simulation",
  CLOUD_SIMULATION_PROFILE: "phase2b-v1",
};
const base = Math.floor(Date.now() / 300000) * 300000 - 300000;
const record = (id = "a") => ({
  fixture: true,
  RayID: `cloud-${id}`,
  Datetime: new Date(base + 10000).toISOString(),
  Action: "block",
  RuleID: "fixture-rule",
  Source: "waf",
  ClientRequestHost: "demo.fixture.invalid",
  ClientRequestPath: "/__soc_test/login",
  ClientIP: "client-a",
});
async function waitFor<T>(fn: () => Promise<T>, done: (v: T) => boolean) {
  const end = Date.now() + 26000;
  for (;;) {
    const value = await fn();
    if (done(value)) return value;
    if (Date.now() > end)
      throw Error(`Cloud candidate local check timed out: ${JSON.stringify(value)}`);
    await new Promise((r) => setTimeout(r, 40));
  }
}
const state = () =>
  db
    .prepare("SELECT * FROM ingestion_objects ORDER BY received_at LIMIT 1")
    .first<{ state: string; valid_rows: number; last_error: string; metrics_json: string }>();
const count = async (table: string) =>
  (await db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).first<{ n: number }>())?.n;
const api = (path: string, auth = token) =>
  runtime.dispatchFetch(`${approvedAccess.origin}${path}`, {
    headers: { ...(auth ? { "Cf-Access-Jwt-Assertion": auth } : {}) },
  });
async function put(content: string, key = "raw/firewall/phase2b-test.ndjson") {
  const object = await bucket.put(key, key.endsWith(".gz") ? gzipSync(content) : content);
  const ref = {
    account: cloudAccount,
    bucket: cloudBucket,
    action: "PutObject",
    object: { key, size: object.size, eTag: object.etag },
    eventTime: object.uploaded.toISOString(),
  };
  await queue.send(ref);
  return ref;
}
beforeAll(async () => {
  pair = await generateKeyPair("RS256", { extractable: true });
  token = await new SignJWT({ email })
    .setProtectedHeader({ alg: "RS256", kid: "cloud-fixture" })
    .setIssuer(approvedAccess.issuer)
    .setAudience(approvedAccess.audience)
    .setSubject(subject)
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(pair.privateKey);
});
async function setup(activeProfile = "phase2b-v1") {
  unexpected = 0;
  const common = {
    modules: true,
    compatibilityDate: "2026-10-27",
    compatibilityFlags: ["nodejs_compat"],
    cf: false,
  };
  const jwks = {
    keys: [{ ...(await exportJWK(pair.publicKey)), alg: "RS256", kid: "cloud-fixture" }],
  };
  runtime = new Miniflare({
    ...convertV4MiniflareOptions({
      workers: [
        {
          name: "api",
          ...common,
          scriptPath: `${root}apps/api/dist/index.js`,
          bindings: {
            APP_ENV: "production",
            AUTH_MODE: "access",
            APP_ORIGIN: approvedAccess.origin,
            ACCESS_ISSUER: approvedAccess.issuer,
            ACCESS_AUDIENCE: approvedAccess.audience,
            OWNER_EMAIL: email,
            OWNER_SUBJECT_SHA256: createHash("sha256").update(subject).digest("hex"),
            SESSION_CSRF_SECRET: "synthetic-csrf-at-least-32-characters",
            SIMULATION_INGEST_READS: activeProfile,
          },
          d1Databases: { APP_DB: "control", SIMULATION_DB: "simulation" },
          r2Buckets: { SIMULATION_EVIDENCE: "evidence" },
          serviceBindings: { ASSETS: async () => new Response("Authenticated test assets") },
          outboundService: async (request) => {
            if (request.url === `${approvedAccess.issuer}/cdn-cgi/access/certs`)
              return Response.json(jwks);
            unexpected++;
            return new Response("Denied", { status: 503 });
          },
        },
        {
          name: "ingest",
          ...common,
          scriptPath: `${root}apps/ingest/dist/index.js`,
          bindings: { ...profileBindings, CLOUD_SIMULATION_PROFILE: activeProfile },
          d1Databases: { SIMULATION_DB: "simulation" },
          r2Buckets: { SIMULATION_STORE: "evidence" },
          queueProducers: { TEST_SOURCE_QUEUE: "example-soc-ingest-simulation" },
          queueConsumers: {
            "example-soc-ingest-simulation": {
              maxBatchSize: 1,
              maxBatchTimeout: 0,
              maxRetries: 3,
              retryDelay: 5,
              deadLetterQueue: "example-soc-ingest-simulation-dlq",
            },
            "example-soc-ingest-simulation-dlq": {
              maxBatchSize: 1,
              maxBatchTimeout: 0,
              maxRetries: 3,
              retryDelay: 5,
            },
          },
          outboundService: async () => {
            unexpected++;
            return new Response("Denied", { status: 503 });
          },
        },
      ],
    }),
    host: "127.0.0.1",
    port: 0,
    telemetry: { enabled: false },
  });
  const control = await runtime.getD1Database("APP_DB", "api");
  db = await runtime.getD1Database("SIMULATION_DB", "api");
  bucket = await runtime.getR2Bucket("SIMULATION_EVIDENCE", "api");
  queue = await runtime.getQueueProducer("TEST_SOURCE_QUEUE", "ingest");
  const sql = async (database: typeof db, source: string) => {
    for (const s of source
      .split(";")
      .map((v) => v.trim())
      .filter(Boolean))
      await database.prepare(s).run();
  };
  for (const database of [control, db])
    await sql(
      database,
      await readFile(`${root}infrastructure/migrations/0001_foundation.sql`, "utf8"),
    );
  for (const file of ["0002_ingestion.sql", "0003_ingestion_metrics.sql"])
    await sql(db, await readFile(`${root}infrastructure/migrations/${file}`, "utf8"));
  if (activeProfile === simulationHealthProfile)
    await sql(
      db,
      await readFile(`${root}infrastructure/migrations/0004_ingestion_observability.sql`, "utf8"),
    );
  await sql(
    control,
    ownerBootstrap({
      verified_login: true,
      intended_owner_email: email,
      subject_sha256: createHash("sha256").update(subject).digest("hex"),
      subject_confirmation: "fixture",
    }),
  );
  await sql(
    db,
    simulationBootstrap(
      await readFile(`${root}infrastructure/seeds/simulation.sql`, "utf8"),
      await readFile(`${root}simulations/fixtures/evidence-001.json`),
    ),
  );
}
afterEach(async () => {
  expect(unexpected).toBe(0);
  await runtime?.dispose();
});

describe("existing cloud profile", () => {
  beforeEach(async () => setup());
  it("runs the cloud simulation candidate queue profile and exposes root-relative evidence through owner-pinned Access", async () => {
    const ref = await put(`${JSON.stringify(record())}\n${JSON.stringify(record())}\n`);
    await queue.send(ref);
    await waitFor(state, (v) => v?.state === "complete");
    expect(await count("ingestion_provenance")).toBe(2);
    expect(await count("ingestion_event_keys")).toBe(1);
    const list = (await (await api("/api/overview")).json()) as {
      incidents: Array<{ id: string }>;
    };
    const id = list.incidents.find((v) => v.id.startsWith("ingest-"))?.id;
    expect(id).toBeTruthy();
    const detail = (await (await api(`/api/incidents/${id}`)).json()) as {
      timeline: unknown[];
      evidence: Array<{ id: string }>;
    };
    expect(detail.timeline).toHaveLength(1);
    const evidence = await api(`/api/evidence/${detail.evidence[0]?.id}`);
    expect(evidence.status).toBe(200);
    expect(await evidence.json()).toMatchObject({
      environment: "simulation",
      evidence: { fixture: true, source: "synthetic" },
    });
    expect((await bucket.list({ prefix: "cases/ingested/" })).objects).toHaveLength(1);
    expect((await bucket.list({ prefix: "simulation/" })).objects).toHaveLength(0);
    expect((await api("/api/ingestion/status")).status).toBe(200);
    expect((await api("/api/ingestion/reconciliation")).status).toBe(404);
    expect(await (await api("/api/session")).json()).toMatchObject({
      simulationHealthEnabled: false,
    });
    expect((await api("/api/ingestion/status", "")).status).toBe(401);
    expect((await api("/api/overview?environment=live")).status).toBe(403);
    expect((await api("/api/incidents/incident-other")).status).toBe(403);
  });
  it("keeps the previous profile usable after additive 0004 migration for rollback", async () => {
    for (const statement of (
      await readFile(`${root}infrastructure/migrations/0004_ingestion_observability.sql`, "utf8")
    )
      .split(";")
      .map((v) => v.trim())
      .filter(Boolean))
      await db.prepare(statement).run();
    await put(JSON.stringify(record()));
    await waitFor(state, (v) => v?.state === "complete");
    expect(
      await db
        .prepare(
          "SELECT first_attempt_at,last_attempt_at,processed_at,archived_at FROM ingestion_objects",
        )
        .first(),
    ).toEqual({
      first_attempt_at: null,
      last_attempt_at: null,
      processed_at: null,
      archived_at: null,
    });
    expect((await api("/api/ingestion/status")).status).toBe(200);
    expect((await api("/api/ingestion/reconciliation")).status).toBe(404);
    expect(await count("ingestion_event_keys")).toBe(1);
  });
  it("bounds four distinct records below conservative statement and R2 operation budgets", async () => {
    await put(["a", "b", "c", "d"].map((id) => JSON.stringify(record(id))).join("\n"));
    const row = await waitFor(state, (v) => v?.state === "complete");
    const metrics = JSON.parse(row?.metrics_json || "{}");
    expect(row?.valid_rows).toBe(4);
    expect(metrics.preparedStatements).toBe(37);
    expect(metrics.r2Operations).toBe(9);
    expect(metrics.elapsedMs).toBeGreaterThanOrEqual(0);
  });
  it("marks the fifth line as a bounded failure, preserving four valid events without accepting the oversized object as complete", {
    timeout: 30000,
  }, async () => {
    const started = Date.now();
    await put(["a", "b", "c", "d", "e"].map((id) => JSON.stringify(record(id))).join("\n"));
    const row = await waitFor(state, (v) => v?.state === "archived");
    expect(Date.now() - started).toBeGreaterThanOrEqual(14000);
    expect(row).toMatchObject({ valid_rows: 4, last_error: "row_limit" });
    expect(await count("ingestion_event_keys")).toBe(4);
    expect((await bucket.list({ prefix: "tool-snapshots/ingest-failures/" })).objects).toHaveLength(
      1,
    );
  });
  it("rejects local/live/foreign envelopes and unapproved keys before any incident is created", {
    timeout: 30000,
  }, async () => {
    const object = await bucket.put("raw/firewall/phase2b-bad.ndjson", JSON.stringify(record()));
    const ref = {
      account: cloudAccount,
      bucket: cloudBucket,
      action: "PutObject",
      object: { key: object.key, size: object.size, eTag: object.etag },
      eventTime: object.uploaded.toISOString(),
    };
    for (const bad of [
      { ...ref, account: "fixture-account" },
      { ...ref, bucket: "example-cloudflare-ai-soc-live" },
      { ...ref, environment: "live" },
      { ...ref, object: { ...ref.object, key: "raw/firewall/other.ndjson" } },
      { ...ref, object: { ...ref.object, size: 16385 } },
    ])
      await queue.send(bad);
    await waitFor(
      () => count("ingestion_failures"),
      (n) => n === 5,
    );
    expect(await count("ingestion_objects")).toBe(0);
  });
  it("has no HTTP upload, notification or replay ingress, including the local origin", async () => {
    const worker = await runtime.getWorker("ingest");
    for (const host of ["https://anything.workers.dev", "http://127.0.0.1:8788"]) {
      for (const path of ["/__local/object", "/notification", "/__local/replay", "/status"]) {
        expect(
          (
            await worker.fetch(`${host}${path}`, {
              method: "POST",
              headers: { "cf-webhook-auth": "synthetic-secret-even-if-present" },
              body: "{}",
            })
          ).status,
        ).toBe(403);
      }
    }
  });
  it("requires the exact cloud simulation opt-in and rejects local secrets in the cloud profile", () => {
    for (const override of [
      { APP_ENV: "production" },
      { DATA_ENVIRONMENT: "live" },
      { CLOUD_SIMULATION_PROFILE: "wrong" },
      { LOCAL_INGEST_SECRET: "forbidden" },
    ])
      expect(cloudEnabled({ ...profileBindings, ...override } as Env)).toBe(false);
  });
});

describe("health cloud candidate", () => {
  beforeEach(async () => setup(simulationHealthProfile));
  it("records four-row timing within budgets and keeps completed duplicate timestamps and expiry unchanged", async () => {
    const ref = await put(
      ["a", "b", "c", "d"].map((id) => JSON.stringify(record(id))).join("\n"),
      pilotRawKeys[0],
    );
    await waitFor(state, (v) => v?.state === "complete");
    const before = await db.prepare("SELECT * FROM ingestion_objects").first<{
      id: string;
      received_at: string;
      first_attempt_at: string;
      last_attempt_at: string;
      processed_at: string;
      expires_at: string;
      metrics_json: string;
    }>();
    expect(before?.received_at).toBe(ref.eventTime);
    expect(Date.parse(before?.first_attempt_at || "")).toBeGreaterThanOrEqual(
      Date.parse(ref.eventTime),
    );
    expect(Date.parse(before?.processed_at || "")).toBeGreaterThanOrEqual(
      Date.parse(before?.first_attempt_at || ""),
    );
    expect(JSON.parse(before?.metrics_json || "{}")).toMatchObject({
      preparedStatements: 37,
      r2Operations: 9,
    });
    const worker = await runtime.getWorker("ingest");
    const duplicate = await worker.queue("example-soc-ingest-simulation", [
      { id: "duplicate", timestamp: new Date(), attempts: 1, body: ref },
    ]);
    expect(duplicate.explicitAcks).toContain("duplicate");
    expect(await db.prepare("SELECT * FROM ingestion_objects").first()).toEqual(before);
    expect(await count("ingestion_event_keys")).toBe(4);
    expect(await (await api("/api/session")).json()).toMatchObject({
      simulationHealthEnabled: true,
    });
    expect(await (await api("/api/ingestion/status")).json()).toMatchObject({
      objects: [
        {
          object_key: pilotRawKeys[0],
          first_attempt_at: before?.first_attempt_at,
          observedWaitSeconds: expect.any(Number),
        },
      ],
    });
    await db.prepare("UPDATE ingestion_objects SET first_attempt_at=NULL").run();
    expect(await (await api("/api/ingestion/status")).json()).toMatchObject({
      objects: [{ first_attempt_at: null, observedWaitSeconds: null }],
    });
  });
  it("limits status and read-only coverage to the fixed pilot keys and enforces owner, zone and environment checks", async () => {
    await put(JSON.stringify(record()), pilotRawKeys[0]);
    await waitFor(state, (v) => v?.state === "complete");
    await bucket.put(pilotRawKeys[1], "missing synthetic checkpoint");
    await bucket.put(`${pilotRawPrefix}foreign.ndjson`, "excluded");
    await bucket.put("raw/firewall/private.ndjson", "outside prefix");
    await db
      .prepare(
        "INSERT INTO ingestion_objects (id,object_key,etag,dataset,received_at,raw_expires_at,expires_at,state) VALUES ('foreign',?,'foreign','firewall',?,'2099-01-01T00:00:00.000Z','2099-01-01T00:00:00.000Z','failed')",
      )
      .bind(`${pilotRawPrefix}foreign.ndjson`, new Date().toISOString())
      .run();
    await db
      .prepare(
        "INSERT INTO ingestion_failures VALUES ('foreign','foreign','foreign_reason','private',?,'2099-01-01T00:00:00.000Z')",
      )
      .bind(new Date().toISOString())
      .run();
    const before = (await db.prepare("SELECT * FROM ingestion_objects ORDER BY id").all()).results;
    const coverage = (await (
      await api("/api/ingestion/reconciliation")
    ).json()) as IngestionCoverage;
    expect(coverage).toMatchObject({
      scope: "cloud-pilot-20261029",
      scanComplete: true,
      scannedObjects: 3,
      excludedObjects: 1,
    });
    expect(Object.fromEntries(coverage.objects.map((v) => [v.key, v.status]))).toEqual({
      [pilotRawKeys[0]]: "complete",
      [pilotRawKeys[1]]: "missing_checkpoint",
    });
    const status = (await (await api("/api/ingestion/status")).json()) as {
      objects: Array<{ object_key: string }>;
      failures: unknown[];
    };
    expect(status.objects.map((v) => v.object_key)).toEqual([pilotRawKeys[0]]);
    expect(status.failures).toEqual([]);
    expect((await db.prepare("SELECT * FROM ingestion_objects ORDER BY id").all()).results).toEqual(
      before,
    );
    expect((await api("/api/ingestion/reconciliation", "")).status).toBe(401);
    expect((await api("/api/ingestion/reconciliation?environment=live")).status).toBe(403);
    const foreignOwner = await new SignJWT({ email })
      .setProtectedHeader({ alg: "RS256", kid: "cloud-fixture" })
      .setIssuer(approvedAccess.issuer)
      .setAudience(approvedAccess.audience)
      .setSubject("another-subject")
      .setIssuedAt()
      .setExpirationTime("1h")
      .sign(pair.privateKey);
    expect((await api("/api/ingestion/reconciliation", foreignOwner)).status).toBe(403);
    const control = await runtime.getD1Database("APP_DB", "api");
    await control.prepare("DELETE FROM zone_access WHERE user_id='soc-owner'").run();
    expect((await api("/api/ingestion/reconciliation")).status).toBe(403);
    expect((await api("/api/ingestion/status")).status).toBe(403);
  });
  it("archives bounded failures with timing and rejects other keys, queues and HTTP ingress", async () => {
    const object = await bucket.put(pilotRawKeys[2], `${JSON.stringify(record())}\n{broken\n`);
    const ref = {
      account: cloudAccount,
      bucket: cloudBucket,
      action: "PutObject",
      object: { key: object.key, size: object.size, eTag: object.etag },
      eventTime: object.uploaded.toISOString(),
    };
    const worker = await runtime.getWorker("ingest");
    for (let attempt = 1; attempt <= 4; attempt++) {
      const result = await worker.queue("example-soc-ingest-simulation", [
        { id: "partial", timestamp: new Date(), attempts: attempt, body: ref },
      ]);
      expect(result.retryMessages.map((v) => v.msgId)).toContain("partial");
    }
    const before = await db.prepare("SELECT * FROM ingestion_objects").first<{
      first_attempt_at: string;
      raw_expires_at: string;
      expires_at: string;
      last_attempt_at: string;
    }>();
    const archived = await worker.queue("example-soc-ingest-simulation-dlq", [
      { id: "archive", timestamp: new Date(), attempts: 1, body: ref },
    ]);
    expect(archived.explicitAcks).toContain("archive");
    const row = await db
      .prepare("SELECT * FROM ingestion_objects")
      .first<{ archived_at: string; processed_at: string | null }>();
    expect(row).toMatchObject({
      state: "archived",
      attempts: 4,
      first_attempt_at: before?.first_attempt_at,
      raw_expires_at: before?.raw_expires_at,
      expires_at: before?.expires_at,
    });
    expect(Date.parse(row?.archived_at || "")).toBeGreaterThanOrEqual(
      Date.parse(before?.last_attempt_at || ""),
    );
    expect(row?.processed_at).toBeNull();
    const rejected = await worker.queue("example-soc-ingest-simulation", [
      {
        id: "foreign",
        timestamp: new Date(),
        attempts: 1,
        body: { ...ref, object: { ...ref.object, key: "raw/firewall/phase2b-outside.ndjson" } },
      },
    ]);
    expect(rejected.retryMessages.map((v) => v.msgId)).toContain("foreign");
    expect(await count("ingestion_objects")).toBe(1);
    const wrongQueue = await worker.queue("example-soc-ingest-live", [
      { id: "wrong-queue", timestamp: new Date(), attempts: 1, body: ref },
    ]);
    expect(wrongQueue.outcome).toBe("exception");
    expect(wrongQueue.explicitAcks).toEqual([]);
    expect(
      (await worker.fetch("http://127.0.0.1:8788/__local/replay", { method: "POST", body: "{}" }))
        .status,
    ).toBe(403);
  });
});
