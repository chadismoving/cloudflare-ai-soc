import { randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";
import { convertV4MiniflareOptions, Miniflare } from "miniflare";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const root = fileURLToPath(new URL("../", import.meta.url));
const origin = "http://127.0.0.1:8788";
const secret = randomBytes(32).toString("hex");
let runtime: Miniflare;
let db: Awaited<ReturnType<Miniflare["getD1Database"]>>;
let bucket: Awaited<ReturnType<Miniflare["getR2Bucket"]>>;
let queue: Awaited<ReturnType<Miniflare["getQueueProducer"]>>;
let outbound = 0;
const base = Math.floor(Date.now() / 300000) * 300000 - 300000;
const record = (ray = "ray-001", time = base + 10000, rule = "rule-a") => ({
  fixture: true,
  RayID: ray,
  Datetime: new Date(time).toISOString(),
  Action: "block",
  RuleID: rule,
  Source: "waf",
  ClientRequestHost: "demo.fixture.invalid",
  ClientRequestPath: "/__soc_test/login",
  ClientIP: "client-a",
});
async function waitFor<T>(
  fn: () => Promise<T>,
  accept: (v: T) => boolean,
  timeout = 11000,
): Promise<T> {
  const end = Date.now() + timeout;
  for (;;) {
    const value = await fn();
    if (accept(value)) return value;
    if (Date.now() > end) throw Error(`Local Queue acceptance timed out: ${JSON.stringify(value)}`);
    await new Promise((r) => setTimeout(r, 40));
  }
}
async function request(path: string, body?: unknown, auth = secret, requestOrigin = origin) {
  return runtime.dispatchFetch(requestOrigin + path, {
    method: body === undefined ? "GET" : "POST",
    headers: { "cf-webhook-auth": auth, "Content-Type": "application/json" },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}
async function put(key: string, content: string | Buffer) {
  const object = await bucket.put(key, content);
  const ref = {
    account: "fixture-account",
    bucket: "soc-local-simulation-evidence",
    action: "PutObject",
    object: { key, size: object.size, eTag: object.etag },
    eventTime: object.uploaded.toISOString(),
  };
  await queue.send(ref);
  return ref;
}
async function state(key: string) {
  return db.prepare("SELECT * FROM ingestion_objects WHERE object_key=?").bind(key).first<{
    id: string;
    state: string;
    attempts: number;
    valid_rows: number;
    invalid_rows: number;
    last_error: string;
    received_at: string;
    first_attempt_at: string | null;
    last_attempt_at: string | null;
    processed_at: string | null;
    archived_at: string | null;
    expires_at: string;
  }>();
}
async function count(table: string) {
  return (await db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).first<{ n: number }>())?.n;
}
async function completed(key: string) {
  return waitFor(
    () => state(key),
    (v) => v?.state === "complete",
  );
}
beforeEach(async () => {
  outbound = 0;
  runtime = new Miniflare({
    ...convertV4MiniflareOptions({
      modules: true,
      scriptPath: `${root}apps/ingest/dist/index.js`,
      compatibilityDate: "2026-10-27",
      compatibilityFlags: ["nodejs_compat"],
      cf: false,
      bindings: { APP_ENV: "local", DATA_ENVIRONMENT: "simulation", LOCAL_INGEST_SECRET: secret },
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
      outboundService: async () => {
        outbound++;
        return new Response("Network disabled", { status: 503 });
      },
    }),
    host: "127.0.0.1",
    port: 0,
    telemetry: { enabled: false },
  });
  db = await runtime.getD1Database("SIMULATION_DB");
  bucket = await runtime.getR2Bucket("SIMULATION_STORE");
  queue = await runtime.getQueueProducer("INGEST_QUEUE");
  for (const file of [
    "0001_foundation.sql",
    "0002_ingestion.sql",
    "0003_ingestion_metrics.sql",
    "0004_ingestion_observability.sql",
  ])
    for (const s of (await readFile(`${root}infrastructure/migrations/${file}`, "utf8"))
      .split(";")
      .map((v) => v.trim())
      .filter(Boolean))
      await db.prepare(s).run();
  await db
    .prepare(
      "INSERT INTO zones VALUES ('fixture-zone','fixture-account','demo.fixture.invalid',1,'simulation')",
    )
    .run();
});
afterEach(async () => {
  await runtime?.dispose();
});

describe("actual local Queue ingestion and deterministic persistence", () => {
  it("streams gzip, deduplicates concurrent object delivery and duplicate logical records across files", async () => {
    const text = `${[record(), record("ray-002", base + 20000)].map((v) => JSON.stringify(v)).join("\n")}\n`;
    const ref = await put("raw/firewall/first.ndjson.gz", gzipSync(text));
    await Promise.all([queue.send(ref), queue.send(ref), put("raw/firewall/second.ndjson", text)]);
    await completed("raw/firewall/first.ndjson.gz");
    await completed("raw/firewall/second.ndjson");
    expect(await count("events")).toBe(2);
    expect(await count("incidents")).toBe(1);
    expect(await count("incident_events")).toBe(2);
    expect(await count("ingestion_provenance")).toBe(4);
    expect(await count("evidence_objects")).toBe(2);
    expect((await bucket.list({ prefix: "simulation/cases/" })).objects).toHaveLength(2);
    expect(outbound).toBe(0);
  });
  it("preserves different security matches sharing RayID and handles late arrivals and fixed window boundaries", async () => {
    for (const [name, r] of [
      ["late", record("ray-late", base + 40000)],
      ["early", record("ray-early", base + 1000)],
      ["match", record("ray-late", base + 40000, "rule-b")],
      ["boundary", record("ray-next", base - 1000)],
    ] as const) {
      const key = `raw/firewall/${name}.ndjson`;
      await put(key, JSON.stringify(r));
      await completed(key);
    }
    expect(await count("events")).toBe(4);
    expect(await count("incidents")).toBe(2);
    const incident = await db
      .prepare("SELECT first_seen,last_seen FROM incidents WHERE first_seen=?")
      .bind(new Date(base + 1000).toISOString())
      .first();
    expect(incident).toMatchObject({ last_seen: new Date(base + 40000).toISOString() });
  });
  it("accepts allowlisted HTTP records and strips unknown fields from evidence", async () => {
    const row = {
      ...record(),
      EdgeStartTimestamp: new Date(base).toISOString(),
      Cookie: "fixture-must-not-be-retained",
      Authorization: "fixture-secret",
    };
    await put("raw/http/http.ndjson", JSON.stringify(row));
    await completed("raw/http/http.ndjson");
    const meta = await db
      .prepare("SELECT object_key FROM evidence_objects")
      .first<{ object_key: string }>();
    const text = await (await bucket.get(meta?.object_key || ""))?.text();
    expect(text).not.toContain("fixture-secret");
    expect(text).not.toContain("Cookie");
    expect(await db.prepare("SELECT source,category FROM events").first()).toEqual({
      source: "synthetic",
      category: "http",
    });
  });
  it("recovers after event transaction commits but completion/ack fails, without duplicate counts or renewed expiry", async () => {
    await db.exec(
      "CREATE TRIGGER fail_complete BEFORE UPDATE OF state ON ingestion_objects WHEN NEW.state='complete' BEGIN SELECT RAISE(ABORT,'test completion failure'); END",
    );
    await put("raw/firewall/crash.ndjson", JSON.stringify(record()));
    await waitFor(
      () => count("events"),
      (n) => n === 1,
    );
    const before = await state("raw/firewall/crash.ndjson");
    await db.exec("DROP TRIGGER fail_complete");
    await completed("raw/firewall/crash.ndjson");
    expect(await count("events")).toBe(1);
    expect(await count("incident_events")).toBe(1);
    expect((await state("raw/firewall/crash.ndjson"))?.expires_at).toBe(before?.expires_at);
  });
  it("archives exhausted transient writes, retries failed archive, then repairs evidence/checkpoint by audited replay", async () => {
    await db.exec(
      "CREATE TRIGGER fail_event BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT,'test DB failure'); END",
    );
    await db.exec(
      "CREATE TRIGGER fail_archive BEFORE INSERT ON ingestion_failures BEGIN SELECT RAISE(ABORT,'test archive failure'); END",
    );
    await put("raw/firewall/recovery.ndjson", JSON.stringify(record()));
    await waitFor(
      () => state("raw/firewall/recovery.ndjson"),
      (v) => (v?.attempts || 0) >= 4,
    );
    expect(await count("events")).toBe(0);
    expect(await count("ingestion_failures")).toBe(0);
    await db.exec("DROP TRIGGER fail_archive");
    const archived = await waitFor(
      () => state("raw/firewall/recovery.ndjson"),
      (v) => v?.state === "archived",
    );
    expect(archived?.archived_at).toBeTruthy();
    expect(Date.parse(archived?.archived_at || "")).toBeGreaterThanOrEqual(
      Date.parse(archived?.last_attempt_at || ""),
    );
    expect(archived?.processed_at).toBeNull();
    expect(await count("ingestion_failures")).toBe(1);
    expect(
      (await bucket.list({ prefix: "simulation/tool-snapshots/ingest-failures/" })).objects,
    ).toHaveLength(1);
    await db.exec("DROP TRIGGER fail_event");
    expect((await request("/__local/replay", { objectId: archived?.id })).status).toBe(202);
    const recovered = await completed("raw/firewall/recovery.ndjson");
    expect(recovered?.first_attempt_at).toBe(archived?.first_attempt_at);
    expect(recovered?.expires_at).toBe(archived?.expires_at);
    expect(recovered?.processed_at).toBeTruthy();
    expect(await count("events")).toBe(1);
    expect(await count("evidence_objects")).toBe(1);
    expect(await count("ingestion_replays")).toBe(1);
  });
  it("keeps valid rows in a partial batch and persists failure instead of marking malformed input complete", async () => {
    await put("raw/firewall/partial.ndjson", `${JSON.stringify(record())}\n{broken\n`);
    const row = await waitFor(
      () => state("raw/firewall/partial.ndjson"),
      (v) => v?.state === "archived",
    );
    expect(row).toMatchObject({ valid_rows: 1, invalid_rows: 1, last_error: "invalid_rows" });
    expect(await count("events")).toBe(1);
    expect(await count("ingestion_failures")).toBe(1);
  });
  it.each([
    ["bad-gzip.ndjson.gz", Buffer.from("not gzip"), "invalid_compression"],
    ["long.ndjson", Buffer.from("x".repeat(65537)), "line_limit"],
    ["bomb.ndjson.gz", gzipSync("\n".repeat(9 * 1024 * 1024)), "row_limit"],
  ])("bounds corrupt or oversized parsing: %s", async (name, data, error) => {
    const key = `raw/firewall/${name}`;
    await put(key, data);
    const row = await waitFor(
      () => state(key),
      (v) => v?.state === "archived",
    );
    expect(row?.last_error).toBe(error);
    expect(await count("events")).toBe(0);
  });
  it("enforces decompression size independently of per-line and row limits", async () => {
    const data = gzipSync(`${" ".repeat(64000)}\n`.repeat(140));
    await put("raw/firewall/expanded.ndjson.gz", data);
    const row = await waitFor(
      () => state("raw/firewall/expanded.ndjson.gz"),
      (v) => v?.state === "archived",
    );
    expect(row?.last_error).toBe("expanded_limit");
  });
  it("rejects replaced, missing, wrong account/bucket/prefix/actions without reading live resources", async () => {
    const object = await bucket.put("raw/firewall/replaced.ndjson", JSON.stringify(record()));
    const ref = {
      account: "fixture-account",
      bucket: "soc-local-simulation-evidence",
      action: "PutObject",
      object: { key: object.key, size: object.size, eTag: object.etag },
      eventTime: object.uploaded.toISOString(),
    };
    await bucket.put(object.key, "changed");
    await queue.send(ref);
    await queue.send({ ...ref, object: { ...ref.object, key: "raw/firewall/missing.ndjson" } });
    await queue.send({ ...ref, bucket: "example-cloudflare-ai-soc-live" });
    await queue.send({ ...ref, account: "untrusted-account" });
    await queue.send({ ...ref, action: "DeleteObject" });
    await queue.send({ ...ref, object: { ...ref.object, key: "cases/forbidden.json" } });
    await waitFor(
      () => count("ingestion_failures"),
      (n) => n === 6,
    );
    expect(await count("events")).toBe(0);
    expect(outbound).toBe(0);
  });
  it("rejects raw expiry and event tombstone replay without extending retention", async () => {
    await put("raw/firewall/expire.ndjson", JSON.stringify(record()));
    await completed("raw/firewall/expire.ndjson");
    const row = await state("raw/firewall/expire.ndjson");
    await db
      .prepare("UPDATE ingestion_objects SET raw_expires_at='2000-01-01T00:00:00.000Z'")
      .run();
    expect((await request("/__local/replay", { objectId: row?.id })).status).toBe(410);
    await db
      .prepare("UPDATE ingestion_event_keys SET event_expires_at='2000-01-01T00:00:00.000Z'")
      .run();
    await put("raw/firewall/expire-copy.ndjson", JSON.stringify(record()));
    const copy = await waitFor(
      () => state("raw/firewall/expire-copy.ndjson"),
      (v) => v?.state === "archived",
    );
    expect(copy?.valid_rows).toBe(0);
    expect(await count("events")).toBe(1);
  });
});

describe("loopback notification authentication and durable acceptance", () => {
  it("fails closed when the runtime is configured for live data", async () => {
    const blocked = new Miniflare({
      ...convertV4MiniflareOptions({
        modules: true,
        scriptPath: `${root}apps/ingest/dist/index.js`,
        compatibilityDate: "2026-10-27",
        compatibilityFlags: ["nodejs_compat"],
        cf: false,
        bindings: { APP_ENV: "local", DATA_ENVIRONMENT: "live", LOCAL_INGEST_SECRET: secret },
      }),
      host: "127.0.0.1",
      port: 0,
      telemetry: { enabled: false },
    });
    try {
      expect(
        (
          await blocked.dispatchFetch(`${origin}/status`, {
            headers: { "cf-webhook-auth": secret },
          })
        ).status,
      ).toBe(403);
    } finally {
      await blocked.dispose();
    }
  });
  it("rejects explicit live claims, oversized compressed objects and unsupported datasets", async () => {
    expect(
      (
        await request("/__local/object", {
          key: "raw/firewall/live.ndjson",
          records: [{ ...record(), environment: "live" }],
          gzip: false,
        })
      ).status,
    ).toBe(422);
    await put("raw/firewall/large.ndjson", Buffer.alloc(1048577));
    await put("raw/unknown/dataset.ndjson", JSON.stringify(record()));
    await waitFor(
      () => count("ingestion_failures"),
      (n) => n === 2,
    );
    expect(await count("events")).toBe(0);
    expect(outbound).toBe(0);
  });
  const notification = () => ({
    fixture: true,
    account_id: "fixture-account",
    policy_id: "fixture-waf-policy",
    alert_type: "waf_alert",
    alert_correlation_id: "alert-a",
    ts: new Date(base).toISOString(),
    data: { zone_id: "fixture-zone", client: "client-a" },
  });
  it("rejects absent/wrong secret, non-loopback host, invalid JSON and ambiguous or untrusted tenancy", async () => {
    expect((await request("/notification", notification(), "")).status).toBe(403);
    expect((await request("/notification", notification(), "wrong")).status).toBe(403);
    expect(
      (await request("/notification", notification(), secret, "https://soc.d.example.invalid"))
        .status,
    ).toBe(403);
    expect(
      (await request("/notification", { ...notification(), account_id: "untrusted" })).status,
    ).toBe(400);
    expect((await request("/notification", { fixture: true, text: "real attack" })).status).toBe(
      400,
    );
    expect(
      (
        await request("/notification", {
          ...notification(),
          data: { zone_id: "other-zone", client: "client-a" },
        })
      ).status,
    ).toBe(400);
    expect(
      (
        await runtime.dispatchFetch(`${origin}/notification`, {
          method: "POST",
          headers: { "cf-webhook-auth": secret },
          body: "{",
        })
      ).status,
    ).toBe(400);
    expect(await count("events")).toBe(0);
  });
  it("distinguishes test-only payloads and durably queues valid notifications with replay dedup", async () => {
    expect(
      await (await request("/notification", { fixture: true, text: "webhook test" })).json(),
    ).toEqual({ testOnly: true, incidentCreated: false });
    const first = await request("/notification", notification());
    expect(first.status).toBe(202);
    expect((await request("/notification", notification())).status).toBe(202);
    await waitFor(
      () => count("events"),
      (n) => n === 1,
    );
    await waitFor(
      () => count("incidents"),
      (n) => n === 1,
    );
    expect(await count("events")).toBe(1);
    expect(await count("ingestion_objects")).toBe(1);
    expect(outbound).toBe(0);
  });
  it("rejects oversized request and disallowed object namespace before persistence", async () => {
    expect(
      (
        await request("/__local/object", {
          key: "cases/test.json",
          records: [record()],
          gzip: false,
        })
      ).status,
    ).toBe(400);
    expect((await request("/notification", { padding: "x".repeat(70000) })).status).toBe(422);
    expect((await bucket.list()).objects).toHaveLength(0);
  });
});
