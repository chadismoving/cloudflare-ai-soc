import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { convertV4MiniflareOptions, Miniflare } from "miniflare";
import { afterEach, beforeEach, expect, it } from "vitest";
import { approvedAccess } from "../apps/api/src/env";
import { collectFacts, digest, findings } from "../apps/api/src/live/analytics";
import { liveProfile, liveZone } from "../packages/shared/src/live";
import { ownerBootstrap, simulationBootstrap } from "../scripts/prepare-console.mjs";

const root = fileURLToPath(new URL("../", import.meta.url)),
  origin = approvedAccess.origin;
let mf: Miniflare,
  control: Awaited<ReturnType<Miniflare["getD1Database"]>>,
  db: typeof control,
  token = "",
  csrf = "",
  unexpected = 0;
async function send(path: string, body?: unknown, status = 200) {
  const r = await mf.dispatchFetch(origin + path, {
    method: body === undefined ? "GET" : "POST",
    headers: {
      Origin: origin,
      "Cf-Access-Jwt-Assertion": token,
      "X-CSRF-Token": csrf,
      ...(body === undefined ? {} : { "Content-Type": "application/json" }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const value = (await r.json()) as Record<string, unknown>;
  expect(r.status, JSON.stringify(value)).toBe(status);
  return value;
}
async function sql(file: string, target = db) {
  for (const s of (await readFile(root + file, "utf8"))
    .split(";")
    .map((s: string) => s.trim())
    .filter(Boolean))
    await target.prepare(s).run();
}
beforeEach(async () => {
  unexpected = 0;
  const pair = await generateKeyPair("RS256", { extractable: true }),
    subject = "synthetic-workbench-owner",
    email = "owner@fixture.invalid";
  const pin = createHash("sha256").update(subject).digest("hex");
  const config = JSON.parse(
    await readFile(`${root}apps/api/wrangler.workbench.review.jsonc`, "utf8"),
  );
  const jwks = {
    keys: [{ ...(await exportJWK(pair.publicKey)), kid: "workbench-test", alg: "RS256" }],
  };
  mf = new Miniflare({
    ...convertV4MiniflareOptions({
      modules: true,
      scriptPath: `${root}apps/api/dist/index.js`,
      compatibilityDate: config.compatibility_date,
      compatibilityFlags: config.compatibility_flags,
      cf: false,
      bindings: {
        ...config.vars,
        LIVE_PROFILE: liveProfile,
        OWNER_EMAIL: email,
        OWNER_SUBJECT_SHA256: pin,
        SESSION_CSRF_SECRET: "synthetic-workbench-csrf-at-least-32-characters",
      },
      d1Databases: { APP_DB: "control", SIMULATION_DB: "simulation", LIVE_DB: "live" },
      r2Buckets: { SIMULATION_EVIDENCE: "evidence" },
      serviceBindings: { ASSETS: async () => new Response("authenticated assets") },
      outboundService: async (req: Request) => {
        if (req.method === "GET" && req.url === `${approvedAccess.issuer}/cdn-cgi/access/certs`)
          return Response.json(jwks);
        unexpected++;
        return new Response("Forbidden network", { status: 503 });
      },
    }),
    host: "127.0.0.1",
    port: 0,
    telemetry: { enabled: false },
  });
  control = await mf.getD1Database("APP_DB");
  db = await mf.getD1Database("SIMULATION_DB");
  await sql("infrastructure/migrations/0001_foundation.sql", control);
  for (const s of ownerBootstrap({
    verified_login: true,
    intended_owner_email: email,
    subject_sha256: pin,
    subject_confirmation: "explicit synthetic fixture",
  })
    .split(";")
    .map((s: string) => s.trim())
    .filter(Boolean))
    await control.prepare(s).run();
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
    await sql(`infrastructure/${file}`);
  const bytes = await readFile(`${root}simulations/fixtures/evidence-001.json`);
  for (const s of simulationBootstrap(
    await readFile(`${root}infrastructure/seeds/simulation.sql`, "utf8"),
    bytes,
  )
    .split(";")
    .map((s: string) => s.trim())
    .filter(Boolean))
    await db.prepare(s).run();
  await (await mf.getR2Bucket("SIMULATION_EVIDENCE")).put("cases/fixture/evidence-001.json", bytes);
  token = await new SignJWT({ email })
    .setProtectedHeader({ alg: "RS256", kid: "workbench-test" })
    .setIssuer(approvedAccess.issuer)
    .setAudience(approvedAccess.audience)
    .setSubject(subject)
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(pair.privateKey);
  const live = await mf.getD1Database("LIVE_DB");
  await sql("infrastructure/live-migrations/0001_live_analytics.sql", live);
  await sql("infrastructure/live-migrations/0002_collection_pause.sql", live);
  await control
    .prepare(
      "INSERT INTO zones VALUES (?,'00000000000000000000000000000001','d.example.invalid',1,'live')",
    )
    .bind(liveZone)
    .run();
  await control
    .prepare("INSERT INTO zone_access VALUES ('soc-owner',?,'read')")
    .bind(liveZone)
    .run();
  csrf = String((await send("/api/session")).csrfToken);
});
afterEach(async () => {
  expect(unexpected).toBe(0);
  await mf?.dispose();
});
it("owner-pinned Access candidate completes twelve scenarios using only simulation storage and mock execution", async () => {
  expect((await send("/api/session")).workbenchEnabled).toBe(true);
  const catalog = (await send("/api/simulations/scenarios")).scenarios as { id: string }[];
  expect(catalog).toHaveLength(12);
  for (const scenario of catalog) {
    const r = await send(
      "/api/simulations/runs",
      {
        scenarioId: scenario.id,
        replayKey: crypto.randomUUID(),
        suiteId: "access-suite",
        exerciseActions: true,
      },
      201,
    );
    expect(r.evaluation).toMatchObject({
      classificationCorrect: true,
      recommendationCorrect: true,
      unauthorizedActions: 0,
      fixtureOnly: true,
    });
  }
  const report = await send("/api/simulations/report?suiteId=access-suite");
  expect(report.runs).toHaveLength(12);
  expect(report.metrics).toMatchObject({ unauthorizedActions: 0, modelQualityBenchmark: false });
  expect(
    (await (await mf.getR2Bucket("SIMULATION_EVIDENCE")).list({ prefix: "cases/workbench/" }))
      .objects,
  ).toHaveLength(12);
  expect(
    (await control.prepare("SELECT name FROM sqlite_master WHERE name LIKE 'wb_%'").all()).results,
  ).toHaveLength(0);
  expect(
    await db.prepare("SELECT state,COUNT(*) AS n FROM wb_evidence_registry GROUP BY state").first(),
  ).toEqual({ state: "registered", n: 12 });
});
it("Access mode keeps fixture login disabled and rejects CSRF-free replay or a downgraded owner", async () => {
  expect((await mf.dispatchFetch(`${origin}/__local/session`, { method: "POST" })).status).toBe(
    404,
  );
  expect(
    (
      await mf.dispatchFetch(`${origin}/api/simulations/runs`, {
        method: "POST",
        headers: { "Cf-Access-Jwt-Assertion": token, "Content-Type": "application/json" },
        body: JSON.stringify({ scenarioId: "waf-spike" }),
      })
    ).status,
  ).toBe(403);
  await control.prepare("UPDATE users SET role='Viewer' WHERE id='soc-owner'").run();
  await send("/api/simulations/runs", { scenarioId: "waf-spike" }, 403);
});

it("live Access routes require a current real-zone grant and never substitute simulation fixtures", async () => {
  expect(await send("/api/session")).toMatchObject({
    liveDataEnabled: true,
    liveConnectorsEnabled: true,
  });
  const overview = await send("/api/live/overview");
  expect(overview).toMatchObject({
    environment: "live",
    zoneId: liveZone,
    latest: null,
    findings: [],
    stale: true,
    aiEnabled: false,
    executionEnabled: false,
  });
  await send("/api/live/overview?zoneId=fixture-zone", undefined, 400);
  await send("/api/live/overview?environment=simulation", undefined, 400);
  await send("/api/live/overview", {}, 405);
  await control.prepare("DELETE FROM zone_access WHERE zone_id=?").bind(liveZone).run();
  await send("/api/live/overview", undefined, 403);
  expect((await send("/api/session")).liveDataEnabled).toBe(false);
  expect((await mf.dispatchFetch(origin + "/api/live/overview")).status).toBe(401);
  expect(
    (await db.prepare("SELECT name FROM sqlite_master WHERE name LIKE 'ld_%'").all()).results,
  ).toEqual([]);
});
it("requires an admin and CSRF protection to persist or resume collection", async () => {
  const path = "/api/live/collection";
  expect(
    (
      await mf.dispatchFetch(origin + path, {
        method: "POST",
        headers: {
          Origin: origin,
          "Cf-Access-Jwt-Assertion": token,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ enabled: false }),
      })
    ).status,
  ).toBe(403);
  await send(path, { enabled: "false" }, 400);
  const paused = await send(path, { enabled: false });
  expect(paused.collection_paused_at).toEqual(expect.any(String));
  expect(await send(path, { enabled: false })).toEqual(paused);
  expect((await send("/api/live/overview")).collector).toMatchObject(paused);
  await control.prepare("UPDATE users SET role='Viewer' WHERE id='soc-owner'").run();
  await send(path, { enabled: true }, 403);
  await control.prepare("UPDATE users SET role='Admin' WHERE id='soc-owner'").run();
  expect(await send(path, { enabled: true })).toEqual({ collection_paused_at: null });
});
it("only real evidence storage supplies live observations and integrity failures fail closed", async () => {
  const live = await mf.getD1Database("LIVE_DB");
  const facts = await collectFacts("test", Date.now() - 30 * 60000, (async (_url, init) => {
    const security = JSON.parse(String(init?.body)).query.includes("firewallEvents");
    return Response.json({
      data: {
        viewer: {
          zones: [
            {
              [security ? "firewallEventsAdaptiveGroups" : "httpRequestsAdaptiveGroups"]: security
                ? [{ count: 100, dimensions: { action: "block", source: "firewallCustom" } }]
                : [],
            },
          ],
        },
      },
      errors: null,
    });
  }) as typeof fetch);
  const text = JSON.stringify(facts),
    sha = await digest(text),
    f = findings(facts, sha)[0];
  if (!f) throw new Error("Missing test finding");
  await live
    .prepare("INSERT INTO ld_findings VALUES (?,?,?,?,?,?,?,?,?,?)")
    .bind(f.id, liveZone, facts.end, f.rule, f.title, f.severity, f.summary, text, sha, f.expiresAt)
    .run();
  const path = `/api/live/findings/${f.id}`;
  expect(await send(path)).toMatchObject({
    environment: "live",
    sha256: sha,
    evidence: facts,
  });
  expect((await send("/api/live/overview")).findings).toHaveLength(1);
  for (const [offset, count, truncated] of [
    [1, 100, false],
    [2, 12, false],
  ] as const) {
    const start = new Date(Date.parse(facts.end) + (offset - 1) * 300000).toISOString();
    const end = new Date(Date.parse(start) + 300000).toISOString();
    const snapshot = JSON.stringify({
      ...facts,
      start,
      end,
      security: {
        ...facts.security,
        groups: [{ action: "block", source: "firewallCustom", count }],
        truncated,
      },
    });
    await live
      .prepare("INSERT INTO ld_snapshots VALUES (?,?,?,?,?,?,?,?)")
      .bind(
        `test-${offset}`,
        liveZone,
        start,
        end,
        facts.collectedAt,
        snapshot,
        await digest(snapshot),
        f.expiresAt,
      )
      .run();
  }
  expect(await send(`${path}/follow-up`)).toMatchObject({
    windows: [
      { state: "threshold_met", count: 100 },
      { state: "below_threshold", count: 12 },
      { state: "not_collected", count: null },
    ],
  });
  await live.prepare("UPDATE ld_snapshots SET facts_json='{}' WHERE id='test-1'").run();
  await send(`${path}/follow-up`, undefined, 503);
  await live.prepare("UPDATE ld_findings SET evidence_json='{}'").run();
  await send(path, undefined, 503);
  expect((await send("/api/overview")).environment).toBe("simulation");
});
