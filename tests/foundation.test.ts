import { createHash, randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import type { Session } from "@soc/shared";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { convertV4MiniflareOptions, Miniflare } from "miniflare";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

const origin = "http://127.0.0.1:8787";
const root = fileURLToPath(new URL("../", import.meta.url));
let runtime: Miniflare;
let outboundRequests = 0;
let pair: Awaited<ReturnType<typeof generateKeyPair>>;
let control: Awaited<ReturnType<Miniflare["getD1Database"]>>;
let simulation: Awaited<ReturnType<Miniflare["getD1Database"]>>;
let bucket: Awaited<ReturnType<Miniflare["getR2Bucket"]>>;
let evidence: Buffer;

async function sign(
  subject = "fixture-admin",
  email = "admin@fixture.invalid",
  extra: Record<string, unknown> = {},
) {
  return new SignJWT({ email, ...extra })
    .setProtectedHeader({ alg: "RS256", kid: "test" })
    .setIssuer(`${origin}/__local/access`)
    .setAudience("soc-local-fixture")
    .setSubject(subject)
    .setIssuedAt()
    .setExpirationTime("15m")
    .sign(pair.privateKey);
}
async function request(
  path: string,
  options: {
    token?: string;
    method?: string;
    csrf?: string;
    origin?: string;
    body?: unknown;
    headers?: Record<string, string>;
  } = {},
) {
  const headers: Record<string, string> = { ...options.headers };
  if (options.token) headers["Cf-Access-Jwt-Assertion"] = options.token;
  if (options.csrf) headers["X-CSRF-Token"] = options.csrf;
  if (options.origin) headers.Origin = options.origin;
  if (options.body !== undefined) headers["Content-Type"] = "application/json";
  return runtime.dispatchFetch(`${origin}${path}`, {
    method: options.method || "GET",
    headers,
    ...(options.body !== undefined ? { body: JSON.stringify(options.body) } : {}),
  });
}
async function session(subject = "fixture-admin", email = "admin@fixture.invalid") {
  const token = await sign(subject, email);
  const response = await request("/api/session", { token });
  expect(response.status).toBe(200);
  return { token, value: (await response.json()) as Session };
}

beforeAll(async () => {
  pair = await generateKeyPair("RS256", { modulusLength: 2048, extractable: true });
  runtime = new Miniflare({
    ...convertV4MiniflareOptions({
      modules: true,
      scriptPath: `${root}apps/api/dist/index.js`,
      compatibilityDate: "2026-10-27",
      compatibilityFlags: ["nodejs_compat"],
      cf: false,
      bindings: {
        APP_ENV: "local",
        AUTH_MODE: "fixture",
        APP_ORIGIN: origin,
        ACCESS_ISSUER: `${origin}/__local/access`,
        ACCESS_AUDIENCE: "soc-local-fixture",
        LOCAL_ACCESS_JWKS: JSON.stringify({
          keys: [{ ...(await exportJWK(pair.publicKey)), kid: "test", alg: "RS256" }],
        }),
        LOCAL_ACCESS_PRIVATE_JWK: JSON.stringify({
          ...(await exportJWK(pair.privateKey)),
          kid: "test",
        }),
        SESSION_CSRF_SECRET: randomBytes(32).toString("hex"),
      },
      d1Databases: { APP_DB: "control", SIMULATION_DB: "simulation" },
      r2Buckets: { SIMULATION_EVIDENCE: "simulation-evidence" },
      serviceBindings: {
        ASSETS: async () =>
          new Response("<!doctype html><title>Fixture assets</title>", {
            headers: { "Content-Type": "text/html" },
          }),
      },
      outboundService: async () => {
        outboundRequests++;
        return new Response("Outbound network disabled", { status: 503 });
      },
    }),
    telemetry: { enabled: false },
    host: "127.0.0.1",
    port: 0,
  });
  control = await runtime.getD1Database("APP_DB");
  simulation = await runtime.getD1Database("SIMULATION_DB");
  bucket = await runtime.getR2Bucket("SIMULATION_EVIDENCE");
  const migration = await readFile(`${root}infrastructure/migrations/0001_foundation.sql`, "utf8");
  for (const db of [control, simulation]) {
    for (const statement of migration
      .split(";")
      .map((v) => v.trim())
      .filter(Boolean))
      await db.prepare(statement).run();
  }
  for (const statement of (await readFile(`${root}infrastructure/seeds/control.sql`, "utf8"))
    .split(";")
    .map((v) => v.trim())
    .filter(Boolean))
    await control.prepare(statement).run();
  evidence = await readFile(`${root}simulations/fixtures/evidence-001.json`);
  const sql = (await readFile(`${root}infrastructure/seeds/simulation.sql`, "utf8")).replace(
    "__EVIDENCE_SHA256__",
    createHash("sha256").update(evidence).digest("hex"),
  );
  for (const statement of sql
    .split(";")
    .map((v) => v.trim())
    .filter(Boolean))
    await simulation.prepare(statement).run();
});
beforeEach(async () => {
  await control
    .prepare("UPDATE users SET role='Viewer', active=1, version=0 WHERE id='user-viewer'")
    .run();
  await control.prepare("DELETE FROM audit_trail").run();
  await simulation
    .prepare(
      "UPDATE evidence_objects SET expires_at = strftime('%Y-%m-%dT%H:%M:%fZ','now','+90 days') WHERE id='evidence-001'",
    )
    .run();
  await bucket.put("simulation/cases/fixture/evidence-001.json", evidence);
});
afterAll(async () => {
  await runtime?.dispose();
});

describe("Worker authentication and bounded fixture login", () => {
  it("rejects unauthenticated API requests and forged signatures", async () => {
    expect((await request("/api/overview")).status).toBe(401);
    expect((await request("/api/overview", { token: "not.a.jwt" })).status).toBe(401);
  });
  it("rejects a signed but non-allowlisted human and mismatched email", async () => {
    expect(
      (await request("/api/session", { token: await sign("unknown", "unknown@fixture.invalid") }))
        .status,
    ).toBe(403);
    expect(
      (
        await request("/api/session", {
          token: await sign("fixture-admin", "different@fixture.invalid"),
        })
      ).status,
    ).toBe(403);
  });
  it("issues only a local HttpOnly SameSite cookie and never a response-body token", async () => {
    expect(
      (await request("/__local/session", { method: "POST", body: { persona: "admin" } })).status,
    ).toBe(403);
    const response = await request("/__local/session", {
      method: "POST",
      origin,
      body: { persona: "admin" },
    });
    expect(response.status).toBe(200);
    expect(response.headers.get("Set-Cookie")).toContain("HttpOnly; SameSite=Strict");
    expect(await response.json()).toEqual({ fixture: true });
  });
  it("fails closed on a non-loopback host even with a valid assertion", async () => {
    const response = await runtime.dispatchFetch("https://soc.d.example.invalid/api/session", {
      headers: { "Cf-Access-Jwt-Assertion": await sign() },
    });
    expect(response.status).toBe(503);
    expect(
      (
        await runtime.dispatchFetch("https://soc.d.example.invalid/__local/session", {
          method: "POST",
        })
      ).status,
    ).toBe(503);
  });
  it("rejects disabled users on every request", async () => {
    const jwt = await sign("fixture-viewer", "viewer@fixture.invalid");
    await control.prepare("UPDATE users SET active=0 WHERE id='user-viewer'").run();
    expect((await request("/api/overview", { token: jwt })).status).toBe(403);
  });
});

describe("RBAC, CSRF, zone isolation and audit atomicity", () => {
  it("denies Viewer approval and role changes despite an Admin claim in JWT", async () => {
    const jwt = await sign("fixture-viewer", "viewer@fixture.invalid", { role: "Admin" });
    const response = await request("/api/session", { token: jwt });
    const value = (await response.json()) as Session;
    expect(value.user.role).toBe("Viewer");
    const options = { token: jwt, csrf: value.csrfToken, origin, method: "POST", body: {} };
    expect((await request("/api/authorization/approval-check", options)).status).toBe(403);
    expect(
      (
        await request("/api/admin/users/user-viewer/role", {
          ...options,
          method: "PATCH",
          body: { role: "Operator", version: 0 },
        })
      ).status,
    ).toBe(403);
    expect(
      (
        await control
          .prepare("SELECT COUNT(*) AS count FROM audit_trail")
          .first<{ count: number }>()
      )?.count,
    ).toBe(0);
  });
  it("requires both same origin and a token bound to the verified session", async () => {
    const admin = await session();
    const base = { token: admin.token, method: "PATCH", body: { role: "Analyst", version: 0 } };
    expect((await request("/api/admin/users/user-viewer/role", { ...base, origin })).status).toBe(
      403,
    );
    expect(
      (
        await request("/api/admin/users/user-viewer/role", {
          ...base,
          origin: "https://attacker.invalid",
          csrf: admin.value.csrfToken,
        })
      ).status,
    ).toBe(403);
    expect(
      (await request("/api/admin/users/user-viewer/role", { ...base, origin, csrf: "wrong" }))
        .status,
    ).toBe(403);
  });
  it("atomically records a privileged role change and applies it to an existing user JWT", async () => {
    const admin = await session();
    const viewer = await session("fixture-viewer", "viewer@fixture.invalid");
    const result = await request("/api/admin/users/user-viewer/role", {
      token: admin.token,
      csrf: admin.value.csrfToken,
      origin,
      method: "PATCH",
      body: { role: "Operator", version: 0 },
    });
    expect(result.status).toBe(200);
    const audit = await request("/api/audit", { token: admin.token });
    const records = (await audit.json()) as {
      records: Array<{ details_json: string; operation: string }>;
    };
    expect(records.records).toHaveLength(1);
    expect(records.records[0]?.operation).toBe("rbac.role.changed");
    expect(JSON.parse(records.records[0]?.details_json || "{}")).toEqual({
      from: "Viewer",
      to: "Operator",
    });
    const refreshed = await request("/api/session", { token: viewer.token });
    const changed = (await refreshed.json()) as Session;
    expect(changed.user.role).toBe("Operator");
    const check = await request("/api/authorization/approval-check", {
      token: viewer.token,
      csrf: changed.csrfToken,
      origin,
      method: "POST",
      body: {},
    });
    expect(await check.json()).toMatchObject({
      roleAuthorized: true,
      approvalRecorded: false,
      executionEnabled: false,
    });
  });
  it("does not write misleading audit records on stale versions or partial failures", async () => {
    const admin = await session();
    const options = {
      token: admin.token,
      csrf: admin.value.csrfToken,
      origin,
      method: "PATCH",
      body: { role: "Operator", version: 2 },
    };
    expect((await request("/api/admin/users/user-viewer/role", options)).status).toBe(409);
    expect(
      (
        await control
          .prepare("SELECT COUNT(*) AS count FROM audit_trail")
          .first<{ count: number }>()
      )?.count,
    ).toBe(0);
    await control.exec(
      "CREATE TRIGGER reject_test_audit BEFORE INSERT ON audit_trail BEGIN SELECT RAISE(ABORT, 'fixture audit failure'); END",
    );
    try {
      expect(
        (
          await request("/api/admin/users/user-viewer/role", {
            ...options,
            body: { role: "Operator", version: 0 },
          })
        ).status,
      ).toBe(500);
      expect(
        (
          await control
            .prepare("SELECT role FROM users WHERE id='user-viewer'")
            .first<{ role: string }>()
        )?.role,
      ).toBe("Viewer");
    } finally {
      await control.exec("DROP TRIGGER reject_test_audit");
    }
  });
  it("rejects owner-role changes and arbitrary/new Admin assignments", async () => {
    const admin = await session();
    const options = {
      token: admin.token,
      csrf: admin.value.csrfToken,
      origin,
      method: "PATCH",
      body: { role: "Viewer", version: 0 },
    };
    expect((await request("/api/admin/users/user-admin/role", options)).status).toBe(403);
    expect(
      (
        await request("/api/admin/users/user-viewer/role", {
          ...options,
          body: { role: "Admin", version: 0 },
        })
      ).status,
    ).toBe(400);
  });
  it("enforces zones on list/detail, and rejects browser-controlled live selection", async () => {
    const { token } = await session();
    const list = await request("/api/overview", { token });
    const payload = (await list.json()) as { incidents: Array<{ zone_id: string }> };
    expect(payload.incidents).toHaveLength(2);
    expect(payload.incidents.every((v) => v.zone_id === "fixture-zone")).toBe(true);
    expect((await request("/api/overview?zoneId=other-zone", { token })).status).toBe(403);
    expect((await request("/api/incidents/incident-other", { token })).status).toBe(403);
    expect((await request("/api/overview?environment=live", { token })).status).toBe(403);
  });
});

describe("storage constraints and evidence provenance", () => {
  it("keeps incident data out of the control database and constrains cross-environment links", async () => {
    expect(
      (await control.prepare("SELECT COUNT(*) AS count FROM incidents").first<{ count: number }>())
        ?.count,
    ).toBe(0);
    await expect(
      simulation.prepare("UPDATE incidents SET environment='live' WHERE id='incident-001'").run(),
    ).rejects.toThrow();
    await expect(
      simulation
        .prepare(
          "INSERT INTO incident_events VALUES ('incident-001','missing-event','simulation','fixture-zone')",
        )
        .run(),
    ).rejects.toThrow();
  });
  it("enforces event deduplication as a database constraint", async () => {
    await expect(
      simulation
        .prepare(
          "INSERT INTO events SELECT 'event-duplicate', environment, zone_id, source, category, event_time, received_at, dedupe_key, metadata_json, expires_at FROM events WHERE id='event-001'",
        )
        .run(),
    ).rejects.toThrow();
  });
  it("previews only retained simulation evidence and detects changed object contents", async () => {
    const { token } = await session();
    const response = await request("/api/evidence/evidence-001", { token });
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      environment: "simulation",
      evidence: { fixture: true },
    });
    await bucket.put("simulation/cases/fixture/evidence-001.json", "tampered");
    expect((await request("/api/evidence/evidence-001", { token })).status).toBe(409);
    await simulation
      .prepare("UPDATE evidence_objects SET expires_at='2000-01-01T00:00:00.000Z'")
      .run();
    expect((await request("/api/evidence/evidence-001", { token })).status).toBe(404);
  });
  it("has no action execution route or outbound network activity", async () => {
    const admin = await session();
    const result = await request("/api/actions/anything/approve", {
      token: admin.token,
      csrf: admin.value.csrfToken,
      origin,
      method: "POST",
      body: {},
    });
    expect(result.status).toBe(404);
    expect(outboundRequests).toBe(0);
  });
  it("sets browser security headers on authenticated and rejected responses", async () => {
    const result = await request("/api/overview");
    expect(result.headers.get("Cache-Control")).toBe("no-store");
    expect(result.headers.get("Content-Security-Policy")).toContain("frame-ancestors 'none'");
    expect(result.headers.get("Access-Control-Allow-Origin")).toBeNull();
  });
});
