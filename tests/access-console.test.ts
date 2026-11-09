import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import type { Session } from "@soc/shared";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { convertV4MiniflareOptions, Miniflare } from "miniflare";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { approvedAccess, type Bindings, isAccessRuntime } from "../apps/api/src/env";
import { ownerBootstrap, simulationBootstrap } from "../scripts/prepare-console.mjs";

const root = fileURLToPath(new URL("../", import.meta.url));
const email = "owner@fixture.invalid";
const subject = "synthetic-confirmed-owner";
const digest = createHash("sha256").update(subject).digest("hex");
const identity = {
  verified_login: true,
  intended_owner_email: email,
  subject_sha256: digest,
  subject_confirmation: "explicit fixture confirmation",
};
const origin = approvedAccess.origin;
const configuration = {
  APP_ENV: "production",
  AUTH_MODE: "access",
  APP_ORIGIN: origin,
  ACCESS_ISSUER: approvedAccess.issuer,
  ACCESS_AUDIENCE: approvedAccess.audience,
  OWNER_EMAIL: email,
  OWNER_SUBJECT_SHA256: digest,
  SESSION_CSRF_SECRET: "synthetic-csrf-secret-at-least-32-characters",
};
let runtime: Miniflare;
let control: Awaited<ReturnType<Miniflare["getD1Database"]>>;
let simulation: Awaited<ReturnType<Miniflare["getD1Database"]>>;
let bucket: Awaited<ReturnType<Miniflare["getR2Bucket"]>>;
let pair: Awaited<ReturnType<typeof generateKeyPair>>;
let assetCalls = 0;
let unexpectedNetwork = 0;
let bytes: Buffer;
const request = (
  path: string,
  token?: string,
  options: { method?: string; body?: string; headers?: Record<string, string> } = {},
) =>
  runtime.dispatchFetch(`${origin}${path}`, {
    ...options,
    headers: { ...(token ? { "Cf-Access-Jwt-Assertion": token } : {}), ...options.headers },
  });
async function sign(
  options: {
    subject?: string;
    email?: string;
    issuer?: string;
    audience?: string;
    expires?: number;
    role?: string;
  } = {},
) {
  return new SignJWT({
    email: options.email ?? email,
    ...(options.role ? { role: options.role } : {}),
  })
    .setProtectedHeader({ alg: "RS256", kid: "console-test" })
    .setIssuedAt()
    .setIssuer(options.issuer ?? approvedAccess.issuer)
    .setAudience(options.audience ?? approvedAccess.audience)
    .setSubject(options.subject ?? subject)
    .setExpirationTime(options.expires ?? Math.floor(Date.now() / 1000) + 600)
    .sign(pair.privateKey);
}
async function runSql(db: typeof control, sql: string) {
  for (const statement of sql
    .split(";")
    .map((v) => v.trim())
    .filter(Boolean))
    await db.prepare(statement).run();
}
async function session() {
  const token = await sign();
  const response = await request("/api/session", token);
  expect(response.status).toBe(200);
  return { token, value: (await response.json()) as Session };
}

beforeAll(async () => {
  pair = await generateKeyPair("RS256", { extractable: true });
  const jwks = {
    keys: [{ ...(await exportJWK(pair.publicKey)), kid: "console-test", alg: "RS256" }],
  };
  runtime = new Miniflare({
    ...convertV4MiniflareOptions({
      modules: true,
      scriptPath: `${root}apps/api/dist/index.js`,
      compatibilityDate: "2026-10-27",
      compatibilityFlags: ["nodejs_compat"],
      cf: false,
      bindings: configuration,
      d1Databases: { APP_DB: "control", SIMULATION_DB: "simulation" },
      r2Buckets: { SIMULATION_EVIDENCE: "isolated-evidence" },
      serviceBindings: {
        ASSETS: async () => {
          assetCalls++;
          return new Response("<title>Authenticated console</title>", {
            headers: { "Content-Type": "text/html" },
          });
        },
      },
      outboundService: async (req: Request) => {
        if (req.url === `${approvedAccess.issuer}/cdn-cgi/access/certs` && req.method === "GET")
          return Response.json(jwks);
        unexpectedNetwork++;
        return new Response("Unexpected network denied", { status: 503 });
      },
    }),
    host: "127.0.0.1",
    port: 0,
    telemetry: { enabled: false },
  });
  control = await runtime.getD1Database("APP_DB");
  simulation = await runtime.getD1Database("SIMULATION_DB");
  bucket = await runtime.getR2Bucket("SIMULATION_EVIDENCE");
  const migration = await readFile(`${root}infrastructure/migrations/0001_foundation.sql`, "utf8");
  for (const db of [control, simulation]) await runSql(db, migration);
  bytes = await readFile(`${root}simulations/fixtures/evidence-001.json`);
  await runSql(
    simulation,
    simulationBootstrap(
      await readFile(`${root}infrastructure/seeds/simulation.sql`, "utf8"),
      bytes,
    ),
  );
  await bucket.put("cases/fixture/evidence-001.json", bytes);
});
beforeEach(async () => {
  await runSql(control, ownerBootstrap(identity));
  await control
    .prepare("UPDATE users SET active=1, role='Admin', email=? WHERE id='soc-owner'")
    .bind(email)
    .run();
  await control.prepare("UPDATE zones SET enabled=1 WHERE id='fixture-zone'").run();
  await control
    .prepare("UPDATE zone_access SET permission='manage' WHERE user_id='soc-owner'")
    .run();
  await simulation
    .prepare(
      "UPDATE evidence_objects SET object_key='cases/fixture/evidence-001.json' WHERE id='evidence-001'",
    )
    .run();
  assetCalls = 0;
});
afterAll(async () => {
  await runtime?.dispose();
});

describe("production console configuration guard", () => {
  it.each([
    ["fixture auth mode", { AUTH_MODE: "fixture" }],
    ["local environment", { APP_ENV: "local" }],
    ["alternate issuer", { ACCESS_ISSUER: "https://other.cloudflareaccess.com" }],
    ["alternate audience", { ACCESS_AUDIENCE: "different-app" }],
    ["missing owner", { OWNER_EMAIL: "" }],
    ["unconfirmed subject", { OWNER_SUBJECT_SHA256: "" }],
    ["missing CSRF secret", { SESSION_CSRF_SECRET: "" }],
  ])("fails closed for %s", (_label, overrides) => {
    expect(
      isAccessRuntime(new Request(origin), { ...configuration, ...overrides } as Bindings),
    ).toBe(false);
  });
  it("rejects alternate hostnames before using authentication or assets", async () => {
    for (const host of [
      "https://example.workers.dev",
      "https://other.d.example.invalid",
      "http://soc.d.example.invalid",
    ])
      expect(
        (
          await runtime.dispatchFetch(`${host}/`, {
            headers: { "Cf-Access-Jwt-Assertion": await sign() },
          })
        ).status,
      ).toBe(503);
    expect(assetCalls).toBe(0);
  });
});

describe("Access, pinned owner and D1 admission in workerd", () => {
  it("requires authentication and D1 admission before frontend, assets and API", async () => {
    for (const path of ["/", "/assets/app.js", "/api/session"])
      expect((await request(path)).status).toBe(401);
    expect(assetCalls).toBe(0);
    const token = await sign();
    expect((await request("/assets/app.js", token)).status).toBe(200);
    expect(assetCalls).toBe(1);
    await control.prepare("UPDATE users SET active=0 WHERE id='soc-owner'").run();
    expect((await request("/assets/app.js", token)).status).toBe(403);
    expect(assetCalls).toBe(1);
  });
  it("reads the Admin role from pre-provisioned D1 and never returns identity/JWT", async () => {
    const { token, value } = await session();
    expect(value).toMatchObject({
      user: { id: "soc-owner", role: "Admin" },
      authMode: "cloudflare-access",
      environment: "simulation",
      liveConnectorsEnabled: false,
      executionEnabled: false,
    });
    expect(JSON.stringify(value)).not.toContain(token);
    expect(JSON.stringify(value)).not.toContain(email);
    expect(JSON.stringify(value)).not.toContain(subject);
    expect(
      (
        await control
          .prepare("SELECT access_subject FROM users WHERE id='soc-owner'")
          .first<{ access_subject: string }>()
      )?.access_subject,
    ).toBe(`sha256:${digest}`);
  });
  it("never registers a first visitor or grants Admin without its D1 row", async () => {
    await control.prepare("DELETE FROM users WHERE id='soc-owner'").run();
    expect((await request("/api/session", await sign())).status).toBe(403);
    expect(
      (await control.prepare("SELECT COUNT(*) AS count FROM users").first<{ count: number }>())
        ?.count,
    ).toBe(0);
  });
  it.each([
    ["other email", { email: "other@fixture.invalid" }, 403],
    ["other subject", { subject: "other-subject" }, 403],
    ["local fixture issuer", { issuer: "http://127.0.0.1:8787/__local/access" }, 401],
    ["other audience", { audience: "another-app" }, 401],
    ["expired token", { expires: 1 }, 401],
  ])("rejects %s", async (_label, options, status) => {
    expect((await request("/api/session", await sign(options))).status).toBe(status);
  });
  it("has no production fixture sign-in, cookie fallback or role editor", async () => {
    expect((await request("/__local/session", undefined, { method: "POST" })).status).toBe(404);
    expect(
      (
        await request("/api/session", undefined, {
          headers: { Cookie: `soc_fixture_session=${await sign()}` },
        })
      ).status,
    ).toBe(401);
    const { token, value } = await session();
    const response = await request("/api/admin/users/user-viewer/role", token, {
      method: "PATCH",
      headers: {
        Origin: origin,
        "X-CSRF-Token": value.csrfToken,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ role: "Operator", version: 0 }),
    });
    expect(response.status).toBe(403);
  });
  it("rechecks role and grants on every request rather than accepting JWT Admin claims", async () => {
    const token = await sign({ role: "Admin" });
    await control.prepare("UPDATE users SET role='Viewer' WHERE id='soc-owner'").run();
    const response = await request("/api/session", token);
    const value = (await response.json()) as Session;
    expect(value.user.role).toBe("Viewer");
    expect((await request("/api/admin/users", token)).status).toBe(403);
    expect(
      (
        await request("/api/authorization/approval-check", token, {
          method: "POST",
          headers: { Origin: origin, "X-CSRF-Token": value.csrfToken },
          body: "{}",
        })
      ).status,
    ).toBe(403);
  });
  it("requires same origin and session-bound CSRF for capability probes", async () => {
    const { token, value } = await session();
    expect(
      (await request("/api/authorization/approval-check", token, { method: "POST" })).status,
    ).toBe(403);
    const response = await request("/api/authorization/approval-check", token, {
      method: "POST",
      headers: { Origin: origin, "X-CSRF-Token": value.csrfToken },
      body: "{}",
    });
    expect(await response.json()).toMatchObject({
      roleAuthorized: true,
      approvalRecorded: false,
      executionEnabled: false,
    });
  });
});

describe("remote-candidate simulation isolation and bootstrap", () => {
  it("keeps ingestion reads disabled in the existing Phase 1 production profile", async () => {
    const token = await sign();
    expect((await request("/api/ingestion/status", token)).status).toBe(404);
    expect(await (await request("/api/session", token)).json()).toMatchObject({
      simulationIngestionEnabled: false,
    });
  });
  it("reads two permitted synthetic records and isolated R2 evidence", async () => {
    const token = await sign();
    const response = await request("/api/overview", token);
    expect(((await response.json()) as { incidents: unknown[] }).incidents).toHaveLength(2);
    const evidence = await request("/api/evidence/evidence-001", token);
    expect(evidence.status).toBe(200);
    expect(await evidence.json()).toMatchObject({
      environment: "simulation",
      evidence: { fixture: true },
    });
    expect((await request("/api/overview?environment=live", token)).status).toBe(403);
    expect((await request("/api/incidents/incident-other", token)).status).toBe(403);
  });
  it("rejects evidence outside the reviewed simulation bucket namespace", async () => {
    await simulation
      .prepare(
        "UPDATE evidence_objects SET object_key='simulation/cases/fixture/evidence-001.json' WHERE id='evidence-001'",
      )
      .run();
    expect((await request("/api/evidence/evidence-001", await sign())).status).toBe(403);
  });
  it("does not overwrite identities on repeated bootstrap or silently grant conflicting IDs", async () => {
    const original = await control
      .prepare("SELECT COUNT(*) AS count FROM audit_trail")
      .first<{ count: number }>();
    await runSql(control, ownerBootstrap(identity));
    expect(await control.prepare("SELECT COUNT(*) AS count FROM audit_trail").first()).toEqual(
      original,
    );
    await control.prepare("DELETE FROM users WHERE id='soc-owner'").run();
    await control
      .prepare(
        "INSERT INTO users VALUES ('soc-owner','other-subject','other@fixture.invalid','Viewer',1,0,'2026-01-01')",
      )
      .run();
    await runSql(control, ownerBootstrap(identity));
    expect(
      (
        await control
          .prepare("SELECT COUNT(*) AS count FROM zone_access WHERE user_id='soc-owner'")
          .first<{ count: number }>()
      )?.count,
    ).toBe(0);
    expect((await request("/api/session", await sign())).status).toBe(403);
    await control.prepare("DELETE FROM users WHERE id='soc-owner'").run();
  });
  it("refuses an unverified or unconfirmed bootstrap identity", () => {
    expect(() => ownerBootstrap({ ...identity, verified_login: false })).toThrow();
    expect(() => ownerBootstrap({ ...identity, subject_confirmation: "" })).toThrow();
  });
  it("makes no external data, AI or Cloudflare API calls", () => {
    expect(unexpectedNetwork).toBe(0);
  });
});
