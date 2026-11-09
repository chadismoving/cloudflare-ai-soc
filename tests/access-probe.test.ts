import { fileURLToPath } from "node:url";
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT } from "jose";
import { convertV4MiniflareOptions, Miniflare } from "miniflare";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  createProbeHandler,
  type ProbeBindings,
  subjectFingerprint,
} from "../apps/access-probe/src/index";

const issuer = "https://access-team.example.invalid";
const origin = "https://soc.d.example.invalid";
const audience = "test-opaque-application-audience";
const email = "owner@fixture.invalid";
const subject = "synthetic-human-subject";
const env: ProbeBindings = {
  APP_ENV: "access-probe",
  ALLOWED_ORIGIN: origin,
  ACCESS_ISSUER: issuer,
  ACCESS_AUDIENCE: audience,
  OWNER_EMAIL: email,
  SUBJECT_BINDING_MODE: "enroll",
};
let pair: Awaited<ReturnType<typeof generateKeyPair>>;
let otherPair: Awaited<ReturnType<typeof generateKeyPair>>;
let handler: ReturnType<typeof createProbeHandler>;
let runtime: Miniflare;
let jwksFetches = 0;
let unexpectedFetches = 0;

async function sign(
  options: {
    issuer?: string;
    audience?: string;
    email?: string;
    subject?: string;
    expires?: number;
    payload?: Record<string, unknown>;
    otherKey?: boolean;
  } = {},
) {
  return new SignJWT({ email: options.email ?? email, ...options.payload })
    .setProtectedHeader({ alg: "RS256", kid: "access-test" })
    .setIssuer(options.issuer ?? issuer)
    .setAudience(options.audience ?? audience)
    .setSubject(options.subject ?? subject)
    .setIssuedAt()
    .setExpirationTime(options.expires ?? Math.floor(Date.now() / 1000) + 300)
    .sign(options.otherKey ? otherPair.privateKey : pair.privateKey);
}
const req = (token?: string, path = "/api/session", extra: RequestInit = {}) =>
  new Request(`${origin}${path}`, {
    ...extra,
    headers: { ...(token ? { "Cf-Access-Jwt-Assertion": token } : {}), ...extra.headers },
  });

beforeAll(async () => {
  pair = await generateKeyPair("RS256", { extractable: true });
  otherPair = await generateKeyPair("RS256");
  const jwks = {
    keys: [{ ...(await exportJWK(pair.publicKey)), kid: "access-test", alg: "RS256" }],
  };
  handler = createProbeHandler(() => createLocalJWKSet(jwks));
  runtime = new Miniflare({
    ...convertV4MiniflareOptions({
      modules: true,
      scriptPath: fileURLToPath(new URL("../apps/access-probe/dist/index.js", import.meta.url)),
      compatibilityDate: "2026-10-27",
      cf: false,
      bindings: { ...env },
      outboundService: async (request: Request) => {
        if (request.url === `${issuer}/cdn-cgi/access/certs` && request.method === "GET") {
          jwksFetches++;
          return Response.json(jwks);
        }
        unexpectedFetches++;
        return new Response("No network allowed", { status: 503 });
      },
    }),
    host: "127.0.0.1",
    port: 0,
    telemetry: { enabled: false },
  });
});
afterAll(async () => {
  await runtime?.dispose();
});

describe("Access probe admission and configuration", () => {
  it.each([
    ["missing audience", { ACCESS_AUDIENCE: "" }],
    ["missing owner", { OWNER_EMAIL: "" }],
    ["fixture mode", { APP_ENV: "local" }],
    ["another trusted issuer", { ACCESS_ISSUER: "https://attacker.cloudflareaccess.com" }],
    ["another origin", { ALLOWED_ORIGIN: "https://other.fixture.invalid" }],
    ["unknown binding mode", { SUBJECT_BINDING_MODE: "auto" }],
    ["pinned mode without subject", { SUBJECT_BINDING_MODE: "pinned" }],
  ])("fails closed for %s", async (_label, overrides) => {
    expect((await handler(req(), { ...env, ...overrides })).status).toBe(503);
  });
  it("denies missing assertion on frontend, API and static paths", async () => {
    for (const path of ["/", "/api/session", "/assets/app.js", "/__local/session"])
      expect((await handler(req(undefined, path), env)).status).toBe(401);
  });
  it("never accepts Access or fixture cookie fallback", async () => {
    const jwt = await sign();
    for (const cookie of [`soc_fixture_session=${jwt}`, `CF_Authorization=${jwt}`])
      expect(
        (await handler(req(undefined, "/", { headers: { Cookie: cookie } }), env)).status,
      ).toBe(401);
  });
  it.each([
    ["wrong audience", { audience: "some-other-app" }, 401],
    ["wrong issuer", { issuer: "http://127.0.0.1:8787/__local/access" }, 401],
    ["expired assertion", { expires: 1 }, 401],
    ["forged assertion", { otherKey: true }, 401],
    ["another email", { email: "other@fixture.invalid" }, 403],
    ["service identity", { payload: { common_name: "automation" } }, 401],
    ["explicitly unverified email", { payload: { email_verified: false } }, 401],
  ])("denies %s", async (_label, options, expected) => {
    expect((await handler(req(await sign(options)), env)).status).toBe(expected);
  });
  it("requires explicit subject pinning after owner verification and grants no role", async () => {
    const jwt = await sign();
    const response = await handler(req(jwt), env);
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body).toMatchObject({
      status: "owner_verified_subject_unconfirmed",
      subjectFingerprint: await subjectFingerprint(subject),
      role: null,
      consoleAdmission: false,
      enrollmentOnly: true,
      dataConnected: false,
      executionEnabled: false,
    });
    const serialized = JSON.stringify(body);
    expect(serialized).not.toContain(jwt);
    expect(serialized).not.toContain(email);
    expect(serialized).not.toContain(subject);
  });
  it("pins both owner email and subject without first-visitor registration", async () => {
    const pinned = {
      ...env,
      SUBJECT_BINDING_MODE: "pinned",
      OWNER_SUBJECT_SHA256: await subjectFingerprint(subject),
    };
    expect((await handler(req(await sign()), pinned)).status).toBe(200);
    expect((await handler(req(await sign({ subject: "different-human" })), pinned)).status).toBe(
      403,
    );
    expect(
      (await handler(req(await sign({ email: "other@fixture.invalid" })), pinned)).status,
    ).toBe(403);
  });
  it("rejects alternate hostnames and plain HTTP independently of edge Access", async () => {
    for (const url of [
      "https://example-soc-access-probe.example.workers.dev/",
      "https://other.d.example.invalid/",
      "http://soc.d.example.invalid/",
      "http://127.0.0.1:8787/",
    ])
      expect(
        (
          await handler(
            new Request(url, { headers: { "Cf-Access-Jwt-Assertion": await sign() } }),
            env,
          )
        ).status,
      ).toBe(403);
  });
  it("has no fixture or write endpoints even for the verified owner", async () => {
    const jwt = await sign();
    expect((await handler(req(jwt, "/__local/session"), env)).status).toBe(404);
    expect((await handler(req(jwt, "/api/session", { method: "POST" }), env)).status).toBe(405);
  });
  it("never caches or reflects invalid JWTs and honors HEAD semantics", async () => {
    const response = await handler(req("invalid-secret-token"), env);
    expect(response.headers.get("Cache-Control")).toBe("no-store");
    expect(response.headers.get("Content-Security-Policy")).toContain("default-src 'none'");
    expect(await response.text()).not.toContain("invalid-secret-token");
    const head = await handler(req(await sign(), "/", { method: "HEAD" }), env);
    expect(head.status).toBe(200);
    expect(await head.text()).toBe("");
  });
});

describe("compiled probe in workerd with trusted JWKS transport", () => {
  it("fetches only the pinned certs URL and caches the trusted JWKS", async () => {
    const token = await sign();
    for (let i = 0; i < 2; i++) {
      const response = await runtime.dispatchFetch(`${origin}/api/session`, {
        headers: { "Cf-Access-Jwt-Assertion": token },
      });
      expect(response.status).toBe(200);
      expect(await response.json()).toHaveProperty("enrollmentOnly", true);
    }
    expect(jwksFetches).toBe(1);
    expect(unexpectedFetches).toBe(0);
  });
  it("denies unsigned frontend/static requests and fixture cookies in workerd", async () => {
    for (const path of ["/", "/api/session", "/assets/app.js"]) {
      const response = await runtime.dispatchFetch(`${origin}${path}`, {
        headers: { Cookie: `soc_fixture_session=${await sign()}` },
      });
      expect(response.status).toBe(401);
    }
    expect(unexpectedFetches).toBe(0);
  });
  it("rejects forged tokens and alternate Worker hosts in workerd", async () => {
    const response = await runtime.dispatchFetch(`${origin}/api/session`, {
      headers: { "Cf-Access-Jwt-Assertion": await sign({ otherKey: true }) },
    });
    expect(response.status).toBe(401);
    expect(
      (await runtime.dispatchFetch("https://example-soc-access-probe.example.workers.dev/")).status,
    ).toBe(403);
    expect(unexpectedFetches).toBe(0);
  });
});
