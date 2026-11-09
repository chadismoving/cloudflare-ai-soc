// Local acceptance preview: generated identity/JWKS, disposable D1/R2, no Cloudflare network.
import { createHash, randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import { fileURLToPath } from "node:url";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { convertV4MiniflareOptions, Miniflare } from "miniflare";
import { ownerBootstrap, simulationBootstrap } from "./prepare-console.mjs";

const root = fileURLToPath(new URL("../", import.meta.url));
const port = 8899;
const previewOrigin = `http://127.0.0.1:${port}`;
const origin = "https://soc.d.example.invalid";
const issuer = "https://access-team.example.invalid";
const audience = "0000000000000000000000000000000000000000000000000000000000000001";
const subject = "acceptance-preview-owner";
const email = "owner@fixture.invalid";
const subjectHash = createHash("sha256").update(subject).digest("hex");
const pair = await generateKeyPair("RS256", { extractable: true });
const jwks = { keys: [{ ...(await exportJWK(pair.publicKey)), kid: "preview", alg: "RS256" }] };
const token = await new SignJWT({ email })
  .setProtectedHeader({ alg: "RS256", kid: "preview" })
  .setIssuer(issuer)
  .setAudience(audience)
  .setSubject(subject)
  .setIssuedAt()
  .setExpirationTime("1h")
  .sign(pair.privateKey);

const runtime = new Miniflare({
  ...convertV4MiniflareOptions({
    modules: true,
    scriptPath: `${root}apps/api/dist/index.js`,
    compatibilityDate: "2026-10-27",
    compatibilityFlags: ["nodejs_compat"],
    cf: false,
    bindings: {
      APP_ENV: "production",
      AUTH_MODE: "access",
      APP_ORIGIN: origin,
      ACCESS_ISSUER: issuer,
      ACCESS_AUDIENCE: audience,
      OWNER_EMAIL: email,
      OWNER_SUBJECT_SHA256: subjectHash,
      SESSION_CSRF_SECRET: randomBytes(32).toString("hex"),
    },
    d1Databases: { APP_DB: "preview-control", SIMULATION_DB: "preview-simulation" },
    r2Buckets: { SIMULATION_EVIDENCE: "preview-evidence" },
    serviceBindings: {
      ASSETS: async (request) => {
        const path = new URL(request.url).pathname;
        if (path !== "/" && !/^\/assets\/[a-zA-Z0-9_.-]+$/.test(path))
          return new Response("Preview asset unavailable", { status: 404 });
        const name = path === "/" ? "index.html" : path.slice(1);
        try {
          let content = await readFile(`${root}apps/console/dist/${name}`);
          const type = name.endsWith(".js")
            ? "text/javascript"
            : name.endsWith(".css")
              ? "text/css"
              : "text/html";
          if (type === "text/html")
            content = Buffer.from(
              content
                .toString()
                .replace(
                  '<div id="root">',
                  '<p class="error-banner">LOCAL ACCEPTANCE PREVIEW · synthetic identity and disposable storage · no Cloudflare connection</p><div id="root">',
                ),
            );
          return new Response(content, { headers: { "Content-Type": type } });
        } catch {
          return new Response("Preview asset unavailable", { status: 404 });
        }
      },
    },
    outboundService: async (request) => {
      if (request.url === `${issuer}/cdn-cgi/access/certs` && request.method === "GET")
        return Response.json(jwks);
      return new Response("External network disabled in preview", { status: 503 });
    },
  }),
  host: "127.0.0.1",
  port: 0,
  telemetry: { enabled: false },
});
const control = await runtime.getD1Database("APP_DB");
const simulation = await runtime.getD1Database("SIMULATION_DB");
const execute = async (db, source) => {
  for (const statement of source
    .split(";")
    .map((v) => v.trim())
    .filter(Boolean))
    await db.prepare(statement).run();
};
const migration = await readFile(`${root}infrastructure/migrations/0001_foundation.sql`, "utf8");
for (const db of [control, simulation]) await execute(db, migration);
await execute(
  control,
  ownerBootstrap({
    verified_login: true,
    intended_owner_email: email,
    subject_sha256: subjectHash,
    subject_confirmation: "Synthetic preview only",
  }),
);
const evidence = await readFile(`${root}simulations/fixtures/evidence-001.json`);
await execute(
  simulation,
  simulationBootstrap(
    await readFile(`${root}infrastructure/seeds/simulation.sql`, "utf8"),
    evidence,
  ),
);
await (await runtime.getR2Bucket("SIMULATION_EVIDENCE")).put(
  "cases/fixture/evidence-001.json",
  evidence,
);

const server = createServer(async (incoming, outgoing) => {
  try {
    if (incoming.headers.host !== `127.0.0.1:${port}`) {
      outgoing.writeHead(403);
      outgoing.end();
      return;
    }
    const url = new URL(incoming.url || "/", previewOrigin);
    if (url.origin !== previewOrigin) {
      outgoing.writeHead(403);
      outgoing.end();
      return;
    }
    const headers = new Headers();
    for (const name of ["content-type", "x-csrf-token", "origin"])
      if (typeof incoming.headers[name] === "string") headers.set(name, incoming.headers[name]);
    if (headers.get("Origin") === previewOrigin) headers.set("Origin", origin);
    headers.set("Cf-Access-Jwt-Assertion", token);
    let body = "";
    for await (const chunk of incoming) {
      body += chunk.toString();
      if (body.length > 8192) {
        outgoing.writeHead(413);
        outgoing.end();
        return;
      }
    }
    const response = await runtime.dispatchFetch(`${origin}${url.pathname}${url.search}`, {
      method: incoming.method || "GET",
      headers,
      ...(!["GET", "HEAD"].includes(incoming.method || "GET") ? { body } : {}),
    });
    outgoing.writeHead(response.status, Object.fromEntries(response.headers));
    outgoing.end(Buffer.from(await response.arrayBuffer()));
  } catch {
    outgoing.writeHead(500);
    outgoing.end("Local preview unavailable");
  }
});
server.listen(port, "127.0.0.1", () =>
  console.log(
    `Synthetic Access-console acceptance preview: ${previewOrigin}. No Cloudflare resources or credentials are used.`,
  ),
);
for (const signal of ["SIGTERM", "SIGINT"])
  process.once(signal, async () => {
    server.close();
    await runtime.dispose();
    process.exit(0);
  });
