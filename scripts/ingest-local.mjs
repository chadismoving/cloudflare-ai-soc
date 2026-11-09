// Local multi-Worker demo only. No Cloudflare account API or remote bindings.
import { createHash, randomBytes } from "node:crypto";
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { fileURLToPath } from "node:url";
import { convertV4MiniflareOptions, Miniflare } from "miniflare";
import { fixtureEnvironment } from "./fixture-env.mjs";

const root = fileURLToPath(new URL("../", import.meta.url));
const folder = `${root}.local/ingest-demo`;
const mode = process.argv[2];
if (!["dev", "demo"].includes(mode)) throw Error("Use dev or demo; no remote operation exists.");
await mkdir(folder, { recursive: true, mode: 0o700 });
const secretPath = `${folder}/secret`;
let secret;
try {
  secret = await readFile(secretPath, "utf8");
} catch (error) {
  if (error.code !== "ENOENT") throw error;
  secret = randomBytes(32).toString("hex");
  await writeFile(secretPath, secret, { mode: 0o600, flag: "wx" });
}
await chmod(secretPath, 0o600);
if (mode === "demo") {
  const call = async (path, body, auth = secret) => {
    const response = await fetch(`http://127.0.0.1:8788${path}`, {
      method: body === undefined ? "GET" : "POST",
      headers: { "cf-webhook-auth": auth, "Content-Type": "application/json" },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const value = await response.json();
    return { status: response.status, value };
  };
  // Re-running within this fixed five-minute bucket reuses identical fixture input.
  const base = Math.floor(Date.now() / 300000) * 300000 - 300000;
  const record = (id, offset = 0) => ({
    fixture: true,
    RayID: `demo-${base}-${id}`,
    Datetime: new Date(base + 10000 + offset).toISOString(),
    Action: "block",
    RuleID: "rule-demo",
    Source: "waf",
    ClientRequestHost: "demo.fixture.invalid",
    ClientRequestPath: "/__soc_test/login",
    ClientIP: "client-demo",
  });
  const input = {
    key: `raw/firewall/demo-${base}.ndjson.gz`,
    records: [record("late", 20000), record("early"), record("early")],
    gzip: true,
  };
  const selected = new Set();
  for (let i = 0; i < 2; i++) {
    const result = await call("/__local/object", input);
    if (result.status !== 202) throw Error("Fixture enqueue failed");
    selected.add(result.value.objectId);
  }
  const partial = await call("/__local/object", {
    key: `raw/firewall/partial-${base}.ndjson`,
    records: [record("partial", 30000)],
    gzip: false,
    fault: "invalid-json",
  });
  if (partial.status !== 202) throw Error("Partial fixture enqueue failed");
  selected.add(partial.value.objectId);
  const notification = {
    fixture: true,
    account_id: "fixture-account",
    policy_id: "fixture-waf-policy",
    alert_type: "waf_alert",
    alert_correlation_id: `demo-${base}`,
    ts: new Date(base + 10000).toISOString(),
    data: { zone_id: "fixture-zone", client: "client-demo" },
  };
  if ((await call("/notification", notification, "invalid-fixture-secret")).status !== 403)
    throw Error("Invalid secret accepted");
  const alert = await call("/notification", notification);
  if (alert.status !== 202) throw Error("Notification enqueue failed");
  selected.add(alert.value.objectId);
  const end = Date.now() + 15000;
  for (;;) {
    const result = await call("/status");
    if (result.status !== 200) throw Error("Status unavailable");
    const own = result.value.objects.filter((v) => selected.has(v.id));
    if (own.length === 3 && own.every((v) => ["complete", "archived"].includes(v.state))) {
      await writeFile(`${folder}/last-demo.json`, JSON.stringify(result.value, null, 2), {
        mode: 0o600,
      });
      console.log(
        JSON.stringify(
          {
            syntheticOnly: true,
            wrongSecretRejected: true,
            objects: own,
            failures: result.value.failures,
            console: "http://127.0.0.1:8787/",
          },
          null,
          2,
        ),
      );
      break;
    }
    if (Date.now() > end) throw Error("Local demo incomplete; inspect protected local status");
    await new Promise((r) => setTimeout(r, 150));
  }
  process.exit(0);
}

const fixed = {
  modules: true,
  compatibilityDate: "2026-10-27",
  compatibilityFlags: ["nodejs_compat"],
  cf: false,
};
const keys = await fixtureEnvironment();
const runtime = new Miniflare({
  ...convertV4MiniflareOptions({
    workers: [
      {
        name: "api",
        ...fixed,
        scriptPath: `${root}apps/api/dist/index.js`,
        bindings: {
          APP_ENV: "local",
          AUTH_MODE: "fixture",
          APP_ORIGIN: "http://127.0.0.1:8787",
          ACCESS_ISSUER: "http://127.0.0.1:8787/__local/access",
          ACCESS_AUDIENCE: "soc-local-fixture",
          ...keys,
        },
        d1Databases: { APP_DB: "ingest-demo-control", SIMULATION_DB: "ingest-demo-simulation" },
        r2Buckets: { SIMULATION_EVIDENCE: "ingest-demo-evidence" },
        serviceBindings: {
          ASSETS: async (request) => {
            const path = new URL(request.url).pathname;
            if (path !== "/" && !/^\/assets\/[a-zA-Z0-9_.-]+$/.test(path))
              return new Response("Not found", { status: 404 });
            const name = path === "/" ? "index.html" : path.slice(1);
            try {
              let value = await readFile(`${root}apps/console/dist/${name}`);
              const type = name.endsWith(".js")
                ? "text/javascript"
                : name.endsWith(".css")
                  ? "text/css"
                  : "text/html";
              if (type === "text/html")
                value = Buffer.from(
                  value
                    .toString()
                    .replace(
                      '<div id="root">',
                      '<p class="error-banner">LOCAL INGESTION DEMO · synthetic identities/data · no Cloudflare connection</p><div id="root">',
                    ),
                );
              return new Response(value, { headers: { "Content-Type": type } });
            } catch {
              return new Response("Local asset unavailable", { status: 404 });
            }
          },
        },
        outboundService: async () => new Response("External network disabled", { status: 503 }),
      },
      {
        name: "ingest",
        ...fixed,
        scriptPath: `${root}apps/ingest/dist/index.js`,
        bindings: { APP_ENV: "local", DATA_ENVIRONMENT: "simulation", LOCAL_INGEST_SECRET: secret },
        d1Databases: { SIMULATION_DB: "ingest-demo-simulation" },
        r2Buckets: { SIMULATION_STORE: "ingest-demo-evidence" },
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
        outboundService: async () => new Response("External network disabled", { status: 503 }),
      },
    ],
  }),
  host: "127.0.0.1",
  port: 0,
  resourcePersistencePath: `${folder}/state`,
  telemetry: { enabled: false },
});
const control = await runtime.getD1Database("APP_DB", "api"),
  simulation = await runtime.getD1Database("SIMULATION_DB", "api");
const execute = async (db, sql) => {
  for (const s of sql
    .split(";")
    .map((v) => v.trim())
    .filter(Boolean))
    await db.prepare(s).run();
};
for (const db of [control, simulation]) {
  await db
    .prepare("CREATE TABLE IF NOT EXISTS local_demo_migrations (name TEXT PRIMARY KEY)")
    .run();
  for (const file of [
    "0001_foundation.sql",
    "0002_ingestion.sql",
    "0003_ingestion_metrics.sql",
    ...(db === simulation ? ["0004_ingestion_observability.sql"] : []),
  ])
    if (
      !(await db.prepare("SELECT name FROM local_demo_migrations WHERE name=?").bind(file).first())
    ) {
      const sql = await readFile(`${root}infrastructure/migrations/${file}`, "utf8");
      const statements = sql
        .split(";")
        .map((v) => v.trim())
        .filter(Boolean);
      await db.batch([
        ...statements.map((s) => db.prepare(s)),
        db.prepare("INSERT INTO local_demo_migrations VALUES (?)").bind(file),
      ]);
    }
}
await execute(control, await readFile(`${root}infrastructure/seeds/control.sql`, "utf8"));
const evidence = await readFile(`${root}simulations/fixtures/evidence-001.json`);
await execute(
  simulation,
  (await readFile(`${root}infrastructure/seeds/simulation.sql`, "utf8")).replace(
    "__EVIDENCE_SHA256__",
    createHash("sha256").update(evidence).digest("hex"),
  ),
);
await (await runtime.getR2Bucket("SIMULATION_EVIDENCE", "api")).put(
  "simulation/cases/fixture/evidence-001.json",
  evidence,
);
const servers = [];
for (const [port, name] of [
  [8787, "api"],
  [8788, "ingest"],
]) {
  const worker = await runtime.getWorker(name);
  const server = createServer(async (incoming, outgoing) => {
    try {
      if (incoming.headers.host !== `127.0.0.1:${port}`) {
        outgoing.writeHead(403);
        outgoing.end();
        return;
      }
      const url = new URL(incoming.url || "/", `http://127.0.0.1:${port}`);
      if (url.origin !== `http://127.0.0.1:${port}`) {
        outgoing.writeHead(403);
        outgoing.end();
        return;
      }
      const headers = new Headers();
      for (const key of ["content-type", "cookie", "origin", "x-csrf-token", "cf-webhook-auth"])
        if (typeof incoming.headers[key] === "string") headers.set(key, incoming.headers[key]);
      const chunks = [];
      let length = 0;
      for await (const chunk of incoming) {
        length += chunk.length;
        if (length > 65536) {
          outgoing.writeHead(413);
          outgoing.end();
          return;
        }
        chunks.push(chunk);
      }
      const response = await worker.fetch(url.toString(), {
        method: incoming.method || "GET",
        headers,
        ...(!["GET", "HEAD"].includes(incoming.method || "GET")
          ? { body: Buffer.concat(chunks) }
          : {}),
      });
      outgoing.writeHead(response.status, Object.fromEntries(response.headers));
      outgoing.end(Buffer.from(await response.arrayBuffer()));
    } catch {
      outgoing.writeHead(503);
      outgoing.end("Local demo unavailable");
    }
  });
  servers.push(server);
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", resolve);
  });
}
console.log(
  "Local simulation console: http://127.0.0.1:8787/ · ingest loopback: 8788. Run npm run demo:ingest. No Cloudflare connection.",
);
for (const signal of ["SIGINT", "SIGTERM"])
  process.once(signal, async () => {
    for (const server of servers) server.close();
    await runtime.dispose();
    process.exit(0);
  });
