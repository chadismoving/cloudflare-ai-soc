import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { parseEnv } from "node:util";

const skip = new Set(["node_modules", ".git", ".local", ".wrangler", "dist", "coverage"]);
async function files(dir) {
  const result = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    if (skip.has(entry.name) || entry.name.startsWith(".dev.vars") || entry.name.startsWith(".env"))
      continue;
    const path = join(dir, entry.name);
    if (entry.isDirectory()) result.push(...(await files(path)));
    else if (/\.(?:ts|tsx|js|mjs|json|jsonc|md|sql|html|css|yml)$/.test(entry.name))
      result.push(path);
  }
  return result;
}
const findings = [];
for (const path of await files(".")) {
  if (path === join("scripts", "scan.mjs")) continue;
  const source = await readFile(path, "utf8");
  if (
    /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/.test(source) ||
    /"d"\s*:\s*"[a-zA-Z0-9_-]{60,}"/.test(source) ||
    /(?:api[_-]?token|api[_-]?key|authorization)\s*[=:]\s*["'](?:Bearer\s+)?[a-zA-Z0-9_-]{35,}["']/i.test(
      source,
    )
  )
    findings.push(`${path}: possible credential literal`);
}
const config = JSON.parse(await readFile("apps/api/wrangler.local.jsonc", "utf8"));
if (
  config.account_id ||
  config.routes ||
  config.env ||
  config.ai ||
  config.vars.APP_ENV !== "local" ||
  config.workers_dev !== false
)
  findings.push("Wrangler configuration is not local-only");
for (const binding of [...config.d1_databases, ...config.r2_buckets]) {
  if (binding.remote !== false) findings.push(`Remote binding allowed: ${binding.binding}`);
}
const probe = JSON.parse(await readFile("apps/access-probe/wrangler.review.jsonc", "utf8"));
if (
  probe.account_id ||
  probe.routes ||
  probe.env ||
  probe.assets ||
  probe.ai ||
  probe.d1_databases ||
  probe.r2_buckets ||
  probe.kv_namespaces ||
  probe.services ||
  probe.workers_dev !== false ||
  probe.preview_urls !== false ||
  probe.observability?.enabled !== false ||
  probe.vars.APP_ENV !== "access-probe" ||
  probe.vars.ALLOWED_ORIGIN !== "https://soc.d.example.invalid" ||
  probe.vars.ACCESS_ISSUER !== "https://access-team.example.invalid" ||
  probe.vars.ACCESS_AUDIENCE !== "" ||
  probe.vars.OWNER_EMAIL ||
  probe.vars.OWNER_SUBJECT_SHA256
)
  findings.push(
    "Access probe review config must remain unprovisioned, deny by default and contain no owner identity",
  );
const ignore = await readFile(".gitignore", "utf8");
const ingest = JSON.parse(await readFile("apps/ingest/wrangler.local.jsonc", "utf8"));
if (
  ingest.account_id ||
  ingest.routes ||
  ingest.env ||
  ingest.ai ||
  ingest.services ||
  ingest.workflows ||
  ingest.durable_objects ||
  ingest.vars.APP_ENV !== "local" ||
  ingest.vars.DATA_ENVIRONMENT !== "simulation" ||
  ingest.vars.LOCAL_INGEST_SECRET ||
  ingest.workers_dev !== false ||
  ingest.preview_urls !== false ||
  ingest.d1_databases?.length !== 1 ||
  ingest.d1_databases[0].database_id !== "00000000-0000-0000-0000-000000000002" ||
  ingest.r2_buckets?.length !== 1 ||
  ingest.r2_buckets[0].bucket_name !== "soc-local-simulation-evidence" ||
  ingest.d1_databases.some((v) => v.remote !== false) ||
  ingest.r2_buckets.some((v) => v.remote !== false) ||
  ingest.queues.producers.some((v) => v.queue !== "soc-local-ingest") ||
  ingest.queues.consumers.length !== 2 ||
  ingest.queues.consumers[0].dead_letter_queue !== "soc-local-ingest-dlq" ||
  ingest.queues.consumers.some(
    (v) => !["soc-local-ingest", "soc-local-ingest-dlq"].includes(v.queue),
  )
)
  findings.push("Ingest configuration must remain isolated and local-only");
const consoleReview = JSON.parse(
  await readFile("apps/api/wrangler.production.review.jsonc", "utf8"),
);
const cloudIngest = JSON.parse(
  await readFile("apps/ingest/wrangler.simulation.review.jsonc", "utf8"),
);
if (
  cloudIngest.account_id ||
  cloudIngest.routes ||
  cloudIngest.env ||
  cloudIngest.ai ||
  cloudIngest.services ||
  cloudIngest.workflows ||
  cloudIngest.durable_objects ||
  cloudIngest.triggers ||
  cloudIngest.vars.LOCAL_INGEST_SECRET ||
  cloudIngest.queues.producers ||
  cloudIngest.workers_dev !== false ||
  cloudIngest.preview_urls !== false ||
  cloudIngest.observability.enabled !== false ||
  cloudIngest.vars.APP_ENV !== "cloud-simulation" ||
  cloudIngest.vars.DATA_ENVIRONMENT !== "simulation" ||
  cloudIngest.vars.CLOUD_SIMULATION_PROFILE !== "phase2b-v1" ||
  cloudIngest.d1_databases.length !== 1 ||
  cloudIngest.d1_databases[0].database_id !== "00000000-0000-4000-8000-000000000012" ||
  cloudIngest.r2_buckets.length !== 1 ||
  cloudIngest.r2_buckets[0].bucket_name !== "example-cloudflare-ai-soc-simulation" ||
  cloudIngest.queues.consumers.length !== 2 ||
  cloudIngest.queues.consumers[0].queue !== "example-soc-ingest-simulation" ||
  cloudIngest.queues.consumers[0].dead_letter_queue !== "example-soc-ingest-simulation-dlq" ||
  cloudIngest.queues.consumers[1].queue !== "example-soc-ingest-simulation-dlq" ||
  cloudIngest.queues.consumers.some(
    (v) => v.max_batch_size !== 1 || v.max_concurrency !== 1 || v.max_retries !== 3,
  ) ||
  [...cloudIngest.d1_databases, ...cloudIngest.r2_buckets].some((v) => v.remote !== false)
)
  findings.push(
    "Cloud simulation candidate must retain isolated storage, no public ingress or API/AI/producer credentials, and bounded consumers",
  );
const phase2Console = JSON.parse(await readFile("apps/api/wrangler.phase2b.review.jsonc", "utf8"));
const compareConsole = structuredClone(phase2Console);
delete compareConsole.vars.SIMULATION_INGEST_READS;
if (
  phase2Console.vars.SIMULATION_INGEST_READS !== "phase2b-v1" ||
  JSON.stringify(compareConsole) !== JSON.stringify(consoleReview)
)
  findings.push("Phase 2B console candidate may only opt into reviewed simulation reads");
if (
  consoleReview.account_id ||
  consoleReview.routes ||
  consoleReview.env ||
  consoleReview.ai ||
  consoleReview.queues ||
  consoleReview.workflows ||
  consoleReview.durable_objects ||
  consoleReview.workers_dev !== false ||
  consoleReview.preview_urls !== false ||
  consoleReview.assets?.run_worker_first !== true ||
  consoleReview.vars.APP_ENV !== "production" ||
  consoleReview.vars.AUTH_MODE !== "access" ||
  consoleReview.vars.OWNER_EMAIL ||
  consoleReview.vars.OWNER_SUBJECT_SHA256 ||
  consoleReview.vars.SESSION_CSRF_SECRET ||
  consoleReview.d1_databases?.length !== 2 ||
  !consoleReview.d1_databases.some(
    (v) =>
      v.binding === "APP_DB" &&
      v.database_id === "00000000-0000-4000-8000-000000000011" &&
      v.remote === false,
  ) ||
  !consoleReview.d1_databases.some(
    (v) =>
      v.binding === "SIMULATION_DB" &&
      v.database_id === "00000000-0000-4000-8000-000000000012" &&
      v.remote === false,
  ) ||
  consoleReview.r2_buckets?.length !== 1 ||
  consoleReview.r2_buckets[0].binding !== "SIMULATION_EVIDENCE" ||
  consoleReview.r2_buckets[0].bucket_name !== "example-cloudflare-ai-soc-simulation" ||
  consoleReview.r2_buckets[0].remote !== false
)
  findings.push(
    "Console review configuration must retain owner-only, Worker-first and isolated simulation bindings",
  );
// Health candidates may only change the explicit opt-in and isolated migration directories.
for (const [path, baseline, flag] of [
  ["apps/ingest/wrangler.health.review.jsonc", cloudIngest, "CLOUD_SIMULATION_PROFILE"],
  ["apps/api/wrangler.health.review.jsonc", phase2Console, "SIMULATION_INGEST_READS"],
]) {
  const candidate = JSON.parse(await readFile(path, "utf8"));
  const expected = structuredClone(baseline);
  expected.vars[flag] = "phase2b-health-v1";
  for (const db of expected.d1_databases)
    db.migrations_dir = `../../.local/ingestion-health-review/migrations/${db.binding === "SIMULATION_DB" ? "simulation" : "none"}`;
  if (JSON.stringify(candidate) !== JSON.stringify(expected))
    findings.push(
      `${path}: health candidate expands beyond reviewed profile/migration differences`,
    );
}
const retention = JSON.parse(await readFile("apps/ingest/wrangler.retention.local.jsonc", "utf8"));
if (
  Object.keys(retention).some(
    (key) =>
      ![
        "$schema",
        "name",
        "main",
        "compatibility_date",
        "compatibility_flags",
        "workers_dev",
        "preview_urls",
        "send_metrics",
        "observability",
        "vars",
        "d1_databases",
      ].includes(key),
  ) ||
  retention.name !== "soc-local-retention" ||
  retention.main !== "src/retention-worker.ts" ||
  retention.workers_dev !== false ||
  retention.preview_urls !== false ||
  retention.send_metrics !== false ||
  retention.observability?.enabled !== false ||
  JSON.stringify(retention.vars) !==
    JSON.stringify({
      APP_ENV: "local",
      DATA_ENVIRONMENT: "simulation",
      RETENTION_PROFILE: "local-retention-v1",
    }) ||
  retention.d1_databases.length !== 1 ||
  retention.d1_databases[0].binding !== "SIMULATION_DB" ||
  retention.d1_databases[0].database_id !== "00000000-0000-0000-0000-000000000002" ||
  retention.d1_databases[0].remote !== false
)
  findings.push(
    "Retention prototype must have only the isolated local simulation D1 binding, no R2/HTTP route/Cron/API/AI/control/live resources",
  );
const retentionReview = JSON.parse(
  await readFile("apps/ingest/wrangler.retention.review.jsonc", "utf8"),
);
if (
  Object.keys(retentionReview).some(
    (key) =>
      ![
        "$schema",
        "name",
        "main",
        "compatibility_date",
        "compatibility_flags",
        "workers_dev",
        "preview_urls",
        "send_metrics",
        "observability",
        "limits",
        "vars",
        "d1_databases",
        "triggers",
      ].includes(key),
  ) ||
  retentionReview.name !== "example-soc-retention-simulation-worker" ||
  retentionReview.main !== "src/retention-worker.ts" ||
  retentionReview.workers_dev !== false ||
  retentionReview.preview_urls !== false ||
  retentionReview.send_metrics !== false ||
  retentionReview.observability?.enabled !== false ||
  JSON.stringify(retentionReview.limits) !== JSON.stringify({ cpu_ms: 1000 }) ||
  JSON.stringify(retentionReview.triggers) !== JSON.stringify({ crons: ["17 * * * *"] }) ||
  JSON.stringify(retentionReview.vars) !==
    JSON.stringify({
      APP_ENV: "cloud-simulation",
      DATA_ENVIRONMENT: "simulation",
      RETENTION_PROFILE: "simulation-retention-v1",
      RETENTION_MODE: "apply",
      RETENTION_DATABASE_ID: "00000000-0000-4000-8000-000000000012",
      RETENTION_ACCOUNT_ID: "00000000000000000000000000000001",
    }) ||
  retentionReview.d1_databases.length !== 1 ||
  retentionReview.d1_databases[0].binding !== "SIMULATION_DB" ||
  retentionReview.d1_databases[0].database_name !== "example-soc-simulation" ||
  retentionReview.d1_databases[0].database_id !== "00000000-0000-4000-8000-000000000012" ||
  retentionReview.d1_databases[0].migrations_dir !== "../../.local/retention-review/migrations" ||
  retentionReview.d1_databases[0].remote !== false
)
  findings.push(
    "Cloud retention review exceeds explicit simulation-only DB/profile/Cron/CPU scope",
  );
const outboxReview = JSON.parse(
  await readFile("apps/ingest/wrangler.retention-outbox.review.jsonc", "utf8"),
);
const expectedOutbox = structuredClone(retentionReview);
expectedOutbox.main = "src/retention-outbox-worker.ts";
expectedOutbox.vars.RETENTION_PROFILE = "simulation-retention-outbox-v1";
expectedOutbox.d1_databases[0].migrations_dir = "../../.local/r2-retention-review/migrations";
if (JSON.stringify(outboxReview) !== JSON.stringify(expectedOutbox))
  findings.push("Outbox candidate exceeds isolated simulation metadata upgrade");
const r2Review = JSON.parse(
  await readFile("apps/ingest/wrangler.r2-retention.review.jsonc", "utf8"),
);
const expectedR2 = structuredClone(expectedOutbox);
expectedR2.name = "example-soc-r2-retention-simulation-worker";
expectedR2.main = "src/r2-retention-worker.ts";
expectedR2.vars.RETENTION_PROFILE = "simulation-r2-retention-v1";
expectedR2.vars.RETENTION_BUCKET = "example-cloudflare-ai-soc-simulation";
expectedR2.r2_buckets = [
  {
    binding: "SIMULATION_STORE",
    bucket_name: "example-cloudflare-ai-soc-simulation",
    remote: false,
  },
];
expectedR2.triggers = { crons: ["37 * * * *"] };
// Property order is immaterial when checking the exact capability set.
const stable = (value) =>
  value && typeof value === "object"
    ? Array.isArray(value)
      ? value.map(stable)
      : Object.fromEntries(
          Object.keys(value)
            .sort()
            .map((k) => [k, stable(value[k])]),
        )
    : value;
if (JSON.stringify(stable(r2Review)) !== JSON.stringify(stable(expectedR2)))
  findings.push("R2 candidate exceeds simulation-only DB/bucket/CPU/Cron scope");
const immutableReview = JSON.parse(
  await readFile("apps/ingest/wrangler.immutable.review.jsonc", "utf8"),
);
const expectedImmutable = JSON.parse(
  await readFile("apps/ingest/wrangler.health.review.jsonc", "utf8"),
);
expectedImmutable.vars.CLOUD_SIMULATION_PROFILE = "phase2b-retention-v1";
expectedImmutable.d1_databases[0].migrations_dir = "../../.local/r2-retention-review/none";
if (JSON.stringify(immutableReview) !== JSON.stringify(expectedImmutable))
  findings.push("Immutable ingestion candidate exceeds existing closed three-key simulation scope");
if (!ignore.includes("**/.dev.vars*") || !ignore.includes(".local/"))
  findings.push("Local secrets/state are not excluded from version control");
try {
  const vars = await readFile("apps/api/.dev.vars", "utf8");
  const decoded = parseEnv(vars);
  const privateKey = decoded.LOCAL_ACCESS_PRIVATE_JWK
    ? JSON.parse(decoded.LOCAL_ACCESS_PRIVATE_JWK)
    : null;
  const secret = decoded.SESSION_CSRF_SECRET;
  const assets = await readdir("apps/console/dist/assets");
  for (const asset of assets.filter((v) => /\.(?:js|css)$/.test(v))) {
    const content = await readFile(`apps/console/dist/assets/${asset}`, "utf8");
    if ((privateKey?.d && content.includes(privateKey.d)) || (secret && content.includes(secret)))
      findings.push(`Local key leaked into console asset: ${asset}`);
  }
} catch (error) {
  if (error.code !== "ENOENT") throw error;
}
if (findings.length) {
  console.error(findings.join("\n"));
  process.exitCode = 1;
} else
  console.log(
    "Source credential scan, local binding guard and generated-client secret check passed. This bounded check is not a full security audit.",
  );

// Workbench candidates are opt-in and must not introduce AI/live/write credentials.
const wbConsole = JSON.parse(await readFile("apps/api/wrangler.workbench.review.jsonc", "utf8"));
const wbExpected = JSON.parse(await readFile("apps/api/wrangler.health.review.jsonc", "utf8"));
wbExpected.vars.SOC_FEATURES = "full-simulation-v1";
wbExpected.vars.SOC_MAINTENANCE_PROFILE = "external-workbench-v1";
for (const db of wbExpected.d1_databases)
  db.migrations_dir = `../../.local/workbench-cloud-review/migrations/${db.binding === "APP_DB" ? "none" : "simulation"}`;
if (JSON.stringify(wbConsole) !== JSON.stringify(wbExpected))
  throw Error("Workbench console bindings expanded beyond review scope");
const wbMetadata = JSON.parse(
  await readFile("apps/ingest/wrangler.workbench-retention.review.jsonc", "utf8"),
);
const metaExpected = JSON.parse(
  await readFile("apps/ingest/wrangler.retention-outbox.review.jsonc", "utf8"),
);
metaExpected.vars.RETENTION_PROFILE = "simulation-retention-workbench-v1";
metaExpected.d1_databases[0].migrations_dir =
  "../../.local/workbench-cloud-review/migrations/simulation";
if (JSON.stringify(wbMetadata) !== JSON.stringify(metaExpected))
  throw Error("Workbench metadata bindings expanded beyond review scope");
const wbMaintenance = JSON.parse(
  await readFile("apps/api/wrangler.workbench-maintenance.review.jsonc", "utf8"),
);
if (
  wbMaintenance.name !== "example-soc-workbench-maintenance-simulation" ||
  wbMaintenance.workers_dev !== false ||
  wbMaintenance.preview_urls !== false ||
  wbMaintenance.observability?.enabled !== false ||
  wbMaintenance.account_id ||
  wbMaintenance.routes ||
  wbMaintenance.ai ||
  wbMaintenance.services ||
  wbMaintenance.queues ||
  wbMaintenance.d1_databases.length !== 1 ||
  wbMaintenance.d1_databases[0].binding !== "SIMULATION_DB" ||
  wbMaintenance.d1_databases[0].database_id !== "00000000-0000-4000-8000-000000000012" ||
  wbMaintenance.r2_buckets.length !== 1 ||
  wbMaintenance.r2_buckets[0].binding !== "SIMULATION_EVIDENCE" ||
  wbMaintenance.r2_buckets[0].bucket_name !== "example-cloudflare-ai-soc-simulation" ||
  [...wbMaintenance.d1_databases, ...wbMaintenance.r2_buckets].some((b) => b.remote !== false) ||
  JSON.stringify(wbMaintenance.triggers) !== JSON.stringify({ crons: ["*/5 * * * *"] }) ||
  Object.keys(wbMaintenance.vars).some(
    (k) =>
      ![
        "APP_ENV",
        "MAINTENANCE_PROFILE",
        "MAINTENANCE_MODE",
        "MAINTENANCE_ACCOUNT_ID",
        "MAINTENANCE_DATABASE_ID",
        "MAINTENANCE_BUCKET",
      ].includes(k),
  )
)
  throw Error("Workbench maintenance scope rejected");
console.log("Workbench candidate simulation-only binding checks passed.");

const wbR2 = JSON.parse(await readFile("apps/ingest/wrangler.workbench-r2.review.jsonc", "utf8"));
const r2Expected = JSON.parse(
  await readFile("apps/ingest/wrangler.r2-retention.review.jsonc", "utf8"),
);
r2Expected.vars.RETENTION_PROFILE = "simulation-r2-retention-workbench-v1";
r2Expected.d1_databases[0].migrations_dir =
  "../../.local/workbench-cloud-review/migrations/simulation";
if (JSON.stringify(wbR2) !== JSON.stringify(r2Expected))
  throw Error("Fixed-five-key R2 candidate scope expanded");

const liveConsole = JSON.parse(await readFile("apps/api/wrangler.live.review.jsonc", "utf8"));
const liveExpected = structuredClone(wbConsole);
liveExpected.vars.LIVE_PROFILE = "zone-analytics-readonly-v1";
liveExpected.d1_databases.push({
  binding: "LIVE_DB",
  database_name: "example-soc-live",
  database_id: "00000000-0000-4000-8000-000000000013",
  migrations_dir: "../../infrastructure/live-migrations",
  remote: false,
});
if (JSON.stringify(liveConsole) !== JSON.stringify(liveExpected))
  throw Error("Live console bindings differ from existing simulation plus isolated live D1");
const liveAiConsole = JSON.parse(await readFile("apps/api/wrangler.live-ai.review.jsonc", "utf8"));
const liveAiExpected = structuredClone(liveExpected);
Object.assign(liveAiExpected.vars, {
  LIVE_AI_MODE: "on-demand-v1",
  LIVE_AI_MODEL: "@cf/zai-org/glm-5.3",
  AI_GATEWAY_ID: "example-soc-ai",
});
liveAiExpected.ai = { binding: "AI" };
if (JSON.stringify(liveAiConsole) !== JSON.stringify(liveAiExpected))
  throw Error(
    "Live investigation configuration must add only the SOC Workers AI binding and settings",
  );
const collector = JSON.parse(await readFile("apps/api/wrangler.collector.review.jsonc", "utf8"));
if (
  collector.name !== "example-soc-analytics-live" ||
  collector.main !== "src/live/collector-worker.ts" ||
  collector.workers_dev !== false ||
  collector.preview_urls !== false ||
  collector.observability?.enabled !== false ||
  collector.assets ||
  collector.ai ||
  collector.r2_buckets ||
  collector.queues ||
  collector.services ||
  collector.routes ||
  collector.triggers ||
  collector.account_id ||
  JSON.stringify(collector.vars) !==
    JSON.stringify({ LIVE_PROFILE: "zone-analytics-readonly-v1" }) ||
  collector.d1_databases.length !== 1 ||
  JSON.stringify(collector.d1_databases[0]) !== JSON.stringify(liveExpected.d1_databases.at(-1))
)
  throw Error("Live collector must have only its isolated live D1 binding and fixed profile");
const liveOpsConsole = JSON.parse(
  await readFile("apps/api/wrangler.live-ops.review.jsonc", "utf8"),
);
const liveOpsExpected = {
  ...liveAiExpected,
  services: [{ binding: "LIVE_REPAIR", service: "example-soc-repair-live" }],
};
if (JSON.stringify(liveOpsConsole) !== JSON.stringify(liveOpsExpected))
  throw Error("Live operations console must add only the private repair service");
const repair = JSON.parse(await readFile("apps/api/wrangler.repair.review.jsonc", "utf8"));
const repairExpected = {
  ...collector,
  name: "example-soc-repair-live",
  main: "src/live/repair-worker.ts",
  vars: { REPAIR_APPLY: "disabled" },
  triggers: { crons: ["*/5 * * * *"] },
};
if (JSON.stringify(repair) !== JSON.stringify(repairExpected))
  throw Error("Repair worker must be private and disabled by default");
const fixture = JSON.parse(await readFile("apps/api/wrangler.repair-fixture.review.jsonc", "utf8"));
const fixtureExpected = {
  $schema: collector.$schema,
  name: "example-soc-repair-test-fixture",
  main: "src/live/repair-fixture-worker.ts",
  compatibility_date: collector.compatibility_date,
  workers_dev: false,
  preview_urls: false,
  send_metrics: false,
  observability: { enabled: false },
};
if (JSON.stringify(fixture) !== JSON.stringify(fixtureExpected))
  throw Error("Repair fixture must have no public routes or data bindings");
const logpush = JSON.parse(
  await readFile("apps/ingest/wrangler.live-logpush.review.jsonc", "utf8"),
);
const consumer = {
  max_batch_size: 1,
  max_batch_timeout: 1,
  max_retries: 3,
  retry_delay: 20,
  max_concurrency: 1,
};
const logpushExpected = {
  ...collector,
  name: "example-soc-ingest-live-worker",
  main: "src/live-logpush-worker.ts",
  limits: { cpu_ms: 10000 },
  vars: { LIVE_LOG_PROFILE: "r2-logpush-v1" },
  r2_buckets: [
    { binding: "LIVE_LOGS", bucket_name: "example-cloudflare-ai-soc-live", remote: false },
  ],
  queues: {
    consumers: [
      {
        queue: "example-soc-ingest-live",
        ...consumer,
        dead_letter_queue: "example-soc-ingest-live-dlq",
      },
      { queue: "example-soc-ingest-live-dlq", ...consumer },
    ],
  },
};
if (JSON.stringify(logpush) !== JSON.stringify(logpushExpected))
  throw Error("Live ingestion must use only the dedicated R2, queues, and live D1");
if (!ignore.split(/\r?\n/).includes("workers-api"))
  throw Error("Local API credential file must be ignored");
console.log("Live Analytics collector and console isolation checks passed.");
