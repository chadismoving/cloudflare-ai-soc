// Offline materialization and build sealing only. Never invokes Cloudflare or reads credentials.
import { createHash } from "node:crypto";
import { chmod, mkdir, readdir, readFile, stat, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const relativeFolder = ".local/ingestion-health-review";
const folder = `${root}${relativeFolder}`;
const mode = process.argv[2] || "prepare";
if (!["prepare", "seal"].includes(mode)) throw Error("Only offline prepare or seal is supported.");
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const write = async (name, value) => {
  await writeFile(`${folder}/${name}`, value, { mode: 0o600 });
  await chmod(`${folder}/${name}`, 0o600);
};
async function walk(dir) {
  const files = [];
  for (const entry of await readdir(`${root}${dir}`, { withFileTypes: true })) {
    const name = `${dir}/${entry.name}`;
    if (entry.isDirectory()) files.push(...(await walk(name)));
    else files.push(name);
  }
  return files.sort();
}
async function inputs() {
  const names = [
    "package-lock.json",
    "scripts/prepare-ingestion-health.mjs",
    "scripts/wrangler-local.mjs",
    "apps/api/wrangler.health.review.jsonc",
    "apps/ingest/wrangler.health.review.jsonc",
    "infrastructure/migrations/0004_ingestion_observability.sql",
  ];
  for (const dir of [
    "apps/api/src",
    "apps/ingest/src",
    "apps/console/src",
    "packages/shared/src",
    "apps/console/dist",
  ])
    names.push(...(await walk(dir)));
  return Object.fromEntries(
    await Promise.all(
      names.sort().map(async (name) => [name, sha256(await readFile(`${root}${name}`))]),
    ),
  );
}
const preparedNames = [
  "ingest.jsonc",
  "console.jsonc",
  "migrations/simulation/0004_ingestion_observability.sql",
];
async function preparedArtifacts() {
  return Object.fromEntries(
    await Promise.all(
      preparedNames.map(async (name) => [name, sha256(await readFile(`${folder}/${name}`))]),
    ),
  );
}
await mkdir(folder, { recursive: true, mode: 0o700 });
await chmod(folder, 0o700);
if (mode === "prepare") {
  for (const name of ["simulation", "none"]) {
    const path = `${folder}/migrations/${name}`;
    await mkdir(path, { recursive: true, mode: 0o700 });
    const entries = await readdir(path);
    if (entries.some((entry) => name === "none" || entry !== "0004_ingestion_observability.sql"))
      throw Error("Unexpected migration file; refusing to prepare a broader scope.");
  }
  await write(
    "migrations/simulation/0004_ingestion_observability.sql",
    await readFile(`${root}infrastructure/migrations/0004_ingestion_observability.sql`),
  );
  for (const [name, app] of [
    ["ingest", "ingest"],
    ["console", "api"],
  ]) {
    const config = JSON.parse(
      await readFile(`${root}apps/${app}/wrangler.health.review.jsonc`, "utf8"),
    );
    config.account_id = "00000000000000000000000000000001";
    config.main = `${root}apps/${app}/src/index.ts`;
    for (const db of config.d1_databases)
      db.migrations_dir = `${folder}/migrations/${db.binding === "SIMULATION_DB" ? "simulation" : "none"}`;
    if (name === "console") {
      config.assets.directory = `${root}apps/console/dist`;
      config.routes = [{ pattern: "soc.d.example.invalid", custom_domain: true }];
    }
    await write(`${name}.jsonc`, `${JSON.stringify(config, null, 2)}\n`);
  }
  await write(
    "prepared.json",
    `${JSON.stringify({ preparedAt: new Date().toISOString(), inputs: await inputs(), artifacts: await preparedArtifacts() }, null, 2)}\n`,
  );
  await write(
    "manifest.json",
    `${JSON.stringify({ state: "unsealed", remoteApprovalRecorded: false }, null, 2)}\n`,
  );
  console.log(
    "Prepared private health configs and simulation-only 0004. No network, fixtures, credentials or remote changes.",
  );
} else {
  const prepared = JSON.parse(await readFile(`${folder}/prepared.json`, "utf8"));
  const current = await inputs();
  if (JSON.stringify(current) !== JSON.stringify(prepared.inputs))
    throw Error(
      "Candidate inputs changed. Re-prepare and repeat both dry-run builds before sealing.",
    );
  if (JSON.stringify(await preparedArtifacts()) !== JSON.stringify(prepared.artifacts))
    throw Error("Prepared config or migration changed. Refusing to seal.");
  for (const name of ["ingest-dist/index.js", "console-dist/index.js"])
    if ((await stat(`${folder}/${name}`)).mtimeMs < Date.parse(prepared.preparedAt))
      throw Error("A candidate build predates this preparation. Repeat both dry-run builds.");
  const artifacts = {};
  for (const name of [
    "ingest.jsonc",
    "console.jsonc",
    "migrations/simulation/0004_ingestion_observability.sql",
    ...(await walk(`${relativeFolder}/ingest-dist`)).map((v) => v.slice(relativeFolder.length + 1)),
    ...(await walk(`${relativeFolder}/console-dist`)).map((v) =>
      v.slice(relativeFolder.length + 1),
    ),
  ])
    artifacts[name] = sha256(await readFile(`${folder}/${name}`));
  const manifest = {
    profile: "phase2b-health-v1",
    state: "offline-candidate-only",
    preparedAt: prepared.preparedAt,
    sealedAt: new Date().toISOString(),
    accountId: "00000000000000000000000000000001",
    simulationDatabaseId: "00000000-0000-4000-8000-000000000012",
    inputs: current,
    artifacts,
    remoteCalls: 0,
    newRawObjects: 0,
    administrativeQueueMessages: 0,
    remoteApprovalRecorded: false,
  };
  await write("manifest.json", `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(
    JSON.stringify({
      profile: manifest.profile,
      state: manifest.state,
      sealedArtifacts: Object.keys(artifacts).length,
      remoteCalls: 0,
    }),
  );
}
