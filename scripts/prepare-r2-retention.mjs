// Offline materialization and seal. No SDK, authentication, deployment or database access.
import { createHash } from "node:crypto";
import { chmod, mkdir, readdir, readFile, stat, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const directory = `${root}.local/r2-retention-review`;
const mode = process.argv[2] || "prepare";
if (!["prepare", "seal"].includes(mode)) throw Error("Only offline prepare/seal supported");
const sha = (b) => createHash("sha256").update(b).digest("hex");
const inputNames = [
  "package-lock.json",
  "scripts/prepare-r2-retention.mjs",
  "scripts/wrangler-local.mjs",
  "apps/ingest/wrangler.retention-outbox.review.jsonc",
  "apps/ingest/wrangler.r2-retention.review.jsonc",
  "apps/ingest/wrangler.immutable.review.jsonc",
  "infrastructure/r2-retention-migrations/0006_r2_deletion_outbox.sql",
  ...(await readdir(`${root}apps/ingest/src`))
    .filter((f) => /\.(ts|json)$/.test(f))
    .map((f) => `apps/ingest/src/${f}`),
  ...(await readdir(`${root}packages/shared/src`))
    .filter((f) => f.endsWith(".ts"))
    .map((f) => `packages/shared/src/${f}`),
].sort();
async function hashes(names, base = root) {
  return Object.fromEntries(
    await Promise.all(names.map(async (n) => [n, sha(await readFile(base + n))])),
  );
}
async function save(name, value) {
  await writeFile(`${directory}/${name}`, value, { mode: 0o600 });
  await chmod(`${directory}/${name}`, 0o600);
}
const generated = [
  "ingest.jsonc",
  "migrations/0006_r2_deletion_outbox.sql",
  ...["metadata", "cleanup"].flatMap((n) =>
    ["apply", "preview", "paused"].map((m) => `${n}-${m}.jsonc`),
  ),
];
await mkdir(`${directory}/migrations`, { recursive: true, mode: 0o700 });
await mkdir(`${directory}/none`, { recursive: true, mode: 0o700 });
if (
  (await readdir(`${directory}/none`)).length ||
  (await readdir(`${directory}/migrations`)).some((n) => n !== "0006_r2_deletion_outbox.sql")
)
  throw Error("Migration scope differs");
if (mode === "prepare") {
  await save(
    "migrations/0006_r2_deletion_outbox.sql",
    await readFile(`${root}infrastructure/r2-retention-migrations/0006_r2_deletion_outbox.sql`),
  );
  for (const [name, file] of [
    ["metadata", "retention-outbox"],
    ["cleanup", "r2-retention"],
    ["ingest", "immutable"],
  ]) {
    const base = JSON.parse(
      await readFile(`${root}apps/ingest/wrangler.${file}.review.jsonc`, "utf8"),
    );
    base.account_id = "00000000000000000000000000000001";
    base.main = `${root}apps/ingest/${base.main}`;
    base.d1_databases[0].migrations_dir = `${directory}/${name === "ingest" ? "none" : "migrations"}`;
    if (name === "ingest") await save("ingest.jsonc", `${JSON.stringify(base, null, 2)}\n`);
    else
      for (const m of ["apply", "preview", "paused"]) {
        const config = structuredClone(base);
        config.vars.RETENTION_MODE = m;
        if (m !== "apply") config.triggers = { crons: [] };
        await save(`${name}-${m}.jsonc`, `${JSON.stringify(config, null, 2)}\n`);
      }
  }
  await save(
    "prepared.json",
    `${JSON.stringify(
      {
        preparedAt: new Date().toISOString(),
        inputs: await hashes(inputNames),
        artifacts: await hashes(generated, `${directory}/`),
      },
      null,
      2,
    )}\n`,
  );
  await save("manifest.json", `${JSON.stringify({ state: "unsealed", remoteApproval: false })}\n`);
  console.log(
    "Prepared isolated 0006, fixed-five-key policy and three offline candidates; remote changes: 0",
  );
} else {
  const before = JSON.parse(await readFile(`${directory}/prepared.json`, "utf8"));
  if (
    JSON.stringify(before.inputs) !== JSON.stringify(await hashes(inputNames)) ||
    JSON.stringify(before.artifacts) !== JSON.stringify(await hashes(generated, `${directory}/`))
  )
    throw Error("Candidate changed; prepare/build again");
  const bundles = [
    "metadata-dist/retention-outbox-worker.js",
    "cleanup-dist/r2-retention-worker.js",
    "ingest-dist/index.js",
  ];
  for (const file of bundles)
    if ((await stat(`${directory}/${file}`)).mtimeMs < Date.parse(before.preparedAt))
      throw Error("Stale bundle");
  await save(
    "manifest.json",
    `${JSON.stringify(
      {
        state: "prepared_not_deployed",
        sealedAt: new Date().toISOString(),
        inputs: before.inputs,
        artifacts: await hashes(
          [...generated, ...bundles, ...bundles.map((f) => `${f}.map`)],
          `${directory}/`,
        ),
        remoteApproval: false,
        remoteWrites: 0,
      },
      null,
      2,
    )}\n`,
  );
  console.log("Sealed three candidates; remote changes: 0");
}
