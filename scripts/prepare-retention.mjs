// Offline only. Does not authenticate, deploy, run Cron, apply SQL or delete data.
import { createHash } from "node:crypto";
import { chmod, mkdir, readdir, readFile, stat, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const folder = `${root}.local/retention-review`;
const mode = process.argv[2] || "prepare";
if (!["prepare", "seal"].includes(mode)) throw Error("Only offline prepare/seal supported");
const sha = (b) => createHash("sha256").update(b).digest("hex");
const files = [
  "apps/ingest/src/retention-worker.ts",
  "apps/ingest/src/retention-plan.ts",
  "apps/ingest/wrangler.retention.review.jsonc",
  "scripts/prepare-retention.mjs",
  "scripts/wrangler-local.mjs",
  "infrastructure/retention-migrations/0005_retention_guard_indexes.sql",
  "package-lock.json",
];
const inputs = async () =>
  Object.fromEntries(await Promise.all(files.map(async (f) => [f, sha(await readFile(root + f))])));
const save = async (name, value) => {
  await writeFile(`${folder}/${name}`, value, { mode: 0o600 });
  await chmod(`${folder}/${name}`, 0o600);
};
const generated = [
  "apply.jsonc",
  "preview.jsonc",
  "paused.jsonc",
  "migrations/0005_retention_guard_indexes.sql",
];
const hashes = async (names) =>
  Object.fromEntries(
    await Promise.all(names.map(async (f) => [f, sha(await readFile(`${folder}/${f}`))])),
  );
await mkdir(`${folder}/migrations`, { recursive: true, mode: 0o700 });
await chmod(folder, 0o700);
if (mode === "prepare") {
  if (
    (await readdir(`${folder}/migrations`)).some(
      (name) => name !== "0005_retention_guard_indexes.sql",
    )
  )
    throw Error("Unexpected migration scope");
  await save(
    "migrations/0005_retention_guard_indexes.sql",
    await readFile(`${root}infrastructure/retention-migrations/0005_retention_guard_indexes.sql`),
  );
  for (const name of ["apply", "preview", "paused"]) {
    const config = JSON.parse(
      await readFile(`${root}apps/ingest/wrangler.retention.review.jsonc`, "utf8"),
    );
    config.account_id = "00000000000000000000000000000001";
    config.main = `${root}apps/ingest/src/retention-worker.ts`;
    config.vars.RETENTION_MODE = name;
    config.d1_databases[0].migrations_dir = `${folder}/migrations`;
    if (name !== "apply") config.triggers = { crons: [] };
    await save(`${name}.jsonc`, `${JSON.stringify(config, null, 2)}\n`);
  }
  await save(
    "prepared.json",
    `${JSON.stringify(
      {
        preparedAt: new Date().toISOString(),
        inputs: await inputs(),
        generated: await hashes(generated),
      },
      null,
      2,
    )}\n`,
  );
  await save(
    "manifest.json",
    `${JSON.stringify({ state: "unsealed", remoteApproval: false }, null, 2)}\n`,
  );
  console.log("Prepared apply/preview/paused candidates and isolated 0005; remote changes: 0");
} else {
  const before = JSON.parse(await readFile(`${folder}/prepared.json`, "utf8"));
  if (
    JSON.stringify(before.inputs) !== JSON.stringify(await inputs()) ||
    JSON.stringify(before.generated) !== JSON.stringify(await hashes(generated))
  )
    throw Error("Inputs/config/migration changed; prepare and dry-run again");
  if ((await stat(`${folder}/dist/retention-worker.js`)).mtimeMs < Date.parse(before.preparedAt))
    throw Error("Stale bundle");
  const artifacts = await hashes([
    ...generated,
    "dist/retention-worker.js",
    "dist/retention-worker.js.map",
  ]);
  await save(
    "manifest.json",
    `${JSON.stringify(
      {
        state: "prepared-not-deployed",
        profile: "simulation-retention-v1",
        sealedAt: new Date().toISOString(),
        inputs: before.inputs,
        artifacts,
        remoteApproval: false,
        remoteWrites: 0,
      },
      null,
      2,
    )}\n`,
  );
  console.log(
    JSON.stringify({
      state: "prepared-not-deployed",
      sealedArtifacts: Object.keys(artifacts).length,
      remoteWrites: 0,
    }),
  );
}
