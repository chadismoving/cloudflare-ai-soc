// Offline preparation and hash sealing only. Never reads credentials or deploys.
import { createHash } from "node:crypto";
import { chmod, cp, mkdir, readdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const folder = `${root}.local/workbench-cloud-review`;
const mode = process.argv[2] || "prepare";
if (!["prepare", "seal", "verify"].includes(mode)) throw Error("Offline prepare/seal/verify only");
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
async function walk(directory) {
  const result = [];
  for (const e of await readdir(`${root}${directory}`, { withFileTypes: true })) {
    const name = `${directory}/${e.name}`;
    if (e.isDirectory()) result.push(...(await walk(name)));
    else result.push(name);
  }
  return result.sort();
}
async function hashNames(names, base = root) {
  return Object.fromEntries(
    await Promise.all(
      [...new Set(names)].sort().map(async (n) => [n, sha(await readFile(base + n))]),
    ),
  );
}
async function inputs() {
  const names = [
    "package-lock.json",
    "package.json",
    "scripts/scan.mjs",
    "tests/workbench.test.ts",
    "tests/workbench-access.test.ts",
    "tests/workbench-retention.test.ts",
    "scripts/prepare-workbench-cloud.mjs",
    "scripts/wrangler-local.mjs",
    "apps/api/wrangler.workbench.review.jsonc",
    "apps/api/wrangler.workbench-maintenance.review.jsonc",
    "apps/ingest/wrangler.workbench-retention.review.jsonc",
    "apps/ingest/wrangler.workbench-r2.review.jsonc",
  ];
  for (const d of [
    "apps/api/src",
    "apps/console/src",
    "apps/console/dist",
    "apps/ingest/src",
    "packages/shared/src",
    "infrastructure/functional-migrations",
  ])
    names.push(...(await walk(d)));
  return hashNames(names);
}
async function save(name, value) {
  await writeFile(`${folder}/${name}`, value, { mode: 0o600 });
  await chmod(`${folder}/${name}`, 0o600);
}
const files = [
  "console.jsonc",
  "console-disabled.jsonc",
  ...["metadata", "maintenance", "cleanup"].flatMap((n) =>
    ["apply", "preview", "paused"].map((m) => `${n}-${m}.jsonc`),
  ),
  "migrations/simulation/0007_soc_workbench.sql",
  "migrations/simulation/0008_workbench_evidence_retention.sql",
];
await mkdir(folder, { recursive: true, mode: 0o700 });
if (mode === "prepare") {
  for (const name of ["simulation", "none"]) {
    await mkdir(`${folder}/migrations/${name}`, { recursive: true, mode: 0o700 });
    if (
      (await readdir(`${folder}/migrations/${name}`)).some(
        (n) =>
          name === "none" ||
          !["0007_soc_workbench.sql", "0008_workbench_evidence_retention.sql"].includes(n),
      )
    )
      throw Error("Migration scope differs");
  }
  for (const name of ["0007_soc_workbench.sql", "0008_workbench_evidence_retention.sql"])
    await save(
      `migrations/simulation/${name}`,
      await readFile(`${root}infrastructure/functional-migrations/${name}`),
    );
  await rm(`${folder}/console-assets`, { recursive: true, force: true });
  await cp(`${root}apps/console/dist`, `${folder}/console-assets`, {
    recursive: true,
    force: true,
  });
  for (const [name, path] of [
    ["console", "apps/api/wrangler.workbench.review.jsonc"],
    ["metadata", "apps/ingest/wrangler.workbench-retention.review.jsonc"],
    ["cleanup", "apps/ingest/wrangler.workbench-r2.review.jsonc"],
    ["maintenance", "apps/api/wrangler.workbench-maintenance.review.jsonc"],
  ]) {
    const c = JSON.parse(await readFile(root + path, "utf8"));
    c.account_id = "00000000000000000000000000000001";
    c.main =
      root + (["metadata", "cleanup"].includes(name) ? "apps/ingest/" : "apps/api/") + c.main;
    for (const db of c.d1_databases)
      db.migrations_dir = `${folder}/migrations/${db.binding === "APP_DB" ? "none" : "simulation"}`;
    if (name === "console") {
      c.assets.directory = `${folder}/console-assets`;
      c.routes = [{ pattern: "soc.d.example.invalid", custom_domain: true }];
      await save("console.jsonc", `${JSON.stringify(c, null, 2)}\n`);
      c.vars.SOC_FEATURES = "disabled";
      await save("console-disabled.jsonc", `${JSON.stringify(c, null, 2)}\n`);
    } else
      for (const m of ["apply", "preview", "paused"]) {
        const variant = structuredClone(c);
        variant.vars[
          ["metadata", "cleanup"].includes(name) ? "RETENTION_MODE" : "MAINTENANCE_MODE"
        ] = m;
        if (m !== "apply") variant.triggers = { crons: [] };
        await save(`${name}-${m}.jsonc`, `${JSON.stringify(variant, null, 2)}\n`);
      }
  }
  const assets = (await walk(".local/workbench-cloud-review/console-assets")).map((n) =>
    n.slice(".local/workbench-cloud-review/".length),
  );
  const artifactNames = [...files, ...assets];
  await save(
    "prepared.json",
    `${JSON.stringify(
      {
        preparedAt: new Date().toISOString(),
        inputs: await inputs(),
        artifactNames,
        artifacts: await hashNames(artifactNames, `${folder}/`),
      },
      null,
      2,
    )}\n`,
  );
  await save("manifest.json", `${JSON.stringify({ state: "unsealed", remoteApproval: false })}\n`);
  console.log(
    "Prepared four offline workbench candidates, isolated 0007/0008 and frozen UI assets; remote changes: 0",
  );
} else {
  const prepared = JSON.parse(await readFile(`${folder}/prepared.json`, "utf8"));
  if (
    JSON.stringify(prepared.inputs) !== JSON.stringify(await inputs()) ||
    JSON.stringify(prepared.artifacts) !==
      JSON.stringify(await hashNames(prepared.artifactNames, `${folder}/`))
  )
    throw Error("Candidate changed; repeat prepare/build/seal");
  const bundles = [
    "console-dist/index.js",
    "metadata-dist/retention-outbox-worker.js",
    "maintenance-dist/maintenance-worker.js",
    "cleanup-dist/r2-retention-worker.js",
  ];
  for (const n of bundles)
    if ((await stat(`${folder}/${n}`)).mtimeMs < Date.parse(prepared.preparedAt))
      throw Error("Stale bundle");
  const artifacts = await hashNames(
    [...prepared.artifactNames, ...bundles, ...bundles.map((n) => `${n}.map`)],
    `${folder}/`,
  );
  if (mode === "verify") {
    const sealed = JSON.parse(await readFile(`${folder}/manifest.json`, "utf8"));
    if (
      JSON.stringify(sealed.artifacts) !== JSON.stringify(artifacts) ||
      sealed.state !== "prepared_not_deployed"
    )
      throw Error("Seal differs");
    console.log("Verified sealed candidate; remote changes: 0");
  } else {
    await save(
      "manifest.json",
      `${JSON.stringify(
        {
          state: "prepared_not_deployed",
          sealedAt: new Date().toISOString(),
          inputs: prepared.inputs,
          artifacts,
          remoteApproval: false,
          remoteCalls: 0,
          accountId: "00000000000000000000000000000001",
          simulationDatabaseId: "00000000-0000-4000-8000-000000000012",
          newRawObjects: 0,
          queueMessages: 0,
          aiInference: 0,
        },
        null,
        2,
      )}\n`,
    );
    console.log("Sealed four workbench candidates; remote changes: 0");
  }
}
