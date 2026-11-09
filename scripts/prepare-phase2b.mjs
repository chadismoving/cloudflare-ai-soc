// Offline only: materialize the exact reviewed cloud simulation candidate and fixture manifest.
import { createHash } from "node:crypto";
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";

const root = fileURLToPath(new URL("../", import.meta.url));
const folder = `${root}.local/phase2b-review`;
await mkdir(`${folder}/fixtures`, { recursive: true, mode: 0o700 });
await chmod(folder, 0o700);
const write = async (name, value) => {
  await writeFile(`${folder}/${name}`, value, { mode: 0o600 });
  await chmod(`${folder}/${name}`, 0o600);
};
for (const [name, source] of [
  ["ingest", "apps/ingest/wrangler.simulation.review.jsonc"],
  ["console", "apps/api/wrangler.phase2b.review.jsonc"],
]) {
  const config = JSON.parse(await readFile(`${root}${source}`, "utf8"));
  config.account_id = "00000000000000000000000000000001";
  config.main = `${root}apps/${name === "ingest" ? "ingest" : "api"}/src/index.ts`;
  for (const db of config.d1_databases) db.migrations_dir = `${root}infrastructure/migrations`;
  if (name === "console") {
    config.routes = [{ pattern: "soc.d.example.invalid", custom_domain: true }];
    config.assets.directory = `${root}apps/console/dist`;
  }
  await write(`${name}.jsonc`, `${JSON.stringify(config, null, 2)}\n`);
}
let manifest;
try {
  manifest = JSON.parse(await readFile(`${folder}/manifest.json`, "utf8"));
} catch (error) {
  if (error.code !== "ENOENT") throw error;
  const base = Math.floor(Date.now() / 300000) * 300000 - 300000;
  const row = (id, offset) => ({
    fixture: true,
    RayID: `phase2b-${id}-${base}`,
    Datetime: new Date(base + offset).toISOString(),
    Action: "block",
    RuleID: "phase2b-fixture-rule",
    Source: "waf",
    ClientRequestHost: "demo.fixture.invalid",
    ClientRequestPath: "/__soc_test/login",
    ClientIP: "client-phase2b",
  });
  const first = row("first", 10000),
    second = row("second", 20000),
    third = row("partial", 30000);
  const prefix = "raw/firewall/phase2b-fixture-";
  const inputs = {
    "main.ndjson.gz": gzipSync(`${JSON.stringify(second)}\n${JSON.stringify(first)}\n`),
    "duplicate.ndjson": Buffer.from(`${JSON.stringify(first)}\n`),
    "partial.ndjson": Buffer.from(`${JSON.stringify(third)}\n{broken\n`),
  };
  const objects = [];
  for (const [name, bytes] of Object.entries(inputs)) {
    await write(`fixtures/${name}`, bytes);
    objects.push({
      key: `${prefix}${name}`,
      file: `fixtures/${name}`,
      size: bytes.length,
      sha256: createHash("sha256").update(bytes).digest("hex"),
      expectedState: name === "partial.ndjson" ? "archived" : "complete",
    });
  }
  manifest = {
    scope: "synthetic-only",
    run: "phase2b-review-20261029",
    prefix,
    notificationRuleName: "soc-phase2b-review-20261029",
    objects,
    maxInitialUploads: 3,
    maxAdministrativeQueueReplays: 1,
    expectedUniqueEvents: 3,
    expectedNewIncidents: 1,
    generatedAt: new Date().toISOString(),
  };
  await write("manifest.json", `${JSON.stringify(manifest, null, 2)}\n`);
}
for (const object of manifest.objects) {
  if (!object.file.startsWith("fixtures/") || object.file.includes(".."))
    throw Error("Invalid fixture path");
  const bytes = await readFile(`${folder}/${object.file}`);
  if (
    bytes.length !== object.size ||
    createHash("sha256").update(bytes).digest("hex") !== object.sha256
  )
    throw Error("Prepared fixture digest mismatch");
}
console.log(
  JSON.stringify({
    prepared: true,
    networkCalls: 0,
    objects: manifest.objects.length,
    totalUploadBytes: manifest.objects.reduce((n, v) => n + v.size, 0),
    prefix: manifest.prefix,
    remoteChanges: 0,
  }),
);
