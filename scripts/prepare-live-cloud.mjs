// Offline build and sealing only. Never reads API credentials or deploys.
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { cp, mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const folder = `${root}.local/live-cloud-v1`;
const sha = (b) => createHash("sha256").update(b).digest("hex");
async function walk(path) {
  const result = [];
  for (const e of await readdir(root + path, { withFileTypes: true })) {
    const name = `${path}/${e.name}`;
    if (e.isDirectory()) result.push(...(await walk(name)));
    else result.push(name);
  }
  return result.sort();
}
async function hashes(names) {
  return Object.fromEntries(
    await Promise.all(names.sort().map(async (n) => [n, sha(await readFile(root + n))])),
  );
}
async function sourceHashes() {
  const names = [
    "package.json",
    "package-lock.json",
    "scripts/prepare-live-cloud.mjs",
    "apps/api/wrangler.live.review.jsonc",
    "apps/api/wrangler.collector.review.jsonc",
    "tests/live-analytics.test.ts",
    "tests/live-collector.test.ts",
    "tests/workbench-access.test.ts",
  ];
  for (const dir of [
    "apps/api/src",
    "apps/console/src",
    "packages/shared/src",
    "infrastructure/live-migrations",
  ])
    names.push(...(await walk(dir)));
  return hashes(names);
}
const save = (n, v) =>
  writeFile(`${folder}/${n}`, JSON.stringify(v, null, 2) + "\n", { mode: 0o600 });
if (process.argv[2] === "verify") {
  const m = JSON.parse(await readFile(`${folder}/manifest.json`, "utf8"));
  if (
    JSON.stringify(m.sources) !== JSON.stringify(await sourceHashes()) ||
    JSON.stringify(m.artifacts) !== JSON.stringify(await hashes(Object.keys(m.artifacts)))
  )
    throw Error("Live candidate changed");
  console.log("Live candidate hashes verified");
} else {
  try {
    await readFile(`${folder}/manifest.json`);
    throw Error("Sealed candidate exists; use verify");
  } catch (e) {
    if (e.code !== "ENOENT") throw e;
  }
  await mkdir(`${folder}/no-migrations`, { recursive: true, mode: 0o700 });
  await cp(`${root}apps/console/dist`, `${folder}/console-assets`, { recursive: true });
  const env = Object.fromEntries(
    Object.entries(process.env).filter(
      ([k]) => !k.startsWith("CLOUDFLARE_") && !k.startsWith("CF_"),
    ),
  );
  Object.assign(env, {
    CLOUDFLARE_LOAD_DEV_VARS_FROM_DOT_ENV: "false",
    WRANGLER_SEND_METRICS: "false",
    WRANGLER_LOG_PATH: `${folder}/build.log`,
  });
  for (const [name, source] of [
    ["console", "live"],
    ["collector", "collector"],
  ]) {
    const c = JSON.parse(await readFile(`${root}apps/api/wrangler.${source}.review.jsonc`, "utf8"));
    c.account_id = "00000000000000000000000000000001";
    c.main = `${root}apps/api/${c.main}`;
    for (const d of c.d1_databases) d.migrations_dir = `${folder}/no-migrations`;
    if (name === "console") {
      c.assets.directory = `${folder}/console-assets`;
      c.routes = [{ pattern: "soc.d.example.invalid", custom_domain: true }];
    }
    await save(`${name}-build.jsonc`, c);
    const child = spawn(
      process.execPath,
      [
        `${root}node_modules/wrangler/bin/wrangler.js`,
        "deploy",
        "--dry-run",
        "--outdir",
        `${folder}/${name}-dist`,
        "--config",
        `${folder}/${name}-build.jsonc`,
      ],
      { env, cwd: root, stdio: "inherit" },
    );
    const code = await new Promise((resolve, reject) => {
      child.on("error", reject);
      child.on("exit", resolve);
    });
    if (code !== 0) throw Error("Offline candidate build failed");
    c.main = `${folder}/${name}-dist/${name === "console" ? "index" : "collector-worker"}.js`;
    await save(`${name}.jsonc`, c);
    if (name === "collector") {
      c.vars.LIVE_PROFILE = "disabled";
      await save("collector-paused.jsonc", c);
    }
  }
  await cp(
    `${root}infrastructure/live-migrations/0001_live_analytics.sql`,
    `${folder}/0001_live_analytics.sql`,
  );
  const names = (await walk(".local/live-cloud-v1")).filter((n) => !n.endsWith(".log"));
  const manifest = {
    sealedAt: new Date().toISOString(),
    sources: await sourceHashes(),
    artifacts: await hashes(names),
    scope: {
      zone: "00000000000000000000000000000002",
      liveDatabase: "00000000-0000-4000-8000-000000000013",
      collector: "example-soc-analytics-live",
      cron: "*/5 * * * *",
      realAI: false,
      securityWrites: false,
    },
  };
  await save("manifest.json", manifest);
  console.log(
    `Sealed live candidate ${sha(JSON.stringify(manifest, null, 2) + "\n")}; remote changes: 0`,
  );
}
