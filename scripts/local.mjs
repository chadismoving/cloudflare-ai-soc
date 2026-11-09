import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { fileURLToPath } from "node:url";
import { fixtureEnvironment, serializeFixtureEnvironment } from "./fixture-env.mjs";

const root = fileURLToPath(new URL("../", import.meta.url));
let config = `${root}apps/api/wrangler.local.jsonc`;
const state = `${root}.local/state`;
const env = Object.fromEntries(
  Object.entries(process.env).filter(([k]) => !k.startsWith("CLOUDFLARE_") && !k.startsWith("CF_")),
);
env.WRANGLER_SEND_METRICS = "false";
env.WRANGLER_LOG_PATH = `${root}.local/wrangler.log`;
env.CI = "true";
const mode = process.argv[2];
if (!["prepare", "dev"].includes(mode))
  throw new Error("Use local.mjs prepare or dev. No remote commands are supported.");

function run(command, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd: root, env, stdio: "inherit" });
    child.on("error", reject);
    child.on("exit", (code) =>
      code === 0 ? resolve() : reject(new Error(`Local command exited ${code}`)),
    );
    for (const signal of ["SIGINT", "SIGTERM"]) process.once(signal, () => child.kill(signal));
  });
}
const wrangler = (args) =>
  run(process.execPath, [
    `${root}node_modules/wrangler/bin/wrangler.js`,
    ...args,
    "--config",
    config,
  ]);
await mkdir(`${root}.local`, { recursive: true, mode: 0o700 });
const vars = `${root}apps/api/.dev.vars`;
try {
  await readFile(vars);
} catch (error) {
  if (error.code !== "ENOENT") throw error;
  await writeFile(vars, serializeFixtureEnvironment(await fixtureEnvironment()), {
    mode: 0o600,
    flag: "wx",
  });
}
await chmod(vars, 0o600);
let localPort = Number(process.env.SOC_LOCAL_PORT || 8787);
if (!Number.isInteger(localPort) || localPort < 1024 || localPort > 65535)
  throw Error("SOC_LOCAL_PORT must be an integer from 1024 to 65535.");
if (mode === "dev") {
  const available = (port) =>
    new Promise((resolve) => {
      const server = createServer();
      server.once("error", () => resolve(false));
      server.listen(port, "127.0.0.1", () => server.close(() => resolve(true)));
    });
  const candidates = process.env.SOC_LOCAL_PORT ? [localPort] : [8787, 8790, 8791, 8792];
  let selected;
  for (const port of candidates)
    if (await available(port)) {
      selected = port;
      break;
    }
  if (!selected)
    throw Error("No selected loopback port is free; set SOC_LOCAL_PORT to another port.");
  localPort = selected;
  const preview = `${root}.local/full-preview`;
  await mkdir(preview, { recursive: true, mode: 0o700 });
  const generated = JSON.parse(await readFile(config, "utf8"));
  generated.main = `${root}apps/api/src/index.ts`;
  generated.assets.directory = `${root}apps/console/dist`;
  generated.vars.APP_ORIGIN = `http://127.0.0.1:${localPort}`;
  generated.vars.ACCESS_ISSUER = `http://127.0.0.1:${localPort}/__local/access`;
  generated.dev.port = localPort;
  for (const database of generated.d1_databases)
    database.migrations_dir = `${root}infrastructure/migrations`;
  config = `${preview}/wrangler.jsonc`;
  await writeFile(config, `${JSON.stringify(generated, null, 2)}\n`, { mode: 0o600 });
  await writeFile(`${preview}/.dev.vars`, await readFile(vars), { mode: 0o600 });
  console.log(`Full simulation workbench: http://127.0.0.1:${localPort}/`);
}
for (const binding of ["APP_DB", "SIMULATION_DB"]) {
  await wrangler(["d1", "migrations", "apply", binding, "--local", "--persist-to", state]);
}
for (const file of ["0007_soc_workbench.sql", "0008_workbench_evidence_retention.sql"])
  await wrangler([
    "d1",
    "execute",
    "SIMULATION_DB",
    "--local",
    "--persist-to",
    state,
    "--file",
    `${root}infrastructure/functional-migrations/${file}`,
  ]);
const evidence = await readFile(`${root}simulations/fixtures/evidence-001.json`);
const digest = createHash("sha256").update(evidence).digest("hex");
const simulation = (await readFile(`${root}infrastructure/seeds/simulation.sql`, "utf8")).replace(
  "__EVIDENCE_SHA256__",
  digest,
);
const seedFile = `${root}.local/simulation-seed.sql`;
await writeFile(seedFile, simulation);
await wrangler([
  "d1",
  "execute",
  "APP_DB",
  "--local",
  "--persist-to",
  state,
  "--file",
  `${root}infrastructure/seeds/control.sql`,
]);
await wrangler([
  "d1",
  "execute",
  "SIMULATION_DB",
  "--local",
  "--persist-to",
  state,
  "--file",
  seedFile,
]);
await wrangler([
  "r2",
  "object",
  "put",
  "soc-local-simulation-evidence/simulation/cases/fixture/evidence-001.json",
  "--file",
  `${root}simulations/fixtures/evidence-001.json`,
  "--local",
  "--persist-to",
  state,
]);
console.log("Local fixture databases/evidence ready. No Cloudflare resources were created.");
if (mode === "dev") {
  await run(process.execPath, [
    `${root}node_modules/vite/bin/vite.js`,
    "build",
    `${root}apps/console`,
    "--config",
    `${root}apps/console/vite.config.ts`,
  ]);
  const timer = setInterval(() => {
    void fetch(`http://127.0.0.1:${localPort}/cdn-cgi/handler/scheduled?cron=local-reconcile`)
      .then((r) => r.body?.cancel())
      .catch(() => {});
  }, 15000);
  try {
    await wrangler([
      "dev",
      "--local",
      "--test-scheduled",
      "--ip",
      "127.0.0.1",
      "--port",
      String(localPort),
      "--persist-to",
      state,
    ]);
  } finally {
    clearInterval(timer);
  }
}
