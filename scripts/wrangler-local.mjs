import { spawn } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const mode = process.argv[2];
const modes = {
  "live-collector-build": ["deploy", "--dry-run", "--outdir", `${root}.local/live-build/collector`],
  "workbench-cleanup-build": [
    "deploy",
    "--dry-run",
    "--outdir",
    `${root}.local/workbench-cloud-review/cleanup-dist`,
  ],
  "workbench-console-build": [
    "deploy",
    "--dry-run",
    "--outdir",
    `${root}.local/workbench-cloud-review/console-dist`,
  ],
  "workbench-metadata-build": [
    "deploy",
    "--dry-run",
    "--outdir",
    `${root}.local/workbench-cloud-review/metadata-dist`,
  ],
  "workbench-maintenance-build": [
    "deploy",
    "--dry-run",
    "--outdir",
    `${root}.local/workbench-cloud-review/maintenance-dist`,
  ],
  "r2-metadata-build": [
    "deploy",
    "--dry-run",
    "--outdir",
    `${root}.local/r2-retention-review/metadata-dist`,
  ],
  "r2-cleanup-build": [
    "deploy",
    "--dry-run",
    "--outdir",
    `${root}.local/r2-retention-review/cleanup-dist`,
  ],
  "r2-ingest-build": [
    "deploy",
    "--dry-run",
    "--outdir",
    `${root}.local/r2-retention-review/ingest-dist`,
  ],
  "r2-test-metadata-build": [
    "deploy",
    "--dry-run",
    "--outdir",
    `${root}.local/test-build/r2-retention/metadata`,
  ],
  "r2-test-cleanup-build": [
    "deploy",
    "--dry-run",
    "--outdir",
    `${root}.local/test-build/r2-retention/cleanup`,
  ],
  "r2-test-ingest-build": [
    "deploy",
    "--dry-run",
    "--outdir",
    `${root}.local/test-build/r2-retention/ingest`,
  ],
  "retention-review-build": [
    "deploy",
    "--dry-run",
    "--outdir",
    `${root}.local/retention-review/dist`,
  ],
  "retention-build": ["deploy", "--dry-run", "--outdir", `${root}.local/retention-dist`],
  "ingest-health-build": [
    "deploy",
    "--dry-run",
    "--outdir",
    `${root}.local/ingestion-health-review/ingest-dist`,
  ],
  "console-health-build": [
    "deploy",
    "--dry-run",
    "--outdir",
    `${root}.local/ingestion-health-review/console-dist`,
  ],
  "ingest-review-build": [
    "deploy",
    "--dry-run",
    "--outdir",
    `${root}.local/phase2b-review/ingest-dist`,
  ],
  "console-phase2b-build": [
    "deploy",
    "--dry-run",
    "--outdir",
    `${root}.local/phase2b-review/console-dist`,
  ],
  "ingest-build": ["deploy", "--dry-run", "--outdir", `${root}apps/ingest/dist`],
  "probe-build": ["deploy", "--dry-run", "--outdir", `${root}apps/access-probe/dist`],
  "console-review-build": ["deploy", "--dry-run", "--outdir", `${root}.local/console-review-dist`],
  build: ["deploy", "--dry-run", "--outdir", `${root}apps/api/dist`],
  types: [
    "types",
    `${root}apps/api/src/worker-bindings.d.ts`,
    "--include-runtime",
    "false",
    "--env-interface",
    "WranglerBindings",
    "--strict-vars",
    "false",
    "--env-file",
    `${root}.local/types.env`,
  ],
};
if (!Object.hasOwn(modes, mode))
  throw new Error("Only offline build/types commands are supported.");
await mkdir(`${root}.local`, { recursive: true, mode: 0o700 });
if (mode === "types") await writeFile(`${root}.local/types.env`, "", { mode: 0o600 });
const env = Object.fromEntries(
  Object.entries(process.env).filter(([k]) => !k.startsWith("CLOUDFLARE_") && !k.startsWith("CF_")),
);
const r2Configs = {
  "live-collector-build": `${root}apps/api/wrangler.collector.review.jsonc`,
  "workbench-cleanup-build": `${root}.local/workbench-cloud-review/cleanup-apply.jsonc`,
  "workbench-console-build": `${root}.local/workbench-cloud-review/console.jsonc`,
  "workbench-metadata-build": `${root}.local/workbench-cloud-review/metadata-apply.jsonc`,
  "workbench-maintenance-build": `${root}.local/workbench-cloud-review/maintenance-apply.jsonc`,
  "r2-metadata-build": `${root}.local/r2-retention-review/metadata-apply.jsonc`,
  "r2-cleanup-build": `${root}.local/r2-retention-review/cleanup-apply.jsonc`,
  "r2-ingest-build": `${root}.local/r2-retention-review/ingest.jsonc`,
  "r2-test-metadata-build": `${root}apps/ingest/wrangler.retention-outbox.review.jsonc`,
  "r2-test-cleanup-build": `${root}apps/ingest/wrangler.r2-retention.review.jsonc`,
  "r2-test-ingest-build": `${root}apps/ingest/wrangler.immutable.review.jsonc`,
};
env.WRANGLER_SEND_METRICS = "false";
env.WRANGLER_LOG_PATH = `${root}.local/build.log`;
if (
  mode === "types" ||
  mode.startsWith("r2-") ||
  mode.startsWith("workbench-") ||
  mode.startsWith("live-")
)
  env.CLOUDFLARE_LOAD_DEV_VARS_FROM_DOT_ENV = "false";
const child = spawn(
  process.execPath,
  [
    `${root}node_modules/wrangler/bin/wrangler.js`,
    ...modes[mode],
    "--config",
    r2Configs[mode] ||
      (mode === "retention-review-build"
        ? `${root}.local/retention-review/apply.jsonc`
        : mode === "retention-build"
          ? `${root}apps/ingest/wrangler.retention.local.jsonc`
          : mode === "ingest-health-build"
            ? `${root}.local/ingestion-health-review/ingest.jsonc`
            : mode === "console-health-build"
              ? `${root}.local/ingestion-health-review/console.jsonc`
              : mode === "ingest-review-build"
                ? `${root}apps/ingest/wrangler.simulation.review.jsonc`
                : mode === "console-phase2b-build"
                  ? `${root}apps/api/wrangler.phase2b.review.jsonc`
                  : mode === "ingest-build"
                    ? `${root}apps/ingest/wrangler.local.jsonc`
                    : mode === "probe-build"
                      ? `${root}apps/access-probe/wrangler.review.jsonc`
                      : mode === "console-review-build"
                        ? `${root}apps/api/wrangler.production.review.jsonc`
                        : `${root}apps/api/wrangler.local.jsonc`),
  ],
  { cwd: root, env, stdio: "inherit" },
);
child.on("error", (error) => {
  console.error(error.message);
  process.exitCode = 1;
});
child.on("exit", (code) => {
  process.exitCode = code ?? 1;
});
