import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

// Offline metadata audit only: no Cloudflare client, bindings, credentials or deletion.
const args = process.argv.slice(2);
if (args.length !== 2) {
  throw Error("Usage: node scripts/audit-retention-snapshot.mjs SNAPSHOT_DIRECTORY OUTPUT_JSON");
}
const directory = resolve(args[0]);
const sources = {};
async function load(name) {
  const content = await readFile(resolve(directory, `${name}.json`), "utf8");
  sources[`${name}.json`] = createHash("sha256").update(content).digest("hex");
  return JSON.parse(content);
}
function timestamp(value) {
  if (typeof value !== "string" || new Date(value).toISOString() !== value) {
    throw Error("Invalid canonical timestamp in snapshot");
  }
  return Date.parse(value);
}
async function rows(table) {
  const snapshot = await load(`data-after-first-${table}`);
  if (snapshot.length !== 1 || !snapshot[0].success || !Array.isArray(snapshot[0].results)) {
    throw Error(`Invalid snapshot: ${table}`);
  }
  if (snapshot[0].results.length > 4096) throw Error("Snapshot exceeds review capacity");
  return snapshot[0].results;
}
const acceptance = await load("first-cron-passed");
if (!acceptance.passed || !acceptance.originalDataAndExpiryUnchanged) {
  throw Error("A passed retention baseline is required");
}
const cutoff = timestamp(acceptance.checkedAt);
const zones = await rows("zones");
if (zones.some((row) => row.environment !== "simulation" || row.account_id !== "fixture-account")) {
  throw Error("Mixed snapshot scope");
}
const objects = await rows("ingestion_objects");
const evidence = await rows("evidence_objects");
const failures = await rows("ingestion_failures");
const targets = [];
const keys = new Set();
function target(table, row, key, expiry, anchor, days, prefix) {
  if (typeof key !== "string" || !key.startsWith(prefix) || key.includes("..") || keys.has(key)) {
    throw Error("Unexpected or duplicate object key; review shared ownership explicitly");
  }
  const expiryMs = timestamp(expiry);
  if (expiryMs - timestamp(anchor) !== days * 86400000) {
    throw Error("Retention anchor differs from the reviewed 30/90-day policy");
  }
  keys.add(key);
  targets.push({
    source_table: table,
    source_id: row.id,
    object_key: key,
    retention_anchor: anchor,
    retention_days: days,
    expires_at: expiry,
    due_at_snapshot: expiryMs <= cutoff,
    observed_r2_presence: "not_checked",
    observed_r2_expiration: "not_checked",
    metadata_deletion_loses_object_reference: true,
  });
}
for (const row of objects) {
  target("ingestion_objects", row, row.object_key, row.raw_expires_at, row.received_at, 30, "raw/");
}
for (const row of evidence) {
  if (row.environment !== "simulation" || !zones.some((zone) => zone.id === row.zone_id)) {
    throw Error("Evidence scope mismatch");
  }
  target("evidence_objects", row, row.object_key, row.expires_at, row.created_at, 90, "cases/");
}
for (const row of failures) {
  target(
    "ingestion_failures",
    row,
    row.archive_key,
    row.expires_at,
    row.created_at,
    90,
    "tool-snapshots/ingest-failures/",
  );
}
targets.sort((a, b) => a.object_key.localeCompare(b.object_key));
const result = {
  state: "offline_snapshot_audit_only",
  snapshot_checked_at_utc: acceptance.checkedAt,
  simulation_database_id: "00000000-0000-4000-8000-000000000012",
  registered_targets: targets.length,
  due_at_snapshot: targets.filter((row) => row.due_at_snapshot).length,
  targets,
  source_sha256: sources,
  cloud_requests: 0,
  object_mutations: 0,
  cloud_inventory_complete: false,
  unregistered_orphan_objects: "unknown_without_separate_inventory",
  deletion_plan_authorized: false,
  limitations: [
    "This is historical D1 metadata, not a fresh R2 inventory or an executable delete manifest.",
    "R2 upload time, lifecycle expiration, missing objects and unregistered orphans are not inferred.",
    "Persist deletion intent before D1 removes the authoritative key and expiry reference.",
  ],
};
await writeFile(resolve(args[1]), `${JSON.stringify(result, null, 2)}\n`, { mode: 0o600 });
console.log(
  JSON.stringify({
    registeredTargets: result.registered_targets,
    dueAtSnapshot: result.due_at_snapshot,
    cloudRequests: 0,
    objectMutations: 0,
  }),
);
