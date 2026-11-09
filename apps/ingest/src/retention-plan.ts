export const retentionLimit = 10;
export const retentionRowCeiling = 4096;
export const retentionCron = "17 * * * *";
export const retentionCloudProfile = "simulation-retention-v1";
export const retentionSimulationDatabase = "00000000-0000-4000-8000-000000000012";
export const retentionTables = [
  "audit_trail",
  "ingestion_provenance",
  "incident_events",
  "events",
  "evidence_objects",
  "ingestion_replays",
  "ingestion_failures",
  "ingestion_objects",
  "ingestion_event_keys",
  "incidents",
  "zones",
] as const;
export const expiryTables = [
  "audit_trail",
  "events",
  "incidents",
  "evidence_objects",
  "ingestion_replays",
  "ingestion_failures",
  "ingestion_objects",
  "ingestion_event_keys",
] as const;
export const expiryFields = [
  ["audit_trail", "expires_at"],
  ["events", "expires_at"],
  ["incidents", "expires_at"],
  ["evidence_objects", "expires_at"],
  ["ingestion_objects", "expires_at"],
  ["ingestion_objects", "raw_expires_at"],
  ["ingestion_event_keys", "expires_at"],
  ["ingestion_event_keys", "event_expires_at"],
  ["ingestion_failures", "expires_at"],
  ["ingestion_replays", "expires_at"],
] as const;
// Every table is checked with LIMIT before expensive full-scope validation is allowed.
export const sizeGuardSql = `SELECT (${retentionTables.map((table) => `(SELECT COUNT(*) FROM (SELECT 1 FROM ${table} LIMIT ${retentionRowCeiling + 1}))>${retentionRowCeiling}`).join(" OR ")}) AS oversized`;
export const scopeGuardSql = `SELECT
 (SELECT COUNT(*) FROM zones WHERE environment<>'simulation' OR account_id<>'fixture-account') AS foreign_zones,
 (SELECT COUNT(*) FROM events WHERE environment<>'simulation' OR source<>'synthetic' OR json_extract(metadata_json,'$.fixture') IS NOT 1) AS foreign_events,
 (SELECT COUNT(*) FROM incidents WHERE environment<>'simulation') AS foreign_incidents,
 (SELECT COUNT(*) FROM evidence_objects WHERE environment<>'simulation') AS foreign_evidence,
 (${expiryFields.map(([table, column]) => `(SELECT COUNT(*) FROM ${table} WHERE strftime('%Y-%m-%dT%H:%M:%fZ',${column}) IS NOT ${column})`).join(" + ")}) AS invalid_deadlines`;
export const remainingSql = `SELECT (${expiryTables.map((table) => `EXISTS (SELECT 1 FROM ${table} WHERE expires_at<=?)`).join(" OR ")}) AS remaining`;
export const inventorySql = `SELECT json_array(${expiryTables.map((table) => `json_object('table_name','${table}','total',(SELECT COUNT(*) FROM ${table}),'expired',(SELECT COUNT(*) FROM ${table} WHERE expires_at<=?),'next_expiry',(SELECT MIN(expires_at) FROM ${table} WHERE expires_at>?))`).join(",")}) AS inventory_json`;
export const inventoryParams = (cutoff: string) => expiryTables.flatMap(() => [cutoff, cutoff]);
export const atomicGuardSql = `INSERT INTO retention_guard (id,valid,counts_json)
 SELECT ?,CASE WHEN (SELECT oversized FROM (${sizeGuardSql}))<>0 THEN 0
 WHEN (SELECT foreign_zones+foreign_events+foreign_incidents+foreign_evidence+invalid_deadlines FROM (${scopeGuardSql}))<>0 THEN 0 ELSE 1 END,'{}'
 WHERE NOT EXISTS (SELECT 1 FROM audit_trail WHERE id=?)`;

function stages() {
  const expiredEvents = "SELECT id FROM events WHERE environment='simulation' AND expires_at<=?";
  const expiredObjects =
    "SELECT id FROM ingestion_objects WHERE expires_at<=? AND raw_expires_at<=?";
  // Child rows are explicitly bounded and removed first. Parent deletes require no children,
  // avoiding an unbounded cascade or removal of a still-retained child.
  const stages = [
    {
      name: "audit_trail",
      sql: "DELETE FROM audit_trail WHERE id IN (SELECT id FROM audit_trail WHERE expires_at<=? ORDER BY expires_at,id LIMIT ?)",
      times: 1,
    },
    {
      name: "ingestion_provenance",
      sql: `DELETE FROM ingestion_provenance WHERE rowid IN (SELECT rowid FROM ingestion_provenance WHERE event_id IN (${expiredEvents}) OR object_id IN (${expiredObjects}) ORDER BY rowid LIMIT ?)`,
      times: 3,
    },
    {
      name: "incident_events",
      sql: `DELETE FROM incident_events WHERE rowid IN (SELECT rowid FROM incident_events WHERE event_id IN (${expiredEvents}) ORDER BY rowid LIMIT ?)`,
      times: 1,
    },
    {
      name: "events",
      sql: `DELETE FROM events WHERE id IN (SELECT e.id FROM events e WHERE e.environment='simulation' AND e.expires_at<=? AND NOT EXISTS (SELECT 1 FROM ingestion_provenance p WHERE p.event_id=e.id) AND NOT EXISTS (SELECT 1 FROM incident_events l WHERE l.event_id=e.id) ORDER BY e.expires_at,e.id LIMIT ?)`,
      times: 1,
    },
    {
      name: "evidence_objects",
      sql: "DELETE FROM evidence_objects WHERE id IN (SELECT id FROM evidence_objects WHERE environment='simulation' AND expires_at<=? ORDER BY expires_at,id LIMIT ?)",
      times: 1,
    },
    {
      name: "ingestion_replays",
      sql: "DELETE FROM ingestion_replays WHERE id IN (SELECT id FROM ingestion_replays WHERE expires_at<=? ORDER BY expires_at,id LIMIT ?)",
      times: 1,
    },
    {
      name: "ingestion_failures",
      sql: "DELETE FROM ingestion_failures WHERE id IN (SELECT id FROM ingestion_failures WHERE expires_at<=? ORDER BY expires_at,id LIMIT ?)",
      times: 1,
    },
    {
      name: "ingestion_objects",
      sql: `DELETE FROM ingestion_objects WHERE id IN (SELECT o.id FROM ingestion_objects o WHERE o.expires_at<=? AND o.raw_expires_at<=? AND NOT EXISTS (SELECT 1 FROM ingestion_provenance p WHERE p.object_id=o.id) AND NOT EXISTS (SELECT 1 FROM ingestion_replays r WHERE r.object_id=o.id) AND NOT EXISTS (SELECT 1 FROM ingestion_failures f WHERE f.object_id=o.id) ORDER BY o.expires_at,o.id LIMIT ?)`,
      times: 2,
    },
    {
      name: "ingestion_event_keys",
      sql: `DELETE FROM ingestion_event_keys WHERE event_key IN (SELECT k.event_key FROM ingestion_event_keys k WHERE k.expires_at<=? AND NOT EXISTS (SELECT 1 FROM events e WHERE e.id=k.event_id) ORDER BY k.expires_at,k.event_key LIMIT ?)`,
      times: 1,
    },
    {
      name: "incidents",
      sql: `DELETE FROM incidents WHERE id IN (SELECT i.id FROM incidents i WHERE i.environment='simulation' AND i.expires_at<=? AND NOT EXISTS (SELECT 1 FROM evidence_objects e WHERE e.incident_id=i.id) AND NOT EXISTS (SELECT 1 FROM incident_events l WHERE l.incident_id=i.id) ORDER BY i.expires_at,i.id LIMIT ?)`,
      times: 1,
    },
  ];
  return stages;
}
export const retentionStages = stages();
export function candidateSql(stage: (typeof retentionStages)[number]) {
  const start = stage.sql.indexOf("(SELECT ");
  if (start < 0 || !stage.sql.endsWith(")")) throw Error("Unexpected retention SQL");
  return stage.sql.slice(start + 1, -1);
}

// The two existing hourly cleaners produce up to 4,320 audit rows per 90 days.
// Workbench candidates permit a bounded 16,384 audit rows; other tables keep 4,096.
export const workbenchAuditLimit = (sql: string) =>
  sql.replaceAll(
    "(SELECT COUNT(*) FROM (SELECT 1 FROM audit_trail LIMIT 4097))>4096",
    "(SELECT COUNT(*) FROM (SELECT 1 FROM audit_trail LIMIT 16385))>16384",
  );
