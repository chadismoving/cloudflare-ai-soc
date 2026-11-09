import { candidateSql, type retentionStages } from "./retention-plan";

// Insert the same bounded candidates that the following DELETE will consume.
// A conflicting immutable task fails the CHECK and rolls back the entire batch.
export function outboxBeforeDelete(
  db: D1Database,
  stage: (typeof retentionStages)[number],
  cutoff: string,
  limit: number,
  guardId: string,
): D1PreparedStatement | null {
  const evidence = stage.name === "evidence_objects";
  if (!evidence && stage.name !== "ingestion_failures") return null;
  const table = evidence ? "evidence_objects" : "ingestion_failures";
  const kind = evidence ? "case" : "archive";
  const key = evidence ? "object_key" : "archive_key";
  const digest = evidence ? "sha256" : "NULL";
  return db
    .prepare(`INSERT INTO r2_deletion_outbox
    (id,source_kind,source_id,object_key,expected_sha256,expires_at,next_attempt_at)
    SELECT '${kind}:'||r.id,'${kind}',r.id,r.${key},${evidence ? `r.${digest}` : digest},r.expires_at,r.expires_at
    FROM ${table} r WHERE r.id IN (${candidateSql(stage)})
    AND EXISTS (SELECT 1 FROM retention_guard WHERE id=?)
    ON CONFLICT(id) DO UPDATE SET valid=CASE WHEN
      r2_deletion_outbox.source_kind=excluded.source_kind
      AND r2_deletion_outbox.source_id=excluded.source_id
      AND r2_deletion_outbox.object_key=excluded.object_key
      AND r2_deletion_outbox.expected_sha256 IS excluded.expected_sha256
      AND r2_deletion_outbox.expires_at=excluded.expires_at THEN 1 ELSE 0 END`)
    .bind(...Array<string>(stage.times).fill(cutoff), limit, guardId);
}
