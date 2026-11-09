import { audit, digest, expiry, now, type WorkContext } from "./store";

type Registry = {
  id: string;
  incident_id: string;
  zone_id: string;
  object_key: string;
  sha256: string;
  created_at: string;
  expires_at: string;
  attempts: number;
};
const limit = 5;
const hour = 3600000;
export async function retainEvidence(db: D1Database, bucket: R2Bucket) {
  const at = now();
  await db
    .prepare(
      "UPDATE wb_evidence_registry SET state='blocked',last_error='lease_exhausted_manual_review' WHERE state='deleting' AND attempts=3 AND lease_until<=?",
    )
    .bind(at)
    .run();
  const due = await db
    .prepare(
      "SELECT * FROM wb_evidence_registry WHERE state IN ('registered','staging','deleting') AND expires_at<=? AND next_attempt_at<=? AND attempts<3 AND (lease_until IS NULL OR lease_until<=?) ORDER BY expires_at,id LIMIT ?",
    )
    .bind(at, at, at, limit)
    .all<Registry>();
  const outcomes: Record<string, number> = {};
  for (const row of due.results) {
    const token = crypto.randomUUID();
    const claimed = await db.batch([
      db
        .prepare(
          "UPDATE wb_evidence_registry SET state='deleting',attempts=attempts+1,lease_token=?,lease_until=?,next_attempt_at=? WHERE id=? AND state IN ('registered','staging','deleting') AND expires_at<=? AND attempts<3 AND (lease_until IS NULL OR lease_until<=?)",
        )
        .bind(
          token,
          new Date(Date.now() + 10 * 60000).toISOString(),
          new Date(Date.now() + hour).toISOString(),
          row.id,
          at,
          at,
        ),
      db
        .prepare(
          "INSERT INTO audit_trail SELECT ?,NULL,'workbench.evidence.delete_intent',id,json_object('attempt',attempts),?,? FROM wb_evidence_registry WHERE id=? AND lease_token=?",
        )
        .bind(`wb-intent-${token}`, at, expiry(at), row.id, token),
    ]);
    if (claimed[0]?.meta.changes !== 1) continue;
    let outcome = "deleted";
    try {
      const key = row.id.slice(9);
      if (
        !/^[a-f0-9]{64}$/.test(key) ||
        row.incident_id !== `sim-${key}` ||
        row.zone_id !== "fixture-zone" ||
        ![`cases/workbench/${key}.json`, `simulation/cases/workbench/${key}.json`].includes(
          row.object_key,
        ) ||
        expiry(row.created_at) !== row.expires_at
      )
        throw Error("ownership_mismatch");
      const registered = await db
        .prepare("SELECT object_key,sha256,expires_at FROM evidence_objects WHERE id=?")
        .bind(row.id)
        .first<{ object_key: string; sha256: string; expires_at: string }>();
      if (
        registered &&
        (registered.object_key !== row.object_key ||
          registered.sha256 !== row.sha256 ||
          registered.expires_at !== row.expires_at)
      )
        throw Error("registration_mismatch");
      const object = await bucket.get(row.object_key);
      if (object) {
        if (object.size > 16384) {
          await object.body.cancel();
          throw Error("content_mismatch");
        }
        const content = await object.text();
        if (content.length > 16384 || (await digest(content)) !== row.sha256)
          throw Error("content_mismatch");
        const parsed = JSON.parse(content);
        if (
          parsed.fixture !== true ||
          parsed.environment !== "simulation" ||
          parsed.source !== "synthetic"
        )
          throw Error("ownership_mismatch");
        const lease = await db
          .prepare(
            "SELECT id FROM wb_evidence_registry WHERE id=? AND state='deleting' AND lease_token=? AND lease_until>?",
          )
          .bind(row.id, token, now())
          .first();
        if (!lease) throw Error("lease_lost");
        await bucket.delete(row.object_key);
      } else outcome = "already_absent";
      await db.batch([
        db
          .prepare(
            "DELETE FROM evidence_objects WHERE id=? AND environment='simulation' AND zone_id=? AND object_key=? AND sha256=? AND expires_at=? AND expires_at<=? AND EXISTS(SELECT 1 FROM wb_evidence_registry WHERE id=? AND lease_token=?)",
          )
          .bind(row.id, row.zone_id, row.object_key, row.sha256, row.expires_at, at, row.id, token),
        db
          .prepare(
            "UPDATE wb_evidence_registry SET state='deleted',completed_at=?,last_error=NULL,lease_until=NULL WHERE id=? AND lease_token=?",
          )
          .bind(at, row.id, token),
        audit(db, null, "workbench.evidence.deleted", row.id, { outcome, token }),
      ]);
    } catch (error) {
      const reason =
        error instanceof Error &&
        /^(ownership_mismatch|registration_mismatch|content_mismatch)$/.test(error.message)
          ? error.message
          : "storage_or_commit_failure";
      const blocked = reason !== "storage_or_commit_failure" || row.attempts + 1 >= 3;
      outcome = blocked ? "blocked" : "retry";
      await db.batch([
        db
          .prepare(
            "UPDATE wb_evidence_registry SET state=?,last_error=?,lease_until=NULL WHERE id=? AND lease_token=?",
          )
          .bind(blocked ? "blocked" : "registered", reason, row.id, token),
        audit(db, null, "workbench.evidence.delete_failed", row.id, { reason, blocked }),
      ]);
    }
    outcomes[outcome] = (outcomes[outcome] || 0) + 1;
  }
  await db
    .prepare(
      "DELETE FROM wb_evidence_registry WHERE id IN (SELECT r.id FROM wb_evidence_registry r WHERE state='deleted' AND completed_at<=? AND NOT EXISTS(SELECT 1 FROM evidence_objects e WHERE e.id=r.id) ORDER BY completed_at,id LIMIT ?)",
    )
    .bind(new Date(Date.now() - 90 * 86400000).toISOString(), limit)
    .run();
  return { at, limit, outcomes, rawDeletion: false };
}

export async function maintenancePrincipal(db: D1Database): Promise<WorkContext["principal"]> {
  const rows = await db
    .prepare(
      "SELECT id FROM zones WHERE id='fixture-zone' AND environment='simulation' AND account_id='fixture-account' AND enabled=1",
    )
    .all<{ id: string }>();
  return {
    id: "system-simulation",
    role: "Admin",
    token: "",
    grants: rows.results.map((z) => ({ zoneId: z.id, permission: "manage" })),
  };
}
