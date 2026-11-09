import { outboxBeforeDelete } from "./retention-outbox";
import {
  atomicGuardSql,
  expiryTables,
  inventoryParams,
  inventorySql,
  remainingSql,
  retentionCron,
  retentionLimit,
  retentionSimulationDatabase,
  retentionStages,
  scopeGuardSql,
  sizeGuardSql,
  workbenchAuditLimit,
} from "./retention-plan";

interface RetentionEnv {
  APP_ENV: string;
  DATA_ENVIRONMENT: string;
  RETENTION_PROFILE: string;
  RETENTION_MODE?: string;
  RETENTION_DATABASE_ID?: string;
  RETENTION_ACCOUNT_ID?: string;
  SIMULATION_DB: D1Database;
}
function runtime(env: RetentionEnv) {
  const local =
    env.APP_ENV === "local" &&
    env.DATA_ENVIRONMENT === "simulation" &&
    ["local-retention-outbox-v1", "local-retention-workbench-v1"].includes(env.RETENTION_PROFILE);
  const cloud =
    env.APP_ENV === "cloud-simulation" &&
    env.DATA_ENVIRONMENT === "simulation" &&
    ["simulation-retention-outbox-v1", "simulation-retention-workbench-v1"].includes(
      env.RETENTION_PROFILE,
    ) &&
    env.RETENTION_DATABASE_ID === retentionSimulationDatabase &&
    env.RETENTION_ACCOUNT_ID === "00000000000000000000000000000001";
  if (!local && !cloud) throw Error("retention_runtime_rejected");
  const mode = env.RETENTION_MODE || (local ? "apply" : "");
  if (!["apply", "preview", "paused"].includes(mode)) throw Error("retention_mode_rejected");
  return { local, mode };
}
export default {
  fetch() {
    return new Response("No HTTP retention interface", {
      status: 403,
      headers: { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" },
    });
  },
  async scheduled(controller: ScheduledController, env: RetentionEnv) {
    const active = runtime(env);
    const workbench = env.RETENTION_PROFILE.endsWith("retention-workbench-v1");
    const boundedSize = workbench ? workbenchAuditLimit(sizeGuardSql) : sizeGuardSql;
    if (controller.cron !== retentionCron) throw Error("retention_cron_rejected");
    if (active.mode === "paused") {
      console.info(JSON.stringify({ operation: "retention.paused" }));
      return;
    }
    const cutoff = new Date().toISOString();
    const db = env.SIMULATION_DB;
    if (active.mode === "preview") {
      const size = await db
        .prepare(
          boundedSize.replace(
            " AS oversized",
            " OR (SELECT COUNT(*) FROM (SELECT 1 FROM r2_deletion_outbox LIMIT 4097))>4076 AS oversized",
          ),
        )
        .first<{ oversized: number }>();
      if (size?.oversized !== 0) throw Error("retention_size_rejected");
      const scope = await db.prepare(scopeGuardSql).first<Record<string, number>>();
      if (!scope || Object.values(scope).some((v) => v !== 0))
        throw Error("retention_fixture_scope_rejected");
      const result = await db
        .prepare(inventorySql)
        .bind(...inventoryParams(cutoff))
        .first<{ inventory_json: string }>();
      console.info(
        JSON.stringify({
          operation: "retention.preview",
          cutoff,
          inventory: JSON.parse(result?.inventory_json || "[]"),
          readOnly: true,
        }),
      );
      return;
    }
    if (!Number.isFinite(controller.scheduledTime)) throw Error("retention_schedule_time_rejected");
    const slot = active.local
      ? controller.scheduledTime
      : Math.floor(controller.scheduledTime / 3600000);
    const id = `retention-${env.RETENTION_PROFILE}-${slot}`;
    const guarded = (workbench ? workbenchAuditLimit(atomicGuardSql) : atomicGuardSql).replace(
      "WHEN (SELECT foreign_zones",
      "WHEN (SELECT COUNT(*) FROM (SELECT 1 FROM r2_deletion_outbox LIMIT 4097))>4076 THEN 0 WHEN (SELECT foreign_zones",
    );
    const statements = [db.prepare(guarded).bind(id, id)];
    const stages = retentionStages.map((stage) => ({
      ...stage,
      sql: !workbench
        ? stage.sql
        : stage.name === "evidence_objects"
          ? stage.sql.replace(
              "AND expires_at<=?",
              "AND object_key NOT LIKE 'cases/workbench/%' AND object_key NOT LIKE 'simulation/cases/workbench/%' AND expires_at<=?",
            )
          : stage.name === "incidents"
            ? stage.sql.replace(
                "ORDER BY i.expires_at",
                "AND NOT EXISTS(SELECT 1 FROM wb_runs w WHERE w.incident_id=i.id) AND NOT EXISTS(SELECT 1 FROM wb_proposals w WHERE w.incident_id=i.id) AND NOT EXISTS(SELECT 1 FROM wb_simulations w WHERE w.incident_id=i.id) AND NOT EXISTS(SELECT 1 FROM wb_threads w WHERE w.incident_id=i.id) ORDER BY i.expires_at",
              )
            : stage.sql,
    }));
    for (const stage of stages) {
      const outbox = outboxBeforeDelete(db, stage, cutoff, retentionLimit, id);
      if (outbox) statements.push(outbox);
      statements.push(
        db
          .prepare(`${stage.sql} AND EXISTS (SELECT 1 FROM retention_guard WHERE id=?)`)
          .bind(...Array<string>(stage.times).fill(cutoff), retentionLimit, id),
      );
      statements.push(
        db
          .prepare(
            "UPDATE retention_guard SET counts_json=json_set(counts_json,?,changes()) WHERE id=?",
          )
          .bind(`$.${stage.name}`, id),
      );
    }
    const operation = active.local
      ? "retention.outbox.local.completed"
      : "retention.outbox.simulation.completed";
    statements.push(
      db
        .prepare(`INSERT INTO audit_trail (id,actor_id,operation,target_id,details_json,created_at,expires_at)
 SELECT ?,NULL,?,'simulation-retention',json_object('profile',?,'cutoff',?,'perTableLimit',?,'deleted',json(counts_json),'expiredRowsRemain',(${remainingSql}),'r2Deletion',json('false'),'durableR2Outbox',json('true')),?,? FROM retention_guard WHERE id=?`)
        .bind(
          id,
          operation,
          env.RETENTION_PROFILE,
          cutoff,
          retentionLimit,
          ...expiryTables.map(() => cutoff),
          cutoff,
          new Date(Date.parse(cutoff) + 90 * 86400000).toISOString(),
          id,
        ),
    );
    statements.push(db.prepare("DELETE FROM retention_guard WHERE id=?").bind(id));
    await db.batch(statements);
    console.info(
      JSON.stringify({
        operation,
        cutoff,
        runId: id,
        maximumLogicalDeletions: 100,
        r2Deletion: false,
      }),
    );
  },
} satisfies ExportedHandler<RetentionEnv>;
