import {
  atomicGuardSql,
  expiryTables,
  inventoryParams,
  inventorySql,
  remainingSql,
  retentionCloudProfile,
  retentionCron,
  retentionLimit,
  retentionSimulationDatabase,
  retentionStages,
  scopeGuardSql,
  sizeGuardSql,
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
    env.RETENTION_PROFILE === "local-retention-v1";
  const cloud =
    env.APP_ENV === "cloud-simulation" &&
    env.DATA_ENVIRONMENT === "simulation" &&
    env.RETENTION_PROFILE === retentionCloudProfile &&
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
    if (controller.cron !== retentionCron) throw Error("retention_cron_rejected");
    if (active.mode === "paused") {
      console.info(JSON.stringify({ operation: "retention.paused" }));
      return;
    }
    const cutoff = new Date().toISOString();
    const db = env.SIMULATION_DB;
    if (active.mode === "preview") {
      const size = await db.prepare(sizeGuardSql).first<{ oversized: number }>();
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
    const statements = [db.prepare(atomicGuardSql).bind(id, id)];
    for (const stage of retentionStages) {
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
    const operation = active.local ? "retention.local.completed" : "retention.simulation.completed";
    statements.push(
      db
        .prepare(`INSERT INTO audit_trail (id,actor_id,operation,target_id,details_json,created_at,expires_at)
 SELECT ?,NULL,?,'simulation-retention',json_object('profile',?,'cutoff',?,'perTableLimit',?,'deleted',json(counts_json),'expiredRowsRemain',(${remainingSql}),'r2Deletion',json('false')),?,? FROM retention_guard WHERE id=?`)
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
