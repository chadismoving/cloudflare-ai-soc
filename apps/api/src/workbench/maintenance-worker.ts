import { maintenancePrincipal, retainEvidence } from "./evidence-retention";
import { reconcile } from "./reconcile";
import { expiry, now } from "./store";

interface Env {
  APP_ENV: string;
  MAINTENANCE_PROFILE: string;
  MAINTENANCE_MODE: string;
  MAINTENANCE_ACCOUNT_ID: string;
  MAINTENANCE_DATABASE_ID: string;
  MAINTENANCE_BUCKET: string;
  SIMULATION_DB: D1Database;
  SIMULATION_EVIDENCE: R2Bucket;
}
export default {
  fetch() {
    return new Response("No HTTP maintenance interface", { status: 403 });
  },
  async scheduled(controller: ScheduledController, env: Env) {
    const local =
      env.APP_ENV === "local" && env.MAINTENANCE_PROFILE === "local-workbench-maintenance-v1";
    const cloud =
      env.APP_ENV === "cloud-simulation" &&
      env.MAINTENANCE_PROFILE === "simulation-workbench-maintenance-v1" &&
      env.MAINTENANCE_ACCOUNT_ID === "00000000000000000000000000000001" &&
      env.MAINTENANCE_DATABASE_ID === "00000000-0000-4000-8000-000000000012" &&
      env.MAINTENANCE_BUCKET === "example-cloudflare-ai-soc-simulation";
    if (
      (!local && !cloud) ||
      !["preview", "apply", "paused"].includes(env.MAINTENANCE_MODE) ||
      controller.cron !== "*/5 * * * *" ||
      !Number.isFinite(controller.scheduledTime)
    )
      throw Error("workbench_maintenance_runtime_rejected");
    if (env.MAINTENANCE_MODE === "paused") return;
    const db = env.SIMULATION_DB,
      at = now();
    if (env.MAINTENANCE_MODE === "preview") {
      const due = await db
        .prepare(
          "SELECT COUNT(*) AS n FROM (SELECT 1 FROM wb_evidence_registry WHERE expires_at<=? AND state IN ('staging','registered','deleting') LIMIT 6)",
        )
        .bind(at)
        .first();
      console.info(
        JSON.stringify({ operation: "workbench.maintenance.preview", due, readOnly: true }),
      );
      return;
    }
    const principal = await maintenancePrincipal(db);
    if (!principal.grants.length) throw Error("workbench_maintenance_zone_rejected");
    const rules = await reconcile({ db, principal });
    const evidence = await retainEvidence(db, env.SIMULATION_EVIDENCE);
    await db
      .prepare(
        "INSERT INTO audit_trail VALUES (?,NULL,'workbench.maintenance.completed','simulation-workbench',?,?,?) ON CONFLICT(id) DO UPDATE SET details_json=json_object('lastRunAt',?,'runs',COALESCE(json_extract(audit_trail.details_json,'$.runs'),0)+1,'latest',json(?))",
      )
      .bind(
        `workbench-maintenance-${at.slice(0, 10)}`,
        JSON.stringify({ lastRunAt: at, runs: 1, latest: { rules, evidence } }),
        at,
        expiry(at),
        at,
        JSON.stringify({ rules, evidence }),
      )
      .run();
  },
} satisfies ExportedHandler<Env>;
