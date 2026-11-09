import fixedPolicy from "./r2-retention-policy.json";
import { scopeGuardSql, sizeGuardSql, workbenchAuditLimit } from "./retention-plan";

interface Policy {
  source_id: string;
  source_kind: string;
  object_key: string;
  sha256: string;
  expires_at: string;
  anchor: string;
}
interface Env {
  APP_ENV: string;
  DATA_ENVIRONMENT: string;
  RETENTION_PROFILE: string;
  RETENTION_MODE: string;
  RETENTION_DATABASE_ID?: string;
  RETENTION_ACCOUNT_ID?: string;
  RETENTION_BUCKET?: string;
  LOCAL_R2_POLICY?: string;
  SIMULATION_DB: D1Database;
  SIMULATION_STORE: R2Bucket;
}
interface Task {
  id: string;
  source_kind: string;
  source_id: string;
  object_key: string;
  expected_sha256: string | null;
  expires_at: string;
  attempts: number;
}
const cron = "37 * * * *";
const limit = 10;
const hour = 3600000;
const iso = (time: number) => new Date(time).toISOString();
const digest = async (value: ArrayBuffer) =>
  Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", value)), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
function runtime(env: Env) {
  const local = env.APP_ENV === "local" && env.RETENTION_PROFILE === "local-r2-retention-v1";
  const cloud =
    env.APP_ENV === "cloud-simulation" &&
    ["simulation-r2-retention-v1", "simulation-r2-retention-workbench-v1"].includes(
      env.RETENTION_PROFILE,
    ) &&
    env.RETENTION_DATABASE_ID === "00000000-0000-4000-8000-000000000012" &&
    env.RETENTION_ACCOUNT_ID === "00000000000000000000000000000001" &&
    env.RETENTION_BUCKET === "example-cloudflare-ai-soc-simulation" &&
    !env.LOCAL_R2_POLICY;
  if (
    (!local && !cloud) ||
    env.DATA_ENVIRONMENT !== "simulation" ||
    !["apply", "preview", "paused"].includes(env.RETENTION_MODE)
  ) {
    throw Error("r2_retention_runtime_rejected");
  }
  const policy: Policy[] =
    local && env.LOCAL_R2_POLICY ? JSON.parse(env.LOCAL_R2_POLICY) : fixedPolicy;
  if (
    !Array.isArray(policy) ||
    policy.length > 5 ||
    new Set(policy.map((p) => p.object_key)).size !== policy.length ||
    policy.some(
      (p) =>
        !["case", "archive"].includes(p.source_kind) ||
        !/^(cases\/(ingested\/[a-f0-9]{64}|fixture\/evidence-001)|tool-snapshots\/ingest-failures\/[a-f0-9]{64})\.json$/.test(
          p.object_key,
        ) ||
        !/^[a-f0-9]{64}$/.test(p.sha256) ||
        new Date(p.anchor).toISOString() !== p.anchor ||
        new Date(p.expires_at).toISOString() !== p.expires_at ||
        Date.parse(p.expires_at) - Date.parse(p.anchor) !== 90 * 86400000,
    )
  ) {
    throw Error("r2_retention_policy_rejected");
  }
  return policy;
}
async function boundedBody(object: R2ObjectBody) {
  if (object.size > 65536) {
    await object.body.cancel();
    throw Error("content_limit");
  }
  const reader = object.body.getReader();
  const parts: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const part = await reader.read();
      if (part.done) break;
      size += part.value.byteLength;
      if (size > 65536) throw Error("content_limit");
      parts.push(part.value);
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
  const result = new Uint8Array(size);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.byteLength;
  }
  return result.buffer;
}
async function auditStatement(
  db: D1Database,
  task: Task,
  token: string,
  operation: string,
  cutoff: string,
  details: Record<string, unknown>,
) {
  return db
    .prepare(`INSERT INTO audit_trail
    (id,actor_id,operation,target_id,details_json,created_at,expires_at)
    SELECT ?,NULL,?,?,?, ?,? FROM r2_deletion_outbox WHERE id=? AND lease_token=?`)
    .bind(
      `${token}:${operation}`,
      operation,
      task.id,
      JSON.stringify(details),
      cutoff,
      iso(Date.parse(cutoff) + 90 * 86400000),
      task.id,
      token,
    );
}
async function processTask(env: Env, task: Task, policy: Policy[], cutoff: string) {
  const db = env.SIMULATION_DB;
  const approved = policy.find(
    (p) =>
      p.object_key === task.object_key &&
      p.source_id === task.source_id &&
      p.source_kind === task.source_kind &&
      p.expires_at === task.expires_at &&
      (task.expected_sha256 === null || task.expected_sha256 === p.sha256),
  );
  const token = crypto.randomUUID();
  // Intent and claim commit together, before any destructive storage request.
  const claim = await db.batch([
    db
      .prepare(`UPDATE r2_deletion_outbox SET state='deleting',attempts=attempts+1,
      lease_token=?,lease_until=?,next_attempt_at=? WHERE id=? AND attempts<3
      AND state IN ('pending','deleting') AND expires_at<=? AND next_attempt_at<=?
      AND (lease_until IS NULL OR lease_until<=?) AND object_key=? AND expires_at=?
      AND expected_sha256 IS ?`)
      .bind(
        token,
        iso(Date.parse(cutoff) + 20 * 60000),
        iso(Date.parse(cutoff) + hour),
        task.id,
        cutoff,
        cutoff,
        cutoff,
        task.object_key,
        task.expires_at,
        task.expected_sha256,
      ),
    await auditStatement(db, task, token, "r2.retention.intent", cutoff, {
      profile: env.RETENTION_PROFILE,
    }),
  ]);
  if (claim[0]?.meta.changes !== 1) return "skipped";
  let outcome = "deleted";
  let failure: string | null = null;
  let blocked = false;
  try {
    if (!approved) {
      blocked = true;
      throw Error("policy_mismatch");
    }
    const object = await env.SIMULATION_STORE.get(task.object_key);
    if (!object) outcome = "already_absent";
    else {
      if ((await digest(await boundedBody(object))) !== approved.sha256) {
        blocked = true;
        throw Error("digest_mismatch");
      }
      // No conditional R2 delete exists. Closed, immutable keys and the writer's
      // 30-day source window precede this 90-day deadline; manual rewrites are excluded.
      await env.SIMULATION_STORE.delete(task.object_key);
      if (await env.SIMULATION_STORE.head(task.object_key)) throw Error("delete_not_confirmed");
    }
  } catch (error) {
    failure =
      error instanceof Error &&
      ["policy_mismatch", "digest_mismatch", "content_limit", "delete_not_confirmed"].includes(
        error.message,
      )
        ? error.message
        : "storage_unavailable";
    if (failure === "content_limit") blocked = true;
  }
  const nextState = failure
    ? blocked || task.attempts + 1 >= 3
      ? "blocked"
      : "pending"
    : "deleted";
  // If this transaction fails after R2 deletion, the lease expires and a later
  // attempt observes the missing object. Do not repeat the DELETE in this invocation.
  await db.batch([
    await auditStatement(
      db,
      task,
      token,
      failure ? "r2.retention.failed" : "r2.retention.deleted",
      cutoff,
      { outcome: failure || outcome, attempt: task.attempts + 1, state: nextState },
    ),
    db
      .prepare(`UPDATE r2_deletion_outbox SET state=?,last_error=?,completed_at=?,lease_until=NULL
      WHERE id=? AND lease_token=?`)
      .bind(nextState, failure, failure ? null : cutoff, task.id, token),
  ]);
  return failure ? nextState : outcome;
}
export default {
  fetch() {
    return new Response("No HTTP retention interface", {
      status: 403,
      headers: { "Cache-Control": "no-store" },
    });
  },
  async scheduled(controller: ScheduledController, env: Env) {
    const policy = runtime(env);
    if (controller.cron !== cron || !Number.isFinite(controller.scheduledTime))
      throw Error("r2_retention_schedule_rejected");
    if (env.RETENTION_MODE === "paused") return;
    const db = env.SIMULATION_DB;
    const size = await db
      .prepare(
        env.RETENTION_PROFILE === "simulation-r2-retention-workbench-v1"
          ? workbenchAuditLimit(sizeGuardSql)
          : sizeGuardSql,
      )
      .first<{ oversized: number }>();
    const count = await db
      .prepare("SELECT COUNT(*) AS n FROM (SELECT 1 FROM r2_deletion_outbox LIMIT 4097)")
      .first<{ n: number }>();
    if (size?.oversized !== 0 || !count || count.n > 4096)
      throw Error("r2_retention_size_rejected");
    const scope = await db.prepare(scopeGuardSql).first<Record<string, number>>();
    if (!scope || Object.values(scope).some((v) => v !== 0))
      throw Error("r2_retention_scope_rejected");
    const cutoff = new Date().toISOString();
    const tasks = await db
      .prepare(`SELECT id,source_kind,source_id,object_key,expected_sha256,expires_at,attempts
      FROM r2_deletion_outbox WHERE state IN ('pending','deleting') AND attempts<3
      AND expires_at<=? AND next_attempt_at<=? AND (lease_until IS NULL OR lease_until<=?)
      ORDER BY next_attempt_at,id LIMIT ?`)
      .bind(cutoff, cutoff, cutoff, limit)
      .all<Task>();
    if (env.RETENTION_MODE === "preview") {
      console.info(
        JSON.stringify({
          operation: "r2.retention.preview",
          dueInBatch: tasks.results.length,
          readOnly: true,
        }),
      );
      return;
    }
    const outcomes: Record<string, number> = {};
    for (const task of tasks.results) {
      const outcome = await processTask(env, task, policy, cutoff);
      outcomes[outcome] = (outcomes[outcome] || 0) + 1;
    }
    const runId = `r2-retention-${env.RETENTION_PROFILE}-${Math.floor(controller.scheduledTime / hour)}`;
    await db.batch([
      db
        .prepare(`DELETE FROM r2_deletion_outbox WHERE id IN
        (SELECT id FROM r2_deletion_outbox WHERE state='deleted' AND completed_at<=?
          ORDER BY completed_at,id LIMIT ?)
        AND NOT EXISTS (SELECT 1 FROM audit_trail WHERE id=?)`)
        .bind(iso(Date.parse(cutoff) - 90 * 86400000), limit, runId),
      db
        .prepare(`INSERT OR IGNORE INTO audit_trail VALUES (?,NULL,'r2.retention.completed',
      'simulation-r2-retention',json_set(?,'$.prunedCompletedTasks',changes()),?,?)`)
        .bind(
          runId,
          JSON.stringify({
            profile: env.RETENTION_PROFILE,
            cutoff,
            perRunLimit: limit,
            outcomes,
            rawDeletion: false,
          }),
          cutoff,
          iso(Date.parse(cutoff) + 90 * 86400000),
        ),
    ]);
  },
} satisfies ExportedHandler<Env>;
