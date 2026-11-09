import { liveProfile, liveZone } from "../../../../packages/shared/src/live";
import { collectFacts, digest, findings, windowAt } from "./analytics";

export interface CollectorBindings {
  LIVE_DB: D1Database;
  LIVE_PROFILE: string;
  GRAPHQL_READ_TOKEN?: string;
}
async function removeExpired(db: D1Database, at: string) {
  const auditBefore = new Date(Date.parse(at) - 90 * 86400000).toISOString();
  let result: D1Result[];
  try {
    result = await db.batch([
      db
        .prepare(
          "DELETE FROM ld_snapshots WHERE id IN (SELECT id FROM ld_snapshots WHERE expires_at<=? LIMIT 500)",
        )
        .bind(at),
      db
        .prepare(
          "DELETE FROM ld_ai_runs WHERE id IN (SELECT id FROM ld_ai_runs WHERE expires_at<=? LIMIT 500)",
        )
        .bind(at),
      db
        .prepare(
          "UPDATE ld_ai_runs SET report_json=NULL WHERE id IN (SELECT id FROM ld_ai_runs WHERE report_expires_at<=? AND report_json IS NOT NULL LIMIT 500)",
        )
        .bind(at),
      db
        .prepare(
          "DELETE FROM ld_findings WHERE id IN (SELECT id FROM ld_findings WHERE expires_at<=? LIMIT 500)",
        )
        .bind(at),
      db
        .prepare(
          "DELETE FROM ld_log_events WHERE id IN (SELECT id FROM ld_log_events WHERE expires_at<=? LIMIT 5000)",
        )
        .bind(at),
      db
        .prepare(
          "DELETE FROM ld_log_objects WHERE id IN (SELECT id FROM ld_log_objects WHERE expires_at<=? LIMIT 500)",
        )
        .bind(at),
      db
        .prepare(
          "DELETE FROM ld_repair_audit WHERE id IN (SELECT id FROM ld_repair_audit WHERE at<=? LIMIT 500)",
        )
        .bind(auditBefore),
      db
        .prepare(`DELETE FROM ld_repairs WHERE id IN (SELECT id FROM ld_repairs WHERE retain_until<=?
        AND status IN ('pending','approved','rejected','rolled_back') LIMIT 500)`)
        .bind(at),
    ]);
  } catch (error) {
    await db
      .prepare(`INSERT INTO ld_ops_state(task,last_attempt,error) VALUES ('retention',?,'cleanup_failed')
      ON CONFLICT(task) DO UPDATE SET last_attempt=excluded.last_attempt,error=excluded.error`)
      .bind(at)
      .run();
    throw error;
  }
  await db
    .prepare(`INSERT INTO ld_ops_state(task,last_attempt,last_success,removed) VALUES ('retention',?,?,?)
    ON CONFLICT(task) DO UPDATE SET last_attempt=excluded.last_attempt,last_success=excluded.last_success,error=NULL,removed=excluded.removed`)
    .bind(
      at,
      at,
      result.reduce((total, item) => total + item.meta.changes, 0),
    )
    .run();
}

export async function collect(
  env: CollectorBindings,
  now = Date.now(),
  cleanupWhenPaused = false,
): Promise<string> {
  if (env.LIVE_PROFILE !== liveProfile) return "disabled";
  const db = env.LIVE_DB,
    at = new Date(now).toISOString(),
    lease = crypto.randomUUID();
  const state = await db
    .prepare("SELECT collection_paused_at FROM ld_state WHERE id=1")
    .first<{ collection_paused_at: string | null }>();
  if (!state) return "disabled";
  if (state.collection_paused_at !== null) {
    if (cleanupWhenPaused) await removeExpired(db, at);
    return "paused";
  }
  const lock = await db
    .prepare(
      "UPDATE ld_state SET lease_token=?,lease_until=?,last_attempt=? WHERE id=1 AND collection_paused_at IS NULL AND (lease_until IS NULL OR lease_until<?)",
    )
    .bind(lease, new Date(now + 90000).toISOString(), at, at)
    .run();
  if (lock.meta.changes !== 1) return "busy";
  try {
    await removeExpired(db, at);
    if (!env.GRAPHQL_READ_TOKEN?.trim()) throw new Error("credential_missing");
    const { end } = windowAt(now);
    const window = await db
      .prepare(
        "SELECT EXISTS(SELECT 1 FROM ld_snapshots WHERE window_end=? AND zone_id=?) AS stored FROM ld_state WHERE id=1 AND lease_token=?",
      )
      .bind(end, liveZone, lease)
      .first<{ stored: number }>();
    if (!window) return "superseded";
    if (window.stored) return "already_collected";
    const facts = await collectFacts(env.GRAPHQL_READ_TOKEN, now);
    if (facts.security.state === "unavailable" && facts.http.state === "unavailable")
      throw new Error(facts.security.error || "datasets_unavailable");
    const body = JSON.stringify(facts),
      sha = await digest(body),
      found = findings(facts, sha);
    const prior = await db
      .prepare("SELECT last_end FROM ld_state WHERE id=1")
      .first<{ last_end: string | null }>();
    const gap = prior?.last_end
      ? Math.max(0, (Date.parse(facts.start) - Date.parse(prior.last_end)) / 1000)
      : 0;
    const fenced = "EXISTS (SELECT 1 FROM ld_state WHERE id=1 AND lease_token=?)";
    const [snapshot] = await db.batch([
      db
        .prepare(
          `INSERT OR IGNORE INTO ld_snapshots(id,zone_id,window_start,window_end,collected_at,facts_json,sha256,expires_at) SELECT ?,?,?,?,?,?,?,? WHERE ${fenced}`,
        )
        .bind(
          `analytics-${Date.parse(end)}`,
          liveZone,
          facts.start,
          end,
          at,
          body,
          sha,
          new Date(Date.parse(end) + 30 * 86400000).toISOString(),
          lease,
        ),
      ...found.map((f) =>
        db
          .prepare(
            `INSERT OR IGNORE INTO ld_findings(id,zone_id,window_end,rule,title,severity,summary,evidence_json,sha256,expires_at) SELECT ?,?,?,?,?,?,?,?,?,? WHERE ${fenced}`,
          )
          .bind(
            f.id,
            liveZone,
            end,
            f.rule,
            f.title,
            f.severity,
            f.summary,
            body,
            sha,
            f.expiresAt,
            lease,
          ),
      ),
      db
        .prepare(
          "UPDATE ld_state SET last_success=?,last_end=?,last_gap_seconds=?,last_error=? WHERE id=1 AND lease_token=?",
        )
        .bind(
          at,
          end,
          gap,
          facts.security.state === "unavailable"
            ? `security:${facts.security.error}`
            : facts.http.state === "unavailable"
              ? `http:${facts.http.error}`
              : null,
          lease,
        ),
    ]);
    return snapshot?.meta.changes ? "collected" : "superseded";
  } catch (error) {
    const allowed = new Set([
      "credential_missing",
      "credential_rejected",
      "rate_limited",
      "provider_unavailable",
      "graphql_rejected",
      "zone_unavailable",
      "invalid_schema",
      "invalid_count",
      "invalid_dimension",
      "duplicate_dimension",
      "response_too_large",
      "invalid_json",
      "empty_response",
      "source_unreachable",
    ]);
    const code =
      error instanceof Error && allowed.has(error.message) ? error.message : "collection_failed";
    await db
      .prepare("UPDATE ld_state SET last_error=? WHERE id=1 AND lease_token=?")
      .bind(code, lease)
      .run();
    return code;
  } finally {
    await db
      .prepare("UPDATE ld_state SET lease_token=NULL,lease_until=NULL WHERE id=1 AND lease_token=?")
      .bind(lease)
      .run();
  }
}
export default {
  fetch() {
    return new Response("Not found", { status: 404 });
  },
  async scheduled(event: ScheduledController, env: CollectorBindings) {
    await collect(env, Date.now(), new Date(event.scheduledTime).getUTCMinutes() === 0);
  },
} satisfies ExportedHandler<CollectorBindings>;
