import { rollback } from "./actions";
import { audit, expiry, now, uid, type WorkContext, zones } from "./store";

export async function reconcile(ctx: Pick<WorkContext, "db" | "principal">) {
  const allowed = zones(ctx);
  if (!allowed.length) return { expiredRules: 0, recoveredRuns: 0 };
  const marks = allowed.map(() => "?").join(","),
    at = now();
  let expiredRules = 0,
    recoveredRuns = 0;
  const rules = await ctx.db
    .prepare(
      `SELECT e.proposal_id FROM wb_rules r JOIN wb_executions e ON e.id=r.execution_id WHERE r.active=1 AND r.owner='example-soc-simulation' AND r.expires_at<=? AND r.zone_id IN (${marks}) LIMIT 50`,
    )
    .bind(at, ...allowed)
    .all<{ proposal_id: string }>();
  for (const row of rules.results) {
    try {
      await rollback(ctx, row.proposal_id, true);
      expiredRules++;
    } catch {
      /* conflict is persisted by rollback; never remove an unverified resource */
    }
  }
  const abandoned = await ctx.db
    .prepare(
      `SELECT r.id,r.zone_id,s.month,s.provider,s.reserved_micro FROM wb_runs r JOIN wb_reservations s ON s.id=r.id WHERE r.status='running' AND s.settled=0 AND r.started_at<? AND r.zone_id IN (${marks}) LIMIT 20`,
    )
    .bind(new Date(Date.now() - 120000).toISOString(), ...allowed)
    .all<{
      id: string;
      zone_id: string;
      month: string;
      provider: string;
      reserved_micro: number;
    }>();
  for (const r of abandoned.results) {
    const guard = uid("recovery");
    try {
      await ctx.db.batch([
        ctx.db
          .prepare(
            "INSERT INTO wb_guards SELECT ?,CASE WHEN EXISTS(SELECT 1 FROM wb_runs r JOIN wb_reservations s ON r.id=s.id WHERE r.id=? AND r.status='running' AND s.settled=0) THEN 1 ELSE 0 END",
          )
          .bind(guard, r.id),
        ctx.db
          .prepare(
            "UPDATE wb_budget SET reserved_micro=reserved_micro-?,spent_micro=spent_micro+? WHERE month=? AND provider=? AND EXISTS(SELECT 1 FROM wb_reservations WHERE id=? AND settled=0)",
          )
          .bind(r.reserved_micro, r.reserved_micro, r.month, r.provider, r.id),
        ctx.db.prepare("UPDATE wb_reservations SET settled=1 WHERE id=? AND settled=0").bind(r.id),
        ctx.db
          .prepare(
            "UPDATE wb_runs SET status='timed_out',stop_reason='interrupted_recovered',ended_at=?,usage_json=?,result_json=? WHERE id=? AND status='running'",
          )
          .bind(
            at,
            JSON.stringify({ costMicro: r.reserved_micro, uncertain: true }),
            JSON.stringify({
              verdict: "insufficient_data",
              severity: "info",
              confidence: 0,
              summary: "Interrupted run recovered. Reserved cost retained conservatively.",
              findings: [],
              limitations: ["interrupted_recovered"],
              falsePositives: [],
              recommendedAction: "none",
            }),
            r.id,
          ),
        audit(ctx.db, null, "agent.interrupted_recovered", r.id, {
          reservationCharged: r.reserved_micro,
        }),
        ctx.db.prepare("DELETE FROM wb_guards WHERE id=?").bind(guard),
      ]);
      recoveredRuns++;
    } catch (error) {
      const current = await ctx.db
        .prepare("SELECT status FROM wb_runs WHERE id=?")
        .bind(r.id)
        .first<{ status: string }>();
      if (current?.status === "running") throw error;
      // Another finalizer won the transaction; do not charge or audit it twice.
    }
  }
  await ctx.db
    .prepare(
      `UPDATE wb_proposals SET status='expired',decision_reason='approval_expired' WHERE status IN ('awaiting_approval','authorized') AND approval_deadline<=? AND zone_id IN (${marks})`,
    )
    .bind(at, ...allowed)
    .run();
  // Only feature-owned minimal rows. Preserve parents until every child is removed.
  const purges = [
    `DELETE FROM wb_messages WHERE id IN (SELECT m.id FROM wb_messages m JOIN wb_threads t ON t.id=m.thread_id WHERE m.expires_at<=? AND t.zone_id IN (${marks}) LIMIT 50)`,
    `DELETE FROM wb_threads WHERE id IN (SELECT id FROM wb_threads WHERE expires_at<=? AND zone_id IN (${marks}) AND NOT EXISTS(SELECT 1 FROM wb_messages WHERE thread_id=wb_threads.id) LIMIT 50)`,
    `DELETE FROM wb_simulations WHERE id IN (SELECT id FROM wb_simulations WHERE expires_at<=? AND zone_id IN (${marks}) LIMIT 50)`,
    `DELETE FROM wb_approvals WHERE id IN (SELECT a.id FROM wb_approvals a JOIN wb_proposals p ON p.id=a.proposal_id WHERE a.expires_at<=? AND p.zone_id IN (${marks}) LIMIT 50)`,
    `DELETE FROM wb_verifications WHERE id IN (SELECT v.id FROM wb_verifications v JOIN wb_executions e ON e.id=v.execution_id WHERE v.expires_at<=? AND e.zone_id IN (${marks}) LIMIT 50)`,
    `DELETE FROM wb_rules WHERE id IN (SELECT r.id FROM wb_rules r JOIN wb_executions e ON r.execution_id=e.id WHERE e.expires_at<=? AND r.zone_id IN (${marks}) AND r.active=0 LIMIT 50)`,
    `DELETE FROM wb_executions WHERE id IN (SELECT id FROM wb_executions WHERE expires_at<=? AND zone_id IN (${marks}) AND NOT EXISTS(SELECT 1 FROM wb_rules WHERE execution_id=wb_executions.id) AND NOT EXISTS(SELECT 1 FROM wb_verifications WHERE execution_id=wb_executions.id) LIMIT 50)`,
    `DELETE FROM wb_proposals WHERE id IN (SELECT id FROM wb_proposals WHERE expires_at<=? AND zone_id IN (${marks}) AND NOT EXISTS(SELECT 1 FROM wb_executions WHERE proposal_id=wb_proposals.id) AND NOT EXISTS(SELECT 1 FROM wb_approvals WHERE proposal_id=wb_proposals.id) LIMIT 50)`,
    `DELETE FROM wb_history WHERE id IN (SELECT id FROM wb_history WHERE expires_at<=? AND zone_id IN (${marks}) LIMIT 50)`,
    `DELETE FROM wb_tools WHERE id IN (SELECT id FROM wb_tools WHERE expires_at<=? AND zone_id IN (${marks}) LIMIT 50)`,
    `DELETE FROM wb_runs WHERE id IN (SELECT id FROM wb_runs WHERE expires_at<=? AND zone_id IN (${marks}) AND status<>'running' AND NOT EXISTS(SELECT 1 FROM wb_proposals WHERE run_id=wb_runs.id) AND NOT EXISTS(SELECT 1 FROM wb_simulations WHERE run_id=wb_runs.id) AND NOT EXISTS(SELECT 1 FROM wb_messages WHERE run_id=wb_runs.id) AND NOT EXISTS(SELECT 1 FROM wb_tools WHERE run_id=wb_runs.id) LIMIT 50)`,
  ];
  await ctx.db.batch([
    ctx.db
      .prepare(
        "DELETE FROM wb_limits WHERE id IN (SELECT id FROM wb_limits WHERE expires_at<=? AND (id LIKE ? OR ?=1) LIMIT 50)",
      )
      .bind(at, `${ctx.principal.id}:%`, ctx.principal.id === "system-simulation" ? 1 : 0),
    ...purges.map((sql) => ctx.db.prepare(sql).bind(at, ...allowed)),
    ctx.db
      .prepare("INSERT OR REPLACE INTO wb_maintenance VALUES ('last_reconcile',?,?)")
      .bind(at, JSON.stringify({ expiredRules, recoveredRuns, expiresAt: expiry(at) })),
  ]);
  return { expiredRules, recoveredRuns, at };
}
