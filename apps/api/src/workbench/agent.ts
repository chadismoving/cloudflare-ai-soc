import { type Finding, findingSchema } from "@soc/shared";
import { assertZone } from "../data";
import { HttpError } from "../http";
import { fixtureFinding, modelStep, type Usage } from "./model";
import { audit, expiry, history, incident, now, settings, uid, type WorkContext } from "./store";
import { callTool, type ToolResult } from "./tools";

const reserveMicro = 1000000;
export async function analyze(
  ctx: WorkContext,
  incidentId: string,
  kind: "triage" | "investigation" = "investigation",
  question = "",
  privateRun = false,
) {
  const item = await incident(ctx, incidentId);
  assertZone(ctx.principal, item.zone_id, "investigate");
  const { policy: p, version } = await settings(ctx.db),
    id = uid("run"),
    start = now(),
    month = start.slice(0, 7),
    guard = uid("guard"),
    model = kind === "triage" ? p.triageModel : p.investigationModel;
  if (
    p.provider === "workers_ai" &&
    (ctx.env.SOC_AI_APPROVED !== "workers-ai-metadata-only-v1" || !ctx.env.AI)
  )
    throw new HttpError(
      503,
      "ai_not_provisioned",
      "The Workers AI adapter is implemented but not activated.",
    );
  await ctx.db
    .prepare("INSERT OR IGNORE INTO wb_budget VALUES (?,?,0,0)")
    .bind(month, p.provider)
    .run();
  try {
    await ctx.db.batch([
      ctx.db
        .prepare(
          "INSERT INTO wb_guards SELECT ?,CASE WHEN (SELECT version FROM wb_settings WHERE id='simulation')=? AND (SELECT spent_micro+reserved_micro+? FROM wb_budget WHERE month=? AND provider=?)<=CAST((SELECT json_extract(policy_json,'$.monthlyBudgetUsd') FROM wb_settings WHERE id='simulation')*1000000 AS INTEGER) THEN 1 ELSE 0 END",
        )
        .bind(guard, version, reserveMicro, month, p.provider),
      ctx.db
        .prepare(
          "UPDATE wb_budget SET reserved_micro=reserved_micro+? WHERE month=? AND provider=?",
        )
        .bind(reserveMicro, month, p.provider),
      ctx.db
        .prepare(
          "INSERT INTO wb_runs(id,incident_id,zone_id,user_id,private_user_id,kind,provider,model_id,status,started_at,expires_at) VALUES (?,?,?,?,?,?,?,?,'running',?,?)",
        )
        .bind(
          id,
          item.id,
          item.zone_id,
          ctx.principal.id,
          privateRun ? ctx.principal.id : null,
          kind,
          p.provider,
          model,
          start,
          expiry(start),
        ),
      ctx.db
        .prepare("INSERT INTO wb_reservations VALUES (?,?,?,?,0)")
        .bind(id, month, p.provider, reserveMicro),
      history(ctx.db, id, item.zone_id, "running", { kind, provider: p.provider }),
      ctx.db.prepare("DELETE FROM wb_guards WHERE id=?").bind(guard),
    ]);
  } catch (error) {
    const b = await ctx.db
      .prepare("SELECT spent_micro,reserved_micro FROM wb_budget WHERE month=? AND provider=?")
      .bind(month, p.provider)
      .first<{ spent_micro: number; reserved_micro: number }>();
    if (b && b.spent_micro + b.reserved_micro + reserveMicro > p.monthlyBudgetUsd * 1000000)
      throw new HttpError(
        402,
        "budget_exhausted",
        "New analyses are unavailable. Check AI usage in Settings.",
      );
    throw error;
  }
  const usage: Usage = {
    calls: 0,
    inputTokens: 0,
    outputTokens: 0,
    costMicro: 0,
    estimated: p.provider === "fixture",
    uncertain: false,
  };
  const controller = new AbortController(),
    deadlineMs =
      (kind === "triage" ? p.triageDeadlineSeconds : p.investigationDeadlineSeconds) * 1000;
  const timer = setTimeout(() => controller.abort(), deadlineMs);
  const results: ToolResult[] = [];
  let result: Finding | null = null,
    reason = "completed",
    status = "completed";
  const bounded = async <T>(work: Promise<T>, ms: number) => {
    let t: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        work,
        new Promise<never>((_, reject) => {
          t = setTimeout(() => reject(Error("deadline_exceeded")), ms);
        }),
      ]);
    } finally {
      if (t) clearTimeout(t);
    }
  };
  try {
    results.push(
      await bounded(callTool(ctx, id, item.id, "traffic_trend"), Math.min(3000, deadlineMs)),
    );
    for (let i = 0; i < 4; i++) {
      const remaining = deadlineMs - (Date.now() - Date.parse(start));
      if (remaining <= 0 || controller.signal.aborted) throw Error("deadline_exceeded");
      const step = await bounded(
        modelStep(
          ctx.env,
          p,
          item.category,
          results,
          question,
          kind === "triage",
          usage,
          controller.signal,
        ),
        Math.min(15000, remaining),
      );
      if (step.kind === "final") {
        result = step.finding;
        break;
      }
      if (results.length >= p.maxToolCalls) {
        reason = "tool_budget";
        break;
      }
      if (results.some((r) => r.name === step.tool)) {
        reason = "repeated_tool";
        break;
      }
      results.push(await bounded(callTool(ctx, id, item.id, step.tool), Math.min(3000, remaining)));
    }
    if (!result) {
      reason = reason === "completed" ? "iteration_budget" : reason;
      result = fixtureFinding(item.category, results, p.maxEvidenceAgeSeconds);
      result.verdict = "insufficient_data";
      result.recommendedAction = "none";
      result.limitations.push(`Stopped: ${reason}.`);
      status = "incomplete";
    }
  } catch (error) {
    controller.abort();
    reason =
      error instanceof Error &&
      ["deadline_exceeded", "fabricated_evidence_reference", "model_usage_missing"].includes(
        error.message,
      )
        ? error.message
        : "model_or_tool_failure";
    status = reason === "deadline_exceeded" ? "timed_out" : "failed";
    if (p.provider === "workers_ai") usage.uncertain = true;
    result = {
      verdict: "insufficient_data",
      severity: "info",
      confidence: 0,
      summary: "Analysis did not complete. No action is authorized.",
      findings: [],
      limitations: [reason],
      falsePositives: [],
      recommendedAction: "none",
    };
  } finally {
    clearTimeout(timer);
  }
  result = findingSchema.parse(result);
  const cost = usage.uncertain ? reserveMicro : usage.costMicro,
    end = now();
  const finalizeGuard = uid("guard");
  const finalized = await ctx.db.batch([
    ctx.db
      .prepare(
        "INSERT INTO wb_guards SELECT ?,CASE WHEN EXISTS(SELECT 1 FROM wb_runs r JOIN wb_reservations s ON r.id=s.id WHERE r.id=? AND r.status='running' AND s.settled=0) THEN 1 ELSE 0 END",
      )
      .bind(finalizeGuard, id),
    ctx.db
      .prepare(
        "UPDATE wb_budget SET reserved_micro=reserved_micro-?,spent_micro=spent_micro+? WHERE month=? AND provider=? AND EXISTS(SELECT 1 FROM wb_reservations WHERE id=? AND settled=0)",
      )
      .bind(reserveMicro, cost, month, p.provider, id),
    ctx.db.prepare("UPDATE wb_reservations SET settled=1 WHERE id=? AND settled=0").bind(id),
    ctx.db
      .prepare(
        "UPDATE wb_runs SET status=?,ended_at=?,stop_reason=?,usage_json=?,result_json=? WHERE id=? AND status='running'",
      )
      .bind(
        status,
        end,
        reason,
        JSON.stringify({
          ...usage,
          costMicro: cost,
          billedReservationOnUncertainty: usage.uncertain,
        }),
        JSON.stringify(result),
        id,
      ),
    history(ctx.db, id, item.zone_id, status, { stopReason: reason }),
    audit(ctx.db, ctx.principal.id, "agent.completed", id, {
      provider: p.provider,
      status,
      stopReason: reason,
    }),
    ctx.db
      .prepare(
        "UPDATE incidents SET severity=?,summary=?,confidence=?,status=? WHERE id=? AND ?=0 AND NOT EXISTS(SELECT 1 FROM wb_proposals WHERE incident_id=? AND status IN ('awaiting_approval','authorized','verified'))",
      )
      .bind(
        result.severity,
        result.summary,
        result.confidence,
        status === "failed" || status === "timed_out"
          ? "failed"
          : result.verdict === "not_incident"
            ? "closed"
            : result.verdict === "incident"
              ? "investigating"
              : "new",
        item.id,
        privateRun ? 1 : 0,
        item.id,
      ),
    ctx.db.prepare("DELETE FROM wb_guards WHERE id=?").bind(finalizeGuard),
  ]);
  if (finalized[3]?.meta.changes !== 1)
    throw new HttpError(
      409,
      "run_interrupted",
      "Run was already recovered or closed; refresh its status.",
    );
  return {
    id,
    incidentId: item.id,
    zoneId: item.zone_id,
    kind,
    provider: p.provider,
    status,
    stopReason: reason,
    usage: { ...usage, costMicro: cost },
    finding: result,
    tools: results,
  };
}
