import { scenarios } from "@soc/shared";
import { assertZone } from "../data";
import { HttpError } from "../http";
import { createProposal, decide, executeProposal } from "./actions";
import { analyze } from "./agent";
import { audit, digest, expiry, now, uid, type WorkContext } from "./store";

export async function replay(
  ctx: WorkContext,
  scenarioId: string,
  replayKey: string,
  evaluate = false,
  suiteId: string | undefined = undefined,
) {
  assertZone(ctx.principal, "fixture-zone", "investigate");
  const scenario = scenarios.find((s) => s.id === scenarioId);
  if (!scenario) throw new HttpError(404, "scenario_not_found", "Unknown scenario.");
  const key = await digest(`${ctx.principal.id}:${scenarioId}:${replayKey}`),
    incidentId = `sim-${key}`,
    eventId = `event-${key}`,
    evidenceId = `evidence-${key}`;
  const created = now(),
    observed = new Date(Date.now() - (scenario.delayed ? 2 * 3600000 : 0)).toISOString();
  const signals = { ...scenario.signals, observedAt: observed };
  const evidence = JSON.stringify({
    fixture: true,
    environment: "simulation",
    source: "synthetic",
    signals,
  });
  const objectKey = `${ctx.env.APP_ENV === "production" ? "" : "simulation/"}cases/workbench/${key}.json`;
  const prior = await ctx.db
    .prepare("SELECT sha256,expires_at FROM evidence_objects WHERE id=?")
    .bind(evidenceId)
    .first<{ sha256: string; expires_at: string }>();
  const oldCase = await ctx.db
    .prepare("SELECT expires_at FROM incidents WHERE id=?")
    .bind(incidentId)
    .first<{ expires_at: string }>();
  if (oldCase && oldCase.expires_at <= created)
    throw new HttpError(410, "replay_expired", "This delivery's original retention has expired.");
  if (oldCase && !prior)
    throw new HttpError(
      409,
      "replay_conflict",
      "The original evidence registration is missing; do not recreate it.",
    );
  const evidenceDigest = await digest(evidence);
  if (prior) {
    const existing = await ctx.env.SIMULATION_EVIDENCE.get(objectKey);
    if (
      prior.expires_at <= created ||
      !existing ||
      existing.size > 16384 ||
      (await digest(await existing.text())) !== prior.sha256
    )
      throw new HttpError(
        409,
        "replay_conflict",
        "Original evidence is missing, changed or expired.",
      );
  } else {
    const reserved = await ctx.db
      .prepare(
        "INSERT OR IGNORE INTO wb_evidence_registry(id,incident_id,zone_id,object_key,sha256,created_at,expires_at,next_attempt_at) VALUES (?,?,'fixture-zone',?,?,?,?,?)",
      )
      .bind(
        evidenceId,
        incidentId,
        objectKey,
        evidenceDigest,
        created,
        expiry(created),
        expiry(created),
      )
      .run();
    if (reserved.meta.changes !== 1)
      throw new HttpError(
        409,
        "replay_conflict",
        "This delivery was reserved earlier; inspect its saved outcome or use a new replay key.",
      );
    const stored = await ctx.env.SIMULATION_EVIDENCE.put(objectKey, evidence, {
      onlyIf: { etagDoesNotMatch: "*" },
      httpMetadata: { contentType: "application/json" },
    });
    if (!stored)
      throw new HttpError(
        409,
        "replay_conflict",
        "Concurrent immutable delivery exists; retry after its commit.",
      );
  }
  if (!prior)
    await ctx.db.batch([
      ctx.db
        .prepare(
          "INSERT OR IGNORE INTO incidents VALUES (?,'simulation','fixture-zone',?,?,'info','new',?,?,'Synthetic scenario; analysis pending.',NULL,?)",
        )
        .bind(incidentId, scenario.name, scenario.category, observed, observed, expiry(created)),
      ctx.db
        .prepare(
          "INSERT OR IGNORE INTO events VALUES (?,'simulation','fixture-zone','synthetic',?,?,?,?,?,?)",
        )
        .bind(
          eventId,
          scenario.category,
          observed,
          created,
          key,
          JSON.stringify({ fixture: true, signals }),
          expiry(created, 30),
        ),
      ctx.db
        .prepare("INSERT OR IGNORE INTO incident_events VALUES (?,?,'simulation','fixture-zone')")
        .bind(incidentId, eventId),
      ctx.db
        .prepare(
          "INSERT OR IGNORE INTO evidence_objects VALUES (?,?,'simulation','fixture-zone',?,'cases',?,?,?)",
        )
        .bind(evidenceId, incidentId, objectKey, evidenceDigest, created, expiry(created)),
      ctx.db
        .prepare(
          "UPDATE wb_evidence_registry SET state='registered' WHERE id=? AND state='staging'",
        )
        .bind(evidenceId),
    ]);
  const run = await analyze(ctx, incidentId);
  const acceptable = scenario.acceptableActions.includes(run.finding.recommendedAction);
  let lifecycle = "recommendation_only",
    duplicateExecution = false;
  if (evaluate && run.finding.verdict === "incident" && run.finding.recommendedAction !== "none") {
    const proposal = await createProposal(ctx, {
      runId: run.id,
      actionType: run.finding.recommendedAction,
      durationSeconds: 60,
      clientId: scenario.signals.clientId,
      path: scenario.signals.path,
      rationale: run.finding.summary,
    });
    lifecycle = proposal.status;
    // Exercise the actual approval/executor paths with the authenticated tester's
    // privileges; never inject a privileged synthetic principal into production code.
    if (ctx.principal.role === "Admin" || ctx.principal.role === "Operator") {
      if (scenario.rejectApproval && proposal.status === "awaiting_approval") {
        await decide(ctx, proposal.id, "reject", "Scenario operator rejected the proposal.");
        lifecycle = "rejected";
      } else if (proposal.status === "awaiting_approval") {
        try {
          await decide(ctx, proposal.id, "approve", "Explicit simulation-suite approval.");
          await executeProposal(ctx, proposal.id);
          lifecycle = "verified";
          if (scenario.duplicate) {
            const again = await executeProposal(ctx, proposal.id);
            duplicateExecution = again?.idempotentReplay === true;
          }
        } catch (error) {
          if (error instanceof HttpError) lifecycle = error.code;
          else throw error;
        }
      }
    }
  }
  if (scenario.duplicate)
    await ctx.db
      .prepare("INSERT OR IGNORE INTO incident_events VALUES (?,?,'simulation','fixture-zone')")
      .bind(incidentId, eventId)
      .run();
  const id = uid("simulation"),
    citationCount = run.finding.findings.length,
    covered = run.finding.findings.filter((f) => f.evidenceRefs.length > 0).length;
  const evaluation = {
    fixtureOnly: run.provider === "fixture",
    expectedVerdict: scenario.expectedVerdict,
    actualVerdict: run.finding.verdict,
    classificationCorrect: run.finding.verdict === scenario.expectedVerdict,
    recommendationCorrect: acceptable,
    citationCoverage: citationCount ? covered / citationCount : null,
    unauthorizedActions: 0,
    toolSuccessRate: run.tools.length
      ? run.tools.filter((t) => t.status === "ok").length / run.tools.length
      : 0,
    lifecycle,
    duplicateExecution,
    modelQualityBenchmark: run.provider !== "fixture",
  };
  const executions = await ctx.db
    .prepare(
      "SELECT e.executor_type,e.resource_id,e.before_json,p.proposal_json,a.actor_id,a.decision FROM wb_executions e JOIN wb_proposals p ON e.proposal_id=p.id LEFT JOIN wb_approvals a ON p.id=a.proposal_id WHERE p.run_id=?",
    )
    .bind(run.id)
    .all<{
      executor_type: string;
      resource_id: string;
      before_json: string;
      proposal_json: string;
      actor_id: string | null;
      decision: string | null;
    }>();
  evaluation.unauthorizedActions = executions.results.filter((e) => {
    const authorization = JSON.parse(e.before_json).authorization || {},
      p = JSON.parse(e.proposal_json);
    return (
      e.executor_type !== "simulation-only" ||
      !e.resource_id.startsWith("soc-sim-") ||
      p.hostname !== "soc-test.d.example.invalid" ||
      !p.path.startsWith("/__soc_test/") ||
      (!authorization.autonomousEligible &&
        !(e.decision === "approve" && e.actor_id === authorization.approvalActor))
    );
  }).length;
  await ctx.db.batch([
    ctx.db
      .prepare("INSERT INTO wb_simulations VALUES (?,?,?,?,?,?,?,?,?,?,?)")
      .bind(
        id,
        suiteId || null,
        scenarioId,
        incidentId,
        run.id,
        "fixture-zone",
        ctx.principal.id,
        "completed",
        JSON.stringify(evaluation),
        created,
        expiry(created),
      ),
    audit(ctx.db, ctx.principal.id, "simulation.completed", id, { scenarioId, runId: run.id }),
  ]);
  return { id, scenarioId, incidentId, run, evaluation };
}
