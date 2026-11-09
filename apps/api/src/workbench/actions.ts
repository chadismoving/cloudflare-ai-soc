import {
  executableActions,
  findingSchema,
  type ProposalInput,
  proposalInputSchema,
} from "@soc/shared";
import { assertZone } from "../data";
import { HttpError } from "../http";
import {
  audit,
  digest,
  expiry,
  history,
  now,
  scoped,
  settings,
  uid,
  type WorkContext,
} from "./store";
import { signals } from "./tools";

type ProposalRow = {
  id: string;
  incident_id: string;
  run_id: string;
  zone_id: string;
  requested_by: string;
  policy_version: number;
  proposal_json: string;
  status: string;
  approval_deadline: string;
};
type RunRow = {
  zone_id: string;
  incident_id: string;
  status: string;
  kind: string;
  result_json: string;
};
interface Proposal extends ProposalInput {
  zoneId: string;
  hostname: string;
  sourceObservedAt: string;
  evidenceRefs: string[];
  expectedImpact: {
    requestSharePercent: number;
    sharedClient: boolean;
    legitimatePercent: number;
    mitigatedPercent: number;
    suspiciousPercent: number;
  };
  verificationPlan: string;
  rollbackPlan: string;
  riskLevel: string;
  requestedBy: string;
}
const executable = (type: string) => executableActions.some((t) => t === type);
async function assess(ctx: WorkContext, row: ProposalRow) {
  const current = await settings(ctx.db),
    p = JSON.parse(row.proposal_json) as Proposal;
  assertZone(ctx.principal, row.zone_id, "read");
  let denial = "";
  if (!executable(p.actionType)) denial = "recommendation_only";
  else if (current.policy.killSwitch) denial = "kill_switch";
  else if (current.policy.mode === "Observe") denial = "observe_only";
  else if (row.policy_version !== current.version) denial = "policy_changed";
  else if (row.approval_deadline <= now()) denial = "approval_expired";
  else if (
    Date.now() - Date.parse(p.sourceObservedAt) >
    current.policy.maxEvidenceAgeSeconds * 1000
  )
    denial = "stale_evidence";
  else if (
    p.durationSeconds > current.policy.maxDurationSeconds ||
    p.expectedImpact.requestSharePercent > current.policy.maxRequestSharePercent ||
    p.expectedImpact.sharedClient
  )
    denial = "impact_limit";
  if (
    !denial &&
    (p.expectedImpact.legitimatePercent >= 80 ||
      p.expectedImpact.mitigatedPercent >= 95 ||
      p.expectedImpact.suspiciousPercent < 20)
  )
    denial = "existing_mitigation_or_benign_impact";
  if (
    !denial &&
    p.actionType === "ip_block" &&
    (p.expectedImpact.legitimatePercent >= 1 || p.expectedImpact.suspiciousPercent <= 99)
  )
    denial = "block_evidence_insufficient";
  return { ...current, proposal: p, denial };
}
export async function createProposal(
  ctx: WorkContext,
  input: ProposalInput,
  forceApproval = false,
) {
  const run = await scoped<RunRow>(ctx, "wb_runs", input.runId);
  assertZone(ctx.principal, run.zone_id, "investigate");
  if (run.status !== "completed" || run.kind !== "investigation")
    throw new HttpError(409, "analysis_required", "A completed investigation is required.");
  const finding = findingSchema.parse(JSON.parse(run.result_json));
  if (finding.verdict !== "incident" || finding.recommendedAction === "none")
    throw new HttpError(409, "unsupported_action", "The finding does not justify a mitigation.");
  if (
    input.actionType !== finding.recommendedAction &&
    !(input.actionType === "managed_challenge" && finding.recommendedAction === "ip_block")
  )
    throw new HttpError(
      409,
      "unsupported_action",
      "Choose the supported recommendation or its narrower challenge alternative.",
    );
  const observed = await signals(ctx, run.incident_id);
  if (!observed || observed.clientId !== input.clientId || observed.path !== input.path)
    throw new HttpError(
      409,
      "scope_mismatch",
      "Target must match the investigated client and exact test path.",
    );
  const { policy: p, version } = await settings(ctx.db),
    id = uid("proposal"),
    at = now(),
    deadline = new Date(Date.now() + 10 * 60000).toISOString();
  const proposal: Proposal = {
    ...input,
    zoneId: run.zone_id,
    hostname: "soc-test.d.example.invalid",
    sourceObservedAt: observed.observedAt,
    evidenceRefs: [...new Set(finding.findings.flatMap((f) => f.evidenceRefs))],
    expectedImpact: {
      requestSharePercent: observed.requestSharePercent,
      sharedClient: observed.sharedClient,
      legitimatePercent: observed.legitimatePercent,
      mitigatedPercent: observed.mitigatedPercent,
      suspiciousPercent: observed.suspiciousPercent,
    },
    verificationPlan:
      "Verify only the owned simulated rule and its TTL; traffic effectiveness is not measured.",
    rollbackPlan:
      "Remove this execution's app-owned simulated rule after digest/ownership verification.",
    riskLevel: input.actionType === "ip_block" ? "high" : "medium",
    requestedBy: ctx.principal.id,
  };
  if (!proposal.evidenceRefs.length)
    throw new HttpError(409, "evidence_required", "Cited evidence is required.");
  const row: ProposalRow = {
    id,
    incident_id: run.incident_id,
    run_id: input.runId,
    zone_id: run.zone_id,
    requested_by: ctx.principal.id,
    policy_version: version,
    proposal_json: JSON.stringify(proposal),
    status: "proposed",
    approval_deadline: deadline,
  };
  const decision = await assess(ctx, row);
  const status = decision.denial
    ? decision.denial === "observe_only"
      ? "observed"
      : decision.denial === "recommendation_only"
        ? "recommendation_only"
        : "blocked"
    : !forceApproval &&
        p.mode === "Autonomous" &&
        !p.requireSecondApprover &&
        p.autonomousActions.some((a) => a === input.actionType) &&
        finding.confidence >= 0.8
      ? "authorized"
      : "awaiting_approval";
  const guard = uid("guard");
  await ctx.db.batch([
    ctx.db
      .prepare(
        "INSERT INTO wb_guards SELECT ?,CASE WHEN (SELECT version FROM wb_settings WHERE id='simulation')=? THEN 1 ELSE 0 END",
      )
      .bind(guard, version),
    ctx.db
      .prepare("INSERT INTO wb_proposals VALUES (?,?,?,?,?,?,?,?,?,?,?,?)")
      .bind(
        id,
        run.incident_id,
        input.runId,
        run.zone_id,
        ctx.principal.id,
        version,
        JSON.stringify(proposal),
        status,
        decision.denial || status,
        at,
        deadline,
        expiry(at),
      ),
    ctx.db
      .prepare("UPDATE incidents SET status=? WHERE id=?")
      .bind(
        status === "awaiting_approval" ? "awaiting_approval" : "investigating",
        run.incident_id,
      ),
    history(ctx.db, id, run.zone_id, "proposed"),
    history(ctx.db, id, run.zone_id, status, { reason: decision.denial || status }),
    audit(ctx.db, ctx.principal.id, "proposal.created", id, {
      actionType: input.actionType,
      status,
      executor: "simulation-only",
    }),
    ctx.db.prepare("DELETE FROM wb_guards WHERE id=?").bind(guard),
  ]);
  if (status === "authorized") await executeProposal(ctx, id, true);
  return { id, status, proposal, decision: decision.denial || status };
}
export async function decide(
  ctx: WorkContext,
  id: string,
  decision: "approve" | "reject",
  reason: string,
) {
  const row = await scoped<ProposalRow>(ctx, "wb_proposals", id);
  assertZone(ctx.principal, row.zone_id, "approve");
  const checked = await assess(ctx, row);
  if (row.status !== "awaiting_approval")
    throw new HttpError(409, "state_conflict", "Proposal is not awaiting approval.");
  if (decision === "approve" && checked.denial)
    throw new HttpError(409, checked.denial, "Policy revalidation denied approval.");
  if (
    decision === "approve" &&
    checked.policy.requireSecondApprover &&
    row.requested_by === ctx.principal.id
  )
    throw new HttpError(
      403,
      "second_approver_required",
      "A different authorized operator must approve.",
    );
  const guard = uid("guard"),
    at = now(),
    status = decision === "approve" ? "authorized" : "rejected";
  await ctx.db.batch([
    ctx.db
      .prepare(
        "INSERT INTO wb_guards SELECT ?,CASE WHEN EXISTS(SELECT 1 FROM wb_proposals WHERE id=? AND status='awaiting_approval' AND approval_deadline>?) AND (SELECT version FROM wb_settings WHERE id='simulation')=? THEN 1 ELSE 0 END",
      )
      .bind(guard, id, at, checked.version),
    ctx.db
      .prepare("INSERT INTO wb_approvals VALUES (?,?,?,?,?,?,?)")
      .bind(uid("approval"), id, ctx.principal.id, decision, reason, at, expiry(at)),
    ctx.db
      .prepare("UPDATE wb_proposals SET status=?,decision_reason=? WHERE id=?")
      .bind(status, reason, id),
    ctx.db.prepare("UPDATE incidents SET status='investigating' WHERE id=?").bind(row.incident_id),
    history(ctx.db, id, row.zone_id, status),
    audit(ctx.db, ctx.principal.id, `proposal.${decision}`, id, { reason }),
    ctx.db.prepare("DELETE FROM wb_guards WHERE id=?").bind(guard),
  ]);
  return { id, status };
}
export async function executeProposal(ctx: WorkContext, id: string, autonomous = false) {
  const row = await scoped<ProposalRow>(ctx, "wb_proposals", id);
  assertZone(ctx.principal, row.zone_id, autonomous ? "investigate" : "approve");
  const existing = await ctx.db
    .prepare("SELECT * FROM wb_executions WHERE proposal_id=?")
    .bind(id)
    .first();
  if (existing) return { ...existing, idempotentReplay: true };
  const checked = await assess(ctx, row),
    p = checked.proposal;
  if (checked.denial)
    throw new HttpError(409, checked.denial, "Execution denied by current server policy.");
  if (row.status !== "authorized")
    throw new HttpError(409, "approval_required", "An authorized proposal is required.");
  const approval = await ctx.db
    .prepare("SELECT * FROM wb_approvals WHERE proposal_id=? AND decision='approve'")
    .bind(id)
    .first<{ actor_id: string }>();
  const auto =
    checked.policy.mode === "Autonomous" &&
    !checked.policy.requireSecondApprover &&
    checked.policy.autonomousActions.some((a) => a === p.actionType);
  if (!approval && !auto)
    throw new HttpError(403, "approval_required", "No valid approval is recorded.");
  if (approval && checked.policy.requireSecondApprover && approval.actor_id === row.requested_by)
    throw new HttpError(403, "second_approver_required", "Approval separation is required.");
  const executionId = `execution-${id}`,
    ruleId = `soc-sim-${id}`,
    at = now(),
    ttl = new Date(Date.now() + p.durationSeconds * 1000).toISOString();
  const config = JSON.stringify({
    action: p.actionType,
    zoneId: row.zone_id,
    hostname: p.hostname,
    path: p.path,
    clientId: p.clientId,
    owner: "example-soc-simulation",
    expiresAt: ttl,
  });
  const hash = await digest(config),
    guard = uid("guard");
  try {
    await ctx.db.batch([
      ctx.db
        .prepare(
          "INSERT INTO wb_guards SELECT ?,CASE WHEN EXISTS(SELECT 1 FROM wb_proposals WHERE id=? AND status='authorized' AND policy_version=? AND approval_deadline>?) AND (SELECT version FROM wb_settings WHERE id='simulation')=? AND NOT EXISTS(SELECT 1 FROM wb_rules WHERE id=?) THEN 1 ELSE 0 END",
        )
        .bind(guard, id, checked.version, at, checked.version, ruleId),
      ctx.db
        .prepare(
          "INSERT INTO wb_executions VALUES (?,?,?,?,'simulation-only',?,'verified',?,?,?,?,?)",
        )
        .bind(
          executionId,
          id,
          row.zone_id,
          `simulation:${id}`,
          ruleId,
          JSON.stringify({
            rule: null,
            authorization: {
              mode: checked.policy.mode,
              policyVersion: checked.version,
              actorId: ctx.principal.id,
              actorRole: ctx.principal.role,
              approvalActor: approval?.actor_id || null,
              autonomousEligible: auto,
            },
          }),
          config,
          at,
          ttl,
          expiry(at),
        ),
      ctx.db
        .prepare("INSERT INTO wb_rules VALUES (?,?,?,'example-soc-simulation',?,?,1,?)")
        .bind(ruleId, executionId, row.zone_id, config, hash, ttl),
      ctx.db
        .prepare(
          "UPDATE wb_proposals SET status='verified',decision_reason='owned_mock_rule_verified' WHERE id=?",
        )
        .bind(id),
      ctx.db.prepare("UPDATE incidents SET status='verifying' WHERE id=?").bind(row.incident_id),
      ...["executing", "applied", "verifying", "verified"].map((state) =>
        history(ctx.db, executionId, row.zone_id, state, { executor: "simulation-only" }),
      ),
      ctx.db
        .prepare("INSERT INTO wb_verifications VALUES (?,?,'configuration_verified',?,?,?)")
        .bind(
          uid("verification"),
          executionId,
          JSON.stringify({
            owned: true,
            active: true,
            trafficEffect: "not_measured",
            ruleDigest: hash,
          }),
          at,
          expiry(at),
        ),
      audit(ctx.db, ctx.principal.id, "simulation.rule.applied", id, {
        ruleId,
        expiresAt: ttl,
        autonomous: auto,
      }),
      ctx.db.prepare("DELETE FROM wb_guards WHERE id=?").bind(guard),
    ]);
  } catch (error) {
    const replay = await ctx.db
      .prepare("SELECT * FROM wb_executions WHERE proposal_id=?")
      .bind(id)
      .first();
    if (replay) return { ...replay, idempotentReplay: true };
    throw error;
  }
  return ctx.db.prepare("SELECT * FROM wb_executions WHERE id=?").bind(executionId).first();
}
export async function rollback(
  ctx: Pick<WorkContext, "db" | "principal">,
  proposalId: string,
  expired = false,
) {
  const row = expired
    ? await ctx.db
        .prepare("SELECT * FROM wb_proposals WHERE id=?")
        .bind(proposalId)
        .first<ProposalRow>()
    : await scoped<ProposalRow>(ctx, "wb_proposals", proposalId);
  if (!row) throw new HttpError(404, "record_not_found", "Proposal is absent.");
  assertZone(ctx.principal, row.zone_id, expired ? "read" : "approve");
  const execution = await ctx.db
    .prepare("SELECT * FROM wb_executions WHERE proposal_id=?")
    .bind(proposalId)
    .first<{
      id: string;
      resource_id: string;
      status: string;
      after_json: string;
      rule_expires_at: string;
    }>();
  if (!execution) throw new HttpError(409, "not_executed", "This proposal has no execution.");
  if (["rolled_back", "closed"].includes(execution.status))
    return { status: execution.status, idempotentReplay: true };
  const rule = await ctx.db
    .prepare(
      "SELECT * FROM wb_rules WHERE id=? AND execution_id=? AND owner='example-soc-simulation'",
    )
    .bind(execution.resource_id, execution.id)
    .first<{ config_json: string; config_digest: string; active: number }>();
  if (
    !rule ||
    rule.config_json !== execution.after_json ||
    rule.config_digest !== (await digest(execution.after_json))
  ) {
    await ctx.db.batch([
      ctx.db
        .prepare("UPDATE wb_executions SET status='rollback_failed' WHERE id=?")
        .bind(execution.id),
      history(ctx.db, execution.id, row.zone_id, "rollback_failed", {
        reason: "ownership_or_digest_conflict",
      }),
      audit(ctx.db, ctx.principal.id, "simulation.rollback_failed", proposalId, {
        reason: "ownership_or_digest_conflict",
      }),
    ]);
    throw new HttpError(
      409,
      "rollback_conflict",
      "Rule ownership or contents changed; manual review required.",
    );
  }
  if (expired && execution.rule_expires_at > now()) return { status: "not_due" };
  const at = now(),
    status = expired ? "closed" : "rolled_back",
    guard = uid("guard");
  await ctx.db.batch([
    ctx.db
      .prepare(
        "INSERT INTO wb_guards SELECT ?,CASE WHEN EXISTS(SELECT 1 FROM wb_rules WHERE id=? AND execution_id=? AND owner='example-soc-simulation' AND config_digest=? AND config_json=?) THEN 1 ELSE 0 END",
      )
      .bind(guard, execution.resource_id, execution.id, rule.config_digest, execution.after_json),
    history(ctx.db, execution.id, row.zone_id, expired ? "expiring" : "rolling_back"),
    ctx.db
      .prepare(
        "UPDATE wb_rules SET active=0 WHERE id=? AND execution_id=? AND owner='example-soc-simulation'",
      )
      .bind(execution.resource_id, execution.id),
    ctx.db.prepare("UPDATE wb_executions SET status=? WHERE id=?").bind(status, execution.id),
    ctx.db.prepare("UPDATE wb_proposals SET status=? WHERE id=?").bind(status, proposalId),
    ctx.db
      .prepare("INSERT INTO wb_verifications VALUES (?,?,?,?,?,?)")
      .bind(
        uid("verification"),
        execution.id,
        expired ? "expired" : "rolled_back",
        JSON.stringify({ ownedRuleRemoved: true, customerRulesTouched: 0 }),
        at,
        expiry(at),
      ),
    ctx.db.prepare("UPDATE incidents SET status='investigating' WHERE id=?").bind(row.incident_id),
    history(ctx.db, execution.id, row.zone_id, status),
    audit(
      ctx.db,
      expired ? null : ctx.principal.id,
      expired ? "simulation.rule.expired" : "simulation.rule.rolled_back",
      proposalId,
      {},
    ),
    ctx.db.prepare("DELETE FROM wb_guards WHERE id=?").bind(guard),
  ]);
  return { id: execution.id, status };
}
export { proposalInputSchema };
