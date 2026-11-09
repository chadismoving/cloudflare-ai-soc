import { z } from "zod";
import { liveZone } from "../../../../packages/shared/src/live";
import type { LivePolicyState } from "../../../../packages/shared/src/live-policy";
import { permitsRepair, readLivePolicy } from "./policy";
import {
  cloudId,
  type RepairRow,
  repairExpression,
  repairHost,
  repairId,
  repairRef,
  repairScope,
} from "./repair-policy";

interface Env {
  LIVE_DB: D1Database;
  WAF_API_TOKEN?: string;
  WAF_RULESET_ID?: string;
  REPAIR_CLIENT_IPV4?: string;
  REPAIR_APPLY?: string;
}
const ruleSchema = z.object({
  id: z.string().regex(cloudId),
  ref: z.string().optional(),
  description: z.string().optional(),
  action: z.string(),
  expression: z.string(),
  enabled: z.boolean(),
});
type Rule = z.infer<typeof ruleSchema>;
const entrySchema = z.object({
  id: z.string().regex(cloudId),
  kind: z.literal("zone"),
  phase: z.literal("http_request_firewall_custom"),
  rules: z.array(ruleSchema).max(1000),
});
const zonePath = `/client/v4/zones/${liveZone}/rulesets`;
const credentials = (env: Env) =>
  !!env.WAF_API_TOKEN?.trim() &&
  cloudId.test(env.WAF_RULESET_ID ?? "") &&
  z.ipv4().safeParse(env.REPAIR_CLIENT_IPV4).success;
const canApply = (env: Env) => credentials(env) && env.REPAIR_APPLY === "verified-test-host-v1";

async function cloud(
  env: Env,
  transport: typeof fetch,
  path: string,
  method = "GET",
  body?: Record<string, unknown>,
) {
  const res = await transport(`https://api.cloudflare.com${zonePath}${path}`, {
    method,
    redirect: "manual",
    signal: AbortSignal.timeout(8000),
    headers: { Authorization: `Bearer ${env.WAF_API_TOKEN}`, "Content-Type": "application/json" },
    ...(body && { body: JSON.stringify(body) }),
  });
  if (!res.ok) throw Error("cloudflare_unavailable");
  const response = z
    .object({ success: z.literal(true), result: z.unknown() })
    .parse(await res.json());
  return response.result;
}

function expected(row: RepairRow) {
  return {
    ref: repairRef(row.id),
    description: `SOC temporary test ${row.id}`,
    action: "managed_challenge",
    expression: repairExpression(repairScope.parse(row)),
    enabled: true,
  };
}

async function lookup(env: Env, row: RepairRow, transport: typeof fetch) {
  const entry = entrySchema.parse(
    await cloud(env, transport, "/phases/http_request_firewall_custom/entrypoint"),
  );
  if (entry.id !== env.WAF_RULESET_ID || (row.ruleset_id && entry.id !== row.ruleset_id))
    throw Error("ruleset_drift");
  const desired = expected(row);
  const matches = entry.rules.filter((rule) => rule.ref === desired.ref || rule.id === row.rule_id);
  const rule = matches[0];
  if (
    matches.length > 1 ||
    (rule &&
      (Object.entries(desired).some(([key, value]) => rule[key as keyof Rule] !== value) ||
        (row.rule_id && rule.id !== row.rule_id)))
  )
    throw Error("rule_drift");
  return { ruleset: entry.id, rule };
}

async function finish(
  env: Env,
  row: RepairRow,
  actor: string,
  status: RepairRow["status"],
  result: string,
  rule?: Rule,
) {
  const at = new Date().toISOString();
  const audit = crypto.randomUUID();
  // Fencing prevents a tardy request from overwriting a later reconciliation.
  await env.LIVE_DB.batch([
    env.LIVE_DB.prepare(
      `INSERT INTO ld_repair_audit SELECT ?,id,?,?,? FROM ld_repairs WHERE id=? AND lease_until=?`,
    ).bind(audit, actor, result, at, row.id, row.lease_until),
    env.LIVE_DB.prepare(`UPDATE ld_repairs SET status=?,result=?,rule_id=COALESCE(?,rule_id),lease_until=NULL
      WHERE id=? AND EXISTS(SELECT 1 FROM ld_repair_audit WHERE id=?)`).bind(
      status,
      result,
      rule?.id ?? null,
      row.id,
      audit,
    ),
  ]);
}

async function claim(env: Env, id: string, actor: string, policy: LivePolicyState | null) {
  const now = Date.now(),
    at = new Date(now).toISOString(),
    lease = new Date(now + 45000).toISOString();
  const audit = crypto.randomUUID();
  const condition = policy
    ? `status='approved' AND approved_by IS NOT NULL AND apply_before>? AND client_ip=?
       AND (?=0 OR approved_by<>requested_by) AND EXISTS(SELECT 1 FROM ld_policy WHERE id=1 AND version=?)
       AND NOT EXISTS(SELECT 1 FROM ld_repairs WHERE status IN ('applying','verified','rolling_back','review'))`
    : "status IN ('applying','verified','rolling_back','review') AND (lease_until IS NULL OR lease_until<=?) AND client_ip=? AND rule_expires_at IS NOT NULL";
  await env.LIVE_DB.batch([
    env.LIVE_DB.prepare(
      `INSERT INTO ld_repair_audit SELECT ?,id,?,?,? FROM ld_repairs WHERE id=? AND ${condition}`,
    ).bind(
      audit,
      actor,
      policy ? "apply_started" : "rollback_started",
      at,
      id,
      at,
      env.REPAIR_CLIENT_IPV4,
      ...(policy ? [Number(policy.policy.requireSecondApprover), policy.version] : []),
    ),
    env.LIVE_DB.prepare(`UPDATE ld_repairs SET status=?,lease_until=?,
      rule_expires_at=COALESCE(rule_expires_at,?),ruleset_id=COALESCE(ruleset_id,?)
      WHERE id=? AND EXISTS(SELECT 1 FROM ld_repair_audit WHERE id=?)`).bind(
      policy ? "applying" : "rolling_back",
      lease,
      policy ? new Date(now + policy.policy.maxDurationSeconds * 1000).toISOString() : null,
      env.WAF_RULESET_ID,
      id,
      audit,
    ),
  ]);
  return env.LIVE_DB.prepare(
    `SELECT * FROM ld_repairs WHERE id=? AND lease_until=? AND EXISTS(SELECT 1 FROM ld_repair_audit WHERE id=?)`,
  )
    .bind(id, lease, audit)
    .first<RepairRow>();
}

export async function executeRepair(
  env: Env,
  id: string,
  actor: string,
  op: "apply" | "rollback",
  transport: typeof fetch = fetch,
): Promise<boolean> {
  if (!repairId.test(id) || !credentials(env) || (op === "apply" && !canApply(env))) return false;
  const policy = op === "apply" ? await readLivePolicy(env.LIVE_DB) : null;
  if (policy && !permitsRepair(policy.policy)) return false;
  const row = await claim(env, id, actor, policy);
  if (!row) return false;
  let result: { status: RepairRow["status"]; code: string; rule?: Rule };
  try {
    const before = await lookup(env, row, transport);
    if (op === "apply") {
      if (!before.rule) {
        const fixture = await transport(`https://${repairHost}${repairScope.parse(row).path}`, {
          method: "GET",
          redirect: "manual",
          signal: AbortSignal.timeout(8000),
        });
        const valid = fixture.ok && fixture.headers.get("X-SOC-Test-Fixture") === "isolated-v1";
        await fixture.body?.cancel();
        if (!valid) throw Error("fixture_unverified");
        if ((await readLivePolicy(env.LIVE_DB)).version !== policy?.version)
          throw Error("policy_changed");
        await cloud(env, transport, `/${before.ruleset}/rules`, "POST", expected(row));
      }
      const { rule } = await lookup(env, row, transport);
      if (!rule) throw Error("verification_pending");
      result = { status: "verified", code: "rule_verified", rule };
    } else {
      if (before.rule)
        await cloud(env, transport, `/${before.ruleset}/rules/${before.rule.id}`, "DELETE");
      if ((await lookup(env, row, transport)).rule) throw Error("verification_pending");
      result = { status: "rolled_back", code: "rule_absent" };
    }
  } catch (error) {
    const code =
      error instanceof Error &&
      [
        "rule_drift",
        "ruleset_drift",
        "fixture_unverified",
        "verification_pending",
        "policy_changed",
      ].includes(error.message)
        ? error.message
        : "cloudflare_unavailable";
    result = { status: "review", code };
  }
  await finish(env, row, actor, result.status, result.code, result.rule);
  return true;
}

export async function reconcileRepairs(env: Env, transport: typeof fetch = fetch) {
  if (!credentials(env)) return;
  const at = new Date().toISOString();
  const expired = await env.LIVE_DB.prepare(`SELECT id FROM ld_repairs
    WHERE status IN ('applying','verified','rolling_back','review') AND rule_expires_at<=?
    AND (lease_until IS NULL OR lease_until<=?) AND COALESCE(result,'') NOT IN ('rule_drift','ruleset_drift')
    ORDER BY rule_expires_at LIMIT 5`)
    .bind(at, at)
    .all<{ id: string }>();
  for (const { id } of expired.results)
    await executeRepair(env, id, "expiry-scheduler", "rollback", transport);
}

export default {
  async fetch(request: Request, env: Env) {
    const path = new URL(request.url).pathname;
    if (path === "/status" && request.method === "GET") {
      const apply = canApply(env) && permitsRepair((await readLivePolicy(env.LIVE_DB)).policy);
      return Response.json({ apply, rollback: credentials(env) });
    }
    if (path !== "/execute" || request.method !== "POST")
      return new Response(null, { status: 404 });
    const body = z
      .strictObject({
        id: z.string().regex(repairId),
        actor: z.string().min(1).max(128),
        op: z.enum(["apply", "rollback"]),
      })
      .safeParse(await request.json());
    if (!body.success) return new Response(null, { status: 400 });
    const { id, actor, op } = body.data;
    const claimed = await executeRepair(env, id, actor, op);
    return Response.json({ claimed }, { status: claimed ? 200 : 409 });
  },
  async scheduled(_event: ScheduledController, env: Env) {
    await reconcileRepairs(env);
  },
} satisfies ExportedHandler<Env>;
