import { type Signals, signalsSchema } from "@soc/shared";
import { assertZone } from "../data";
import { digest, expiry, incident, injection, now, redact, uid, type WorkContext } from "./store";

export const toolNames = [
  "traffic_trend",
  "waf_actions",
  "bot_scores",
  "audit_events",
  "request_samples",
  "prior_incidents",
] as const;
export type ToolName = (typeof toolNames)[number];
export interface ToolResult {
  ref: string;
  name: string;
  status: string;
  observedAt: string;
  data: Record<string, unknown>;
}
export async function signals(ctx: WorkContext, incidentId: string): Promise<Signals | null> {
  const item = await incident(ctx, incidentId);
  const row = await ctx.db
    .prepare(
      "SELECT e.metadata_json FROM events e JOIN incident_events l ON e.id=l.event_id WHERE l.incident_id=? AND e.zone_id=? AND e.environment='simulation' AND e.expires_at>? ORDER BY e.event_time DESC LIMIT 1",
    )
    .bind(item.id, item.zone_id, now())
    .first<{ metadata_json: string }>();
  if (!row) return null;
  const meta = JSON.parse(row.metadata_json);
  const s = meta.signals;
  const parsed = signalsSchema.safeParse(s);
  if (
    !parsed.success ||
    meta.fixture !== true ||
    Date.parse(parsed.data.observedAt) > Date.now() + 300000
  )
    return null;
  return parsed.data;
}
export async function callTool(
  ctx: WorkContext,
  runId: string,
  incidentId: string,
  name: ToolName,
): Promise<ToolResult> {
  const started = performance.now(),
    item = await incident(ctx, incidentId);
  assertZone(ctx.principal, item.zone_id, "investigate");
  const s = await signals(ctx, incidentId);
  let data: Record<string, unknown> = {},
    status = "ok";
  if (!s) {
    status = "unavailable";
    data = { reason: "Source has no normalized metrics; do not invent them." };
  } else if (s.toolFailure && name !== "request_samples") {
    status = "unavailable";
    data = { reason: "Synthetic upstream outage" };
  } else if (name === "traffic_trend")
    data = {
      requests: s.requests,
      baselineRequests: s.baselineRequests,
      suspiciousPercent: s.suspiciousPercent,
      legitimatePercent: s.legitimatePercent,
      path: s.path,
      clientId: s.clientId,
    };
  else if (name === "waf_actions")
    data = {
      mitigatedPercent: s.mitigatedPercent,
      challengeSolvePercent: s.challengeSolvePercent,
      sharedClient: s.sharedClient,
    };
  else if (name === "bot_scores")
    data = {
      botScore: s.botScore,
      coverage: s.botScore === null ? "missing" : "fixture aggregate",
    };
  else if (name === "audit_events")
    data = { unexpectedConfigurationChange: s.auditChange, accountChangesExecutable: false };
  else if (name === "request_samples")
    data = {
      path: s.path,
      clientId: s.clientId,
      sharedClient: s.sharedClient,
      injectionDetected: injection(s.untrustedText || ""),
      untrustedSample: s.untrustedText ? "[UNTRUSTED_INSTRUCTION_REMOVED]" : null,
    };
  else {
    const rows = await ctx.db
      .prepare(
        "SELECT id,category,status,last_seen FROM incidents WHERE zone_id=? AND environment='simulation' AND expires_at>? ORDER BY last_seen DESC LIMIT 10",
      )
      .bind(item.zone_id, now())
      .all();
    data = { incidents: rows.results };
  }
  const at = now(),
    id = uid("tool"),
    args = JSON.stringify({ incidentId, zoneId: item.zone_id }),
    serialized = redact(JSON.stringify({ adapter: "simulation-d1", ...data }));
  if (serialized.length > 12000) status = "unavailable";
  const result =
    serialized.length > 12000
      ? JSON.stringify({ reason: "Tool result exceeded the bounded context limit." })
      : serialized;
  await ctx.db
    .prepare("INSERT INTO wb_tools VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)")
    .bind(
      id,
      runId,
      item.zone_id,
      name,
      args,
      await digest(args),
      result,
      await digest(result),
      status,
      Math.round(performance.now() - started),
      s?.observedAt || item.last_seen,
      at,
      expiry(at),
    )
    .run();
  return {
    ref: `tool:${id}`,
    name,
    status,
    observedAt: s?.observedAt || item.last_seen,
    data: JSON.parse(result),
  };
}
