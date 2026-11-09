import { defaultWorkbenchPolicy, type WorkbenchPolicy, workbenchPolicySchema } from "@soc/shared";
import type { Principal } from "../auth";
import { assertZone } from "../data";
import type { Bindings } from "../env";
import { HttpError } from "../http";

export interface WorkContext {
  db: D1Database;
  env: Bindings;
  principal: Principal;
}
export const now = () => new Date().toISOString();
export const expiry = (from = now(), days = 90) =>
  new Date(Date.parse(from) + days * 86400000).toISOString();
export const uid = (prefix: string) => `${prefix}-${crypto.randomUUID()}`;
export async function digest(value: string) {
  return Array.from(
    new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))),
    (b) => b.toString(16).padStart(2, "0"),
  ).join("");
}
export function enabled(env: Bindings) {
  return (
    env.SOC_FEATURES === "full-simulation-v1" &&
    ((env.APP_ENV === "local" && env.AUTH_MODE === "fixture") ||
      (env.APP_ENV === "production" && env.AUTH_MODE === "access"))
  );
}
export function redact(text: string): string {
  return text
    .slice(0, 16000)
    .replace(/(?:Bearer\s+)[a-zA-Z0-9._-]+/gi, "Bearer [REDACTED]")
    .replace(
      /\b(?:cookie|password|authorization|api[_-]?(?:key|token)|secret)\s*[:=]\s*[^\s,;"}]+/gi,
      "[REDACTED_CREDENTIAL]",
    )
    .replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, "[REDACTED_EMAIL]")
    .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, "[REDACTED_IP]")
    .replace(/\b(?:[a-f0-9]{1,4}:){2,}[a-f0-9:]*\b/gi, "[REDACTED_IP]");
}
export const injection = (text: string) =>
  /ignore (?:all |previous )?instructions|system prompt|reveal.{0,30}(?:token|secret)|execute.{0,30}(?:global|production)|bypass.{0,20}(?:approval|permission)/i.test(
    text,
  );
export async function settings(
  db: D1Database,
): Promise<{ version: number; policy: WorkbenchPolicy }> {
  const row = await db
    .prepare("SELECT version,policy_json FROM wb_settings WHERE id='simulation'")
    .first<{ version: number; policy_json: string }>();
  if (!row)
    throw new HttpError(
      503,
      "workbench_not_prepared",
      "Run npm run local:prepare to install the local workbench schema.",
    );
  return { version: row.version, policy: workbenchPolicySchema.parse(JSON.parse(row.policy_json)) };
}
export function audit(
  db: D1Database,
  actor: string | null,
  operation: string,
  target: string,
  details: unknown,
) {
  const at = now(),
    serialized = redact(JSON.stringify({ actorId: actor, details }));
  return db
    .prepare("INSERT INTO audit_trail VALUES (?,?,?,?,?,?,?)")
    .bind(
      uid("audit"),
      null,
      operation,
      target,
      serialized.length <= 1900
        ? serialized
        : JSON.stringify({ actorId: actor, details: { truncated: true } }),
      at,
      expiry(at),
    );
}
export function history(
  db: D1Database,
  target: string,
  zone: string,
  state: string,
  details: unknown = {},
) {
  const at = now();
  return db
    .prepare("INSERT INTO wb_history VALUES (?,?,?,?,?,?,?)")
    .bind(uid("transition"), target, zone, state, JSON.stringify(details), at, expiry(at));
}
export async function incident(ctx: WorkContext, id: string) {
  const row = await ctx.db
    .prepare("SELECT * FROM incidents WHERE id=? AND environment='simulation' AND expires_at>?")
    .bind(id, now())
    .first<{
      id: string;
      zone_id: string;
      category: string;
      title: string;
      last_seen: string;
      summary: string;
    }>();
  if (!row) throw new HttpError(404, "incident_not_found", "Incident absent or expired.");
  assertZone(ctx.principal, row.zone_id);
  return row;
}
export async function scoped<T extends { zone_id: string }>(
  ctx: Pick<WorkContext, "db" | "principal">,
  table: "wb_runs" | "wb_tools" | "wb_proposals" | "wb_executions" | "wb_simulations",
  id: string,
) {
  const row = await ctx.db
    .prepare(`SELECT * FROM ${table} WHERE id=? AND expires_at>?`)
    .bind(id, now())
    .first<T>();
  if (!row) throw new HttpError(404, "record_not_found", "Record absent or expired.");
  assertZone(ctx.principal, row.zone_id);
  if (
    table === "wb_runs" &&
    "private_user_id" in row &&
    row.private_user_id &&
    row.private_user_id !== ctx.principal.id
  )
    throw new HttpError(404, "record_not_found", "Record absent or expired.");
  if (table === "wb_tools" && "run_id" in row) {
    const owner = await ctx.db
      .prepare("SELECT private_user_id FROM wb_runs WHERE id=?")
      .bind(String(row.run_id))
      .first<{ private_user_id: string | null }>();
    if (owner?.private_user_id && owner.private_user_id !== ctx.principal.id) {
      const proposals = await ctx.db
        .prepare("SELECT proposal_json FROM wb_proposals WHERE run_id=? AND expires_at>? LIMIT 20")
        .bind(String(row.run_id), now())
        .all<{ proposal_json: string }>();
      if (
        !proposals.results.some((p) =>
          JSON.parse(p.proposal_json).evidenceRefs.includes(`tool:${id}`),
        )
      )
        throw new HttpError(404, "record_not_found", "Record absent or expired.");
    }
  }
  return row;
}
export function zones(
  ctx: Pick<WorkContext, "principal">,
  permission: "read" | "investigate" | "approve" | "manage" = "read",
) {
  return ctx.principal.grants
    .filter((g) => {
      try {
        assertZone(ctx.principal, g.zoneId, permission);
        return true;
      } catch {
        return false;
      }
    })
    .map((g) => g.zoneId);
}
export async function rateLimit(ctx: WorkContext) {
  const at = now(),
    id = `${ctx.principal.id}:${at.slice(0, 16)}`;
  const r = await ctx.db
    .prepare("INSERT INTO wb_limits VALUES (?,1,?) ON CONFLICT(id) DO UPDATE SET n=n+1 RETURNING n")
    .bind(id, expiry(at, 1))
    .first<{ n: number }>();
  if (!r || r.n > 30)
    throw new HttpError(
      429,
      "rate_limited",
      "Thirty workbench commands per minute; retry shortly.",
    );
}
export { defaultWorkbenchPolicy };
