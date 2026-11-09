import { z } from "zod";
import {
  type LivePolicy,
  type LivePolicyState,
  livePolicySchema,
} from "../../../../packages/shared/src/live-policy";
import type { Principal } from "../auth";
import { HttpError, json, readJson } from "../http";

export const permitsRepair = (policy: LivePolicy) =>
  policy.mode !== "Observe" && !policy.killSwitch;

export async function readLivePolicy(db: D1Database): Promise<LivePolicyState> {
  const row = await db
    .prepare("SELECT version,policy_json FROM ld_policy WHERE id=1")
    .first<{ version: number; policy_json: string }>();
  if (!row) throw new HttpError(503, "live_policy_missing", "Live policy is unavailable.");
  return { version: row.version, policy: livePolicySchema.parse(JSON.parse(row.policy_json)) };
}

const update = z.strictObject({
  version: z.number().int().nonnegative(),
  policy: livePolicySchema,
});

export async function policyRoute(request: Request, db: D1Database, principal: Principal) {
  if (request.method === "GET") return json(await readLivePolicy(db));
  if (request.method !== "PUT") throw new HttpError(405, "invalid_method", "Use GET or PUT.");
  if (principal.role !== "Admin")
    throw new HttpError(403, "live_policy_admin_required", "An administrator is required.");
  const input = update.safeParse(await readJson(request));
  if (!input.success)
    throw new HttpError(400, "invalid_live_policy", "Check the live policy values and limits.");
  const { version, policy } = input.data;
  const contents = JSON.stringify(policy);
  const [changed] = await db.batch([
    db
      .prepare("UPDATE ld_policy SET version=version+1,policy_json=? WHERE id=1 AND version=?")
      .bind(contents, version),
    db
      .prepare(`INSERT INTO ld_policy_audit(version,changed_at,changed_by,policy_json)
      SELECT version,?,?,policy_json FROM ld_policy WHERE id=1 AND changes()=1`)
      .bind(new Date().toISOString(), principal.id),
  ]);
  if (!changed?.meta.changes)
    throw new HttpError(
      409,
      "live_policy_conflict",
      "The live policy changed. Reload it before saving.",
    );
  return json({ version: version + 1, policy } satisfies LivePolicyState);
}
