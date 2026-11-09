import type { Principal } from "../auth";
import type { Bindings } from "../env";
import { HttpError, json, readJson } from "../http";
import { redact } from "../workbench/store";
import { permitsRepair, readLivePolicy } from "./policy";
import {
  type RepairRow,
  repairDraft,
  repairExpression,
  repairHost,
  repairId,
  repairScope,
} from "./repair-policy";

export async function repairRoute(
  request: Request,
  env: Bindings,
  db: D1Database,
  principal: Principal,
) {
  if (principal.role !== "Admin")
    throw new HttpError(403, "repair_admin_required", "An administrator is required.");
  const path = new URL(request.url).pathname;
  if (new URL(request.url).search)
    throw new HttpError(400, "invalid_scope", "Repairs are scoped to the test host.");
  if (request.method === "GET" && path === "/api/live/repairs") {
    const [repairs, audit, { policy }] = await Promise.all([
      db.prepare("SELECT * FROM ld_repairs ORDER BY created_at DESC LIMIT 30").all<RepairRow>(),
      db
        .prepare("SELECT repair_id,actor,action,at FROM ld_repair_audit ORDER BY at DESC LIMIT 40")
        .all(),
      readLivePolicy(db),
    ]);
    let execution = { apply: false, rollback: false };
    try {
      const status = await env.LIVE_REPAIR?.fetch("https://repair.internal/status");
      if (status?.ok) execution = await status.json<typeof execution>();
    } catch {
      /* Saved proposals and audit stay visible if the executor is unavailable. */
    }
    return json({
      host: repairHost,
      execution,
      policyPaused: !permitsRepair(policy),
      requiresSecondApprover: policy.requireSecondApprover,
      maxDurationSeconds: policy.maxDurationSeconds,
      repairs: (repairs?.results ?? []).map((row) => ({
        ...row,
        expression: repairExpression(repairScope.parse(row)),
      })),
      audit: audit?.results ?? [],
    });
  }
  if (request.method !== "POST") throw new HttpError(405, "invalid_method", "Use GET or POST.");
  const now = Date.now(),
    at = new Date(now).toISOString(),
    auditId = crypto.randomUUID();
  if (path === "/api/live/repairs") {
    const draft = repairDraft.safeParse(await readJson(request));
    if (!draft.success)
      throw new HttpError(
        400,
        "invalid_repair",
        "Provide one /__soc_test/ path, one IPv4 address, and a test justification.",
      );
    const id = crypto.randomUUID();
    await db.batch([
      db
        .prepare(`INSERT INTO ld_repairs(id,path,client_ip,note,status,requested_by,created_at,apply_before,retain_until)
        VALUES (?,?,?,?,'pending',?,?,?,?)`)
        .bind(
          id,
          draft.data.path,
          draft.data.client_ip,
          redact(draft.data.note),
          principal.id,
          at,
          new Date(now + 15 * 60000).toISOString(),
          new Date(now + 90 * 86400000).toISOString(),
        ),
      db
        .prepare("INSERT INTO ld_repair_audit VALUES (?,?,?,?,?)")
        .bind(auditId, id, principal.id, "proposed", at),
    ]);
    return json({ id }, 201);
  }
  const operation = /^\/api\/live\/repairs\/([^/]+)\/(approve|reject|apply|rollback)$/.exec(path);
  const id = operation?.[1] ?? "",
    op = operation?.[2];
  if (!op || !repairId.test(id))
    throw new HttpError(404, "repair_missing", "Repair proposal unavailable.");
  const currentPolicy = op === "approve" || op === "apply" ? await readLivePolicy(db) : null;
  if (currentPolicy && !permitsRepair(currentPolicy.policy))
    throw new HttpError(
      409,
      "repair_paused",
      "Live repair approval and execution are paused in Settings.",
    );
  if (op === "approve" || op === "reject") {
    const results = await db.batch([
      db
        .prepare(
          `INSERT INTO ld_repair_audit SELECT ?,id,?,?,? FROM ld_repairs WHERE id=? AND status='pending' AND apply_before>?
          ${currentPolicy ? "AND (?=0 OR requested_by<>?) AND EXISTS(SELECT 1 FROM ld_policy WHERE id=1 AND version=?)" : ""}`,
        )
        .bind(
          auditId,
          principal.id,
          op,
          at,
          id,
          at,
          ...(currentPolicy
            ? [
                Number(currentPolicy.policy.requireSecondApprover),
                principal.id,
                currentPolicy.version,
              ]
            : []),
        ),
      db
        .prepare(`UPDATE ld_repairs SET status=?,approved_by=?,approved_at=?
        WHERE id=? AND EXISTS(SELECT 1 FROM ld_repair_audit WHERE id=?)`)
        .bind(
          op === "approve" ? "approved" : "rejected",
          op === "approve" ? principal.id : null,
          op === "approve" ? at : null,
          id,
          auditId,
        ),
    ]);
    if (!results[1]?.meta.changes)
      throw new HttpError(
        409,
        "repair_conflict",
        "This proposal is no longer eligible. Check its status and approval requirements.",
      );
  } else {
    if (!env.LIVE_REPAIR)
      throw new HttpError(
        503,
        "executor_unavailable",
        "The controlled test executor is unavailable.",
      );
    const response = await env.LIVE_REPAIR.fetch("https://repair.internal/execute", {
      method: "POST",
      body: JSON.stringify({ id, actor: principal.id, op }),
    });
    if (!response.ok)
      throw new HttpError(
        409,
        "repair_conflict",
        "Execution is unavailable, the proposal expired, or an existing rule needs review.",
      );
  }
  const updated = await db
    .prepare("SELECT status,result FROM ld_repairs WHERE id=?")
    .bind(id)
    .first<Pick<RepairRow, "status" | "result">>();
  return json(updated);
}
