import {
  incidentSchema,
  permits,
  pilotRawKeys,
  policy,
  roleChangeSchema,
  simulationHealthProfile,
} from "@soc/shared";
import { z } from "zod";
import {
  authenticate,
  csrfToken,
  fixtureSession,
  type Principal,
  requireCsrf,
  requireOrigin,
  sessionCookie,
} from "./auth";
import { assertZone, evidenceBinding, readContext } from "./data";
import { type Bindings, isAccessRuntime, isLocalFixture } from "./env";
import { HttpError, json, protect, readJson } from "./http";
import { observedWaitSeconds, reconcileIngestion } from "./ingestion-health";
import { liveEnabled, liveRoute } from "./live/route";
import { reconcile as reconcileWorkbench } from "./workbench/reconcile";
import { workbenchRoute } from "./workbench/route";
import { enabled as workbenchEnabled } from "./workbench/store";

const personaSchema = z.strictObject({ persona: z.enum(["admin", "viewer"]) });
const identifier = /^[a-zA-Z0-9_-]{1,128}$/;

async function route(request: Request, env: Bindings): Promise<Response> {
  const local = isLocalFixture(request, env);
  const access = isAccessRuntime(request, env);
  const healthReads = local || (access && env.SIMULATION_INGEST_READS === simulationHealthProfile);
  const ingestionReads = healthReads || (access && env.SIMULATION_INGEST_READS === "phase2b-v1");
  if (!local && !access)
    throw new HttpError(503, "runtime_unavailable", "This runtime is unavailable or unconfigured.");
  const url = new URL(request.url);
  const path = url.pathname;
  if (local && path === "/__local/session" && request.method === "POST") {
    requireOrigin(request, env);
    const input = personaSchema.safeParse(await readJson(request));
    if (!input.success)
      throw new HttpError(400, "invalid_persona", "Choose an Admin or Viewer fixture.");
    const token = await fixtureSession(input.data.persona, env);
    return json({ fixture: true }, 200, { "Set-Cookie": sessionCookie(token) });
  }
  if (local && path === "/__local/logout" && request.method === "POST") {
    await requireCsrf(request, await authenticate(request, env), env);
    return json({ signedOut: true }, 200, { "Set-Cookie": sessionCookie("") });
  }
  if (path.startsWith("/__local/")) throw new HttpError(404, "not_found", "Route not found.");
  // In Access mode even static assets require backend JWT and current D1 admission.
  const accessPrincipal = access ? await authenticate(request, env) : null;
  if (!path.startsWith("/api/")) {
    if (!["GET", "HEAD"].includes(request.method))
      throw new HttpError(405, "method_not_allowed", "Method not allowed.");
    return env.ASSETS.fetch(request);
  }

  const principal = accessPrincipal || (await authenticate(request, env));
  if (path.startsWith("/api/live/")) {
    if (!access)
      throw new HttpError(503, "live_unavailable", "Live data requires verified owner access.");
    if (!["GET", "HEAD"].includes(request.method)) await requireCsrf(request, principal, env);
    return liveRoute(request, env, principal);
  }
  const context = readContext(env, url.searchParams.get("environment"));
  if (!["GET", "HEAD"].includes(request.method)) await requireCsrf(request, principal, env);

  if (path === "/api/session" && request.method === "GET") {
    return json({
      user: {
        id: principal.id,
        role: principal.role,
        label: access ? `Verified owner · ${principal.role}` : `${principal.role} fixture`,
      },
      zoneGrants: principal.grants,
      csrfToken: await csrfToken(principal, env),
      environment: "simulation",
      authMode: access ? "cloudflare-access" : "signed-local-fixture",
      simulationIngestionEnabled: ingestionReads,
      simulationHealthEnabled: healthReads,
      liveConnectorsEnabled: access && liveEnabled(env),
      liveDataEnabled:
        access &&
        liveEnabled(env) &&
        principal.grants.some((g) => g.zoneId === "00000000000000000000000000000002"),
      executionEnabled: false,
      workbenchEnabled: workbenchEnabled(env),
    });
  }
  const featureResponse = await workbenchRoute(request, { db: context.db, env, principal });
  if (featureResponse) return featureResponse;
  if (path === "/api/overview" && request.method === "GET") {
    const zoneIds = principal.grants
      .filter((v) => permits(principal.role, "read", v.permission))
      .map((v) => v.zoneId);
    if (!zoneIds.length)
      return json({
        incidents: [],
        policy,
        environment: "simulation",
        seeded: true,
        aiRuns: 0,
        executedActions: 0,
      });
    const requestedZone = url.searchParams.get("zoneId");
    if (requestedZone) assertZone(principal, requestedZone);
    const allowed = requestedZone ? [requestedZone] : zoneIds;
    const rows = await context.db
      .prepare(
        `SELECT * FROM incidents WHERE environment = 'simulation' AND expires_at > strftime('%Y-%m-%dT%H:%M:%fZ','now') AND zone_id IN (${allowed.map(() => "?").join(",")}) ORDER BY last_seen DESC LIMIT 50`,
      )
      .bind(...allowed)
      .all();
    return json({
      incidents: rows.results.map((v) => incidentSchema.parse(v)),
      policy,
      environment: "simulation",
      seeded: true,
      aiRuns: 0,
      executedActions: 0,
    });
  }
  if (healthReads && path === "/api/ingestion/reconciliation" && request.method === "GET") {
    assertZone(principal, "fixture-zone");
    return json(
      await reconcileIngestion(
        context.evidence,
        context.db,
        access ? "cloud-pilot-20261029" : "local-raw",
      ),
    );
  }
  if (ingestionReads && path === "/api/ingestion/status" && request.method === "GET") {
    assertZone(principal, "fixture-zone");
    const scoped = access && healthReads;
    const keys = scoped ? [...pilotRawKeys] : [];
    const keyFilter = scoped ? ` AND object_key IN (${keys.map(() => "?").join(",")})` : "";
    const fields = healthReads
      ? "id,object_key,state,valid_rows,invalid_rows,attempts,last_error,metrics_json,received_at,first_attempt_at,last_attempt_at,processed_at,archived_at"
      : "id,object_key,state,valid_rows,invalid_rows,attempts,last_error,metrics_json";
    const objects = await context.db
      .prepare(
        `SELECT ${fields} FROM ingestion_objects WHERE expires_at>?${keyFilter} ORDER BY received_at DESC LIMIT 20`,
      )
      .bind(new Date().toISOString(), ...keys)
      .all();
    const failureFilter = scoped
      ? ` AND object_id IN (SELECT id FROM ingestion_objects WHERE object_key IN (${keys.map(() => "?").join(",")}))`
      : "";
    const failures = await context.db
      .prepare(
        `SELECT reason,created_at FROM ingestion_failures WHERE expires_at>?${failureFilter} ORDER BY created_at DESC LIMIT 20`,
      )
      .bind(new Date().toISOString(), ...keys)
      .all();
    return json({
      simulation: true,
      objects: healthReads
        ? objects.results.map((object) => ({
            ...object,
            observedWaitSeconds: observedWaitSeconds(
              object.received_at as string,
              object.first_attempt_at as string | null,
            ),
          }))
        : objects.results,
      failures: failures.results,
      cloudDeliveryVerified: false,
    });
  }
  const detail = /^\/api\/incidents\/([a-zA-Z0-9_-]{1,128})$/.exec(path);
  if (detail && request.method === "GET") {
    const row = await context.db
      .prepare(
        "SELECT * FROM incidents WHERE id = ? AND environment = 'simulation' AND expires_at > strftime('%Y-%m-%dT%H:%M:%fZ','now')",
      )
      .bind(detail[1])
      .first();
    if (!row) throw new HttpError(404, "incident_not_found", "Incident not found.");
    const incident = incidentSchema.parse(row);
    assertZone(principal, incident.zone_id);
    const timeline =
      ingestionReads && incident.id.startsWith("ingest-")
        ? (
            await context.db
              .prepare(
                "SELECT e.id,e.event_time,e.received_at,e.metadata_json,(SELECT COUNT(*) FROM ingestion_provenance p WHERE p.event_id=e.id) AS deliveryReferences FROM events e JOIN incident_events l ON l.event_id=e.id WHERE l.incident_id=? AND e.environment='simulation' AND e.zone_id=? AND e.expires_at>? ORDER BY e.event_time,e.id LIMIT 100",
              )
              .bind(incident.id, incident.zone_id, new Date().toISOString())
              .all()
          ).results
        : [];
    const evidence = await context.db
      .prepare(
        "SELECT id, kind, created_at FROM evidence_objects WHERE incident_id = ? AND environment = 'simulation'",
      )
      .bind(incident.id)
      .all();
    return json({
      incident,
      evidence: evidence.results,
      analysisPerformed: false,
      notice: "Seeded fixture. No AI investigation has run.",
      timeline,
    });
  }
  const evidenceRoute = /^\/api\/evidence\/([a-zA-Z0-9_-]{1,128})$/.exec(path);
  if (evidenceRoute && request.method === "GET") {
    const row = await context.db
      .prepare(
        "SELECT * FROM evidence_objects WHERE id = ? AND environment = 'simulation' AND expires_at > ?",
      )
      .bind(evidenceRoute[1], new Date().toISOString())
      .first<{ zone_id: string; environment: "simulation"; object_key: string; sha256: string }>();
    if (!row) throw new HttpError(404, "evidence_unavailable", "Evidence is absent or expired.");
    assertZone(principal, row.zone_id);
    const object = await evidenceBinding(context, row.environment, row.object_key).get(
      row.object_key,
    );
    if (!object)
      throw new HttpError(404, "evidence_unavailable", "Evidence object is unavailable.");
    if (object.size > 65536)
      throw new HttpError(413, "evidence_too_large", "Evidence exceeds the preview limit.");
    const bytes = await object.arrayBuffer();
    const digest = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)), (v) =>
      v.toString(16).padStart(2, "0"),
    ).join("");
    if (digest !== row.sha256)
      throw new HttpError(
        409,
        "evidence_digest_mismatch",
        "Evidence failed integrity verification.",
      );
    return json({
      environment: "simulation",
      evidence: JSON.parse(new TextDecoder().decode(bytes)),
    });
  }
  if (path === "/api/admin/users" && request.method === "GET") {
    requireAdmin(principal);
    const users = await env.APP_DB.prepare(
      "SELECT id, role, active, version FROM users ORDER BY id",
    ).all();
    return json({ users: users.results });
  }
  const roleRoute = /^\/api\/admin\/users\/([a-zA-Z0-9_-]{1,128})\/role$/.exec(path);
  if (roleRoute && request.method === "PATCH") {
    if (access)
      throw new HttpError(403, "membership_locked", "Owner-only pilot membership is fixed.");
    requireAdmin(principal);
    const targetId = roleRoute[1] || "";
    if (!identifier.test(targetId) || targetId === principal.id || targetId === "user-admin")
      throw new HttpError(403, "owner_role_locked", "The owner Admin fixture role is fixed.");
    const body = roleChangeSchema.safeParse(await readJson(request));
    if (!body.success)
      throw new HttpError(
        400,
        "invalid_role_change",
        "Supply a non-Admin role and current version.",
      );
    const current = await env.APP_DB.prepare("SELECT role, version FROM users WHERE id = ?")
      .bind(targetId)
      .first<{ role: string; version: number }>();
    if (!current) throw new HttpError(404, "user_not_found", "User not found.");
    if (current.version !== body.data.version)
      throw new HttpError(409, "version_conflict", "The role changed. Refresh before retrying.");
    const now = new Date();
    const expiry = new Date(now.getTime() + policy.evidenceRetentionDays * 86400000);
    const result = await env.APP_DB.batch([
      env.APP_DB.prepare(
        "UPDATE users SET role = ?, version = version + 1 WHERE id = ? AND version = ?",
      ).bind(body.data.role, targetId, body.data.version),
      env.APP_DB.prepare(
        "INSERT INTO audit_trail (id, actor_id, operation, target_id, details_json, created_at, expires_at) SELECT ?, ?, 'rbac.role.changed', ?, ?, ?, ? WHERE changes() = 1",
      ).bind(
        crypto.randomUUID(),
        principal.id,
        targetId,
        JSON.stringify({ from: current.role, to: body.data.role }),
        now.toISOString(),
        expiry.toISOString(),
      ),
    ]);
    if (result[0]?.meta.changes !== 1)
      throw new HttpError(409, "version_conflict", "The role changed. Refresh before retrying.");
    return json({ changed: true });
  }
  if (path === "/api/audit" && request.method === "GET") {
    requireAdmin(principal);
    const rows = await env.APP_DB.prepare(
      "SELECT id, actor_id, operation, target_id, details_json, created_at FROM audit_trail WHERE expires_at > ? ORDER BY created_at DESC LIMIT 50",
    )
      .bind(new Date().toISOString())
      .all();
    return json({ records: rows.results });
  }
  if (path === "/api/authorization/approval-check" && request.method === "POST") {
    const grant = principal.grants.find((v) => v.zoneId === "fixture-zone");
    if (!grant || !permits(principal.role, "approve", grant.permission))
      throw new HttpError(403, "approval_forbidden", "Your role cannot approve actions.");
    return json({
      roleAuthorized: true,
      approvalRecorded: false,
      executionEnabled: false,
      fixture: local,
    });
  }
  throw new HttpError(404, "not_found", "Route not found.");
}

function requireAdmin(principal: Principal): void {
  if (principal.role !== "Admin")
    throw new HttpError(403, "admin_required", "Admin permission is required.");
}

export default {
  async scheduled(_controller: ScheduledController, env: Bindings) {
    if (!workbenchEnabled(env) || env.SOC_MAINTENANCE_PROFILE === "external-workbench-v1")
      throw new Error("workbench_scheduler_disabled");
    const available = await env.SIMULATION_DB.prepare(
      "SELECT id FROM zones WHERE environment='simulation' AND account_id='fixture-account' AND enabled=1",
    ).all<{ id: string }>();
    await reconcileWorkbench({
      db: env.SIMULATION_DB,
      principal: {
        id: "system-simulation",
        role: "Admin",
        token: "",
        grants: available.results.map((z) => ({ zoneId: z.id, permission: "manage" as const })),
      },
    });
  },
  async fetch(request: Request, env: Bindings): Promise<Response> {
    const requestId = crypto.randomUUID();
    try {
      return protect(await route(request, env), requestId);
    } catch (error) {
      const known = error instanceof HttpError;
      return protect(
        json(
          {
            error: {
              code: known ? error.code : "internal_error",
              message: known ? error.message : "The request could not be completed.",
            },
            requestId,
          },
          known ? error.status : 500,
        ),
        requestId,
      );
    }
  },
} satisfies ExportedHandler<Bindings>;
