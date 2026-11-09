import {
  type LiveFacts,
  type LiveFinding,
  type LiveFollowUpWindow,
  type LiveObservations,
  type LiveOverview,
  livePriorities,
  liveProfile,
  liveZone,
} from "../../../../packages/shared/src/live";
import type { Principal } from "../auth";
import { assertZone } from "../data";
import type { Bindings } from "../env";
import { HttpError, json, readJson } from "../http";
import { digest, findings, httpErrorCounts, mitigationCount } from "./analytics";
import {
  investigate,
  investigationBudget,
  investigationState,
  liveAiEnabled,
} from "./investigation";
import { logsRoute, operationsRoute } from "./operations";
import { policyRoute } from "./policy";
import { repairRoute } from "./repair-route";

async function verifiedFacts(row: { facts_json: string; sha256: string }): Promise<LiveFacts> {
  if ((await digest(row.facts_json)) !== row.sha256)
    throw new HttpError(503, "evidence_integrity", "Evidence integrity verification failed.");
  return JSON.parse(row.facts_json) as LiveFacts;
}

async function followUp(
  db: D1Database,
  evidence: LiveFacts,
  rule: LiveFinding["rule"],
  now: string,
): Promise<LiveFollowUpWindow[]> {
  const end = Date.parse(evidence.end);
  if (!Number.isFinite(end))
    throw new HttpError(503, "evidence_integrity", "Evidence window is invalid.");
  const ends = [1, 2, 3].map((step) => new Date(end + step * 300000).toISOString());
  const snapshots = await db
    .prepare(
      "SELECT window_end,facts_json,sha256 FROM ld_snapshots WHERE zone_id=? AND expires_at>? AND window_end IN (?,?,?)",
    )
    .bind(liveZone, now, ...ends)
    .all<{ window_end: string; facts_json: string; sha256: string }>();
  return Promise.all(
    ends.map(async (windowEnd): Promise<LiveFollowUpWindow> => {
      const row = snapshots.results.find((snapshot) => snapshot.window_end === windowEnd);
      if (!row) return { end: windowEnd, state: "not_collected", count: null, total: null };
      const facts = await verifiedFacts(row);
      const isHttp = rule === "http-5xx-v1";
      const dataset = isHttp ? facts.http : facts.security;
      const http = httpErrorCounts(facts);
      if (dataset.state !== "available" || dataset.truncated || (isHttp && http.total === 0))
        return { end: windowEnd, state: "insufficient_data", count: null, total: null };
      return {
        end: windowEnd,
        state: findings(facts, row.sha256).some((finding) => finding.rule === rule)
          ? "threshold_met"
          : "below_threshold",
        count: isHttp ? http.failed : mitigationCount(facts),
        total: isHttp ? http.total : null,
      };
    }),
  );
}

export function liveEnabled(env: Bindings): boolean {
  return env.LIVE_PROFILE === liveProfile && !!env.LIVE_DB;
}

async function observations(db: D1Database, url: URL, now: string) {
  const priority = livePriorities.find((level) => level === url.searchParams.get("priority"));
  const before = url.searchParams.get("before");
  const windowMs = before?.match(/^(?:http-5xx-v1|mitigation-volume-v1)-(\d{1,15})$/)?.[1];
  if (
    [...url.searchParams.keys()].some((key) => !["priority", "before"].includes(key)) ||
    (url.searchParams.has("priority") && !priority) ||
    (before !== null && !windowMs)
  )
    throw new HttpError(400, "invalid_observation_filter", "Choose a valid priority and page.");
  const end = windowMs ? new Date(Number(windowMs)).toISOString() : null;
  const scope = "FROM ld_findings WHERE zone_id=? AND expires_at>?";
  const limit = 100;
  const [totals, page] = await db.batch([
    db.prepare(`SELECT severity, COUNT(*) AS total ${scope} GROUP BY severity`).bind(liveZone, now),
    db
      .prepare(`SELECT id,title,severity,summary,window_end AS windowEnd ${scope}
        ${priority ? "AND severity=?" : ""}
        ${end ? "AND (window_end<? OR (window_end=? AND id>?))" : ""}
        ORDER BY window_end DESC,id LIMIT ?`)
      .bind(
        liveZone,
        now,
        ...(priority ? [priority] : []),
        ...(end ? [end, end, before] : []),
        limit + 1,
      ),
  ]);
  if (!totals || !page) throw Error("Observation query did not return both results");
  const counts = { low: 0, medium: 0, high: 0 };
  for (const { severity, total } of totals.results as {
    severity: LiveFinding["severity"];
    total: number;
  }[]) {
    if (livePriorities.includes(severity)) counts[severity] = total;
  }
  const found = page.results as LiveObservations["findings"];
  const findings = found.slice(0, limit);
  return json({
    counts,
    findings,
    next: found.length > limit ? (findings.at(-1)?.id ?? null) : null,
  } satisfies LiveObservations);
}

export async function liveRoute(
  request: Request,
  env: Bindings,
  principal: Principal,
): Promise<Response> {
  if (!liveEnabled(env))
    throw new HttpError(
      503,
      "live_unavailable",
      "Live data collection is not configured. No simulation data is substituted.",
    );
  assertZone(principal, liveZone);
  const url = new URL(request.url);
  const db = env.LIVE_DB as D1Database;
  if (url.pathname === "/api/live/logs") return logsRoute(request, db);
  if (url.pathname === "/api/live/operations") return operationsRoute(request, db);
  if (url.pathname === "/api/live/repairs" || url.pathname.startsWith("/api/live/repairs/"))
    return repairRoute(request, env, db, principal);
  if (url.pathname === "/api/live/findings" && request.method === "GET")
    return observations(db, url, new Date().toISOString());
  if (
    (url.search && [...url.searchParams.keys()].some((k) => k !== "environment")) ||
    (url.searchParams.has("environment") && url.searchParams.get("environment") !== "live")
  )
    throw new HttpError(400, "invalid_scope", "This data source is fixed to d.example.invalid.");
  const now = new Date().toISOString();
  if (url.pathname === "/api/live/settings/policy") return policyRoute(request, db, principal);
  if (url.pathname === "/api/live/settings/ai" && request.method === "GET") {
    return json(await investigationBudget(db));
  }
  if (url.pathname === "/api/live/collection" && request.method === "POST") {
    if (principal.role !== "Admin")
      throw new HttpError(
        403,
        "collection_admin_required",
        "Only an admin can control collection.",
      );
    const body = (await readJson(request)) as { enabled?: unknown } | null;
    if (typeof body?.enabled !== "boolean" || Object.keys(body).length !== 1)
      throw new HttpError(
        400,
        "invalid_collection_state",
        "Specify whether collection is enabled.",
      );
    await db
      .prepare(
        "UPDATE ld_state SET collection_paused_at=?,lease_token=NULL,lease_until=NULL WHERE id=1 AND (collection_paused_at IS NULL) != ?",
      )
      .bind(body.enabled ? null : now, body.enabled ? 1 : 0)
      .run();
    const state = await db
      .prepare("SELECT collection_paused_at FROM ld_state WHERE id=1")
      .first<{ collection_paused_at: string | null }>();
    if (!state) throw new HttpError(503, "collector_missing", "Collection control is unavailable.");
    return json(state);
  }
  const detail =
    /^\/api\/live\/findings\/(http-5xx-v1-\d+|mitigation-volume-v1-\d+)(\/follow-up|\/investigation)?$/.exec(
      url.pathname,
    );
  const aiRequest = detail?.[2] === "/investigation";
  if (request.method !== "GET" && !(aiRequest && request.method === "POST"))
    throw new HttpError(405, "readonly_source", "This endpoint is read-only.");
  if (aiRequest && !liveAiEnabled(env))
    throw new HttpError(503, "live_ai_unavailable", "Live AI investigation is unavailable.");
  if (aiRequest && request.method === "POST" && principal.role !== "Admin")
    throw new HttpError(403, "live_ai_admin_required", "Only an admin can start an investigation.");
  if (detail) {
    const row = await db
      .prepare("SELECT * FROM ld_findings WHERE id=? AND zone_id=? AND expires_at>?")
      .bind(detail[1], liveZone, now)
      .first<{
        id: string;
        rule: LiveFinding["rule"];
        title: string;
        severity: LiveFinding["severity"];
        summary: string;
        evidence_json: string;
        sha256: string;
        expires_at: string;
      }>();
    if (!row)
      throw new HttpError(404, "finding_not_found", "This observation is unavailable or expired.");
    const evidence = await verifiedFacts({ facts_json: row.evidence_json, sha256: row.sha256 });
    const finding: LiveFinding = {
      id: row.id,
      rule: row.rule,
      title: row.title,
      severity: row.severity,
      summary: row.summary,
      evidence,
      sha256: row.sha256,
      expiresAt: row.expires_at,
    };
    if (detail[2] === "/follow-up")
      return json({ windows: await followUp(db, evidence, row.rule, now) });
    if (aiRequest) {
      if (request.method === "GET") return json(await investigationState(db, row.id));
      const windows = await followUp(db, evidence, row.rule, now);
      const evidenceWindows = windows.some((window) => window.count !== null) ? windows : [];
      return json(await investigate(env, db, finding, evidenceWindows));
    }
    return json({ environment: "live", ...finding });
  }
  if (url.pathname !== "/api/live/overview")
    throw new HttpError(404, "not_found", "Route not found.");
  const [state, latest, windows, found] = await Promise.all([
    db
      .prepare(
        "SELECT last_attempt,last_success,last_error,last_end,last_gap_seconds,collection_paused_at FROM ld_state WHERE id=1",
      )
      .first<NonNullable<LiveOverview["collector"]>>(),
    db
      .prepare(
        "SELECT facts_json,sha256 FROM ld_snapshots WHERE zone_id=? AND expires_at>? ORDER BY window_end DESC LIMIT 1",
      )
      .bind(liveZone, now)
      .first<{ facts_json: string; sha256: string }>(),
    db
      .prepare(
        "SELECT window_start AS start,window_end AS end,collected_at AS collectedAt,json_extract(facts_json,'$.security.state') AS securityState,json_extract(facts_json,'$.http.state') AS httpState FROM ld_snapshots WHERE zone_id=? AND expires_at>? ORDER BY window_end DESC LIMIT 24",
      )
      .bind(liveZone, now)
      .all<LiveOverview["windows"][number]>(),
    db
      .prepare(
        "SELECT id,rule,title,severity,summary,sha256,expires_at AS expiresAt FROM ld_findings WHERE zone_id=? AND expires_at>? ORDER BY window_end DESC,id LIMIT 100",
      )
      .bind(liveZone, now)
      .all<LiveOverview["findings"][number]>(),
  ]);
  if (latest && (await digest(latest.facts_json)) !== latest.sha256)
    throw new HttpError(503, "evidence_integrity", "Snapshot integrity verification failed.");
  return json({
    environment: "live",
    zoneId: liveZone,
    zoneName: "d.example.invalid",
    source: "cloudflare-graphql-adaptive",
    collector: state,
    latest: latest
      ? { facts: JSON.parse(latest.facts_json) as LiveFacts, sha256: latest.sha256 }
      : null,
    windows: windows.results,
    findings: found.results,
    stale: !state?.last_end || Date.now() - Date.parse(state.last_end) > 15 * 60000,
    aiEnabled: liveAiEnabled(env),
    executionEnabled: false,
  } satisfies LiveOverview);
}
