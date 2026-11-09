import { HttpError, json } from "../http";

export async function logsRoute(request: Request, db: D1Database) {
  if (request.method !== "GET")
    throw new HttpError(405, "invalid_method", "Log evidence is read-only.");
  const query = new URL(request.url).searchParams;
  const dataset = query.get("dataset") ?? "http";
  const ray = query.get("ray");
  const finding = query.get("finding");
  if (
    ![...query.keys()].every((key) => ["dataset", "ray", "finding"].includes(key)) ||
    !["http", "firewall"].includes(dataset) ||
    (ray !== null && !/^[a-f0-9]{16}$/i.test(ray))
  )
    throw new HttpError(
      400,
      "invalid_log_filter",
      "Select a dataset and optionally a valid Cloudflare Ray ID.",
    );
  const now = new Date().toISOString();
  let after = new Date(Date.now() - 86400000).toISOString(),
    before = now;
  if (finding !== null) {
    const row = await db
      .prepare("SELECT window_end FROM ld_findings WHERE id=? AND expires_at>?")
      .bind(finding, now)
      .first<{ window_end: string }>();
    if (!row)
      throw new HttpError(404, "finding_not_found", "This observation is unavailable or expired.");
    before = row.window_end;
    after = new Date(Date.parse(before) - 300000).toISOString();
  } else if (ray) after = new Date(Date.now() - 30 * 86400000).toISOString();
  const rows = await db
    .prepare(`SELECT e.id,e.occurred_at,e.ray_id,e.host,e.status,e.action,e.source,e.rule_id,o.object_key,o.object_at,o.outcome
    FROM ld_log_events e JOIN ld_log_objects o ON o.id=e.object_id
    WHERE e.dataset=? AND e.occurred_at>=? AND e.occurred_at<? AND e.expires_at>? AND o.outcome IN ('complete','partial')
    ${ray ? "AND e.ray_id=?" : ""} ORDER BY e.occurred_at DESC,e.id LIMIT 101`)
    .bind(dataset, after, before, now, ...(ray ? [ray.toLowerCase()] : []))
    .all();
  return json({
    dataset,
    after,
    before,
    truncated: rows.results.length > 100,
    events: rows.results.slice(0, 100),
  });
}

type SourceHealth = { lastObject: string | null; lastSuccess: string | null; errors: number };
type Task = {
  task: string;
  last_attempt: string;
  last_success: string | null;
  error: string | null;
  removed: number;
};

export async function operationsRoute(request: Request, db: D1Database) {
  if (request.method !== "GET")
    throw new HttpError(405, "invalid_method", "Operations status is read-only.");
  if (new URL(request.url).search)
    throw new HttpError(400, "invalid_scope", "Operations status has a fixed scope.");
  const now = Date.now(),
    at = new Date(now).toISOString(),
    hourAgo = new Date(now - 3600000).toISOString();
  const [analytics, sourceEntries, tasks, repair] = await Promise.all([
    db
      .prepare(
        "SELECT last_attempt,last_success,last_error,collection_paused_at FROM ld_state WHERE id=1",
      )
      .first<{
        last_success: string | null;
        last_error: string | null;
        collection_paused_at: string | null;
      }>(),
    Promise.all(
      ["http", "firewall"].map(async (dataset) => {
        const row = await db
          .prepare(`SELECT
        (SELECT processed_at FROM ld_log_objects WHERE dataset=? ORDER BY processed_at DESC LIMIT 1) AS lastObject,
        (SELECT processed_at FROM ld_log_objects WHERE dataset=? AND outcome IN ('complete','partial') ORDER BY processed_at DESC LIMIT 1) AS lastSuccess,
        (SELECT COUNT(*) FROM ld_log_objects WHERE dataset=? AND processed_at>=? AND outcome!='complete') AS errors`)
          .bind(dataset, dataset, dataset, hourAgo)
          .first<SourceHealth>();
        return [dataset, row ?? { lastObject: null, lastSuccess: null, errors: 0 }] as const;
      }),
    ),
    db.prepare("SELECT * FROM ld_ops_state ORDER BY task").all<Task>(),
    db
      .prepare(
        "SELECT COUNT(*) AS total FROM ld_repairs WHERE status='review' OR (rule_expires_at<=? AND status IN ('applying','verified','rolling_back'))",
      )
      .bind(at)
      .first<{ total: number }>(),
  ]);
  const alerts: string[] = [];
  if (!analytics?.collection_paused_at) {
    if (analytics?.last_error) alerts.push(`Analytics reported ${analytics.last_error}.`);
    else if (!analytics?.last_success || now - Date.parse(analytics.last_success) > 15 * 60000)
      alerts.push("Analytics has no successful run in the last 15 minutes.");
  }
  for (const [dataset, state] of sourceEntries) {
    if (state.errors)
      alerts.push(
        `${dataset.toUpperCase()} had ${state.errors} incomplete or rejected deliveries in the last hour.`,
      );
    if (state.lastSuccess && now - Date.parse(state.lastSuccess) > 3600000)
      alerts.push(
        `${dataset.toUpperCase()} has received no usable batch in the last hour. Check job health and traffic.`,
      );
  }
  const retention = tasks.results.find((task) => task.task === "retention");
  if (
    !retention?.last_success ||
    now - Date.parse(retention.last_success) > 75 * 60000 ||
    retention.error
  )
    alerts.push("Retention cleanup needs attention.");
  const notifications = tasks.results.find((task) => task.task === "logpush_notification");
  if (notifications?.error && notifications.last_attempt >= hourAgo)
    alerts.push("An invalid R2 notification was rejected in the last hour.");
  if (repair?.total)
    alerts.push(`${repair.total} repair action(s) need expiry verification or operator review.`);
  return json({
    analytics,
    sources: Object.fromEntries(sourceEntries),
    tasks: tasks.results,
    alerts,
  });
}
