import { z } from "zod";
import { liveAccount } from "../../../packages/shared/src/live";
import { bytes, lines } from "./ndjson";
import { dateAfter, fail, hash, IngestError } from "./schema";

const bucket = "example-cloudflare-ai-soc-live";
const bounds = { compressed: 8 * 1048576, expanded: 32 * 1048576, lines: 10000, line: 32768 };
const objectRef = z.object({
  account: z.literal(liveAccount),
  bucket: z.literal(bucket),
  action: z.enum(["PutObject", "CopyObject", "CompleteMultipartUpload"]),
  eventTime: z.iso.datetime(),
  object: z.object({
    key: z
      .string()
      .max(240)
      .regex(
        /^raw\/(?:http|firewall)\/(?:(?:\d{8}|\d{4}-\d{2}-\d{2})\/)?(?:[a-zA-Z0-9_.-]+\.(?:log|ndjson)\.gz|test\.txt\.gz)$/,
      ),
    size: z.number().int().min(1),
    eTag: z.string().regex(/^[a-f0-9]{32}(?:-\d+)?$/),
  }),
});
type Reference = z.infer<typeof objectRef>;
type Dataset = "http" | "firewall";
const fields = z.object({
  RayID: z.string().regex(/^[a-f0-9]{16}$/i),
  ClientRequestHost: z
    .string()
    .max(253)
    .toLowerCase()
    .regex(/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*d\.example\.invalid$/),
  EdgeResponseStatus: z.number().int().min(0).max(599).optional(),
});
const http = fields.extend({ EdgeStartTimestamp: z.iso.datetime() });
const firewall = fields.extend({
  Datetime: z.iso.datetime(),
  MatchIndex: z.number().int().nonnegative(),
  Action: z.string().regex(/^[a-z0-9_-]{1,48}$/i),
  Source: z.string().regex(/^[a-z0-9_-]{1,48}$/i),
  RuleID: z.string().regex(/^[a-z0-9_-]{0,80}$/i),
});

interface Env {
  LIVE_DB: D1Database;
  LIVE_LOGS: R2Bucket;
  LIVE_LOG_PROFILE: string;
}
interface EventRow {
  identity: string;
  at: string;
  ray: string;
  host: string;
  status: number | null;
  action: string | null;
  source: string | null;
  rule: string | null;
}

function decode(line: string, dataset: Dataset, now: number): EventRow | null {
  let raw: unknown;
  try {
    raw = JSON.parse(line);
  } catch {
    return null;
  }
  const parsed = (dataset === "http" ? http : firewall).safeParse(raw);
  if (!parsed.success) return null;
  const row = parsed.data;
  const ts = "Datetime" in row ? row.Datetime : row.EdgeStartTimestamp;
  const at = Date.parse(ts);
  if (at <= now - 30 * 86400000 || at > now + 300000) return null;
  const ray = row.RayID.toLowerCase();
  const match = "MatchIndex" in row ? [row.MatchIndex, row.RuleID, row.Source, row.Action] : [];
  return {
    identity: JSON.stringify([dataset, ray, ts, row.ClientRequestHost, ...match]),
    at: new Date(at).toISOString(),
    ray,
    host: row.ClientRequestHost,
    status: row.EdgeResponseStatus ?? null,
    action: "Action" in row ? row.Action : null,
    source: "Source" in row ? row.Source : null,
    rule: "RuleID" in row ? row.RuleID || null : null,
  };
}

const datasetOf = (ref: Reference): Dataset =>
  ref.object.key.startsWith("raw/http/") ? "http" : "firewall";
const objectId = (ref: Reference) =>
  hash(JSON.stringify([ref.bucket, ref.object.key, ref.object.eTag]));

async function recordObject(
  db: D1Database,
  ref: Reference,
  outcome: string,
  accepted: number,
  rejected: number,
  error: string | null,
) {
  const at = new Date().toISOString();
  await db
    .prepare(`INSERT INTO ld_log_objects VALUES (?,?,?,?,?,?,?,?,?,?,?)
      ON CONFLICT(id) DO UPDATE SET processed_at=excluded.processed_at,accepted=excluded.accepted,
      rejected=excluded.rejected,outcome=excluded.outcome,error=excluded.error WHERE ld_log_objects.outcome='failed'`)
    .bind(
      await objectId(ref),
      datasetOf(ref),
      ref.object.key,
      ref.eventTime,
      at,
      ref.object.size,
      accepted,
      rejected,
      outcome,
      error,
      dateAfter(at, 90),
    )
    .run();
}

export async function importLogObject(env: Env, ref: Reference) {
  const id = await objectId(ref);
  const previous = await env.LIVE_DB.prepare("SELECT outcome FROM ld_log_objects WHERE id=?")
    .bind(id)
    .first<{ outcome: string }>();
  if (previous && previous.outcome !== "failed") return;
  const now = Date.now();
  const eventTime = Date.parse(ref.eventTime);
  if (eventTime <= now - 30 * 86400000 || eventTime > now + 300000)
    fail("object_time_outside_window");
  if (ref.object.size > bounds.compressed) fail("body_limit");
  const object = await env.LIVE_LOGS.get(ref.object.key, {
    onlyIf: { etagMatches: ref.object.eTag },
  });
  if (
    !object ||
    !("body" in object) ||
    object.etag !== ref.object.eTag ||
    object.size !== ref.object.size
  )
    throw Error("object_unavailable");
  const dataset = datasetOf(ref);
  const accepted: EventRow[] = [];
  let rejected = 0;
  for await (const line of lines(await bytes(object.body, bounds.compressed), true, bounds)) {
    if (!line.trim()) continue;
    const row = decode(line, dataset, now);
    if (row) accepted.push(row);
    else rejected++;
  }
  if (!accepted.length) {
    await recordObject(env.LIVE_DB, ref, "failed", 0, rejected, "no_valid_rows");
    return;
  }
  for (let offset = 0; offset < accepted.length; offset += 500) {
    const batch = accepted.slice(offset, offset + 500);
    const statements: D1PreparedStatement[] = [];
    for (let chunk = 0; chunk < batch.length; chunk += 9) {
      const group = batch.slice(chunk, chunk + 9);
      const values = await Promise.all(
        group.map(async (row) => [
          await hash(row.identity),
          dataset,
          row.at,
          row.ray,
          row.host,
          row.status,
          row.action,
          row.source,
          row.rule,
          id,
          dateAfter(row.at, 30),
        ]),
      );
      const placeholders = group.map(() => "(?,?,?,?,?,?,?,?,?,?,?)").join(",");
      statements.push(
        env.LIVE_DB.prepare(`INSERT INTO ld_log_events VALUES ${placeholders}
        ON CONFLICT(id) DO UPDATE SET object_id=excluded.object_id
        WHERE ld_log_events.object_id<>excluded.object_id AND NOT EXISTS(
          SELECT 1 FROM ld_log_objects WHERE id=ld_log_events.object_id AND outcome IN ('complete','partial'))`).bind(
          ...values.flat(),
        ),
      );
    }
    // A retried object can replay any completed batch without duplicating logical events.
    await env.LIVE_DB.batch(statements);
  }
  await recordObject(
    env.LIVE_DB,
    ref,
    rejected ? "partial" : "complete",
    accepted.length,
    rejected,
    rejected ? "invalid_rows" : null,
  );
}

export default {
  async queue(batch: MessageBatch<unknown>, env: Env) {
    if (
      env.LIVE_LOG_PROFILE !== "r2-logpush-v1" ||
      !["example-soc-ingest-live", "example-soc-ingest-live-dlq"].includes(batch.queue)
    ) {
      batch.retryAll();
      return;
    }
    for (const message of batch.messages) {
      const ref = objectRef.safeParse(message.body);
      // Cloudflare writes this probe when validating the Logpush destination.
      if (ref.success && ref.data.object.key.endsWith("/test.txt.gz")) {
        message.ack();
        continue;
      }
      try {
        if (!ref.success) {
          await env.LIVE_DB.prepare(`INSERT INTO ld_ops_state(task,last_attempt,error) VALUES ('logpush_notification',?,'invalid_notification')
            ON CONFLICT(task) DO UPDATE SET last_attempt=excluded.last_attempt,error=excluded.error`)
            .bind(new Date().toISOString())
            .run();
        } else if (batch.queue === "example-soc-ingest-live-dlq") {
          await recordObject(env.LIVE_DB, ref.data, "failed", 0, 0, "retry_exhausted");
        } else {
          await importLogObject(env, ref.data);
        }
        message.ack();
      } catch (error) {
        if (ref.success && error instanceof IngestError) {
          try {
            await recordObject(env.LIVE_DB, ref.data, "failed", 0, 0, error.message);
            message.ack();
          } catch {
            message.retry();
          }
        } else message.retry();
      }
    }
  },
} satisfies ExportedHandler<Env>;
