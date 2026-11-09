import { z } from "zod";
import { bytes, lines } from "./ndjson";
import {
  type Env,
  localEnabled,
  metered,
  profile,
  retentionWritesEnabled,
  timingEnabled,
  type Usage,
} from "./profile";
import {
  bucketName,
  dateAfter,
  fail,
  hash,
  IngestError,
  limits,
  normalize,
  notificationSchema,
  type Reference,
  refSchema,
} from "./schema";

type ObjectRow = {
  id: string;
  object_key: string;
  etag: string;
  dataset: string;
  received_at: string;
  raw_expires_at: string;
  expires_at: string;
  state: string;
};
const now = () => new Date().toISOString();
function queueBinding(env: Env) {
  if (!env.INGEST_QUEUE) return fail("producer_unavailable");
  return env.INGEST_QUEUE;
}
const reason = (error: unknown) =>
  error instanceof IngestError ? error.message : "processing_unavailable";
const idFor = (ref: Reference) =>
  hash(JSON.stringify([ref.bucket, ref.object.key, ref.object.eTag]));
function sourceWriteOpen(row: ObjectRow) {
  return (
    row.raw_expires_at === dateAfter(row.received_at, 30) &&
    row.expires_at === dateAfter(row.received_at, 90) &&
    row.raw_expires_at > now()
  );
}
async function persist(env: Env, row: ObjectRow, input: unknown, line: number) {
  if (retentionWritesEnabled(env) && !sourceWriteOpen(row)) fail("object_expired");
  const candidate = normalize(input, row.dataset);
  const time = Date.parse(candidate.time);
  if (time < Date.now() - 30 * 86400000 || time > Date.now() + 300000)
    fail("event_time_outside_window");
  const eventKey = await hash(
    JSON.stringify([
      "fixture-account",
      "fixture-zone",
      candidate.emulatedSource,
      ...candidate.identity,
    ]),
  );
  const eventId = `event-${eventKey}`;
  const incidentId = `ingest-${await hash(JSON.stringify(["fixture-account", "fixture-zone", candidate.emulatedSource, candidate.category, candidate.client, Math.floor(time / 300000)]))}`;
  const prior = await env.SIMULATION_DB.prepare(
    "SELECT event_expires_at FROM ingestion_event_keys WHERE event_key=?",
  )
    .bind(eventKey)
    .first<{ event_expires_at: string }>();
  if (prior && prior.event_expires_at <= now()) fail("event_expired");
  const evidence = JSON.stringify({
    fixture: true,
    environment: "simulation",
    source: "synthetic",
    ...candidate,
  });
  const digest = await hash(evidence);
  const key = `${profile(env).prefix}cases/ingested/${eventKey}.json`;
  const existing = await env.SIMULATION_STORE.get(key);
  if (existing) {
    if (
      existing.size > limits.line ||
      (await hash(await bytes(existing.body, limits.line))) !== digest
    )
      fail("evidence_conflict");
  } else {
    const written = await env.SIMULATION_STORE.put(key, evidence, {
      onlyIf: { etagDoesNotMatch: "*" },
      httpMetadata: { contentType: "application/json" },
    });
    if (!written) {
      const concurrent = await env.SIMULATION_STORE.get(key);
      if (!concurrent || (await hash(await bytes(concurrent.body, limits.line))) !== digest)
        fail("evidence_conflict");
    }
  }
  const eventExpiry = dateAfter(row.received_at, 30),
    caseExpiry = dateAfter(row.received_at, 90);
  const metadata = JSON.stringify({
    fixture: true,
    emulatedSource: candidate.emulatedSource,
    client: candidate.client,
    path: candidate.path,
    schemaVersion: 1,
  });
  // No increment counters: links are unique, so concurrent deliveries cannot double-count.
  await env.SIMULATION_DB.batch([
    env.SIMULATION_DB.prepare("INSERT OR IGNORE INTO ingestion_event_keys VALUES (?,?,?,?)").bind(
      eventKey,
      eventId,
      eventExpiry,
      caseExpiry,
    ),
    env.SIMULATION_DB.prepare(
      "INSERT OR IGNORE INTO events SELECT ?, 'simulation','fixture-zone','synthetic',?,?,?,?,?,event_expires_at FROM ingestion_event_keys WHERE event_key=? AND event_expires_at>?",
    ).bind(
      eventId,
      candidate.category,
      candidate.time,
      row.received_at,
      eventKey,
      metadata,
      eventKey,
      now(),
    ),
    env.SIMULATION_DB.prepare(
      "INSERT OR IGNORE INTO incidents SELECT ?, 'simulation','fixture-zone',?,?,'info','new',?,?,'Synthetic ingestion: deterministic grouping only; no AI classification or action.',NULL,? WHERE EXISTS (SELECT 1 FROM events WHERE id=? AND expires_at>?)",
    ).bind(
      incidentId,
      `Synthetic ${candidate.emulatedSource} signals`,
      candidate.category,
      candidate.time,
      candidate.time,
      caseExpiry,
      eventId,
      now(),
    ),
    env.SIMULATION_DB.prepare(
      "INSERT OR IGNORE INTO incident_events SELECT ?,?,'simulation','fixture-zone' WHERE EXISTS (SELECT 1 FROM events WHERE id=? AND expires_at>?)",
    ).bind(incidentId, eventId, eventId, now()),
    env.SIMULATION_DB.prepare(
      "UPDATE incidents SET first_seen=(SELECT MIN(event_time) FROM events JOIN incident_events ON events.id=incident_events.event_id WHERE incident_id=?), last_seen=(SELECT MAX(event_time) FROM events JOIN incident_events ON events.id=incident_events.event_id WHERE incident_id=?) WHERE id=?",
    ).bind(incidentId, incidentId, incidentId),
    env.SIMULATION_DB.prepare(
      "INSERT OR IGNORE INTO evidence_objects SELECT ?,?,'simulation','fixture-zone',?,'cases',?,?,? WHERE EXISTS (SELECT 1 FROM events WHERE id=? AND expires_at>?)",
    ).bind(
      `evidence-${eventKey}`,
      incidentId,
      key,
      digest,
      row.received_at,
      caseExpiry,
      eventId,
      now(),
    ),
    env.SIMULATION_DB.prepare(
      "INSERT OR IGNORE INTO ingestion_provenance SELECT ?,?,? WHERE EXISTS (SELECT 1 FROM events WHERE id=? AND expires_at>?)",
    ).bind(row.id, eventId, line, eventId, now()),
  ]);
}

async function processObject(env: Env, value: unknown, usage: () => Usage) {
  const started = now();
  const observed = timingEnabled(env);
  const active = profile(env);
  const parsed = active.schema.safeParse(value);
  if (!parsed.success) fail("reference_rejected");
  const ref = parsed.data;
  const object = await env.SIMULATION_STORE.get(ref.object.key);
  if (!object) fail("object_missing");
  if (object.etag !== ref.object.eTag || object.size !== ref.object.size) fail("object_replaced");
  const id = await idFor(ref),
    received = object.uploaded.toISOString();
  const dataset = ref.object.key.split("/")[1] || "";
  await env.SIMULATION_DB.prepare(
    observed
      ? "INSERT OR IGNORE INTO ingestion_objects (id,object_key,etag,dataset,received_at,raw_expires_at,expires_at,state,first_attempt_at) VALUES (?,?,?,?,?,?,?,'processing',?)"
      : "INSERT OR IGNORE INTO ingestion_objects (id,object_key,etag,dataset,received_at,raw_expires_at,expires_at,state) VALUES (?,?,?,?,?,?,?,'processing')",
  )
    .bind(
      id,
      ref.object.key,
      ref.object.eTag,
      dataset,
      received,
      dateAfter(received, 30),
      dateAfter(received, 90),
      ...(observed ? [started] : []),
    )
    .run();
  const row = await env.SIMULATION_DB.prepare("SELECT * FROM ingestion_objects WHERE id=?")
    .bind(id)
    .first<ObjectRow>();
  if (!row) fail("checkpoint_unavailable");
  if (row.raw_expires_at <= now()) fail("object_expired");
  if (row.state === "complete") return;
  let valid = 0,
    invalid = 0;
  await env.SIMULATION_DB.prepare(
    observed
      ? "UPDATE ingestion_objects SET attempts=attempts+1,last_attempt_at=? WHERE id=?"
      : "UPDATE ingestion_objects SET attempts=attempts+1 WHERE id=?",
  )
    .bind(...(observed ? [started, id] : [id]))
    .run();
  try {
    const content = await bytes(object.body, active.limits.compressed);
    const digest = await hash(content);
    await env.SIMULATION_DB.prepare("UPDATE ingestion_objects SET digest=? WHERE id=?")
      .bind(digest, id)
      .run();
    let line = 0;
    for await (const text of lines(content, ref.object.key.endsWith(".gz"), active.limits)) {
      line++;
      try {
        let record: unknown;
        try {
          record = JSON.parse(text);
        } catch {
          fail("invalid_json");
        }
        await persist(env, row, record, line);
        valid++;
      } catch (error) {
        if (!(error instanceof IngestError)) throw error;
        invalid++;
      }
    }
    if (!valid || invalid) fail(invalid ? "invalid_rows" : "empty_object");
    await env.SIMULATION_DB.prepare(
      observed
        ? "UPDATE ingestion_objects SET state='complete',valid_rows=?,invalid_rows=?,metrics_json=?,last_error=NULL,processed_at=? WHERE id=?"
        : "UPDATE ingestion_objects SET state='complete',valid_rows=?,invalid_rows=?,metrics_json=?,last_error=NULL WHERE id=?",
    )
      .bind(valid, invalid, JSON.stringify(usage()), ...(observed ? [now()] : []), id)
      .run();
  } catch (error) {
    await env.SIMULATION_DB.prepare(
      "UPDATE ingestion_objects SET state=?,valid_rows=?,invalid_rows=?,last_error=?,metrics_json=? WHERE id=? AND state<>'complete'",
    )
      .bind(
        valid ? "partial" : "failed",
        valid,
        invalid,
        reason(error),
        JSON.stringify(usage()),
        id,
      )
      .run();
    throw error;
  }
}

async function archive(env: Env, value: unknown) {
  const parsed = profile(env).schema.safeParse(value);
  const id = await hash(JSON.stringify(value));
  const objectId = parsed.success ? await idFor(parsed.data) : null;
  const row = objectId
    ? await env.SIMULATION_DB.prepare("SELECT * FROM ingestion_objects WHERE id=?")
        .bind(objectId)
        .first<ObjectRow & { last_error: string }>()
    : null;
  if (row?.state === "complete") return; // A concurrent delivery already completed it.
  if (retentionWritesEnabled(env) && (!parsed.success || !row || !sourceWriteOpen(row))) {
    const skipped = now();
    await env.SIMULATION_DB.prepare(
      "INSERT OR IGNORE INTO audit_trail VALUES (?,NULL,'ingestion.archive.skipped',?,'{\"reason\":\"source_missing_or_expired\"}',?,?)",
    )
      .bind(`archive-skipped-${id}`, objectId ?? id, skipped, dateAfter(skipped, 90))
      .run();
    return; // Do not recreate a missing source or start a new ninety-day retention clock.
  }
  const created = row?.received_at ?? now();
  const key = `${profile(env).prefix}tool-snapshots/ingest-failures/${id}.json`;
  const report = {
    fixture: true,
    objectId,
    reason: row?.last_error || (parsed.success ? "object_unavailable" : "reference_rejected"),
    rawReference: parsed.success ? parsed.data.object.key : null,
  };
  // Only bounded, allowlisted references and error codes, never untrusted payloads.
  if (retentionWritesEnabled(env)) {
    const content = JSON.stringify(report);
    const expected = await hash(content);
    const written = await env.SIMULATION_STORE.put(key, content, {
      onlyIf: { etagDoesNotMatch: "*" },
      httpMetadata: { contentType: "application/json" },
    });
    if (!written) {
      const existing = await env.SIMULATION_STORE.get(key);
      if (
        !existing ||
        existing.size > 8192 ||
        (await hash(await bytes(existing.body, 8192))) !== expected
      )
        fail("archive_conflict");
    }
  } else await env.SIMULATION_STORE.put(key, JSON.stringify(report));
  await env.SIMULATION_DB.batch([
    env.SIMULATION_DB.prepare("INSERT OR IGNORE INTO ingestion_failures VALUES (?,?,?,?,?,?)").bind(
      id,
      objectId,
      report.reason,
      key,
      created,
      dateAfter(created, 90),
    ),
    env.SIMULATION_DB.prepare(
      timingEnabled(env)
        ? "UPDATE ingestion_objects SET state='archived',archived_at=COALESCE(archived_at,?) WHERE id=? AND state<>'complete'"
        : "UPDATE ingestion_objects SET state='archived' WHERE id=? AND state<>'complete'",
    ).bind(...(timingEnabled(env) ? [now(), objectId] : [objectId])),
  ]);
}
async function enqueue(env: Env, key: string, content: Uint8Array) {
  const written = await env.SIMULATION_STORE.put(key, content, {
    onlyIf: { etagDoesNotMatch: "*" },
  });
  const object = written || (await env.SIMULATION_STORE.get(key));
  if (!object) fail("object_unavailable");
  if (
    !written &&
    (await hash(await bytes((object as R2ObjectBody).body, limits.compressed))) !==
      (await hash(content))
  )
    fail("object_conflict");
  const ref = refSchema.parse({
    account: "fixture-account",
    bucket: bucketName,
    action: "PutObject",
    object: { key, size: object.size, eTag: object.etag },
    eventTime: object.uploaded.toISOString(),
  });
  await queueBinding(env).send(ref);
  return { objectId: await idFor(ref), queued: true, simulation: true };
}
async function authorized(request: Request, env: Env) {
  if (!localEnabled(env) || new URL(request.url).origin !== "http://127.0.0.1:8788") return false;
  const origin = request.headers.get("Origin");
  if (origin && origin !== "http://127.0.0.1:8788") return false;
  // Hash equal-length buffers, then use Workers' constant-time comparison.
  const supplied = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(request.headers.get("cf-webhook-auth") || ""),
  );
  const expected = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(env.LOCAL_INGEST_SECRET),
  );
  return crypto.subtle.timingSafeEqual(supplied, expected);
}
export default {
  async fetch(request: Request, env: Env) {
    const reply = (value: unknown, status = 200) =>
      Response.json(value, {
        status,
        headers: {
          "Cache-Control": "no-store",
          "X-Content-Type-Options": "nosniff",
          "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
        },
      });
    if (!(await authorized(request, env))) return reply({ error: "local_ingest_denied" }, 403);
    try {
      const path = new URL(request.url).pathname;
      if (request.method === "GET" && path === "/status") {
        const objects = await env.SIMULATION_DB.prepare(
          "SELECT id,object_key,state,valid_rows,invalid_rows,attempts,last_error FROM ingestion_objects WHERE expires_at>? ORDER BY received_at DESC LIMIT 20",
        )
          .bind(now())
          .all();
        const failures = await env.SIMULATION_DB.prepare(
          "SELECT id,reason,object_id FROM ingestion_failures WHERE expires_at>? LIMIT 20",
        )
          .bind(now())
          .all();
        return reply({ simulation: true, objects: objects.results, failures: failures.results });
      }
      if (request.method !== "POST" || !request.body) return reply({ error: "not_found" }, 404);
      let input: unknown;
      try {
        input = JSON.parse(new TextDecoder().decode(await bytes(request.body, 65536)));
      } catch (error) {
        if (error instanceof IngestError) throw error;
        return reply({ error: "invalid_json" }, 400);
      }
      if (path === "/notification") {
        if (
          z
            .strictObject({ fixture: z.literal(true), text: z.literal("webhook test") })
            .safeParse(input).success
        )
          return reply({ testOnly: true, incidentCreated: false });
        const parsed = notificationSchema.safeParse(input);
        if (!parsed.success) return reply({ error: "invalid_notification" }, 400);
        const key = `raw/notification/${await hash(JSON.stringify(parsed.data))}.ndjson`;
        return reply(
          await enqueue(env, key, new TextEncoder().encode(`${JSON.stringify(parsed.data)}\n`)),
          202,
        );
      }
      if (path === "/__local/object") {
        const data = z
          .strictObject({
            key: refSchema.shape.object.shape.key,
            records: z.array(z.unknown()).min(1).max(1000),
            gzip: z.boolean(),
            fault: z.literal("invalid-json").optional(),
          })
          .safeParse(input);
        if (!data.success || data.data.key.endsWith(".gz") !== data.data.gzip)
          return reply({ error: "fixture_rejected" }, 400);
        for (const record of data.data.records)
          normalize(record, data.data.key.split("/")[1] || "");
        let content = new TextEncoder().encode(
          `${data.data.records.map((v) => JSON.stringify(v)).join("\n")}\n${data.data.fault ? "{broken\n" : ""}`,
        );
        if (data.data.gzip)
          content = await bytes(
            new Blob([content]).stream().pipeThrough(new CompressionStream("gzip")),
            limits.compressed,
          );
        return reply(await enqueue(env, data.data.key, content), 202);
      }
      if (path === "/__local/replay") {
        const parsed = z
          .strictObject({ objectId: z.string().regex(/^[a-f0-9]{64}$/) })
          .safeParse(input);
        if (!parsed.success) return reply({ error: "invalid_replay" }, 400);
        const row = await env.SIMULATION_DB.prepare("SELECT * FROM ingestion_objects WHERE id=?")
          .bind(parsed.data.objectId)
          .first<ObjectRow>();
        if (!row || row.raw_expires_at <= now())
          return reply({ error: "replay_expired_or_missing" }, 410);
        const object = await env.SIMULATION_STORE.head(row.object_key);
        if (!object || object.etag !== row.etag)
          return reply({ error: "object_replaced_or_missing" }, 409);
        const ref = refSchema.parse({
          account: "fixture-account",
          bucket: bucketName,
          action: "PutObject",
          object: { key: row.object_key, size: object.size, eTag: row.etag },
          eventTime: row.received_at,
        });
        const replayId = crypto.randomUUID(),
          created = now();
        await env.SIMULATION_DB.prepare("INSERT INTO ingestion_replays VALUES (?,?,'pending',?,?)")
          .bind(replayId, row.id, created, dateAfter(created, 90))
          .run();
        try {
          await queueBinding(env).send(ref);
        } catch {
          await env.SIMULATION_DB.prepare("UPDATE ingestion_replays SET state='failed' WHERE id=?")
            .bind(replayId)
            .run();
          fail("queue_unavailable");
        }
        await env.SIMULATION_DB.prepare("UPDATE ingestion_replays SET state='queued' WHERE id=?")
          .bind(replayId)
          .run();
        return reply({ replayId, queued: true }, 202);
      }
      return reply({ error: "not_found" }, 404);
    } catch (error) {
      return reply({ error: reason(error) }, error instanceof IngestError ? 422 : 503);
    }
  },
  async queue(batch: MessageBatch, env: Env) {
    const active = profile(env);
    if (
      ![active.queue, active.dlq].includes(batch.queue) ||
      (active.cloud && batch.messages.length !== 1)
    )
      throw new Error("Simulation runtime unavailable");
    for (const message of batch.messages) {
      const measured = metered(env);
      try {
        if (batch.queue === active.dlq) await archive(measured.env, message.body);
        else await processObject(measured.env, message.body, measured.snapshot);
        message.ack();
      } catch {
        message.retry();
      }
    }
  },
} satisfies ExportedHandler<Env>;
