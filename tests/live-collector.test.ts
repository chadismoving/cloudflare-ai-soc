import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";
import { convertV4MiniflareOptions, Miniflare } from "miniflare";
import { afterEach, beforeEach, expect, it } from "vitest";
import type { Bindings } from "../apps/api/src/env";
import { executeRepair, reconcileRepairs } from "../apps/api/src/live/repair-worker";
import { liveRoute } from "../apps/api/src/live/route";
import logpush, { importLogObject } from "../apps/ingest/src/live-logpush-worker";
import {
  type LiveObservations,
  liveAccount,
  liveInvestigationModel,
  liveProfile,
  liveZone,
} from "../packages/shared/src/live";
import { defaultLivePolicy, type LivePolicy } from "../packages/shared/src/live-policy";

const root = fileURLToPath(new URL("../", import.meta.url));
let mf: Miniflare,
  db: Awaited<ReturnType<Miniflare["getD1Database"]>>,
  calls = 0,
  mode = "ok";
let hold: { started: () => void; wait: Promise<void> } | undefined;
beforeEach(async () => {
  calls = 0;
  mode = "ok";
  hold = undefined;
  mf = new Miniflare({
    ...convertV4MiniflareOptions({
      modules: true,
      scriptPath: root + ".local/live-build/collector/collector-worker.js",
      compatibilityDate: "2026-10-27",
      compatibilityFlags: ["nodejs_compat"],
      cf: false,
      bindings: { LIVE_PROFILE: liveProfile, GRAPHQL_READ_TOKEN: "synthetic-only-credential" },
      d1Databases: { LIVE_DB: "live-test" },
      r2Buckets: { LIVE_LOGS: "isolated-test-logs" },
      outboundService: async (req: Request) => {
        expect(req.url).toBe("https://api.cloudflare.com/client/v4/graphql");
        calls++;
        if (hold) {
          hold.started();
          await hold.wait;
        }
        const query = ((await req.json()) as { query: string }).query;
        const security = query.includes("firewallEvents"),
          key = security ? "firewallEventsAdaptiveGroups" : "httpRequestsAdaptiveGroups";
        if (mode === "failed" || (mode === "partial" && security))
          return Response.json({ errors: [{ message: "private-provider-error" }] });
        return Response.json({
          data: {
            viewer: {
              zones: [
                {
                  [key]: security
                    ? [{ count: 101, dimensions: { action: "block", source: "firewallCustom" } }]
                    : [{ count: 200, dimensions: { edgeResponseStatus: 200 } }],
                },
              ],
            },
          },
          errors: null,
        });
      },
    }),
    host: "127.0.0.1",
    port: 0,
    telemetry: { enabled: false },
  });
  db = await mf.getD1Database("LIVE_DB");
  for (const file of [
    "0001_live_analytics.sql",
    "0002_collection_pause.sql",
    "0003_live_ai.sql",
    "0004_live_operations.sql",
    "0005_live_policy.sql",
  ]) {
    for (const statement of (
      await readFile(`${root}infrastructure/live-migrations/${file}`, "utf8")
    )
      .split(";")
      .map((s) => s.trim())
      .filter(Boolean))
      await db.prepare(statement).run();
  }
});
afterEach(async () => {
  await mf?.dispose();
});
const run = async () => {
  expect((await (await mf.getWorker()).scheduled({ cron: "*/5 * * * *" })).outcome).toBe("ok");
};
const admin = {
  id: "local-admin",
  role: "Admin",
  token: "unused",
  grants: [{ zoneId: liveZone, permission: "read" }],
} as const;
function liveRequest(path: string, body?: Record<string, string>) {
  return liveRoute(
    new Request(`https://soc.d.example.invalid/api/live${path}`, {
      method: body ? "POST" : "GET",
      ...(body && { body: JSON.stringify(body), headers: { "Content-Type": "application/json" } }),
    }),
    { LIVE_PROFILE: liveProfile, LIVE_DB: db } as unknown as Bindings,
    { ...admin, grants: [...admin.grants] },
  );
}

function saveLivePolicy(version: number, policy: LivePolicy, role: "Admin" | "Viewer" = "Admin") {
  return liveRoute(
    new Request("https://soc.d.example.invalid/api/live/settings/policy", {
      method: "PUT",
      body: JSON.stringify({ version, policy }),
      headers: { "Content-Type": "application/json" },
    }),
    { LIVE_PROFILE: liveProfile, LIVE_DB: db } as unknown as Bindings,
    { ...admin, role, grants: [...admin.grants] },
  );
}

it("saves independent live policy once per version and audits administrator changes", async () => {
  const read = () => liveRequest("/settings/policy").then((response) => response.json());
  expect(await read()).toEqual({ version: 0, policy: defaultLivePolicy });
  const policy = { ...defaultLivePolicy, monthlyBudgetUsd: 12.5, killSwitch: true };
  await expect(saveLivePolicy(0, policy, "Viewer")).rejects.toMatchObject({ status: 403 });
  await expect(saveLivePolicy(0, { ...policy, maxDurationSeconds: 601 })).rejects.toMatchObject({
    status: 400,
  });
  const concurrent = await Promise.allSettled([
    saveLivePolicy(0, policy),
    saveLivePolicy(0, policy),
  ]);
  expect(concurrent.filter((result) => result.status === "fulfilled")).toHaveLength(1);
  expect(concurrent.find((result) => result.status === "rejected")).toMatchObject({
    reason: { status: 409 },
  });
  expect(await read()).toEqual({ version: 1, policy });
  expect(
    (await db.prepare("SELECT version,changed_by FROM ld_policy_audit").all()).results,
  ).toEqual([{ version: 1, changed_by: admin.id }]);
});

it("ingests gzip batches, preserves match identity and provenance, and expires individual rows", async () => {
  const bucket = await mf.getR2Bucket("LIVE_LOGS");
  const occurred = new Date(Date.now() - 60000).toISOString();
  const sample = {
    RayID: "1234567890abcdef",
    ClientRequestHost: "demo.d.example.invalid",
    Datetime: occurred,
    EdgeResponseStatus: 403,
    MatchIndex: 0,
    RuleID: "rule-1",
    Action: "block",
    Source: "firewallmanaged",
    ClientIP: "192.0.2.31",
  };
  const gzip = Uint8Array.from(
    gzipSync(
      [JSON.stringify(sample), JSON.stringify({ ...sample, MatchIndex: 1 }), "malformed"].join(
        "\n",
      ),
    ),
  );
  const key = "raw/firewall/20260101/20260101T000000Z_20260101T000100Z_00000000.log.gz";
  const obj = await bucket.put(key, gzip);
  const storage = {
    LIVE_DB: db,
    LIVE_LOGS: bucket,
    LIVE_LOG_PROFILE: "r2-logpush-v1",
  } as unknown as Parameters<typeof importLogObject>[0];
  const ref = {
    account: liveAccount,
    bucket: "example-cloudflare-ai-soc-live",
    action: "PutObject",
    eventTime: new Date().toISOString(),
    object: { key, eTag: obj.etag, size: gzip.length },
  } as const;
  const acknowledgments: string[] = [];
  const messages = [
    ref,
    { ...ref, object: { ...ref.object, key: "raw/firewall/00010101/test.txt.gz" } },
  ].map((body) => ({
    body,
    ack: () => acknowledgments.push(body.object.key),
    retry: () => {
      throw new Error("Logpush notification should be acknowledged");
    },
  }));
  await logpush.queue(
    { queue: "example-soc-ingest-live", messages } as unknown as MessageBatch,
    storage,
  );
  expect(acknowledgments).toEqual([key, "raw/firewall/00010101/test.txt.gz"]);
  expect(
    await db.prepare("SELECT error FROM ld_ops_state WHERE task='logpush_notification'").first(),
  ).toBeNull();
  await importLogObject(storage, ref);
  const other = await bucket.put("raw/firewall/duplicate.log.gz", gzip);
  await importLogObject(storage, {
    ...ref,
    object: { ...ref.object, key: other.key, eTag: other.etag },
  });
  const received = (await (
    await liveRequest("/logs?dataset=firewall&ray=1234567890abcdef")
  ).json()) as { events: Record<string, unknown>[] };
  expect(received.events).toHaveLength(2);
  expect(received.events[0]).toMatchObject({
    object_key: key,
    rule_id: "rule-1",
    outcome: "partial",
  });
  expect(JSON.stringify(received)).not.toContain(sample.ClientIP);
  await db.prepare("UPDATE ld_log_events SET expires_at='2000-01-01T00:00:00.000Z'").run();
  await run();
  expect(await db.prepare("SELECT COUNT(*) AS total FROM ld_log_events").first()).toEqual({
    total: 0,
  });
  expect(await db.prepare("SELECT COUNT(*) AS total FROM ld_log_objects").first()).toEqual({
    total: 2,
  });
  const ops = await (await liveRequest("/operations")).json();
  expect(ops).toMatchObject({
    sources: { firewall: { errors: 2 } },
    tasks: expect.arrayContaining([expect.objectContaining({ task: "retention", removed: 2 })]),
  });
});

it("counts retained observations and filters before paginating, including a tied window", async () => {
  const latest = Math.floor(Date.now() / 1000) * 1000;
  const tied = latest - 99 * 300000;
  const expiry = new Date(latest + 86400000).toISOString();
  await db
    .prepare(`WITH RECURSIVE positions(n) AS (VALUES(0) UNION ALL SELECT n+1 FROM positions WHERE n<99)
      INSERT INTO ld_findings SELECT
        'http-5xx-v1-' || CAST(?-n*300000 AS INTEGER),?,
        strftime('%Y-%m-%dT%H:%M:%fZ', (?-n*300000)/1000.0, 'unixepoch'),
        'http-5xx-v1','Server errors','medium','Example','{}',?,?
      FROM positions`)
    .bind(latest, liveZone, latest, "a".repeat(64), expiry)
    .run();
  const low = `mitigation-volume-v1-${tied}`;
  const insert = db.prepare("INSERT INTO ld_findings VALUES (?,?,?,?,?,?,?,?,?,?)");
  for (const [id, timestamp, expiresAt] of [
    [low, tied, expiry],
    [`mitigation-volume-v1-${tied - 300000}`, tied - 300000, "2000-01-01T00:00:00.000Z"],
  ] as const)
    await insert
      .bind(
        id,
        liveZone,
        new Date(timestamp).toISOString(),
        "mitigation-volume-v1",
        "Mitigations",
        "low",
        "Example",
        "{}",
        "a".repeat(64),
        expiresAt,
      )
      .run();
  const all = (await (await liveRequest("/findings")).json()) as LiveObservations;
  expect(all.counts).toEqual({ low: 1, medium: 100, high: 0 });
  expect(all.findings).toHaveLength(100);
  expect(all.next).toBe(`http-5xx-v1-${tied}`);
  const older = await (await liveRequest(`/findings?before=${all.next}`)).json();
  const filtered = (await (await liveRequest("/findings?priority=low")).json()) as LiveObservations;
  expect(filtered).toEqual(older);
  expect(filtered.findings).toMatchObject([
    { id: low, severity: "low", windowEnd: new Date(tied).toISOString() },
  ]);
  expect(filtered.next).toBeNull();
  expect(await (await liveRequest("/findings?priority=high")).json()).toMatchObject({
    findings: [],
    next: null,
  });
});

it("requires approval, verifies the created challenge, and removes only the intact owned rule", async () => {
  const { id } = (await (
    await liveRequest("/repairs", {
      path: "/__soc_test/check",
      client_ip: "192.0.2.31",
      note: "Isolated scope rehearsal",
    })
  ).json()) as { id: string };
  const ruleset = "a".repeat(32),
    rule = "b".repeat(32);
  const settings = {
    LIVE_DB: db,
    WAF_API_TOKEN: "test-only",
    WAF_RULESET_ID: ruleset,
    REPAIR_CLIENT_IPV4: "192.0.2.31",
    REPAIR_APPLY: "verified-test-host-v1",
  } as unknown as Parameters<typeof executeRepair>[0];
  let saved: Record<string, unknown> | undefined;
  let writes = 0;
  const transport = (async (url: string, options: RequestInit) => {
    if (url === "https://soc-test.d.example.invalid/__soc_test/check")
      return new Response("Isolated fixture", { headers: { "X-SOC-Test-Fixture": "isolated-v1" } });
    expect(url).toContain(`/zones/${liveZone}/rulesets/`);
    if (options.method === "POST") {
      writes++;
      saved = { ...JSON.parse(String(options.body)), id: rule };
      expect(saved?.expression).toBe(
        '(http.host eq "soc-test.d.example.invalid" and http.request.uri.path eq "/__soc_test/check" and ip.src eq 192.0.2.31)',
      );
    }
    if (options.method === "DELETE") {
      expect(url.endsWith(`/rules/${rule}`)).toBe(true);
      writes++;
      saved = undefined;
    }
    return Response.json({
      success: true,
      result: {
        id: ruleset,
        kind: "zone",
        phase: "http_request_firewall_custom",
        rules: saved ? [saved] : [],
      },
    });
  }) as typeof fetch;
  expect(await executeRepair(settings, id, "local-admin", "apply", transport)).toBe(false);
  const policy = { ...defaultLivePolicy, maxDurationSeconds: 120 };
  await saveLivePolicy(0, { ...policy, requireSecondApprover: true });
  await expect(liveRequest(`/repairs/${id}/approve`, {})).rejects.toMatchObject({ status: 409 });
  await saveLivePolicy(1, policy);
  await liveRequest(`/repairs/${id}/approve`, {});
  await saveLivePolicy(2, { ...policy, mode: "Observe" });
  expect(await executeRepair(settings, id, "local-admin", "apply", transport)).toBe(false);
  await saveLivePolicy(3, policy);
  const start = Date.now();
  expect(await executeRepair(settings, id, "local-admin", "apply", transport)).toBe(true);
  const applied = await db
    .prepare("SELECT rule_expires_at FROM ld_repairs WHERE id=?")
    .bind(id)
    .first<{ rule_expires_at: string }>();
  expect(Date.parse(applied?.rule_expires_at ?? "")).toBeGreaterThanOrEqual(start + 120000);
  expect(Date.parse(applied?.rule_expires_at ?? "")).toBeLessThanOrEqual(Date.now() + 120000);
  expect(await executeRepair(settings, id, "local-admin", "apply", transport)).toBe(false);
  expect(
    await db.prepare("SELECT status,rule_id FROM ld_repairs WHERE id=?").bind(id).first(),
  ).toEqual({ status: "verified", rule_id: rule });
  expect(saved).toBeDefined();
  await saveLivePolicy(4, { ...policy, killSwitch: true });
  const exact = saved;
  saved = { ...saved, enabled: false };
  await executeRepair(settings, id, "local-admin", "rollback", transport);
  expect(writes).toBe(1);
  expect(
    await db.prepare("SELECT status,result FROM ld_repairs WHERE id=?").bind(id).first(),
  ).toEqual({ status: "review", result: "rule_drift" });
  saved = exact;
  await db
    .prepare(
      "UPDATE ld_repairs SET status='verified',result='rule_verified',rule_expires_at='2000-01-01T00:00:00.000Z' WHERE id=?",
    )
    .bind(id)
    .run();
  await reconcileRepairs({ ...settings, REPAIR_APPLY: "disabled" }, transport);
  expect(
    await db.prepare("SELECT status,result FROM ld_repairs WHERE id=?").bind(id).first(),
  ).toEqual({ status: "rolled_back", result: "rule_absent" });
  expect(writes).toBe(2);
});
it("normal scheduled entry collects and hashes real-source-shaped data once, with no public ingestion endpoint", async () => {
  await run();
  await run();
  expect(calls).toBe(2);
  const row = await db.prepare("SELECT * FROM ld_snapshots").first();
  expect(row?.zone_id).toBe("00000000000000000000000000000002");
  expect(String(row?.facts_json)).not.toContain("synthetic-only-credential");
  expect(await db.prepare("SELECT count(*) AS n FROM ld_findings").first()).toEqual({ n: 1 });
  expect(
    (await mf.dispatchFetch("https://collector.invalid/collect", { method: "POST" })).status,
  ).toBe(404);
  expect(await db.prepare("SELECT lease_token,last_error FROM ld_state").first()).toEqual({
    lease_token: null,
    last_error: null,
  });
});
it("stores partial coverage explicitly and does not invent security observations", async () => {
  mode = "partial";
  await run();
  expect(await db.prepare("SELECT count(*) AS n FROM ld_findings").first()).toEqual({ n: 0 });
  expect(await db.prepare("SELECT last_error FROM ld_state").first()).toEqual({
    last_error: "security:graphql_rejected",
  });
  expect(
    JSON.stringify(await db.prepare("SELECT facts_json FROM ld_snapshots").first()),
  ).not.toContain("private-provider-error");
});
it("records total source failure without advancing coverage, and respects the collector lease", async () => {
  mode = "failed";
  await run();
  expect(await db.prepare("SELECT last_end,last_error FROM ld_state").first()).toEqual({
    last_end: null,
    last_error: "graphql_rejected",
  });
  expect(await db.prepare("SELECT count(*) AS n FROM ld_snapshots").first()).toEqual({ n: 0 });
  await db
    .prepare("UPDATE ld_state SET lease_token='other',lease_until='2099-01-01T00:00:00.000Z'")
    .run();
  await run();
  expect(calls).toBe(2);
});
it("makes no Analytics calls or new observations while paused and collects after resuming", async () => {
  await db.prepare("UPDATE ld_state SET collection_paused_at='2026-11-01T00:00:00.000Z'").run();
  await run();
  expect(calls).toBe(0);
  expect(await db.prepare("SELECT last_attempt FROM ld_state").first()).toEqual({
    last_attempt: null,
  });
  expect(await db.prepare("SELECT count(*) AS n FROM ld_findings").first()).toEqual({ n: 0 });
  await db.prepare("UPDATE ld_state SET collection_paused_at=NULL").run();
  await run();
  expect(calls).toBe(2);
  expect(await db.prepare("SELECT count(*) AS n FROM ld_snapshots").first()).toEqual({ n: 1 });
});
it("discards an in-flight batch when a pause revokes its lease, even after a quick resume", async () => {
  let started = () => {},
    release = () => {};
  const requestStarted = new Promise<void>((resolve) => {
    started = resolve;
  });
  const reply = new Promise<void>((resolve) => {
    release = resolve;
  });
  hold = { started, wait: reply };
  const running = run();
  await requestStarted;
  try {
    await db
      .prepare(
        "UPDATE ld_state SET collection_paused_at='2026-11-01T00:00:00.000Z',lease_token=NULL,lease_until=NULL",
      )
      .run();
    await db.prepare("UPDATE ld_state SET collection_paused_at=NULL").run();
  } finally {
    hold = undefined;
    release();
  }
  await running;
  expect(await db.prepare("SELECT count(*) AS n FROM ld_snapshots").first()).toEqual({ n: 0 });
  expect(await db.prepare("SELECT last_success FROM ld_state").first()).toEqual({
    last_success: null,
  });
});
it("retains observation evidence independently after its 30-day source snapshot expires", async () => {
  await run();
  const evidence = await db
    .prepare("SELECT evidence_json,sha256,expires_at FROM ld_findings")
    .first();
  await db.prepare("UPDATE ld_snapshots SET expires_at='2000-01-01T00:00:00.000Z'").run();
  mode = "failed";
  await run();
  expect(await db.prepare("SELECT count(*) AS n FROM ld_snapshots").first()).toEqual({ n: 0 });
  expect(
    await db.prepare("SELECT evidence_json,sha256,expires_at FROM ld_findings").first(),
  ).toEqual(evidence);
  await db.prepare("UPDATE ld_findings SET expires_at='2000-01-01T00:00:00.000Z'").run();
  await run();
  expect(await db.prepare("SELECT count(*) AS n FROM ld_findings").first()).toEqual({ n: 0 });
});

it("reserves and reconciles one AI run per finding, using only aggregate evidence", async () => {
  await run();
  const row = await db.prepare("SELECT id FROM ld_findings").first<{ id: string }>();
  if (!row) throw Error("Missing synthetic finding");
  const report = {
    summary: "A mitigation threshold was reached.",
    findings: [
      { claim: "The stored window contains 101 mitigation events.", evidenceRefs: ["observation"] },
    ],
    limitations: ["These are estimated aggregates."],
    nextChecks: ["Review the corresponding security events."],
  };
  let aiCalls = 0;
  let reportOverride: unknown = report;
  let expectedModel: LivePolicy["investigationModel"] = liveInvestigationModel;
  const env = {
    LIVE_PROFILE: liveProfile,
    LIVE_DB: db,
    LIVE_AI_MODE: "on-demand-v1",
    LIVE_AI_MODEL: liveInvestigationModel,
    AI_GATEWAY_ID: "example-soc-ai",
    AI: {
      async run(model: string, input: { messages: { content: string }[] }, options: unknown) {
        aiCalls++;
        expect(model).toBe(expectedModel);
        expect(options).toMatchObject({
          gateway: { id: "example-soc-ai", skipCache: true, collectLog: false },
          extraHeaders: { "cf-aig-collect-log-payload": "false" },
        });
        const evidence = JSON.parse(input.messages[1]?.content ?? "{}");
        expect(evidence.observation.security.mitigationCount).toBe(101);
        expect(JSON.stringify(evidence)).not.toContain(liveZone);
        return {
          choices: [{ message: { content: JSON.stringify(reportOverride) } }],
          usage: { prompt_tokens: 100, completion_tokens: 100 },
        };
      },
    },
  } as unknown as Bindings;
  const principal = {
    id: "local-admin",
    role: "Admin",
    token: "unused",
    grants: [{ zoneId: liveZone, permission: "read" }],
  } as const;
  const endpoint = (id: string, method = "POST") =>
    liveRoute(
      new Request(`https://soc.d.example.invalid/api/live/findings/${id}/investigation`, {
        method,
      }),
      env,
      { ...principal, grants: [...principal.grants] },
    );
  const settingsBudget = async () =>
    (
      await liveRoute(new Request("https://soc.d.example.invalid/api/live/settings/ai"), env, {
        ...principal,
        grants: [...principal.grants],
      })
    ).json();
  expect(await (await endpoint(row.id, "GET")).json()).toMatchObject({ status: "ready" });
  const first = await Promise.all([endpoint(row.id), endpoint(row.id)]);
  expect(await first[0].json()).toMatchObject({
    status: expect.stringMatching(/complete|running/),
  });
  expect(await (await endpoint(row.id)).json()).toMatchObject({
    status: "complete",
    report,
    costMicro: 580,
    usageKnown: true,
  });
  expect(aiCalls).toBe(1);
  expect(await settingsBudget()).toEqual({
    estimatedMicro: 580,
    limitMicro: 50_000_000,
    warning: false,
    canInvestigate: true,
  });

  const another = `${row.id}0`;
  await db
    .prepare(
      "INSERT INTO ld_findings SELECT ?,zone_id,'alternate-window',rule,title,severity,summary,evidence_json,sha256,expires_at FROM ld_findings WHERE id=?",
    )
    .bind(another, row.id)
    .run();
  reportOverride = {
    ...report,
    findings: [{ claim: "No supplied evidence", evidenceRefs: ["follow-up"] }],
  };
  await saveLivePolicy(0, { ...defaultLivePolicy, killSwitch: true });
  await expect(endpoint(another)).rejects.toMatchObject({ status: 409, code: "live_ai_disabled" });
  expectedModel = "@cf/zai-org/glm-5.3-flash";
  const policy = { ...defaultLivePolicy, investigationModel: expectedModel, monthlyBudgetUsd: 1 };
  await saveLivePolicy(1, policy);
  expect(await (await endpoint(another)).json()).toMatchObject({
    status: "failed",
    failure: "invalid_response",
    report: null,
    costMicro: 65,
    model: expectedModel,
  });
  expect(aiCalls).toBe(2);
  await db
    .prepare("UPDATE ld_ai_runs SET cost_micro=1000000,usage_known=0 WHERE finding_id=?")
    .bind(row.id)
    .run();
  await db
    .prepare("UPDATE ld_ai_runs SET started_at='2026-01-01T00:00:00.000Z' WHERE finding_id=?")
    .bind(another)
    .run();
  await expect(endpoint(another)).rejects.toMatchObject({ status: 429, code: "live_ai_budget" });
  expect(aiCalls).toBe(2);
  expect(await settingsBudget()).toEqual({
    estimatedMicro: 65,
    limitMicro: 1_000_000,
    warning: true,
    canInvestigate: false,
  });
});
