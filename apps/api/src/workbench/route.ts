import { scenarios, workbenchPolicySchema } from "@soc/shared";
import { z } from "zod";
import { assertZone } from "../data";
import { HttpError, json, readJson } from "../http";
import { createProposal, decide, executeProposal, proposalInputSchema, rollback } from "./actions";
import { analyze } from "./agent";
import { reconcile } from "./reconcile";
import { replay } from "./simulations";
import {
  audit,
  enabled,
  expiry,
  incident,
  injection,
  now,
  rateLimit,
  redact,
  scoped,
  settings,
  uid,
  type WorkContext,
  zones,
} from "./store";
import { callTool, signals, toolNames } from "./tools";

const id = z.string().regex(/^[a-zA-Z0-9_-]{1,128}$/);
const commandSchema = z.strictObject({ reason: z.string().min(3).max(300) });
async function input<T extends z.ZodType>(request: Request, schema: T): Promise<z.infer<T>> {
  const parsed = schema.safeParse(await readJson(request));
  if (!parsed.success)
    throw new HttpError(
      400,
      "invalid_input",
      parsed.error.issues
        .map((i) => `${i.path.join(".")}: ${i.message}`)
        .join("; ")
        .slice(0, 500),
    );
  return parsed.data;
}
function admin(ctx: WorkContext) {
  if (ctx.principal.role !== "Admin")
    throw new HttpError(403, "admin_required", "Admin is required.");
}
async function list(
  ctx: WorkContext,
  table: "wb_runs" | "wb_proposals" | "wb_simulations" | "wb_executions" | "wb_history",
  filter = "",
  params: unknown[] = [],
) {
  const allowed = zones(ctx);
  if (!allowed.length) return [];
  return (
    await ctx.db
      .prepare(
        `SELECT * FROM ${table} WHERE zone_id IN (${allowed.map(() => "?").join(",")}) AND expires_at>? ${table === "wb_runs" ? "AND (private_user_id IS NULL OR private_user_id=?)" : ""} ${filter} ORDER BY rowid DESC LIMIT 100`,
      )
      .bind(...allowed, now(), ...(table === "wb_runs" ? [ctx.principal.id] : []), ...params)
      .all()
  ).results;
}
async function chat(
  ctx: WorkContext,
  body: {
    zoneId: string;
    incidentId?: string | undefined;
    threadId?: string | undefined;
    message: string;
  },
) {
  assertZone(ctx.principal, body.zoneId, "investigate");
  let threadId = body.threadId;
  let thread: {
    id: string;
    user_id: string;
    zone_id: string;
    incident_id: string | null;
    expires_at: string;
  } | null = null;
  if (threadId) {
    thread = await ctx.db
      .prepare("SELECT * FROM wb_threads WHERE id=? AND expires_at>?")
      .bind(threadId, now())
      .first();
    if (
      !thread ||
      thread.user_id !== ctx.principal.id ||
      thread.zone_id !== body.zoneId ||
      (body.incidentId || null) !== thread.incident_id
    )
      throw new HttpError(
        403,
        "conversation_forbidden",
        "Conversation identity, zone and incident are fixed.",
      );
  }
  if (body.incidentId) {
    const item = await incident(ctx, body.incidentId);
    if (item.zone_id !== body.zoneId)
      throw new HttpError(403, "zone_forbidden", "Incident is outside this chat zone.");
  }
  const at = now();
  if (!threadId) {
    threadId = uid("thread");
    await ctx.db
      .prepare("INSERT INTO wb_threads VALUES (?,?,?,?,?,?)")
      .bind(threadId, ctx.principal.id, body.zoneId, body.incidentId || null, at, expiry(at))
      .run();
  }
  const deadline = thread?.expires_at || expiry(at),
    message = redact(body.message);
  let answer =
      "No current incident evidence is available. Replay a scenario or select an incident first.",
    runId: string | null = null,
    proposalId: string | null = null;
  if (injection(message)) {
    answer =
      "This request attempted to change instructions, expose secrets or bypass permissions. It was not executed. Tool access remains read-only.";
  } else {
    const selected =
      body.incidentId ||
      (
        await ctx.db
          .prepare(
            "SELECT id FROM incidents WHERE zone_id=? AND environment='simulation' AND expires_at>? ORDER BY last_seen DESC LIMIT 1",
          )
          .bind(body.zoneId, at)
          .first<{ id: string }>()
      )?.id;
    if (selected) {
      const previous = threadId
        ? (
            await ctx.db
              .prepare(
                "SELECT role,content FROM wb_messages WHERE thread_id=? AND expires_at>? ORDER BY rowid DESC LIMIT 5",
              )
              .bind(threadId, now())
              .all<{ role: string; content: string }>()
          ).results
            .reverse()
            .filter((m) => !injection(m.content))
            .map((m) => `${m.role}: ${m.content.slice(0, 500)}`)
            .join("\n")
        : "";
      const run = await analyze(
        ctx,
        selected,
        "investigation",
        `${previous}\nuser: ${message}`,
        true,
      );
      runId = run.id;
      answer =
        run.finding.summary +
        "\n" +
        run.finding.findings.map((f) => `${f.claim} [${f.evidenceRefs.join(", ")}]`).join("\n");
      if (/why|點解|alternative|rather than/i.test(message))
        answer +=
          "\nPolicy checks the exact test path/client, current evidence, request share and shared-client risk. A recommendation alone never grants execution permission.";
      if (
        /(?:propose|create|prepare|draft|建立|草擬|提出).{0,80}(?:block|challenge|rate.?limit|封鎖|攔截|限速)/i.test(
          message,
        ) &&
        run.status === "completed" &&
        run.finding.verdict === "incident" &&
        run.finding.recommendedAction !== "none"
      ) {
        const s = await signals(ctx, selected);
        if (s) {
          const p = await createProposal(
            ctx,
            {
              runId: run.id,
              actionType: run.finding.recommendedAction,
              clientId: s.clientId,
              path: s.path,
              durationSeconds: 300,
              rationale: run.finding.summary,
            },
            true,
          );
          proposalId = p.id;
          answer += `\nCreated proposal ${p.id}; chat did not execute it.`;
        }
      }
    }
  }
  await ctx.db.batch([
    ctx.db
      .prepare("INSERT INTO wb_messages VALUES (?,?, 'user',?,NULL,?,?)")
      .bind(uid("message"), threadId, message, at, deadline),
    ctx.db
      .prepare("INSERT INTO wb_messages VALUES (?,?,'assistant',?,?,?,?)")
      .bind(uid("message"), threadId, redact(answer), runId, now(), deadline),
    audit(ctx.db, ctx.principal.id, "chat.completed", threadId, {
      runId,
      proposalId,
      injectionRejected: injection(message),
    }),
  ]);
  return { threadId, answer, runId, proposalId };
}
export async function workbenchRoute(request: Request, ctx: WorkContext): Promise<Response | null> {
  if (!enabled(ctx.env)) return null;
  const url = new URL(request.url),
    path = url.pathname,
    method = request.method;
  if (
    !["GET", "HEAD"].includes(method) &&
    !path.startsWith("/api/admin/") &&
    path !== "/api/authorization/approval-check"
  )
    await rateLimit(ctx);
  if (path === "/api/workbench/state" && method === "GET") {
    const cfg = await settings(ctx.db),
      month = now().slice(0, 7),
      budget = await ctx.db
        .prepare("SELECT * FROM wb_budget WHERE month=? AND provider=?")
        .bind(month, cfg.policy.provider)
        .first();
    const runs = await list(ctx, "wb_runs"),
      actions = await list(ctx, "wb_executions"),
      maintenance = await ctx.db
        .prepare("SELECT * FROM wb_maintenance WHERE id='last_reconcile'")
        .first();
    return json({
      environment: "simulation",
      provider: cfg.policy.provider,
      fixtureOnly: cfg.policy.provider === "fixture",
      liveSecurityWrites: false,
      workersAiReady: !!ctx.env.AI && ctx.env.SOC_AI_APPROVED === "workers-ai-metadata-only-v1",
      policy: cfg.policy,
      policyVersion: cfg.version,
      budget: budget || { month, provider: cfg.policy.provider, spent_micro: 0, reserved_micro: 0 },
      budgetWarning: !!budget && Number(budget.spent_micro) >= cfg.policy.monthlyBudgetUsd * 800000,
      analysisRuns: runs.length,
      executions: actions.length,
      maintenance,
      serverTime: now(),
      toolNames,
      roles: ctx.principal.role,
    });
  }
  if (path === "/api/settings/policies") {
    if (method === "GET") return json(await settings(ctx.db));
    if (method === "PUT") {
      admin(ctx);
      const body = await input(
        request,
        z.strictObject({ version: z.number().int().nonnegative(), policy: workbenchPolicySchema }),
      );
      if (
        body.policy.provider === "workers_ai" &&
        (!ctx.env.AI || ctx.env.SOC_AI_APPROVED !== "workers-ai-metadata-only-v1")
      )
        throw new HttpError(
          503,
          "ai_not_provisioned",
          "Real Workers AI is not provisioned; fixture mode remains available.",
        );
      const result = await ctx.db.batch([
        ctx.db
          .prepare(
            "UPDATE wb_settings SET version=version+1,policy_json=?,updated_at=? WHERE id='simulation' AND version=?",
          )
          .bind(JSON.stringify(body.policy), now(), body.version),
        ctx.db
          .prepare(
            "INSERT INTO audit_trail SELECT ?,?,'policy.changed','simulation',?,?,? WHERE changes()=1",
          )
          .bind(
            uid("audit"),
            null,
            JSON.stringify({
              actorId: ctx.principal.id,
              mode: body.policy.mode,
              killSwitch: body.policy.killSwitch,
            }),
            now(),
            expiry(),
          ),
      ]);
      if (result[0]?.meta.changes !== 1)
        throw new HttpError(409, "version_conflict", "Policy changed; reload before saving.");
      return json(await settings(ctx.db));
    }
  }
  if (path === "/api/workbench/reconcile" && method === "POST") {
    admin(ctx);
    return json(await reconcile(ctx));
  }
  if (path === "/api/incidents" && method === "GET") {
    const allowed = zones(ctx);
    return json({
      incidents: allowed.length
        ? (
            await ctx.db
              .prepare(
                `SELECT * FROM incidents WHERE environment='simulation' AND expires_at>? AND zone_id IN (${allowed.map(() => "?").join(",")}) ORDER BY last_seen DESC LIMIT 100`,
              )
              .bind(now(), ...allowed)
              .all()
          ).results
        : [],
    });
  }
  let match =
    /^\/api\/incidents\/([a-zA-Z0-9_-]+)\/(triage|investigate|chat|timeline|workbench|status)$/.exec(
      path,
    );
  if (match) {
    const iid = match[1] || "",
      operation = match[2];
    const item = await incident(ctx, iid);
    if (method === "POST" && operation === "status") {
      assertZone(ctx.principal, item.zone_id, "investigate");
      const body = await input(
        request,
        z.strictObject({
          status: z.enum(["new", "investigating", "resolved", "closed"]),
          reason: z.string().min(3).max(300),
        }),
      );
      await ctx.db.batch([
        ctx.db.prepare("UPDATE incidents SET status=? WHERE id=?").bind(body.status, iid),
        audit(ctx.db, ctx.principal.id, "incident.status_changed", iid, {
          status: body.status,
          reason: redact(body.reason),
        }),
      ]);
      return json({ id: iid, status: body.status });
    }
    if (method === "POST" && (operation === "triage" || operation === "investigate"))
      return json(await analyze(ctx, iid, operation === "triage" ? "triage" : "investigation"));
    if (method === "POST" && operation === "chat") {
      const body = await input(
        request,
        z.strictObject({ message: z.string().min(1).max(2000), threadId: id.optional() }),
      );
      return json(await chat(ctx, { ...body, incidentId: iid, zoneId: item.zone_id }));
    }
    if (method === "GET" && operation === "timeline")
      return json({
        transitions: await list(
          ctx,
          "wb_history",
          `AND (target_id=? OR target_id IN (SELECT id FROM wb_runs WHERE incident_id=? AND (private_user_id IS NULL OR private_user_id=?)) OR target_id IN (SELECT id FROM wb_proposals WHERE incident_id=?) OR target_id IN (SELECT e.id FROM wb_executions e JOIN wb_proposals p ON p.id=e.proposal_id WHERE p.incident_id=?))`,
          [iid, iid, ctx.principal.id, iid, iid],
        ),
        events: (
          await ctx.db
            .prepare(
              "SELECT e.* FROM events e JOIN incident_events l ON e.id=l.event_id WHERE l.incident_id=? AND e.zone_id=? AND e.expires_at>?",
            )
            .bind(iid, item.zone_id, now())
            .all()
        ).results,
      });
    if (method === "GET" && operation === "workbench")
      return json({
        runs: await list(ctx, "wb_runs", "AND incident_id=?", [iid]),
        proposals: await list(ctx, "wb_proposals", "AND incident_id=?", [iid]),
      });
  }
  if (path === "/api/chat" && method === "POST") {
    const body = await input(
      request,
      z.strictObject({ zoneId: id, message: z.string().min(1).max(2000), threadId: id.optional() }),
    );
    return json(await chat(ctx, body));
  }
  if (path === "/api/chat/threads" && method === "GET")
    return json({
      threads: (
        await ctx.db
          .prepare(
            "SELECT id,zone_id,incident_id,created_at FROM wb_threads WHERE user_id=? AND expires_at>? ORDER BY created_at DESC LIMIT 50",
          )
          .bind(ctx.principal.id, now())
          .all()
      ).results,
    });
  match = /^\/api\/chat\/threads\/([a-zA-Z0-9_-]+)$/.exec(path);
  if (match && method === "GET") {
    const thread = await ctx.db
      .prepare("SELECT * FROM wb_threads WHERE id=? AND user_id=? AND expires_at>?")
      .bind(match[1], ctx.principal.id, now())
      .first<{ zone_id: string }>();
    if (!thread) throw new HttpError(404, "thread_not_found", "Thread not found.");
    assertZone(ctx.principal, thread.zone_id, "investigate");
    return json({
      messages: (
        await ctx.db
          .prepare(
            "SELECT role,content,run_id,created_at FROM wb_messages WHERE thread_id=? AND expires_at>? ORDER BY rowid LIMIT 100",
          )
          .bind(match[1], now())
          .all()
      ).results,
    });
  }
  if (path === "/api/agent-runs" && method === "GET")
    return json({ runs: await list(ctx, "wb_runs") });
  match = /^\/api\/agent-runs\/([a-zA-Z0-9_-]+)$/.exec(path);
  if (match && method === "GET") {
    const run = await scoped<{ zone_id: string }>(ctx, "wb_runs", match[1] || "");
    return json({
      run,
      tools: (
        await ctx.db
          .prepare("SELECT * FROM wb_tools WHERE run_id=? AND expires_at>? ORDER BY rowid")
          .bind(match[1], now())
          .all()
      ).results,
      history: await list(ctx, "wb_history", "AND target_id=?", [match[1]]),
    });
  }
  match = /^\/api\/tool-calls\/([a-zA-Z0-9_-]+)$/.exec(path);
  if (match && method === "GET")
    return json({ tool: await scoped(ctx, "wb_tools", match[1] || "") });
  if (path === "/api/actions" && method === "GET")
    return json({
      proposals: await list(ctx, "wb_proposals"),
      executions: await list(ctx, "wb_executions"),
    });
  if (path === "/api/actions" && method === "POST")
    return json(await createProposal(ctx, await input(request, proposalInputSchema)), 201);
  match = /^\/api\/actions\/([a-zA-Z0-9_-]+)(?:\/(approve|reject|execute|rollback))?$/.exec(path);
  if (match) {
    const aid = match[1] || "",
      op = match[2];
    const proposal = await scoped<{ zone_id: string }>(ctx, "wb_proposals", aid);
    if (!op && method === "GET") {
      const execution = await ctx.db
        .prepare("SELECT * FROM wb_executions WHERE proposal_id=?")
        .bind(aid)
        .first<{ id: string }>();
      return json({
        proposal,
        execution,
        approvals: (
          await ctx.db.prepare("SELECT * FROM wb_approvals WHERE proposal_id=?").bind(aid).all()
        ).results,
        verification: execution
          ? (
              await ctx.db
                .prepare("SELECT * FROM wb_verifications WHERE execution_id=? ORDER BY created_at")
                .bind(execution.id)
                .all()
            ).results
          : [],
        history: await list(ctx, "wb_history", "AND target_id IN (?,?)", [
          aid,
          execution?.id || aid,
        ]),
      });
    }
    if (method === "POST" && (op === "approve" || op === "reject")) {
      const body = await input(request, commandSchema);
      return json(await decide(ctx, aid, op, redact(body.reason)));
    }
    if (method === "POST" && op === "execute") return json(await executeProposal(ctx, aid));
    if (method === "POST" && op === "rollback") return json(await rollback(ctx, aid));
  }
  if (path === "/api/simulations/scenarios" && method === "GET")
    return json({
      scenarios: scenarios.map(({ id, name, description, category }) => ({
        id,
        name,
        description,
        category,
      })),
    });
  if (path === "/api/simulations/runs" && method === "GET")
    return json({ runs: await list(ctx, "wb_simulations") });
  if (path === "/api/simulations/runs" && method === "POST") {
    const body = await input(
      request,
      z.strictObject({
        scenarioId: id,
        replayKey: id.optional(),
        exerciseActions: z.boolean().default(false),
        suiteId: id.optional(),
      }),
    );
    if (body.exerciseActions) assertZone(ctx.principal, "fixture-zone", "approve");
    return json(
      await replay(
        ctx,
        body.scenarioId,
        body.replayKey || crypto.randomUUID(),
        body.exerciseActions,
        body.suiteId,
      ),
      201,
    );
  }
  match = /^\/api\/simulations\/runs\/([a-zA-Z0-9_-]+)\/evaluation$/.exec(path);
  if (match && method === "GET") return json(await scoped(ctx, "wb_simulations", match[1] || ""));
  if (path === "/api/simulations/report" && method === "GET") {
    const suiteId = url.searchParams.get("suiteId");
    if (suiteId && !id.safeParse(suiteId).success)
      throw new HttpError(400, "invalid_suite", "Invalid suite ID.");
    const rows = await list(
      ctx,
      "wb_simulations",
      `AND user_id=? ${suiteId ? "AND suite_id=?" : ""}`,
      [ctx.principal.id, ...(suiteId ? [suiteId] : [])],
    );
    const own = rows.slice(0, 12);
    const evaluations = own.map((r) => JSON.parse(r.evaluation_json as string));
    let tp = 0,
      fp = 0,
      fn = 0,
      tn = 0;
    for (const e of evaluations) {
      if (e.expectedVerdict === "incident") {
        if (e.actualVerdict === "incident") tp++;
        else fn++;
      } else if (e.expectedVerdict === "not_incident") {
        if (e.actualVerdict === "incident") fp++;
        else if (e.actualVerdict === "not_incident") tn++;
      }
    }
    return json({
      runs: own,
      metrics: {
        truePositive: tp,
        falsePositive: fp,
        falseNegative: fn,
        abstentions: evaluations.filter((e) => e.actualVerdict === "insufficient_data").length,
        trueNegative: tn,
        precision: tp + fp ? tp / (tp + fp) : null,
        recall: tp + fn ? tp / (tp + fn) : null,
        classificationAccuracy: evaluations.length
          ? evaluations.filter((e) => e.classificationCorrect).length / evaluations.length
          : null,
        unauthorizedActions: evaluations.reduce((n, e) => n + e.unauthorizedActions, 0),
        fixtureOnly: evaluations.every((e) => e.fixtureOnly),
        modelQualityBenchmark:
          evaluations.length === 12 &&
          new Set(own.map((r) => r.scenario_id)).size === 12 &&
          evaluations.every((e) => e.modelQualityBenchmark),
      },
    });
  }
  if (path === "/api/workbench/audit" && method === "GET") {
    admin(ctx);
    return json({
      records: (
        await ctx.db
          .prepare("SELECT * FROM audit_trail WHERE expires_at>? ORDER BY rowid DESC LIMIT 100")
          .bind(now())
          .all()
      ).results,
    });
  }
  if (path === "/api/mcp" && method !== "POST")
    return new Response(null, { status: 405, headers: { Allow: "POST" } });
  if (path === "/api/mcp" && method === "POST") {
    const body = await input(
      request,
      z.object({
        jsonrpc: z.literal("2.0"),
        id: z.union([z.string(), z.number()]).optional(),
        method: z.string(),
        params: z.record(z.string(), z.unknown()).optional(),
      }),
    );
    const reply = (result: unknown) => json({ jsonrpc: "2.0", id: body.id ?? null, result });
    if (body.method === "initialize")
      return reply({
        protocolVersion: "2025-03-26",
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: "soc-simulation-readonly", version: "1.0.0" },
      });
    if (body.method === "notifications/initialized") return new Response(null, { status: 202 });
    if (body.method === "tools/list")
      return reply({
        tools: toolNames.map((name) => ({
          name,
          description: "Read-only simulated SOC evidence; no Cloudflare writes.",
          inputSchema: {
            type: "object",
            properties: { incidentId: { type: "string" } },
            required: ["incidentId"],
            additionalProperties: false,
          },
          annotations: { readOnlyHint: true, destructiveHint: false },
        })),
      });
    if (body.method === "tools/call") {
      const parsed = z
        .strictObject({ name: z.enum(toolNames), arguments: z.strictObject({ incidentId: id }) })
        .safeParse(body.params);
      if (!parsed.success)
        return json({
          jsonrpc: "2.0",
          id: body.id ?? null,
          error: { code: -32602, message: "Unknown tool or invalid arguments." },
        });
      const item = await incident(ctx, parsed.data.arguments.incidentId);
      assertZone(ctx.principal, item.zone_id, "investigate");
      const rid = uid("run"),
        at = now();
      await ctx.db
        .prepare(
          "INSERT INTO wb_runs(id,incident_id,zone_id,user_id,kind,provider,model_id,status,started_at,ended_at,stop_reason,expires_at) VALUES (?,?,?,?, 'tool','fixture','none','completed',?,?,'mcp_tool_only',?)",
        )
        .bind(rid, item.id, item.zone_id, ctx.principal.id, at, at, expiry(at))
        .run();
      const result = await callTool(ctx, rid, item.id, parsed.data.name);
      return reply({
        content: [{ type: "text", text: JSON.stringify(result) }],
        isError: result.status !== "ok",
      });
    }
    return json({
      jsonrpc: "2.0",
      id: body.id ?? null,
      error: { code: -32601, message: "Method not found." },
    });
  }
  return null;
}
