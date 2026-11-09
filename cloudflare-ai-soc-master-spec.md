# Cloudflare AI Security Operations Agent — Master Implementation Specification

**Status:** Implementation brief for Codex  
**Delivery:** Milestone-based, with mandatory Phase 0 feasibility validation  
**Target:** Cloudflare Enterprise account; TypeScript monorepo; Cloudflare-native runtime  
**Primary purpose:** Demonstrate practical agentic AI security investigation, safe response, and evaluation—not recreate Cloudflare Security Analytics.

## 1. Mission and non-goals

Build an AI SOC application that consumes Cloudflare security/account signals, correlates incidents, investigates with bounded dynamic tool use, presents evidence-backed findings, and proposes or safely executes approved security responses. Include incident-scoped and general interactive investigation chat, transparent operational traces, and an isolated simulation/evaluation harness.

**Non-goals for MVP:** Zero Trust Access monitoring; multi-tenant SaaS; direct LLM access to write-capable Cloudflare APIs; a replacement for Cloudflare's native analytics UI; unbounded autonomous rule modification; unsupported claims of guaranteed real-time delivery.

## 2. Confirmed decisions

| Area       | Decision                                                                                                                                                        |
| ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Monitoring | Application Security (WAF, DDoS, Bot Management, rate limiting, HTTP) + Account Security (audit/config/API activity when available)                             |
| Ingestion  | Notifications/webhooks + Logpush + GraphQL read-only investigation + Audit Logs                                                                                 |
| Autonomy   | Observe / Approve / Autonomous; **default Approve**                                                                                                             |
| Agent      | Dynamic bounded orchestration; light triage model + stronger investigation model                                                                                |
| Runtime    | Workers, Queues, Agents SDK, Workflows, D1, R2, Access                                                                                                          |
| Models     | **Workers AI only**, via AI Gateway where supported                                                                                                             |
| Response   | Application security: temporary IP protection, WAF custom rules, rate limiting, bot protection recommendations and approved changes; account security read-only |
| Console    | Full AI SOC console + incident-specific and general AI chat                                                                                                     |
| Testing    | Live + isolated simulation with evaluation                                                                                                                      |
| Access     | Cloudflare Access + application RBAC (Viewer, Analyst, Operator, Admin)                                                                                         |
| Delivery   | Local development + production, GitHub Actions, manual production approval                                                                                      |
| Execution  | Phases with tests, acceptance criteria, demos, and gates                                                                                                        |

## 3. Critical implementation principles

1. **Trust boundaries:** Logs, HTTP headers, alert payloads, MCP responses, and chat input are untrusted data, not instructions. Use schema validation, length limits, encoding, and provenance tagging.
2. **Read/write separation:** Read-only investigation credentials and tools must be separate from least-privilege write executor credentials. Models never receive write tokens.
3. **Deterministic enforcement:** An independent policy engine—not the model—authorizes each action. Enforce identity, role, environment, mode, scope, zone, hostname, action type, blast radius, expiration, approvals, and idempotency.
4. **Simulation isolation:** Mock data adapters, mock MCP/tool responses, mock executor, separate data namespace/resources, and server-side environment binding. Never trust a frontend `simulation=true` flag to decide whether a real write is allowed.
5. **Evidence first:** Every conclusion references source, time window, query/tool call, confidence, and relevant metrics. Do not manufacture an explanation when data is missing.
6. **Bounded agency:** Explicit tool allowlists, max iterations, per-tool timeouts, overall time/token budgets, retry limits, and escalation paths.
7. **Safe defaults:** Default Approve mode; start all production write action types in approval-required mode. Any autonomous temporary mitigation is opt-in, narrowly scoped, time-limited, and subject to impact checks.
8. **Rollback reality:** Not every Cloudflare setting supports equivalent reversible writes. Implement rollback per action type, verify state, and report partial/failed rollback.
9. **API-first UI:** Console uses authenticated backend endpoints; never exposes Cloudflare API credentials to browser.
10. **No assumed Cloudflare feature parity:** Phase 0 verifies actual account entitlements, datasets, supported endpoints, SDKs, and model/tool capabilities.

## 4. Logical architecture

```text
Cloudflare Notifications --> Authenticated Webhook Worker ---+
Cloudflare Logpush -------> Supported Log Destination/Adapter +--> Queue --> Normalize/Dedup/Correlate
Cloudflare Audit Logs ---> Verified Audit Ingest Adapter ----+                        |
                                                                                    v
                                                                              Incident Store (D1)
                                                                                    |
                                                                               Triage Agent
                                                                              (Workers AI)
                                                                                    |
                                                                           Investigation Agent
                                                                            (Agents SDK)
                                                                            /     |       \
                                                            GraphQL MCP / API   Evidence   More queries
                                                             read-only adapter     R2      (bounded)
                                                                                    |
                                                                            Findings + proposed action
                                                                                    |
                                                                         Deterministic Policy Engine
                                                                           /         |          \
                                                                        Observe    Approval     Auto (allowlist)
                                                                                      |             |
                                                                                 Workflow / Durable state
                                                                                      |
                                                                            Least-privilege Executor
                                                                                      |
                                                                            Verify / Expire / Rollback
                                                                                      |
                                                                       D1 Audit + R2 Evidence + Console
```

**Orchestration ownership:** Define one authoritative owner for each incident lifecycle transition. Use Workflows for durable process boundaries (approval wait, retries, scheduled verification); use Agents SDK for stateful agent sessions/tool orchestration. Do not have both independently manage the same loop. If an SDK feature is incompatible, use an adapter or simpler Worker/Workflow implementation while retaining behavior.

**Logpush caveat:** Cloudflare Logpush requires an actual supported destination and dataset configuration; do not assume it can directly POST to a Worker or Queue. Select and document a supported delivery path after Phase 0. A native R2 destination may be suitable if supported for selected datasets; implement batch parsing/ingestion accordingly.

## 5. Event ingestion and correlation

### 5.1 Source adapters

- **Notifications:** Validate webhook authenticity using the mechanism Cloudflare actually supports for the selected notification type; if no cryptographic signature is provided, protect endpoint with an appropriate secret/authenticated intermediary and explicitly document limitations. Normalize alert type, timestamps, zone/account identifiers, severity, and payload reference.
- **Logpush:** Select datasets for security/HTTP visibility supported by Enterprise and configured zones. Handle compression, schema evolution, late arrivals, duplicates, and batch sizes. Record dataset name and delivery lag.
- **Audit:** Verify account audit log retrieval/export capabilities and event coverage, including rule/config changes and token-related events only if exposed. Poll or ingest using a supported path; never invent unavailable fields.
- **GraphQL:** Read-only contextual investigation and scheduled health checks, not assumed to be an event stream. Validate retention, query cost, pagination, rate limits, and dimensions.

### 5.2 Normalized event shape

```ts
type SecurityEvent = {
  id: string;
  source: "notification" | "logpush" | "audit" | "synthetic";
  environment: "live" | "simulation";
  accountId: string;
  zoneId?: string;
  hostname?: string;
  category: "waf" | "ddos" | "bot" | "rate_limit" | "http" | "account_audit" | "unknown";
  eventTime: string;
  receivedAt: string;
  severityHint?: "info" | "low" | "medium" | "high" | "critical";
  dimensions: Record<string, string | number | boolean | null>;
  evidenceRef: string;
  schemaVersion: number;
  sourceEventId?: string;
  dedupeKey: string;
};
```

Store minimal searchable fields in D1; raw payloads in R2 with retention rules. Avoid collecting unnecessary personal data; mask or hash IP addresses where practical while retaining the ability to enforce approved responses securely.

### 5.3 Correlation

Use deterministic grouping before LLM calls: account/zone, attack category, overlapping time window, IP/ASN/path/JA4 or other available dimensions. Deduplicate notifications and logs referring to the same incident. Preserve evidence links and avoid interpreting multiple alerts as independent incidents without proof. Maintain incident state transitions (`new`, `triaging`, `investigating`, `awaiting_approval`, `mitigating`, `verifying`, `resolved`, `closed`, `failed`).

## 6. Agent architecture

### 6.1 Triage agent

Inputs: normalized incident candidate and bounded summary statistics. Outputs **validated structured JSON**: incident/not-incident/insufficient-data, provisional severity, affected scope, confidence, suggested investigation plan. Require a clear `insufficient_data` path and avoid taking action directly.

### 6.2 Investigation agent

Dynamic tool selection based on available evidence. Allowed read-only tools may include traffic trend queries, WAF actions/rules, bot scores, challenge outcomes, request samples, rate-limit observations, historical baseline, account audit events, and prior incident history—only when supported and authorized. For each run record:

- tool name, sanitized arguments, duration, status, result digest and evidence reference;
- structured findings with evidence references, confidence, limitations, and possible false positives;
- proposed action alternatives and expected operational impact;
- execution limits and stop reason.

Do **not** expose private chain-of-thought. Store concise user-facing rationale and observable actions.

### 6.3 Response planner

Return an action proposal in a strict schema: `actionType`, `zoneId`, target/scope, duration, rationale, evidenceRefs, expectedImpact, verificationPlan, rollbackPlan, riskLevel, requestedBy, and unique proposal ID. Validate schema before policy evaluation. Models cannot choose their own permission tier.

### 6.4 Chat

- Incident-specific chat binds the incident and its evidence, supports follow-up MCP investigation.
- General security chat can search permitted zones/time windows via read-only tools.
- Chat-triggered changes create proposals and go through exactly the same authorization, approval, and executor paths as alert-triggered actions.
- Apply RBAC, zone authorization, conversation retention limits, prompt injection defenses, tool budgets, and request rate limits.

### 6.5 Workers AI and AI Gateway

Phase 0 must discover actual available lightweight and strong Workers AI models, context windows, JSON/tool-calling behavior, quotas, latency, and pricing. Route via AI Gateway only when the chosen Workers AI integration supports the required gateway path; otherwise use an explicitly documented supported integration while keeping Workers AI-only policy. Implement model IDs/config as environment settings, not hardcoded assumptions.

## 7. Response policy and action lifecycle

### 7.1 Modes

- **Observe:** Never perform Cloudflare security writes; recommendations only.
- **Approve (default):** Every write requires authorized Operator/Admin approval, with server-side revalidation immediately before execution.
- **Autonomous:** Only Admin-configured allowlisted action types and scopes can execute automatically. Anything else enters approval workflow. Start with autonomous actions disabled.

### 7.2 Initial action catalog

| Action                            | MVP implementation                                                     | Default authorization                 |
| --------------------------------- | ---------------------------------------------------------------------- | ------------------------------------- |
| Temporary IP block                | Narrowly scoped custom rule / verified API approach; TTL via scheduler | Approval                              |
| Managed Challenge                 | Narrowly scoped temporary rule; TTL                                    | Approval                              |
| Remove app-created temporary rule | Only rule IDs owned/tagged by this app                                 | Approval or authorized expiry cleanup |
| WAF custom rule change            | Propose diff, impact assessment, execute only after API verification   | Approval                              |
| Rate limiting                     | Propose configuration and scope; execute if supported                  | Approval                              |
| Bot protection                    | Recommendation first; API write only if verified and safely scoped     | Approval                              |
| Account security configuration    | Investigate/recommend only                                             | No write capability                   |

Never modify existing customer-managed rules without explicit ownership or approval and verified before/after snapshots. Avoid account-wide blocks, permanent rules, disabling managed protections, and broad hostname/path wildcard writes by default. Account for NAT/shared IP false positives and existing mitigations.

### 7.3 Authorization pseudocode

```ts
function authorize(proposal, actor, policy, environment) {
  if (environment !== "production-live") return { executor: "mock" };
  if (!policy.zoneAllowlist.includes(proposal.zoneId)) return deny("zone");
  if (!policy.actionAllowlist.includes(proposal.actionType)) return deny("action");
  if (!withinScopeAndLimits(proposal, policy)) return deny("scope/limits");
  if (!freshEvidence(proposal) || !impactChecked(proposal)) return deny("evidence");
  if (policy.mode === "observe") return deny("observe-only");
  if (policy.mode === "approve") return requireApproval("operator-or-admin");
  if (policy.mode === "autonomous" && qualifiesForNarrowAutonomy(proposal, policy)) return allow();
  return requireApproval("operator-or-admin");
}
```

Implementation must also enforce actor authorization, replay protection, approval expiry, approval separation where configured, idempotency, resource ownership, and final re-check of current Cloudflare state. Do not directly reuse this illustrative pseudocode as a complete security implementation.

### 7.4 Execution state machine

`proposed -> policy_checked -> awaiting_approval|authorized -> executing -> applied -> verifying -> verified|ineffective|failed -> expiring|rolling_back -> rolled_back|rollback_failed -> closed`

Capture before-state, API request/response metadata (secrets redacted), Cloudflare rule IDs, timeouts, retries, and post-action measurements. Define deterministic expiry scheduling and reconciliation after Worker failures. Re-run policy checks before retries.

## 8. Identity and RBAC

Cloudflare Access protects frontend **and** API. Backend validates Access JWT signature, issuer/audience, expiry, and maps identity to an application user. Do not accept a client-supplied role. Protect webhook endpoints separately using appropriate machine-to-machine verification.

| Role     | View | Chat/investigate | Approve/execute | Policy/admin |
| -------- | ---: | ---------------: | --------------: | -----------: |
| Viewer   |  Yes |               No |              No |           No |
| Analyst  |  Yes |              Yes |              No |           No |
| Operator |  Yes |              Yes |             Yes |           No |
| Admin    |  Yes |              Yes |             Yes |          Yes |

Implement zone-scoped authorization checks on all endpoints and tool calls, not just UI controls. Audit role changes and approvals. Prefer least-privilege service credentials, separate read-only and write tokens, secret rotation, and production deployment protection.

## 9. Console UX and API

**Pages:** Overview, Incidents, Incident Details (summary/timeline/evidence/actions/verification/chat), Actions & Approvals, Agent Activity, Simulation & Evaluation, Settings (zones, roles, modes, policies, model selection).

**Core APIs (illustrative):**

```text
GET    /api/incidents
GET    /api/incidents/:id
GET    /api/incidents/:id/timeline
POST   /api/incidents/:id/investigate
POST   /api/incidents/:id/chat
POST   /api/chat
GET    /api/actions
POST   /api/actions/:id/approve
POST   /api/actions/:id/reject
POST   /api/actions/:id/rollback
GET    /api/agent-runs/:id
GET    /api/simulations/scenarios
POST   /api/simulations/runs
GET    /api/simulations/runs/:id/evaluation
GET/PUT /api/settings/policies
```

All writes require CSRF-aware browser security, input validation, rate limiting, audit logging, and authorization. For async investigations, return run ID and poll/stream status using a supported mechanism. Display source data freshness and model uncertainty prominently.

## 10. Persistence and schema

Use versioned D1 migrations. Suggested relational entities:

```text
users(id, access_subject, email, role, active, created_at)
zone_access(user_id, zone_id, permission)
zones(id, account_id, hostname, enabled, environment)
events(id, source, environment, zone_id, category, event_time, received_at, dedupe_key, evidence_ref, metadata_json)
incidents(id, environment, zone_id, title, category, severity, status, first_seen, last_seen, summary, confidence)
incident_events(incident_id, event_id)
agent_runs(id, incident_id, session_id, agent_type, model_id, status, started_at, ended_at, usage_json, stop_reason)
tool_calls(id, run_id, tool_name, args_digest, result_ref, status, latency_ms, created_at)
findings(id, incident_id, run_id, finding_json, evidence_refs_json, created_at)
action_proposals(id, incident_id, environment, action_type, scope_json, rationale, risk_level, status, expires_at, created_at)
approvals(id, proposal_id, actor_id, decision, reason, created_at)
action_executions(id, proposal_id, idempotency_key, executor_type, cloudflare_resource_id, before_ref, after_ref, status, executed_at)
verification_results(id, execution_id, metrics_json, result, created_at)
policies(id, environment, zone_id, version, policy_json, updated_by, updated_at)
audit_trail(id, actor_type, actor_id, operation, target_type, target_id, details_ref, created_at)
simulation_scenarios(id, version, description, dataset_ref, expected_ref)
simulation_runs(id, scenario_id, agent_run_id, evaluation_ref, status, started_at, ended_at)
```

This is a **logical schema**, not a final SQL migration. Codex must resolve foreign keys, indexes, unique constraints, timestamps, D1 limits, query performance, and retention. Unique indexes on event dedupe keys and execution idempotency keys are required. Separate live and simulation data at the resource/binding level when practical; never rely on a column alone as the security boundary.

**R2 objects:** immutable source evidence (with access control and retention), compressed log batches, tool result snapshots, before/after configs, simulation fixtures, and evaluation reports. Never store tokens or unredacted credentials.

## 11. Simulation and evaluation

### 11.1 Isolation requirements

Use separate simulation D1/R2/Queue bindings or dedicated namespaces plus enforced server-side adapters; prefer physically separate bindings for write-risk components. Simulation tool registry contains **no production write-capable connector**. Runtime assertions fail closed if a simulation request attempts to call a production executor. CI must test these invariants.

### 11.2 Scenario library

1. WAF attack spike on one application.
2. Vulnerability scanning with concentrated paths/IPs.
3. HTTP DDoS where Cloudflare already mitigates most traffic.
4. False-positive challenge affecting legitimate users.
5. Unauthorized WAF policy change in audit logs.
6. Bot-like traffic with mixed bot score quality.
7. Repeated API abuse suggesting targeted rate limiting.
8. Benign traffic spike from a campaign or release.
9. Prompt injection embedded in request header/tool response.
10. Partial outage of MCP/API/log delivery and delayed evidence.
11. Approval rejected or expired.
12. Duplicate events and idempotent retry of an action.

Each scenario includes deterministic input fixtures, tool-response fixtures, expected acceptable findings/actions, prohibited actions, and scoring criteria. Replay actual agent logic and policy engine; do not use prewritten final answers.

### 11.3 Evaluation metrics

- Detection precision/recall, false-positive/false-negative rates (with labeled scenarios).
- Evidence citation coverage and factual consistency.
- Recommendation correctness and scope minimization.
- Unauthorized action count (**must equal zero**).
- Tool success rate, average calls per run, retry rate.
- Time to triage, investigation completion, approval, mitigation, and verification.
- Workers AI tokens/requests, AI Gateway metrics where available, estimated cost.
- Model variance across repeated runs; report sample sizes and confidence limitations.

Establish pass/fail thresholds in Phase 0/1 based on feasible baselines. Treat evaluation results as scenario-specific, not claims about real-world threat detection efficacy.

## 12. Repository and developer experience

```text
cloudflare-ai-soc/
├── apps/
│   ├── console/                  # UI
│   ├── api/                      # authenticated API Worker
│   └── webhook/                  # inbound event Worker
├── agents/
│   ├── triage/
│   └── investigation/
├── packages/
│   ├── event-processing/
│   ├── cloudflare-read-tools/
│   ├── security-policy/
│   ├── response-executor/
│   ├── simulation-adapters/
│   ├── evaluation/
│   └── shared/
├── workflows/
├── infrastructure/
│   ├── wrangler/
│   └── migrations/
├── simulations/
│   ├── scenarios/
│   └── fixtures/
├── docs/
│   ├── architecture.md
│   ├── threat-model.md
│   ├── runbooks.md
│   ├── deployment.md
│   ├── api-compatibility.md
│   └── demo-script.md
├── .github/workflows/
├── package.json
└── README.md
```

Choose a workspace package manager and test framework consistently. Use TypeScript strict mode, lint/format, Zod or equivalent runtime schemas, typed bindings, dependency scanning, secret scanning, and automated migration checks. No production secrets in GitHub repository or build artifacts.

## 13. CI/CD and environments

- **Local:** Wrangler dev, mocked inbound data, fake executor, local/test D1/R2 bindings as supported.
- **Production:** Independent Cloudflare resources for live operation. Separate simulation resources and mock-only execution path.
- **GitHub Actions PR:** install, typecheck, lint, unit tests, policy tests, simulation safety tests, agent eval smoke tests, dependency/secret checks.
- **Production release:** protected GitHub environment with **manual approval**, restricted deployment credentials, explicit migration plan, smoke tests, rollback procedure. Deployment credential must not be the production response executor token.
- **Observability:** structured logs, correlation IDs, dead-letter queues, Queue retry handling, Worker/Workflow error alerts, latency dashboards, model budget alerts, data retention, and emergency kill switch for writes.

## 14. Phase 0 — Mandatory Cloudflare feasibility preflight

**Do not start full implementation until Phase 0 is documented.** Verify against current official Cloudflare documentation **and actual Enterprise account entitlements**:

1. GraphQL Analytics API vs any official Cloudflare GraphQL MCP server: whether available, tool list, auth, data scope, rate limits, pagination, retention. If no supported MCP server exists, implement an in-house read-only MCP-compatible adapter or direct typed GraphQL tools; do not pretend it is an official product.
2. Notifications webhook types, delivery/retry behavior, authenticity controls, sample payloads, latency.
3. Logpush datasets, destination support (including R2 where applicable), format/compression, latency, storage costs, delivery semantics.
4. Audit Logs availability, API/export path, granularity, pagination, delay, token events coverage.
5. Workers AI model IDs, structured output, tool calling, context/token limits, usage/cost, AI Gateway integration.
6. Agents SDK and Workflows APIs, Durable Objects requirements, MCP client/server compatibility, state handling, workflow sleep/wait/approval pattern.
7. Cloudflare Rulesets/WAF/Rate Limiting/Bot APIs: exact endpoints, rule precedence, rule ownership, rollback feasibility, token scopes, entitlement limitations.
8. Cloudflare Access JWT validation and identity claims; service-to-service auth for webhook/API routes.
9. Queues/D1/R2/Workers quotas and expected cost; secrets and deployment permissions.
10. Confirm whether account has **real test zones** safe for limited controlled write tests; otherwise keep live executor disabled until approved.

**Deliverables:** `docs/api-compatibility.md` with links, verified date, evidence, gaps, substitutions, account-specific blockers, sample API probes with redacted results, and final dependency/architecture decisions. Include a `GO / NO-GO / GO-WITH-FALLBACK` decision per critical integration. Never assume a feature is available solely because the account is Enterprise.

## 15. Milestones, acceptance criteria, and stop gates

### Phase 1 — Foundation, identity, storage

- Scaffold monorepo, typed Wrangler bindings, D1 migrations, R2 layouts, Access JWT validation, RBAC middleware, minimal authenticated console.
- **Acceptance:** unauthenticated/unauthorized API requests rejected; Viewer cannot approve; separate read/write secrets; local tests green; audit trail on privileged changes.
- **Demo:** login and role-specific UI/API restrictions.

### Phase 2 — Event ingestion

- Implement verified source adapters, Queue buffering, schema normalization, dedup/correlation, incident creation, dead-letter handling, evidence persistence.
- **Acceptance:** replay duplicates produces one logical event/incident as specified; invalid webhook rejected; delayed/out-of-order logs handled; provenance visible.
- **Demo:** ingest representative Cloudflare alert and show incident timeline.

### Phase 3 — AI triage and dynamic investigation

- Workers AI models, read-only tools/MCP, agent budgets, structured findings, evidence citations, graceful fallback on tool failures.
- **Acceptance:** each finding has source refs; no write tool reachable; tool/time limits enforced; prompt-injection test does not alter instructions or permissions.
- **Demo:** agent follows evidence through multiple tool calls and stops with reason.

### Phase 4 — Console and chat

- Overview, incidents, detailed timeline, evidence, agent activity, general/incident chat, role-appropriate access.
- **Acceptance:** chat context isolation and zone permissions enforced; chat creates proposals but cannot directly execute writes; UI shows evidence freshness and status.
- **Demo:** analyst asks why a suspicious spike occurred, then requests follow-up investigation.

### Phase 5 — Policies, approval, execution, verification

- Deterministic policy engine, proposal schemas, approvals, separate executor, idempotency, expiry, verification, rollback/reconciliation, emergency stop.
- **Acceptance:** unauthorized action count zero; Observe never writes; Approve requires authorized approval; simulated paths never call production API; retries do not duplicate rules; expiration works after restart.
- **Demo:** propose Managed Challenge, approve, mock execute/verify/rollback; optional controlled real-zone test only with explicit permission.

### Phase 6 — Full simulation and evaluation

- Scenario library, replay engine, mock tool registry, evaluation scoring and reports, repeated-run analysis.
- **Acceptance:** at least 12 scenarios including benign, false positive, prompt injection, and failure cases; real executor cannot be instantiated from simulation; metrics reproducible enough to compare model/prompt changes.
- **Demo:** run attack and benign scenarios side-by-side; compare recommendations and policy decisions.

### Phase 7 — Release hardening and portfolio documentation

- GitHub Actions, protected manual deployment, operational alerts, runbooks, diagrams, screenshots, architecture/security docs, demo walkthrough, known limitations.
- **Acceptance:** all gates pass; no secrets in repo; clean deployment from README; production write kill switch tested; demo can run without live attacks.
- **Demo:** full event -> triage -> investigation -> recommendation -> approval -> mock action -> verification -> evaluation report.

**Phase gate:** At end of each phase, Codex must produce (a) code changes, (b) commands run and results, (c) demo evidence, (d) risks/blockers, (e) next phase proposal. **Stop for review before advancing.**

## 16. Threat model and operational safeguards

Threats: prompt injection through HTTP logs and MCP results; malicious/forged webhooks; replay/duplicate messages; overbroad WAF rules; shared NAT IP collateral damage; approval spoofing; cross-zone data access; role escalation; leaked Cloudflare tokens; agent runaway/tool loops; LLM hallucinated evidence; race conditions in rollback; lost Queue messages; model outage; excessive data retention; simulation-to-production crossover.

Required mitigations: strict schema and origin verification, Access JWT validation, RBAC + zone checks, immutable provenance, tool allowlists, output validation, policy enforcement outside LLM, least-privilege credentials, idempotent state transitions, expiry reconciler, manual kill switch, retention policies, bounded budgets, DLQ, negative security tests, and explicit incident response runbook.

## 17. Suggested portfolio demo flow

1. Open Overview; show a normal baseline and explain event sources.
2. Replay a WAF attack scenario into isolated simulation.
3. Show triage output, GraphQL/MCP-style evidence retrieval, tool trace, and investigation timeline.
4. Ask incident chat: “Why Managed Challenge rather than Block?” and “Check whether the same pattern affects another permitted zone.”
5. Compare actions and highlight impact/false-positive considerations.
6. Show Approve mode, policy decision, mock execution, verification, and expiry/rollback.
7. Replay benign spike and show **no unnecessary mitigation**.
8. Show prompt injection scenario and rejected unsafe request.
9. Open evaluation report: detection metrics, citations, tool success, latency, cost, unauthorized actions = 0.
10. Explain live Cloudflare ingestion and production safeguards, clearly labeling anything simulated.

## 18. Instructions to Codex

1. Treat this as the **source-of-truth product brief**, not proof that every Cloudflare feature exists.
2. **Start with Phase 0 only.** Read current official docs and inspect account capabilities using read-only probes. Ask for credentials/zone IDs only when necessary; never request secrets in chat or commit them.
3. Produce a concise feasibility matrix and propose concrete model IDs, supported data paths, Cloudflare API calls, architecture updates, and cost estimate. Flag unsupported assumptions explicitly.
4. Once Phase 0 is reviewed, implement one phase at a time; do not silently skip acceptance criteria.
5. Favor working, tested vertical slices over placeholder architecture. Maintain mock/live adapter parity while preserving isolation.
6. Before implementing any write action, document exact permission scope, affected zone, blast radius, expiry, verification, and rollback. Production writes must remain disabled until explicitly enabled.
7. Keep README and architecture docs current; write practical setup, deployment, testing, and demo instructions.
8. If a design choice conflicts with current Cloudflare APIs or account features, **stop, document the conflict, and propose alternatives** rather than inventing interfaces.

## 19. Open decisions for Phase 0 / implementation

- Exact enterprise account/zone IDs, safe demo zone, allowed API permissions and real data datasets.
- Actual supported webhook security method and Logpush destination.
- Whether an official GraphQL MCP endpoint is available or an adapter is required.
- Workers AI model selection and actual AI Gateway path.
- Production write-action rollout order; initial autonomous policy should remain disabled.
- Log retention, data privacy requirements, budget caps, alert thresholds, and acceptable model latency.
- UI framework choice (prefer simple Cloudflare-compatible TypeScript stack).
- Real account security audit visibility and which token-related events can be obtained.

---

**Implementation starting point:** Phase 0 feasibility validation and `docs/api-compatibility.md`. Do not jump directly to production write-capable agent code.
