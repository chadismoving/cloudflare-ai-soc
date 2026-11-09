import { executableActions, type Incident, type Session, type WorkbenchPolicy } from "@soc/shared";
import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "./client";
import "./workbench.css";

type Row = Record<string, unknown>;
const obj = (v: unknown): Row =>
  v && typeof v === "object" && !Array.isArray(v) ? (v as Row) : {};
const rows = (v: unknown): Row[] => (Array.isArray(v) ? v.map(obj) : []);
const text = (v: unknown) => (v === null || v === undefined ? "—" : String(v));
const decoded = (v: unknown): Row => {
  try {
    return obj(typeof v === "string" ? JSON.parse(v) : v);
  } catch {
    return {};
  }
};
const fmt = (v: unknown) => {
  const d = new Date(String(v));
  return Number.isNaN(d.getTime()) ? "—" : d.toLocaleString();
};
const money = (v: unknown) => `US$${(Number(v || 0) / 1000000).toFixed(5)}`;
const pages = [
  "Overview",
  "Incidents",
  "Actions & Approvals",
  "Agent Activity",
  "Chat",
  "Simulation & Evaluation",
  "Settings",
] as const;
type Page = (typeof pages)[number];
function Pill({ children }: { children: React.ReactNode }) {
  return <span className="wb-pill">{children}</span>;
}
function Json({ value }: { value: unknown }) {
  return <pre className="wb-json">{JSON.stringify(value, null, 2)}</pre>;
}
function Empty({ children }: { children: React.ReactNode }) {
  return <p className="wb-empty">{children}</p>;
}
function Download({ value, name }: { value: unknown; name: string }) {
  return (
    <button
      type="button"
      onClick={() => {
        const url = URL.createObjectURL(
          new Blob([JSON.stringify(value, null, 2)], { type: "application/json" }),
        );
        const a = document.createElement("a");
        a.href = url;
        a.download = name;
        a.click();
        URL.revokeObjectURL(url);
      }}
    >
      Export JSON
    </button>
  );
}
export function Workbench({ session, onSignOut }: { session: Session; onSignOut: () => void }) {
  const [page, setPage] = useState<Page>("Overview"),
    [initialIncident, setInitialIncident] = useState(""),
    [state, setState] = useState<Row>({}),
    [incidents, setIncidents] = useState<Incident[]>([]),
    [version, setVersion] = useState(0),
    [error, setError] = useState(""),
    [notice, setNotice] = useState(""),
    [busy, setBusy] = useState(false),
    [drawer, setDrawer] = useState<{ title: string; value: unknown } | null>(null);
  const navigation = useRef(0);
  const navigate = (next: Page) => {
    if (next === page) return;
    navigation.current++;
    setNotice("");
    setPage(next);
  };
  const canAnalyze = session.user.role !== "Viewer",
    canApprove = ["Admin", "Operator"].includes(session.user.role),
    admin = session.user.role === "Admin";
  const refresh = useCallback(async () => {
    const [s, i] = await Promise.all([
      api<Row>("/api/workbench/state"),
      api<{ incidents: Incident[] }>("/api/incidents"),
    ]);
    setState(s);
    setIncidents(i.incidents);
  }, []);
  useEffect(() => {
    void refresh().catch((e) => setError(e.message));
  }, [refresh]);
  const mutate = async <T,>(path: string, body?: unknown, method = "POST"): Promise<T> =>
    api<T>(path, { method, csrf: session.csrfToken, ...(body === undefined ? {} : { body }) });
  const task = async <T,>(work: () => Promise<T>, message = "Saved."): Promise<T | undefined> => {
    const startedOnNavigation = navigation.current;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      const value = await work();
      await refresh();
      setVersion((v) => v + 1);
      if (message && startedOnNavigation === navigation.current) setNotice(message);
      return value;
    } catch (e) {
      setError(e instanceof Error ? e.message : "Operation failed.");
      return undefined;
    } finally {
      setBusy(false);
    }
  };
  const inspect = async (path: string, title: string) => {
    try {
      setDrawer({ title, value: await api(path) });
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unavailable.");
    }
  };
  const policy = obj(state.policy);
  return (
    <div className="wb-shell">
      <aside className="wb-sidebar">
        <a className="wb-brand" href="/">
          ◈ AI SOC<small>Security operations workspace</small>
        </a>
        <div className="wb-environment">
          <span className="wb-online" /> Isolated simulation
          <small>
            {state.provider === "workers_ai"
              ? "Workers AI connected"
              : "Deterministic fixture model"}
          </small>
        </div>
        <nav aria-label="Workspace navigation">
          {pages.map((p, i) => (
            <button
              type="button"
              key={p}
              className={page === p ? "active" : ""}
              onClick={() => navigate(p)}
            >
              <span>{["◫", "≋", "✓", "⌁", "◌", "▷", "⚙"][i]}</span>
              {p}
            </button>
          ))}
        </nav>
        <div className="wb-sidefoot">
          <Pill>PRODUCTION WRITES OFF</Pill>
          <p>Every rule shown here is simulated. Live Cloudflare rules remain untouched.</p>
          <span>{session.user.label}</span>
          <button type="button" onClick={onSignOut}>
            Sign out
          </button>
        </div>
      </aside>
      <div className="wb-content">
        <header className="wb-top">
          <span>
            Workspace / <strong>{page}</strong>
          </span>
          <div>
            <Pill>{text(policy.mode)} mode</Pill>
            <Pill>{session.user.role}</Pill>
            <button type="button" disabled={busy} onClick={() => void task(refresh, "Refreshed.")}>
              Refresh
            </button>
            {admin && (
              <button
                type="button"
                className={policy.killSwitch ? "wb-danger active" : "wb-danger"}
                disabled={busy}
                onClick={() =>
                  void task(
                    async () => {
                      const current = await api<{ version: number; policy: WorkbenchPolicy }>(
                        "/api/settings/policies",
                      );
                      await mutate(
                        "/api/settings/policies",
                        {
                          version: current.version,
                          policy: { ...current.policy, killSwitch: !current.policy.killSwitch },
                        },
                        "PUT",
                      );
                    },
                    policy.killSwitch
                      ? "Simulation execution resumed."
                      : "Emergency stop enabled. Expiry and rollback remain available.",
                  )
                }
              >
                {policy.killSwitch ? "Resume simulation" : "Emergency stop"}
              </button>
            )}
          </div>
        </header>
        <main className="wb-main">
          <div className="wb-page-title">
            <div>
              <span className="wb-eyebrow">EVIDENCE → DECISION → VERIFIED ACTION</span>
              <h1>{page}</h1>
            </div>
            <span className="wb-subtle">{fmt(state.serverTime)}</span>
          </div>
          <div className="wb-scope">
            <strong>
              {state.provider === "workers_ai"
                ? "Workers AI / simulation evidence"
                : "Fixture analysis / simulation execution"}
            </strong>
            <span>
              {state.provider === "fixture"
                ? "Responses and token costs are deterministic test estimates; no real AI inference is billed."
                : "Model output is schema-checked; every security action still uses the mock executor."}
            </span>
          </div>
          {error && (
            <div className="wb-error" role="alert">
              {error}
              <button type="button" onClick={() => setError("")}>
                Dismiss
              </button>
            </div>
          )}
          {notice && (
            <div className="wb-notice" role="status">
              {notice}
            </div>
          )}
          {busy && (
            <div className="wb-progress" role="status">
              Working… bounded analysis can take up to 90 seconds.
            </div>
          )}
          {page === "Overview" && (
            <>
              <div className="wb-stats">
                {[
                  ["Listed incidents", incidents.length],
                  ["Recent analysis runs", state.analysisRuns || 0],
                  ["Recent simulated executions", state.executions || 0],
                ].map(([label, value]) => (
                  <section key={String(label)}>
                    <small>{text(label)}</small>
                    <strong>{text(value)}</strong>
                  </section>
                ))}
              </div>
              <div className="wb-columns">
                <section className="wb-panel">
                  <h2>Start a complete test</h2>
                  <ol>
                    <li>Replay a scenario in Simulation & Evaluation.</li>
                    <li>Open its incident; inspect findings and tool evidence.</li>
                    <li>Create a scoped proposal, then approve and execute it.</li>
                    <li>Verify the simulated rule, roll it back or let its TTL expire.</li>
                    <li>Compare the evaluation and exported trace.</li>
                  </ol>
                  <button
                    type="button"
                    className="wb-primary"
                    onClick={() => navigate("Simulation & Evaluation")}
                  >
                    Open scenario library →
                  </button>
                </section>
                <section className="wb-panel">
                  <h2>Operational controls</h2>
                  <dl>
                    <dt>Mode</dt>
                    <dd>{text(policy.mode)}</dd>
                    <dt>Emergency stop</dt>
                    <dd>{policy.killSwitch ? "Enabled" : "Off"}</dd>
                    <dt>Last expiry reconciliation</dt>
                    <dd>{fmt(obj(state.maintenance).updated_at)}</dd>
                  </dl>
                  {admin && (
                    <button
                      type="button"
                      disabled={busy}
                      onClick={() =>
                        void task(
                          () => mutate("/api/workbench/reconcile"),
                          "Expiry and interrupted-run reconciliation finished.",
                        )
                      }
                    >
                      Reconcile now
                    </button>
                  )}
                  <p className="wb-subtle">
                    {session.authMode === "signed-local-fixture"
                      ? "Local development reconciles every 15 seconds; persisted TTLs survive a restart."
                      : "Simulation maintenance is scheduled every five minutes; delivery time can vary. Persisted TTLs survive a restart."}{" "}
                  </p>
                </section>
              </div>
              <section className="wb-panel">
                <h2>Recent incidents</h2>
                <IncidentTable
                  incidents={incidents.slice(0, 6)}
                  onSelect={(id) => {
                    setInitialIncident(id);
                    navigate("Incidents");
                  }}
                />
              </section>
            </>
          )}
          {page === "Incidents" && (
            <Incidents
              initialIncident={initialIncident}
              session={session}
              incidents={incidents}
              version={version}
              canAnalyze={canAnalyze}
              busy={busy}
              task={task}
              mutate={mutate}
              inspect={inspect}
            />
          )}
          {page === "Actions & Approvals" && (
            <Actions
              version={version}
              busy={busy}
              canApprove={canApprove}
              killed={!!policy.killSwitch}
              task={task}
              mutate={mutate}
              inspect={inspect}
            />
          )}
          {page === "Agent Activity" && <Activity version={version} inspect={inspect} />}
          {page === "Chat" && (
            <section className="wb-panel">
              <h2>General security chat</h2>
              <Chat
                session={session}
                canAnalyze={canAnalyze}
                mutate={mutate}
                task={task}
                inspect={inspect}
              />
            </section>
          )}
          {page === "Simulation & Evaluation" && (
            <Simulation
              busy={busy}
              canAnalyze={canAnalyze}
              canApprove={canApprove}
              version={version}
              task={task}
              mutate={mutate}
              inspect={inspect}
            />
          )}
          {page === "Settings" && (
            <Settings session={session} state={state} busy={busy} task={task} mutate={mutate} />
          )}
        </main>
        <footer className="wb-footer">
          Authenticated, zone-scoped API · Read-only investigation tools · Mock executor only{" "}
          <span>Source freshness and uncertainty are shown in each finding.</span>
        </footer>
      </div>
      {drawer && (
        <div className="wb-overlay">
          <section className="wb-drawer" role="dialog" aria-modal="true" aria-label={drawer.title}>
            <header>
              <h2>{drawer.title}</h2>
              <button type="button" onClick={() => setDrawer(null)}>
                Close ✕
              </button>
            </header>
            <Download value={drawer.value} name="soc-evidence-trace.json" />
            <Json value={drawer.value} />
          </section>
        </div>
      )}
    </div>
  );
}
type Mutate = <T>(path: string, body?: unknown, method?: string) => Promise<T>;
type Task = <T>(work: () => Promise<T>, message?: string) => Promise<T | undefined>;
type Inspect = (path: string, title: string) => Promise<void>;
function IncidentTable({
  incidents,
  onSelect,
}: {
  incidents: Incident[];
  onSelect: (id: string) => void;
}) {
  return (
    <div className="wb-table-wrap">
      <table>
        <thead>
          <tr>
            <th>Incident</th>
            <th>Category</th>
            <th>Severity</th>
            <th>State</th>
            <th>Last seen</th>
          </tr>
        </thead>
        <tbody>
          {incidents.map((i) => (
            <tr key={i.id}>
              <td>
                <button type="button" className="wb-link" onClick={() => onSelect(i.id)}>
                  {i.title}
                </button>
                <small>{i.id.slice(0, 24)}</small>
              </td>
              <td>{i.category}</td>
              <td>
                <Pill>{i.severity}</Pill>
              </td>
              <td>{i.status}</td>
              <td>{fmt(i.last_seen)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {!incidents.length && <Empty>No permitted incidents. Replay a scenario to begin.</Empty>}
    </div>
  );
}
function Incidents({
  initialIncident,
  session,
  incidents,
  version,
  canAnalyze,
  busy,
  task,
  mutate,
  inspect,
}: {
  initialIncident: string;
  session: Session;
  incidents: Incident[];
  version: number;
  canAnalyze: boolean;
  busy: boolean;
  task: Task;
  mutate: Mutate;
  inspect: Inspect;
}) {
  const [selected, setSelected] = useState(initialIncident),
    [query, setQuery] = useState(""),
    [tab, setTab] = useState("Findings"),
    [detail, setDetail] = useState<Row>({}),
    [runs, setRuns] = useState<Row[]>([]),
    [active, setActive] = useState<Row>({}),
    [tools, setTools] = useState<Row[]>([]),
    [duration, setDuration] = useState(300);
  const load = useCallback(async () => {
    if (!selected) return;
    const [d, w] = await Promise.all([
      api<Row>(`/api/incidents/${selected}`),
      api<Row>(`/api/incidents/${selected}/workbench`),
    ]);
    setDetail(d);
    setRuns(rows(w.runs));
    const latest = rows(w.runs).find((r) => r.kind === "investigation") || rows(w.runs)[0];
    if (latest) {
      const r = await api<Row>(`/api/agent-runs/${latest.id}`);
      setActive(obj(r.run));
      setTools(rows(r.tools));
    } else {
      setActive({});
      setTools([]);
    }
  }, [selected]);
  useEffect(() => {
    if (!selected && incidents[0]) setSelected(incidents[0].id);
  }, [incidents, selected]);
  // biome-ignore lint/correctness/useExhaustiveDependencies: version reloads persisted state after commands.
  useEffect(() => {
    void load();
  }, [load, version]);
  const finding = decoded(active.result_json),
    scope = decoded(tools.find((t) => t.name === "traffic_trend")?.result_json),
    item = obj(detail.incident);
  const analyze = async (kind: string) => {
    await task(
      () => mutate(`/api/incidents/${selected}/${kind}`),
      `${kind} finished. Inspect its evidence and stop reason.`,
    );
    await load();
  };
  return (
    <>
      <label className="wb-search">
        Search incidents
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Title, category, severity or status"
        />
      </label>
      <section className="wb-panel">
        <IncidentTable
          incidents={incidents.filter((i) =>
            `${i.title} ${i.category} ${i.severity} ${i.status}`
              .toLowerCase()
              .includes(query.toLowerCase()),
          )}
          onSelect={setSelected}
        />
      </section>
      {selected && (
        <section className="wb-panel">
          <div className="wb-panel-top">
            <div>
              <h2>{text(item.title)}</h2>
              <p className="wb-subtle">
                Source last seen {fmt(item.last_seen)} · {text(item.zone_id)}
              </p>
            </div>
            <div>
              <button
                type="button"
                disabled={!canAnalyze || busy}
                onClick={() => void analyze("triage")}
              >
                Triage
              </button>
              <button
                type="button"
                className="wb-primary"
                disabled={!canAnalyze || busy}
                onClick={() => void analyze("investigate")}
              >
                Investigate
              </button>
            </div>
          </div>
          {canAnalyze && (
            <div className="wb-toolbar">
              <span className="wb-subtle">Case state: {text(item.status)}</span>
              <button
                type="button"
                disabled={busy}
                onClick={() =>
                  void task(
                    () =>
                      mutate(`/api/incidents/${selected}/status`, {
                        status: "closed",
                        reason: "Analyst reviewed and closed this simulation case.",
                      }),
                    "Case closed. Any active simulated rule still follows its own TTL.",
                  )
                }
              >
                Close case
              </button>
              <button
                type="button"
                disabled={busy}
                onClick={() =>
                  void task(
                    () =>
                      mutate(`/api/incidents/${selected}/status`, {
                        status: "investigating",
                        reason: "Analyst reopened this simulation case.",
                      }),
                    "Case reopened.",
                  )
                }
              >
                Reopen case
              </button>
            </div>
          )}
          <div className="wb-tabs">
            {["Findings", "Evidence", "Tools", "Timeline", "Chat"].map((t) => (
              <button
                type="button"
                key={t}
                className={tab === t ? "active" : ""}
                onClick={() => setTab(t)}
              >
                {t}
              </button>
            ))}
          </div>
          {tab === "Findings" && (
            <>
              <div className="wb-inline">
                <Pill>{text(finding.verdict || "Not analyzed")}</Pill>
                <span>
                  Confidence{" "}
                  {finding.confidence === undefined
                    ? "—"
                    : `${Math.round(Number(finding.confidence) * 100)}%`}
                </span>
                <span>
                  {text(active.provider)} · {text(active.stop_reason)}
                </span>
              </div>
              <p>{text(finding.summary || item.summary)}</p>
              {rows(finding.findings).map((f, i) => (
                <article key={String(i)} className="wb-finding">
                  <p>{text(f.claim)}</p>
                  {Array.isArray(f.evidenceRefs) &&
                    f.evidenceRefs.map((ref) => (
                      <button
                        type="button"
                        className="wb-link"
                        key={String(ref)}
                        onClick={() =>
                          void inspect(
                            `/api/tool-calls/${String(ref).replace("tool:", "")}`,
                            "Cited tool evidence",
                          )
                        }
                      >
                        {String(ref).slice(0, 28)} ↗
                      </button>
                    ))}
                </article>
              ))}
              <ul>
                {Array.isArray(finding.limitations) &&
                  finding.limitations.map((v) => <li key={String(v)}>{String(v)}</li>)}
              </ul>
              <p className="wb-subtle">
                False-positive considerations:{" "}
                {Array.isArray(finding.falsePositives)
                  ? finding.falsePositives.join(" ")
                  : "Not evaluated."}
              </p>
              {canAnalyze &&
                active.kind === "investigation" &&
                active.status === "completed" &&
                finding.verdict === "incident" &&
                finding.recommendedAction !== "none" && (
                  <div className="wb-propose">
                    <h3>Propose {text(finding.recommendedAction)}</h3>
                    <p>
                      One client: {text(scope.clientId)} · exact path: {text(scope.path)}
                    </p>
                    <label>
                      Temporary duration
                      <select
                        value={duration}
                        onChange={(e) => setDuration(Number(e.target.value))}
                      >
                        <option value={60}>1 minute</option>
                        <option value={300}>5 minutes</option>
                        <option value={900}>15 minutes</option>
                      </select>
                    </label>
                    <button
                      type="button"
                      disabled={busy || !scope.clientId}
                      onClick={() =>
                        void task(
                          () =>
                            mutate("/api/actions", {
                              runId: active.id,
                              actionType: finding.recommendedAction,
                              durationSeconds: duration,
                              clientId: scope.clientId,
                              path: scope.path,
                              rationale: finding.summary,
                            }),
                          "Proposal created. Open Actions & Approvals to review it.",
                        )
                      }
                    >
                      Create scoped proposal
                    </button>
                  </div>
                )}
              {runs.length > 0 && (
                <label>
                  Inspect an earlier run
                  <select
                    value={String(active.id || "")}
                    onChange={(e) =>
                      void api<Row>(`/api/agent-runs/${e.target.value}`).then((r) => {
                        setActive(obj(r.run));
                        setTools(rows(r.tools));
                      })
                    }
                  >
                    {runs.map((r) => (
                      <option key={text(r.id)} value={text(r.id)}>
                        {text(r.kind)} · {text(r.status)} · {fmt(r.started_at)}
                      </option>
                    ))}
                  </select>
                </label>
              )}
            </>
          )}
          {tab === "Evidence" && (
            <>
              {rows(detail.evidence).map((e) => (
                <p key={text(e.id)}>
                  <button
                    type="button"
                    onClick={() =>
                      void inspect(`/api/evidence/${e.id}`, "Immutable source evidence")
                    }
                  >
                    {text(e.id)} ↗
                  </button>
                </p>
              ))}
              {!rows(detail.evidence).length && <Empty>No evidence objects registered.</Empty>}
            </>
          )}
          {tab === "Tools" && (
            <>
              {tools.map((t) => (
                <details key={text(t.id)}>
                  <summary>
                    {text(t.name)} · {text(t.status)} · {text(t.latency_ms)} ms · source{" "}
                    {fmt(t.observed_at)}
                  </summary>
                  <Json
                    value={{
                      arguments: decoded(t.args_json),
                      result: decoded(t.result_json),
                      resultDigest: t.result_digest,
                    }}
                  />
                </details>
              ))}
              {!tools.length && <Empty>Run an investigation to inspect tool calls.</Empty>}
            </>
          )}
          {tab === "Timeline" && (
            <button
              type="button"
              onClick={() =>
                void inspect(
                  `/api/incidents/${selected}/timeline`,
                  "Incident timeline and provenance",
                )
              }
            >
              Open source timeline
            </button>
          )}
          {tab === "Chat" && (
            <Chat
              key={selected}
              session={session}
              incidentId={selected}
              fixedZone={String(item.zone_id || "fixture-zone")}
              canAnalyze={canAnalyze}
              mutate={mutate}
              task={task}
              inspect={inspect}
            />
          )}
        </section>
      )}
    </>
  );
}
function Actions({
  version,
  busy,
  canApprove,
  killed,
  task,
  mutate,
  inspect,
}: {
  version: number;
  busy: boolean;
  canApprove: boolean;
  killed: boolean;
  task: Task;
  mutate: Mutate;
  inspect: Inspect;
}) {
  const [actions, setActions] = useState<Row[]>([]),
    [selected, setSelected] = useState(""),
    [detail, setDetail] = useState<Row>({}),
    [reason, setReason] = useState("Reviewed this isolated simulated action.");
  const load = useCallback(async () => {
    const data = await api<Row>("/api/actions");
    setActions(rows(data.proposals));
    if (selected) setDetail(await api(`/api/actions/${selected}`));
  }, [selected]);
  // biome-ignore lint/correctness/useExhaustiveDependencies: version reloads persisted state after commands.
  useEffect(() => {
    void load();
  }, [load, version]);
  const p = obj(detail.proposal),
    proposal = decoded(p.proposal_json),
    execution = obj(detail.execution);
  const command = async (op: string) => {
    await task(
      () =>
        mutate(
          `/api/actions/${selected}/${op}`,
          op === "approve" || op === "reject" ? { reason } : undefined,
        ),
      `${op} completed in simulation.`,
    );
    await load();
  };
  return (
    <>
      <section className="wb-panel">
        <h2>Proposals and execution records</h2>
        <div className="wb-table-wrap">
          <table>
            <thead>
              <tr>
                <th>Proposal</th>
                <th>Action</th>
                <th>State</th>
                <th>Approval deadline</th>
              </tr>
            </thead>
            <tbody>
              {actions.map((a) => (
                <tr key={text(a.id)}>
                  <td>
                    <button
                      type="button"
                      className="wb-link"
                      onClick={() => setSelected(String(a.id))}
                    >
                      {text(a.id).slice(0, 25)}
                    </button>
                  </td>
                  <td>{text(decoded(a.proposal_json).actionType)}</td>
                  <td>
                    <Pill>{text(a.status)}</Pill>
                  </td>
                  <td>{fmt(a.approval_deadline)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {!actions.length && (
          <Empty>Create a proposal from a completed investigation or chat.</Empty>
        )}
      </section>
      {selected && (
        <section className="wb-panel">
          <h2>
            {text(proposal.actionType)} · {text(p.status)}
          </h2>
          <p>{text(proposal.rationale)}</p>
          <div className="wb-inline">
            <Pill>SIMULATED RULE ONLY</Pill>
            <span>Risk: {text(proposal.riskLevel)}</span>
            <span>Policy version {text(p.policy_version)}</span>
          </div>
          <Json
            value={{
              hostname: proposal.hostname,
              path: proposal.path,
              clientId: proposal.clientId,
              durationSeconds: proposal.durationSeconds,
              expectedImpact: proposal.expectedImpact,
              evidenceRefs: proposal.evidenceRefs,
            }}
          />
          <p>{text(proposal.verificationPlan)}</p>
          <p>{text(proposal.rollbackPlan)}</p>
          <label>
            Approval / rejection reason
            <input value={reason} maxLength={300} onChange={(e) => setReason(e.target.value)} />
          </label>
          <div className="wb-toolbar">
            <button
              type="button"
              disabled={!canApprove || busy || p.status !== "awaiting_approval" || killed}
              onClick={() => void command("approve")}
            >
              Approve
            </button>
            <button
              type="button"
              disabled={!canApprove || busy || p.status !== "awaiting_approval"}
              onClick={() => void command("reject")}
            >
              Reject
            </button>
            <button
              type="button"
              className="wb-primary"
              disabled={!canApprove || busy || p.status !== "authorized" || killed}
              onClick={() => void command("execute")}
            >
              Execute simulated action
            </button>
            <button
              type="button"
              disabled={
                !canApprove ||
                busy ||
                !["verified", "rollback_failed"].includes(String(execution.status))
              }
              onClick={() => void command("rollback")}
            >
              Rollback owned rule
            </button>
            <button
              type="button"
              onClick={() =>
                void inspect(
                  `/api/actions/${selected}`,
                  "Approval, execution and verification trace",
                )
              }
            >
              Full trace
            </button>
          </div>
          <h3>Verification</h3>
          <Json value={detail.verification || []} />
          <p className="wb-subtle">
            Verification checks configuration and TTL. Traffic reduction has not been measured.
            Emergency stop prevents new executions; owned-rule rollback and expiry continue.
          </p>
        </section>
      )}
    </>
  );
}
function Activity({ version, inspect }: { version: number; inspect: Inspect }) {
  const [runs, setRuns] = useState<Row[]>([]);
  // biome-ignore lint/correctness/useExhaustiveDependencies: version reloads persisted state after commands.
  useEffect(() => {
    void api<Row>("/api/agent-runs").then((r) => setRuns(rows(r.runs)));
  }, [version]);
  return (
    <section className="wb-panel">
      <h2>Observable agent activity</h2>
      <p className="wb-subtle">
        Tools, sanitized arguments, evidence digests and stop reasons. Private model reasoning is
        not stored.
      </p>
      <div className="wb-table-wrap">
        <table>
          <thead>
            <tr>
              <th>Run</th>
              <th>Provider / model</th>
              <th>Status</th>
              <th>Stop reason</th>
              <th>Metered estimate</th>
            </tr>
          </thead>
          <tbody>
            {runs.map((r) => (
              <tr key={text(r.id)}>
                <td>
                  <button
                    type="button"
                    className="wb-link"
                    onClick={() => void inspect(`/api/agent-runs/${r.id}`, "Agent trace")}
                  >
                    {text(r.kind)} · {text(r.id).slice(-8)}
                  </button>
                  <small>{fmt(r.started_at)}</small>
                </td>
                <td>
                  {text(r.provider)}
                  <small>{text(r.model_id)}</small>
                </td>
                <td>{text(r.status)}</td>
                <td>{text(r.stop_reason)}</td>
                <td>{money(decoded(r.usage_json).costMicro)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {!runs.length && (
        <Empty>No analysis yet. Replay a scenario or investigate an incident.</Empty>
      )}
    </section>
  );
}
function Chat({
  session,
  incidentId,
  fixedZone,
  canAnalyze,
  mutate,
  task,
  inspect,
}: {
  session: Session;
  incidentId?: string;
  fixedZone?: string;
  canAnalyze: boolean;
  mutate: Mutate;
  task: Task;
  inspect: Inspect;
}) {
  const [zone, setZone] = useState(fixedZone || session.zoneGrants[0]?.zoneId || ""),
    [threads, setThreads] = useState<Row[]>([]),
    [thread, setThread] = useState(""),
    [messages, setMessages] = useState<Row[]>([]),
    [draft, setDraft] = useState(""),
    [sending, setSending] = useState(false);
  useEffect(() => {
    void api<Row>("/api/chat/threads").then((r) => setThreads(rows(r.threads)));
  }, []);
  async function select(id: string) {
    setThread(id);
    setMessages(id ? rows((await api<Row>(`/api/chat/threads/${id}`)).messages) : []);
  }
  const send = async () => {
    if (!draft.trim() || sending) return;
    setSending(true);
    try {
      const result = await task(
        () =>
          mutate<Row>(incidentId ? `/api/incidents/${incidentId}/chat` : "/api/chat", {
            message: draft,
            ...(incidentId ? {} : { zoneId: zone }),
            ...(thread ? { threadId: thread } : {}),
          }),
        "",
      );
      if (result) {
        setDraft("");
        await select(String(result.threadId));
        setThreads(rows((await api<Row>("/api/chat/threads")).threads));
      }
    } finally {
      setSending(false);
    }
  };
  return (
    <div className="wb-chat">
      <div className="wb-toolbar">
        {!fixedZone && (
          <label>
            Authorized zone
            <select
              value={zone}
              onChange={(e) => {
                setZone(e.target.value);
                void select("");
              }}
            >
              {session.zoneGrants.map((g) => (
                <option key={g.zoneId}>{g.zoneId}</option>
              ))}
            </select>
          </label>
        )}
        <label>
          Conversation
          <select value={thread} onChange={(e) => void select(e.target.value)}>
            <option value="">New conversation</option>
            {threads
              .filter((t) => t.zone_id === zone && (t.incident_id || undefined) === incidentId)
              .map((t) => (
                <option key={text(t.id)} value={text(t.id)}>
                  {fmt(t.created_at)} · {text(t.id).slice(-8)}
                </option>
              ))}
          </select>
        </label>
      </div>
      <div className="wb-messages">
        {messages.map((m, i) => (
          <article className={`wb-message ${m.role}`} key={String(i)}>
            <strong>{text(m.role)}</strong>
            <p>{text(m.content)}</p>
            {!!m.run_id && (
              <button
                type="button"
                className="wb-link"
                onClick={() =>
                  void inspect(`/api/agent-runs/${m.run_id}`, "Conversation evidence and tools")
                }
              >
                View cited run ↗
              </button>
            )}
          </article>
        ))}
        {!messages.length && (
          <Empty>
            Ask about evidence, false positives, alternative actions or a proposed mitigation.
          </Empty>
        )}
      </div>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void send();
        }}
      >
        <label>
          Message
          <textarea
            value={draft}
            disabled={!canAnalyze}
            maxLength={2000}
            onChange={(e) => setDraft(e.target.value)}
            placeholder={
              canAnalyze ? "Why challenge rather than block?" : "Viewer cannot investigate or chat."
            }
          />
        </label>
        <button
          type="submit"
          className="wb-primary"
          disabled={!canAnalyze || sending || !draft.trim()}
        >
          Send
        </button>
      </form>
      <p className="wb-subtle">
        Conversations are private to the current identity and fixed zone/incident. Chat can create
        proposals; it cannot execute them. Secrets and IPs are redacted before storage.
      </p>
    </div>
  );
}
function Simulation({
  busy,
  canAnalyze,
  canApprove,
  version,
  task,
  mutate,
  inspect,
}: {
  busy: boolean;
  canAnalyze: boolean;
  canApprove: boolean;
  version: number;
  task: Task;
  mutate: Mutate;
  inspect: Inspect;
}) {
  const [catalog, setCatalog] = useState<Row[]>([]),
    [report, setReport] = useState<Row>({}),
    [loadError, setLoadError] = useState(""),
    [progress, setProgress] = useState(""),
    [exercise, setExercise] = useState(false),
    [keys, setKeys] = useState<Record<string, string>>({});
  const stop = useRef(false);
  const [suiteId, setSuiteId] = useState("");
  // biome-ignore lint/correctness/useExhaustiveDependencies: version reloads persisted state after a suite.
  useEffect(() => {
    let current = true;
    void Promise.all([
      api<Row>("/api/simulations/scenarios"),
      api<Row>(
        `/api/simulations/report${suiteId ? `?suiteId=${encodeURIComponent(suiteId)}` : ""}`,
      ),
    ])
      .then(([scenarios, evaluation]) => {
        if (!current) return;
        setCatalog(rows(scenarios.scenarios));
        setReport(evaluation);
        setLoadError("");
      })
      .catch((error: unknown) => {
        if (current)
          setLoadError(error instanceof Error ? error.message : "Cannot load scenarios.");
      });
    return () => {
      current = false;
    };
  }, [version, suiteId]);
  const runOne = async (scenario: string, repeat = false) => {
    const key = repeat && keys[scenario] ? keys[scenario] : crypto.randomUUID();
    setKeys((v) => ({ ...v, [scenario]: key }));
    const result = await task(
      () =>
        mutate<Row>("/api/simulations/runs", {
          scenarioId: scenario,
          replayKey: key,
          exerciseActions: false,
        }),
      "Scenario analyzed. Open its incident to review findings.",
    );
    if (result)
      await inspect(`/api/agent-runs/${obj(result.run).id}`, "Scenario findings and trace");
  };
  const suite = async () => {
    if (!catalog.length || loadError) return;
    stop.current = false;
    const currentSuite = crypto.randomUUID();
    setSuiteId(currentSuite);
    await task(async () => {
      let i = 0;
      try {
        for (const scenario of catalog) {
          if (stop.current) break;
          setProgress(`${i + 1} / ${catalog.length}: ${scenario.name}`);
          await mutate("/api/simulations/runs", {
            scenarioId: scenario.id,
            replayKey: crypto.randomUUID(),
            exerciseActions: exercise,
            suiteId: currentSuite,
          });
          i++;
        }
        setReport(await api(`/api/simulations/report?suiteId=${currentSuite}`));
        setProgress(stop.current ? "Stopped after the current scenario." : "Suite completed.");
      } catch (error) {
        setProgress(
          `Suite interrupted. ${i} / ${catalog.length} scenarios confirmed complete; check saved results before rerunning.`,
        );
        throw error;
      }
    }, "Evaluation report updated.");
  };
  const metrics = obj(report.metrics);
  return (
    <>
      <section className="wb-panel">
        <div className="wb-panel-top">
          <div>
            <h2>End-to-end scenario suite</h2>
            <p>
              Each case replays the actual investigation and policy paths against synthetic
              evidence.
            </p>
          </div>
          <Download value={report} name="soc-evaluation-report.json" />
        </div>
        {loadError && (
          <p className="wb-error" role="alert">
            {loadError} Use Refresh after reconnecting.
          </p>
        )}
        <div className="wb-toolbar">
          <label className="wb-check">
            <input
              type="checkbox"
              disabled={!canApprove || busy}
              checked={exercise}
              onChange={(e) => setExercise(e.target.checked)}
            />
            Explicitly exercise mock approvals, execution and rejected approvals
          </label>
          <button
            type="button"
            className="wb-primary"
            disabled={!canAnalyze || busy || !catalog.length || !!loadError}
            onClick={() => void suite()}
          >
            Run all 12 scenarios
          </button>
          {busy && (
            <button
              type="button"
              onClick={() => {
                stop.current = true;
              }}
            >
              Stop after current case
            </button>
          )}
        </div>
        <p role="status">{progress}</p>
        <p className="wb-subtle">
          Fixture-mode scores test software behavior, not LLM detection quality. Existing policy,
          emergency stop, evidence freshness and role restrictions apply during the suite.
        </p>
        <Json value={metrics} />
      </section>
      <div className="wb-scenarios">
        {catalog.map((s) => (
          <section key={text(s.id)} className="wb-panel">
            <span className="wb-eyebrow">{text(s.category)}</span>
            <h3>{text(s.name)}</h3>
            <p>{text(s.description)}</p>
            <div className="wb-toolbar">
              <button
                type="button"
                disabled={!canAnalyze || busy}
                onClick={() => void runOne(String(s.id))}
              >
                Replay & investigate
              </button>
              {keys[String(s.id)] && (
                <button
                  type="button"
                  disabled={!canAnalyze || busy}
                  onClick={() => void runOne(String(s.id), true)}
                >
                  Repeat same delivery
                </button>
              )}
            </div>
          </section>
        ))}
      </div>
      <section className="wb-panel">
        <h2>Evaluation history</h2>
        {rows(report.runs).map((r) => (
          <details key={text(r.id)}>
            <summary>
              {text(r.scenario_id)} · {fmt(r.created_at)}
            </summary>
            <Json value={decoded(r.evaluation_json)} />
            <button
              type="button"
              onClick={() => void inspect(`/api/agent-runs/${r.run_id}`, "Evaluation source run")}
            >
              Inspect actual run
            </button>
          </details>
        ))}
      </section>
    </>
  );
}
function Settings({
  session,
  state,
  busy,
  task,
  mutate,
}: {
  session: Session;
  state: Row;
  busy: boolean;
  task: Task;
  mutate: Mutate;
}) {
  const [policy, setPolicy] = useState<WorkbenchPolicy | null>(null),
    [policyVersion, setPolicyVersion] = useState(0),
    [users, setUsers] = useState<Row[]>([]),
    [audit, setAudit] = useState<Row[]>([]);
  const admin = session.user.role === "Admin";
  const load = useCallback(async () => {
    const p = await api<{ policy: WorkbenchPolicy; version: number }>("/api/settings/policies");
    setPolicy(p.policy);
    setPolicyVersion(p.version);
    if (admin) {
      setUsers(rows((await api<Row>("/api/admin/users")).users));
      setAudit(rows((await api<Row>("/api/workbench/audit")).records));
    }
  }, [admin]);
  useEffect(() => {
    void load();
  }, [load]);
  if (!policy) return <Empty>Loading policy…</Empty>;
  const patch = <K extends keyof WorkbenchPolicy>(key: K, value: WorkbenchPolicy[K]) =>
    setPolicy((p) => (p ? { ...p, [key]: value } : p));
  const save = async () => {
    await task(
      () => mutate("/api/settings/policies", { version: policyVersion, policy }, "PUT"),
      "Policy saved; existing proposals will be revalidated.",
    );
    await load();
  };
  return (
    <>
      <section className="wb-panel">
        <h2>Simulation AI usage and budget</h2>
        <dl>
          <dt>Monthly AI usage estimate</dt>
          <dd>{money(obj(state.budget).spent_micro)}</dd>
          <dt>Monthly AI budget</dt>
          <dd>US${text(obj(state.policy).monthlyBudgetUsd)}</dd>
        </dl>
        {state.budgetWarning === true && (
          <p role="status">AI usage has reached the 80% budget threshold.</p>
        )}
        <p className="wb-subtle">
          Fixture usage is simulated. Workers AI billing is tracked separately.
        </p>
      </section>
      <section className="wb-panel">
        <h2>Deterministic response policy</h2>
        <p>Simulation only. Production execution is absent from this runtime.</p>
        <div className="wb-form-grid">
          <label>
            Mode
            <select
              disabled={!admin}
              value={policy.mode}
              onChange={(e) => patch("mode", e.target.value as WorkbenchPolicy["mode"])}
            >
              {["Observe", "Approve", "Autonomous"].map((v) => (
                <option key={v}>{v}</option>
              ))}
            </select>
          </label>
          <label>
            Model provider
            <select
              disabled={!admin}
              value={policy.provider}
              onChange={(e) => patch("provider", e.target.value as WorkbenchPolicy["provider"])}
            >
              <option value="fixture">Deterministic fixture (no AI bill)</option>
              <option value="workers_ai" disabled={!state.workersAiReady}>
                Workers AI (deployment acceptance required)
              </option>
            </select>
          </label>
          {(["triageModel", "investigationModel"] as const).map((key) => (
            <label key={key}>
              {key}
              <select
                disabled={!admin}
                value={policy[key]}
                onChange={(e) => patch(key, e.target.value as WorkbenchPolicy[typeof key])}
              >
                <option>@cf/zai-org/glm-5.3-flash</option>
                <option>@cf/zai-org/glm-5.3</option>
              </select>
            </label>
          ))}
          {(
            [
              "monthlyBudgetUsd",
              "maxDurationSeconds",
              "maxRequestSharePercent",
              "maxEvidenceAgeSeconds",
              "maxToolCalls",
              "triageDeadlineSeconds",
              "investigationDeadlineSeconds",
            ] as const
          ).map((key) => (
            <label key={key}>
              {key === "monthlyBudgetUsd" ? "Monthly AI budget (USD)" : key}
              <input
                type="number"
                disabled={!admin}
                value={policy[key]}
                onChange={(e) => patch(key, Number(e.target.value))}
              />
            </label>
          ))}
        </div>
        <div className="wb-toolbar">
          <label className="wb-check">
            <input
              type="checkbox"
              disabled={!admin}
              checked={policy.requireSecondApprover}
              onChange={(e) => patch("requireSecondApprover", e.target.checked)}
            />
            Require a different approver
          </label>
          <label className="wb-check">
            <input
              type="checkbox"
              disabled={!admin}
              checked={policy.killSwitch}
              onChange={(e) => patch("killSwitch", e.target.checked)}
            />
            Emergency stop
          </label>
        </div>
        <h3>Autonomous allowlist (simulation)</h3>
        <div className="wb-toolbar">
          {executableActions.map((a) => (
            <label className="wb-check" key={a}>
              <input
                type="checkbox"
                disabled={!admin}
                checked={policy.autonomousActions.includes(a)}
                onChange={(e) =>
                  patch(
                    "autonomousActions",
                    e.target.checked
                      ? [...policy.autonomousActions, a]
                      : policy.autonomousActions.filter((v) => v !== a),
                  )
                }
              />
              {a}
            </label>
          ))}
        </div>
        <button
          type="button"
          className="wb-primary"
          disabled={!admin || busy}
          onClick={() => void save()}
        >
          Save policy version {policyVersion}
        </button>
        <p className="wb-subtle">
          No prompt or response content is stored in Gateway by the adapter. The real route still
          needs deployment and privacy acceptance.
        </p>
      </section>
      {admin && (
        <section className="wb-panel">
          <h2>Local role tests</h2>
          <p>
            {session.authMode === "cloudflare-access"
              ? "Owner-only pilot membership is locked."
              : "Change the secondary fixture user, then sign out and select that identity to test its permissions."}
          </p>
          {users.map((u) => (
            <div className="wb-toolbar" key={text(u.id)}>
              <span>
                {text(u.id)} · {text(u.role)}
              </span>
              {u.id !== "user-admin" && session.authMode === "signed-local-fixture" && (
                <select
                  value={text(u.role)}
                  onChange={(e) =>
                    void task(
                      () =>
                        mutate(
                          `/api/admin/users/${u.id}/role`,
                          { role: e.target.value, version: u.version },
                          "PATCH",
                        ),
                      "Role updated. Re-enter the secondary session.",
                    ).then(load)
                  }
                >
                  {["Viewer", "Analyst", "Operator"].map((r) => (
                    <option key={r}>{r}</option>
                  ))}
                </select>
              )}
            </div>
          ))}
        </section>
      )}
      {admin && (
        <section className="wb-panel">
          <h2>Workbench audit trail</h2>
          <Download value={audit} name="soc-simulation-audit.json" />
          {audit.slice(0, 30).map((r) => (
            <details key={text(r.id)}>
              <summary>
                {text(r.operation)} · {fmt(r.created_at)}
              </summary>
              <Json value={decoded(r.details_json)} />
            </details>
          ))}
        </section>
      )}
    </>
  );
}
