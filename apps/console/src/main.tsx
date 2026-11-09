import {
  type AuditRecord,
  type Incident,
  type IngestionCoverage,
  policy,
  type Session,
} from "@soc/shared";
import { StrictMode, useCallback, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import "./style.css";

import { ApiError, api } from "./client";
import { Workspace } from "./live";

type Page = "overview" | "incidents" | "settings";
function Icon({ name }: { name: "grid" | "signal" | "settings" | "shield" | "arrow" | "log" }) {
  const paths = {
    grid: "M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z",
    signal: "M3 17h3l3-10 5 14 3-12 2 8h2",
    settings: "M4 6h16M4 12h16M4 18h16M8 3v6M16 9v6M10 15v6",
    shield: "M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6zM8 12l3 3 5-6",
    arrow: "M5 12h14m-6-6 6 6-6 6",
    log: "M6 3h12v18H6zM9 8h6M9 12h6M9 16h4",
  };
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d={paths[name]} />
    </svg>
  );
}
function Badge({ children, tone = "muted" }: { children: React.ReactNode; tone?: string }) {
  return <span className={`badge ${tone}`}>{children}</span>;
}
function date(value: string): string {
  return new Intl.DateTimeFormat("en", {
    hour: "2-digit",
    minute: "2-digit",
    month: "short",
    day: "numeric",
  }).format(new Date(value));
}

function App() {
  const [session, setSession] = useState<Session | null>(null);
  const [ready, setReady] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [page, setPage] = useState<Page>("overview");
  const [auditVersion, setAuditVersion] = useState(0);
  const localUi = session
    ? session.authMode === "signed-local-fixture"
    : window.location.hostname === "127.0.0.1";
  const refreshSession = useCallback(async () => {
    try {
      setSession(await api<Session>("/api/session"));
    } catch (e) {
      if (!(e instanceof ApiError && e.status === 401))
        setError(e instanceof Error ? e.message : "Session unavailable.");
      setSession(null);
    } finally {
      setReady(true);
    }
  }, []);
  useEffect(() => {
    void refreshSession();
  }, [refreshSession]);

  async function signIn(persona: "admin" | "viewer") {
    setBusy(true);
    setError("");
    try {
      await api("/__local/session", { method: "POST", body: { persona } });
      await refreshSession();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Sign-in failed.");
    } finally {
      setBusy(false);
    }
  }
  async function signOut() {
    if (!session) return;
    if (session.authMode === "cloudflare-access") {
      window.location.assign("/cdn-cgi/access/logout");
      return;
    }
    try {
      await api("/__local/logout", { method: "POST", csrf: session.csrfToken });
      setSession(null);
      setPage("overview");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Sign-out failed.");
    }
  }
  if (session?.workbenchEnabled)
    return <Workspace session={session} onSignOut={() => void signOut()} />;
  const items: Array<{ id: Page; label: string; icon: "grid" | "signal" | "settings" }> = [
    { id: "overview", label: "Overview", icon: "grid" },
    { id: "incidents", label: "Incidents", icon: "signal" },
    { id: "settings", label: "Settings", icon: "settings" },
  ];
  return (
    <div className="app">
      <aside className="sidebar">
        <a className="brand" href="/">
          <span className="brand-mark">
            <Icon name="shield" />
          </span>
          <span>
            AI SOC<small>Cloudflare workspace</small>
          </span>
        </a>
        <div className="workspace">
          <span className="workspace-avatar">{localUi ? "L" : "A"}</span>
          <span>
            {localUi ? "Local foundation" : "Access foundation"}
            <small>{localUi ? "Isolated development" : "Owner-only pilot"}</small>
          </span>
          <span className="workspace-chevron">⌄</span>
        </div>
        <div className="nav-label">WORKSPACE</div>
        <nav aria-label="Main navigation">
          {items.map((item) => (
            <button
              type="button"
              key={item.id}
              className={page === item.id ? "nav-item active" : "nav-item"}
              onClick={() => setPage(item.id)}
              disabled={!session}
            >
              <Icon name={item.icon} />
              {item.label}
              {item.id === "overview" && <span className="nav-active-dot" />}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="mini-status">
            <span className="dot" />
            Live connectors disabled
          </div>
          <p>Phase 1 · {localUi ? "local scope" : "simulation data"}</p>
          <div className="phase-track">
            <span />
          </div>
          <small>No live collection or security writes.</small>
        </div>
      </aside>
      <div className="main">
        <header className="topbar">
          <div className="breadcrumb">
            Workspace <span>/</span> <strong>{items.find((v) => v.id === page)?.label}</strong>
          </div>
          <div className="topbar-right">
            <Badge tone="lime">
              {localUi ? "LOCAL FIXTURE" : session ? "ACCESS VERIFIED" : "ACCESS REQUIRED"}
            </Badge>
            {session && (
              <>
                <div className="identity">
                  <span className="avatar">{session.user.role[0]}</span>
                  <span>{session.user.label}</span>
                </div>
                <button type="button" className="text-button" onClick={() => void signOut()}>
                  Sign out
                </button>
              </>
            )}
          </div>
        </header>
        <main>
          {error && (
            <div role="alert" className="error-banner">
              {error}
              <button type="button" onClick={() => setError("")}>
                Dismiss
              </button>
            </div>
          )}
          {!ready ? (
            <div className="loading" role="status">
              Checking your session…
            </div>
          ) : !session && !localUi ? (
            <section className="welcome">
              <div className="eyebrow">OWNER-ONLY WORKSPACE</div>
              <h1>Access session unavailable.</h1>
              <p>
                Reload to sign in through Cloudflare Access. Your identity must also be allowed by
                the application.
              </p>
              <a href="/">Reload and sign in</a>
            </section>
          ) : !session ? (
            <section className="welcome">
              <div className="eyebrow">
                <span className="dot" /> LOCAL SIMULATION WORKSPACE
              </div>
              <h1>
                A clear view.
                <br />
                <span>A controlled boundary.</span>
              </h1>
              <p>
                Review seeded security signals and verify access controls in an isolated workspace.
              </p>
              <div className="login-card">
                <div className="card-heading">
                  <Icon name="shield" />
                  <div>
                    <h2>Choose a fixture session</h2>
                    <p>Signed JWTs. Server-side permissions.</p>
                  </div>
                </div>
                <button
                  type="button"
                  className="persona"
                  disabled={busy}
                  onClick={() => void signIn("admin")}
                >
                  <span className="persona-icon">A</span>
                  <span>
                    <strong>Admin fixture</strong>
                    <small>Inspect the workspace, roles and audit trail</small>
                  </span>
                  <Icon name="arrow" />
                </button>
                <button
                  type="button"
                  className="persona"
                  disabled={busy}
                  onClick={() => void signIn("viewer")}
                >
                  <span className="persona-icon secondary">V</span>
                  <span>
                    <strong>Secondary user fixture</strong>
                    <small>Viewer by default · role stored on the server</small>
                  </span>
                  <Icon name="arrow" />
                </button>
                <div className="fixture-note">
                  This is a local authentication demo. It sends no login email and does not verify
                  your real Cloudflare Access identity.
                </div>
              </div>
              <div className="welcome-foot">
                <span>
                  <Icon name="log" /> Synthetic evidence only
                </span>
                <span>
                  <Icon name="shield" /> No live executor
                </span>
              </div>
            </section>
          ) : page === "settings" ? (
            <Settings
              session={session}
              onChange={() => setAuditVersion((v) => v + 1)}
              onError={setError}
            />
          ) : (
            <Overview
              session={session}
              page={page}
              auditVersion={auditVersion}
              onSettings={() => setPage("settings")}
              onError={setError}
            />
          )}
        </main>
        <footer>
          <span>
            <span className="dot" /> Isolated workspace
          </span>
          <span>Synthetic evidence · live security writes disabled</span>
        </footer>
      </div>
    </div>
  );
}

function Overview({
  session,
  page,
  auditVersion,
  onSettings,
  onError,
}: {
  session: Session;
  page: Page;
  auditVersion: number;
  onSettings: () => void;
  onError: (v: string) => void;
}) {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selected, setSelected] = useState("");
  const [loaded, setLoaded] = useState(false);
  useEffect(() => {
    let active = true;
    api<{ incidents: Incident[] }>("/api/overview")
      .then((v) => {
        if (active) {
          setIncidents(v.incidents);
          setSelected(v.incidents[0]?.id || "");
          setLoaded(true);
        }
      })
      .catch((e) => onError(e.message));
    return () => {
      active = false;
    };
  }, [onError]);
  return (
    <>
      <div className="page-heading">
        <div>
          <div className="eyebrow">YOUR WORKSPACE, AT A GLANCE</div>
          <h1>{page === "incidents" ? "Incident workspace" : "Security overview"}</h1>
          <p>Review simulation incidents and trace each record to its evidence.</p>
        </div>
        <Badge tone="outline">
          APPROVE MODE <span className="tiny-separator">/</span> EXECUTOR OFF
        </Badge>
      </div>
      <div className="scope-banner">
        <div>
          <span className="scope-symbol">S</span>
          <div>
            <strong>Simulation workspace</strong>
            <span>Curated fixtures · Live feeds are not connected</span>
          </div>
        </div>
        <button type="button" onClick={onSettings}>
          View boundaries <Icon name="arrow" />
        </button>
      </div>
      <div className="metrics">
        <Metric
          label="SIMULATION INCIDENTS"
          value={loaded ? `${incidents.length}` : "—"}
          note="Fixture records in your permitted zone"
          accent
        />
        <Metric label="MODEL RUNS" value="0" note="Analysis starts in a later phase" />
        <Metric label="EXECUTED ACTIONS" value="0" note="Live and autonomous execution disabled" />
        <Metric
          label="AI BUDGET POLICY"
          value="$50"
          note="Monthly policy · usage is not connected"
        />
      </div>
      {session.simulationIngestionEnabled && (
        <IngestionStatus
          cloud={session.authMode === "cloudflare-access"}
          health={session.simulationHealthEnabled === true}
        />
      )}
      <div className="incident-layout">
        <section className="panel incident-panel">
          <div className="panel-heading">
            <div>
              <span className="panel-kicker">SIGNAL INBOX</span>
              <h2>
                Incidents <span className="count">{incidents.length}</span>
              </h2>
            </div>
            <Badge>SIMULATION</Badge>
          </div>
          <div className="table-scroll">
            <table className="incidents-table">
              <thead>
                <tr>
                  <th>Signal</th>
                  <th>Severity</th>
                  <th>Last seen</th>
                </tr>
              </thead>
              <tbody>
                {incidents.map((v) => (
                  <tr key={v.id} className={selected === v.id ? "selected" : ""}>
                    <td>
                      <button
                        type="button"
                        className="incident-select"
                        onClick={() => setSelected(v.id)}
                      >
                        <span className={`signal-icon ${v.category}`}>
                          <Icon name={v.category === "waf" ? "shield" : "signal"} />
                        </span>
                        <span>
                          <strong>{v.title}</strong>
                          <small>
                            {v.id} <span>·</span> {v.category.toUpperCase()} <span>·</span>{" "}
                            {v.id.startsWith("ingest-") ? "Synthetic ingestion" : "Seeded fixture"}
                          </small>
                        </span>
                      </button>
                    </td>
                    <td>
                      <Badge tone={v.severity === "high" ? "amber" : "blue"}>
                        {v.severity.toUpperCase()}
                      </Badge>
                    </td>
                    <td className="muted nowrap">{date(v.last_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {!loaded && <p className="empty">Loading fixture records…</p>}
          {loaded && !incidents.length && (
            <p className="empty">No fixture incidents available for this identity.</p>
          )}
          <div className="table-foot">
            <span>Showing permitted simulation records only</span>
            <span>{incidents.length} records</span>
          </div>
        </section>
        <IncidentDetail id={selected} onError={onError} />
      </div>
      <div className="lower-grid">
        <section className="panel">
          <div className="panel-heading">
            <div>
              <span className="panel-kicker">VERIFICATION STATUS</span>
              <h2>Foundation boundaries</h2>
            </div>
            <Icon name="shield" />
          </div>
          <div className="boundary-row">
            <span>Authentication</span>
            <span>
              {session.authMode === "cloudflare-access"
                ? "Owner-pinned Access JWT"
                : "Signed local JWT fixture"}
            </span>
            <Badge tone="lime">
              {session.authMode === "cloudflare-access" ? "VERIFIED" : "LOCAL"}
            </Badge>
          </div>
          <div className="boundary-row">
            <span>Data source</span>
            <span>Separate simulation D1 / R2</span>
            <Badge tone="lime">ISOLATED</Badge>
          </div>
          <div className="boundary-row">
            <span>Cloudflare Access</span>
            <span>
              {session.authMode === "cloudflare-access"
                ? "Signature, audience and owner checked"
                : "This session uses a local fixture"}
            </span>
            <Badge>{session.authMode === "cloudflare-access" ? "ENFORCED" : "FIXTURE"}</Badge>
          </div>
          <div className="boundary-row">
            <span>Security executor</span>
            <span>No write-capable connector</span>
            <Badge>DISABLED</Badge>
          </div>
        </section>
        <AuditPanel session={session} version={auditVersion} onError={onError} />
      </div>
    </>
  );
}
function Metric({
  label,
  value,
  note,
  accent = false,
}: {
  label: string;
  value: string;
  note: string;
  accent?: boolean;
}) {
  return (
    <section className={`metric ${accent ? "accent" : ""}`}>
      <div className="metric-label">
        {label}
        <span>↗</span>
      </div>
      <div className="metric-value">{value}</div>
      <p>{note}</p>
    </section>
  );
}

function IncidentDetail({ id, onError }: { id: string; onError: (v: string) => void }) {
  const [data, setData] = useState<{
    incident: Incident;
    evidence: Array<{ id: string; kind: string }>;
    timeline?: Array<{
      id: string;
      event_time: string;
      received_at: string;
      metadata_json: string;
      deliveryReferences: number;
    }>;
  } | null>(null);
  const [evidence, setEvidence] = useState<unknown>(null);
  useEffect(() => {
    setData(null);
    setEvidence(null);
    if (!id) return;
    let active = true;
    api<{
      incident: Incident;
      evidence: Array<{ id: string; kind: string }>;
      timeline?: Array<{
        id: string;
        event_time: string;
        received_at: string;
        metadata_json: string;
        deliveryReferences: number;
      }>;
    }>(`/api/incidents/${encodeURIComponent(id)}`)
      .then((v) => {
        if (active) setData(v);
      })
      .catch((e) => onError(e.message));
    return () => {
      active = false;
    };
  }, [id, onError]);
  async function preview(key: string) {
    try {
      setEvidence(await api(`/api/evidence/${encodeURIComponent(key)}`));
    } catch (e) {
      onError(e instanceof Error ? e.message : "Evidence unavailable.");
    }
  }
  return (
    <section className="panel detail-panel">
      <div className="panel-heading">
        <div>
          <span className="panel-kicker">SELECTED RECORD</span>
          <h2>Incident context</h2>
        </div>
        <Icon name="log" />
      </div>
      {!data ? (
        <p className="empty">{id ? "Loading context…" : "Select an incident."}</p>
      ) : (
        <div className="detail-body">
          <Badge tone={data.incident.severity === "high" ? "amber" : "blue"}>
            {data.incident.category.toUpperCase()} / {data.incident.severity.toUpperCase()}
          </Badge>
          <h3>{data.incident.title}</h3>
          <p>{data.incident.summary}</p>
          {!!data.timeline?.length && (
            <>
              <div className="detail-label">SYNTHETIC EVENT TIMELINE</div>
              <p>
                {data.timeline.length} logical events shown (maximum 100). Source kinds are
                emulated. Transport verification is recorded separately.
              </p>
              {data.timeline.map((event) => (
                <div className="analysis-state" key={event.id}>
                  <div>
                    <strong>
                      {JSON.parse(event.metadata_json).emulatedSource} ·{" "}
                      {new Date(event.event_time).toLocaleTimeString()}
                    </strong>
                    <p>
                      Received {new Date(event.received_at).toLocaleTimeString()} · lag{" "}
                      {Math.round(
                        (Date.parse(event.received_at) - Date.parse(event.event_time)) / 1000,
                      )}
                      s · {event.deliveryReferences} source references
                    </p>
                  </div>
                </div>
              ))}
            </>
          )}
          <div className="detail-divider" />
          <div className="detail-label">EVIDENCE & PROVENANCE</div>
          {data.evidence.length ? (
            data.evidence.map((v) => (
              <button
                type="button"
                key={v.id}
                className="evidence-button"
                onClick={() => void preview(v.id)}
              >
                <Icon name="log" />
                <span>
                  {v.id}
                  <small>Synthetic · integrity checked on preview</small>
                </span>
                <Icon name="arrow" />
              </button>
            ))
          ) : (
            <p className="muted">No attached fixture object.</p>
          )}
          {evidence !== null && (
            <pre className="evidence-preview">{JSON.stringify(evidence, null, 2)}</pre>
          )}
          <div className="analysis-state">
            <span className="dot" />
            <div>
              <strong>AI analysis has not run</strong>
              <p>No model finding, confidence score or action recommendation is available.</p>
            </div>
          </div>
          <button type="button" className="disabled-action" disabled>
            Investigation available in a later phase
          </button>
        </div>
      )}
    </section>
  );
}

function IngestionStatus({ cloud, health }: { cloud: boolean; health: boolean }) {
  const [coverage, setCoverage] = useState<IngestionCoverage | null>(null);
  const [checking, setChecking] = useState(false);
  const [healthError, setHealthError] = useState("");
  async function checkCoverage() {
    setChecking(true);
    setHealthError("");
    try {
      setCoverage(await api<IngestionCoverage>("/api/ingestion/reconciliation"));
    } catch (error) {
      setCoverage(null);
      setHealthError(error instanceof Error ? error.message : "Coverage check failed");
    } finally {
      setChecking(false);
    }
  }
  const [value, setValue] = useState<{
    objects: Array<{
      id: string;
      object_key: string;
      state: string;
      valid_rows: number;
      invalid_rows: number;
      attempts: number;
      last_error: string | null;
      metrics_json?: string;
      received_at?: string;
      first_attempt_at?: string | null;
      processed_at?: string | null;
      archived_at?: string | null;
      observedWaitSeconds?: number | null;
    }>;
    failures: Array<{ reason: string }>;
  } | null>(null);
  useEffect(() => {
    let active = true;
    api<NonNullable<typeof value>>("/api/ingestion/status")
      .then((v) => {
        if (active) setValue(v);
      })
      .catch((error) => {
        if (active) setHealthError(error.message);
      });
    return () => {
      active = false;
    };
  }, []);
  if (!health && !value?.objects.length && !value?.failures.length && !healthError) return null;
  return (
    <section className="panel">
      <div className="panel-heading">
        <div>
          <span className="panel-kicker">
            {cloud ? "CLOUD SIMULATION PILOT" : "LOCAL QUEUE PIPELINE"}
          </span>
          <h2>Simulation ingestion</h2>
          <p>
            {value?.objects.length ?? "—"} recent objects · {value?.failures.length ?? "—"} archived
            failures · refresh to update
          </p>
        </div>
        <Badge>{cloud ? "SYNTHETIC ONLY" : "LOCAL ONLY"}</Badge>
      </div>
      <div className="detail-body">
        <details className="ingestion-records">
          <summary>Recent object checkpoints ({value?.objects.length ?? 0})</summary>
          {value?.objects.map((object) => (
            <p key={object.id} className="ingestion-object">
              <strong>{object.state.toUpperCase()}</strong> · {object.object_key}
              <br />
              {object.valid_rows} valid / {object.invalid_rows} invalid rows · {object.attempts}{" "}
              attempts {object.last_error && `· ${object.last_error}`}
              {health && (
                <>
                  <br />
                  <small>
                    R2 upload: {object.received_at || "Unknown"} · First processing:{" "}
                    {object.first_attempt_at || "Unknown (not recorded)"}
                  </small>
                  <br />
                  <small>
                    Observed upload-to-processing wait:{" "}
                    {object.observedWaitSeconds == null
                      ? "Unknown (not recorded)"
                      : `${object.observedWaitSeconds}s`}{" "}
                    · Completed: {object.processed_at || "Not recorded"} · Archived:{" "}
                    {object.archived_at || "Not recorded"}
                  </small>
                </>
              )}
              {object.metrics_json && (
                <>
                  <br />
                  <small>Processing trace: {object.metrics_json}</small>
                </>
              )}
            </p>
          ))}
        </details>
        {healthError && <p role="alert">{healthError}</p>}
        {health && (
          <div className="ingestion-coverage">
            <button
              className="secondary-button"
              type="button"
              onClick={checkCoverage}
              disabled={checking}
            >
              {checking ? "Checking…" : "Check raw object coverage"}
            </button>
            <p>
              {cloud ? "Read-only cloud pilot check" : "Read-only local check"} · up to 20 R2
              metadata entries. No automatic replay.
            </p>
            {coverage && (
              <>
                <p>
                  {coverage.scope === "cloud-pilot-20261029"
                    ? "Fixed 29 October pilot prefix · "
                    : "Local raw prefix · "}
                  {coverage.scanComplete
                    ? "Raw prefix scan complete"
                    : "Partial scan — coverage unknown beyond this page"}{" "}
                  · {coverage.scannedObjects} scanned · {coverage.excludedObjects} excluded ·{" "}
                  {coverage.checkedAt}
                </p>
                <details className="ingestion-records">
                  <summary>Raw object results ({coverage.objects.length})</summary>
                  {coverage.objects.map((object) => (
                    <p className="ingestion-object" key={object.key}>
                      <strong>{object.status.replaceAll("_", " ").toUpperCase()}</strong> ·{" "}
                      {object.key}
                      <br />
                      Uploaded {object.uploadedAt} · age {object.ageSeconds}s
                    </p>
                  ))}
                </details>
                <p>
                  A checkpoint describes processing state; this scan does not prove notification
                  reliability or delivery latency.
                </p>
              </>
            )}
          </div>
        )}
        <p>
          Failure archives retain bounded reasons and references.{" "}
          {cloud
            ? "Pilot delivery is assessed in its acceptance record; live sources remain disconnected."
            : "Cloudflare delivery, timed purge and live collection remain unverified."}
        </p>
      </div>
    </section>
  );
}

function AuditPanel({
  session,
  version,
  onError,
}: {
  session: Session;
  version: number;
  onError: (v: string) => void;
}) {
  const [records, setRecords] = useState<AuditRecord[]>([]);
  useEffect(() => {
    if (session.user.role !== "Admin") return;
    let active = true;
    api<{ records: AuditRecord[] }>(`/api/audit?refresh=${version}`)
      .then((v) => {
        if (active) setRecords(v.records);
      })
      .catch((e) => onError(e.message));
    return () => {
      active = false;
    };
  }, [session.user.role, version, onError]);
  return (
    <section className="panel">
      <div className="panel-heading">
        <div>
          <span className="panel-kicker">PRIVILEGED OPERATIONS</span>
          <h2>Access audit</h2>
        </div>
        <Badge>{session.authMode === "cloudflare-access" ? "D1" : "LOCAL"}</Badge>
      </div>
      {session.user.role !== "Admin" ? (
        <div className="audit-empty">
          <Icon name="shield" />
          <h3>Admin access required</h3>
          <p>Role management and its audit records are restricted server-side.</p>
        </div>
      ) : records.length ? (
        <div className="audit-list">
          {records.map((v) => (
            <div className="audit-entry" key={v.id}>
              <span className="dot" />
              <div>
                <strong>
                  {v.operation === "rbac.owner.provisioned"
                    ? "Owner access provisioned"
                    : "Fixture role changed"}
                </strong>
                <p>
                  {v.target_id} · {v.details_json}
                </p>
                <small>{date(v.created_at)}</small>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="audit-empty">
          <Icon name="log" />
          <h3>No privileged changes recorded</h3>
          <p>
            {session.authMode === "cloudflare-access"
              ? "Owner-only membership is fixed in this pilot."
              : "Change the secondary fixture user's role in Settings to inspect the audit trail."}
          </p>
        </div>
      )}
    </section>
  );
}

function Settings({
  session,
  onChange,
  onError,
}: {
  session: Session;
  onChange: () => void;
  onError: (v: string) => void;
}) {
  const [users, setUsers] = useState<Array<{ id: string; role: string; version: number }>>([]);
  const [targetRole, setTargetRole] = useState("Viewer");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const loadUsers = useCallback(async () => {
    if (session.user.role !== "Admin") return;
    try {
      const value = await api<{ users: Array<{ id: string; role: string; version: number }> }>(
        "/api/admin/users",
      );
      setUsers(value.users);
      setTargetRole(value.users.find((v) => v.id === "user-viewer")?.role || "Viewer");
    } catch (e) {
      onError(e instanceof Error ? e.message : "Users unavailable.");
    }
  }, [session.user.role, onError]);
  useEffect(() => {
    void loadUsers();
  }, [loadUsers]);
  async function saveRole() {
    const target = users.find((v) => v.id === "user-viewer");
    if (!target) return;
    setBusy(true);
    setMessage("");
    try {
      await api("/api/admin/users/user-viewer/role", {
        method: "PATCH",
        csrf: session.csrfToken,
        body: { role: targetRole, version: target.version },
      });
      await loadUsers();
      onChange();
      setMessage("Role updated and audit event recorded atomically in the local control database.");
    } catch (e) {
      onError(e instanceof Error ? e.message : "Role update failed.");
    } finally {
      setBusy(false);
    }
  }
  async function checkPermission() {
    setMessage("");
    try {
      await api("/api/authorization/approval-check", {
        method: "POST",
        csrf: session.csrfToken,
        body: {},
      });
      setMessage(
        "Your role passes the approval permission check. No approval was recorded and no action was executed.",
      );
    } catch (e) {
      setMessage(e instanceof Error ? `Denied: ${e.message}` : "Permission check failed.");
    }
  }
  return (
    <>
      <div className="page-heading">
        <div>
          <div className="eyebrow">CONFIGURATION & TRUST BOUNDARIES</div>
          <h1>Workspace settings</h1>
          <p>Review agreed policies and server-enforced access controls.</p>
        </div>
        <Badge tone="lime">SIMULATION ONLY</Badge>
      </div>
      <div className="settings-grid">
        <section className="panel">
          <div className="panel-heading">
            <div>
              <span className="panel-kicker">APPROVED DESIGN</span>
              <h2>Operating policies</h2>
            </div>
            <Icon name="settings" />
          </div>
          <dl className="settings-list">
            <div>
              <dt>Response mode</dt>
              <dd>
                Approve <Badge>EXECUTOR OFF</Badge>
              </dd>
            </div>
            <div>
              <dt>AI budget</dt>
              <dd>
                ${policy.aiMonthlyBudgetUsd} / month · warning at ${policy.aiWarningUsd}
              </dd>
            </div>
            <div>
              <dt>Analysis deadlines</dt>
              <dd>
                {policy.triageDeadlineSeconds}s triage / {policy.investigationDeadlineSeconds}s
                investigation
              </dd>
            </div>
            <div>
              <dt>Data retention</dt>
              <dd>
                {policy.rawRetentionDays}d raw / {policy.evidenceRetentionDays}d case evidence
              </dd>
            </div>
            <div>
              <dt>Gateway content logs</dt>
              <dd>Disabled in the design · route not connected</dd>
            </div>
            <div>
              <dt>Model candidates</dt>
              <dd>
                <code>GLM 5.3 Flash</code> / <code>GLM 5.3</code>
                <small>Selection recorded. No AI invocation in this build.</small>
              </dd>
            </div>
          </dl>
          <div className="panel-note">
            These are policy definitions. AI budget admission, retention jobs and timeout execution
            are not implemented in this foundation.
          </div>
        </section>
        <section className="panel">
          <div className="panel-heading">
            <div>
              <span className="panel-kicker">IDENTITY & PERMISSIONS</span>
              <h2>
                {session.authMode === "cloudflare-access" ? "Owner access" : "Fixture access"}
              </h2>
            </div>
            <Badge>{session.user.role.toUpperCase()}</Badge>
          </div>
          <div className="settings-content">
            <p>
              {session.authMode === "cloudflare-access"
                ? "Cloudflare Access JWT and the confirmed owner fingerprint are verified server-side. "
                : "Authentication uses an expiring, signed local JWT. "}
              Permissions and zone grants are read from the control database on every request.
            </p>
            <div className="identity-row">
              <span className="avatar">A</span>
              <div>
                <strong>
                  {session.authMode === "cloudflare-access" ? "Verified owner" : "Owner fixture"}
                </strong>
                <small>
                  {session.authMode === "cloudflare-access" ? session.user.role : "Admin"} · role
                  locked
                </small>
              </div>
              <Badge>FIXED</Badge>
            </div>
            {session.authMode === "signed-local-fixture" && (
              <div className="identity-row">
                <span className="avatar secondary">V</span>
                <div>
                  <strong>Secondary fixture</strong>
                  <small>Viewer by default · local demo identity</small>
                </div>
              </div>
            )}
            {session.authMode === "cloudflare-access" ? (
              <div className="panel-note inline">
                Only the confirmed owner can sign in. Membership and role changes are disabled for
                this pilot.
              </div>
            ) : session.user.role === "Admin" ? (
              <div className="role-editor">
                <label htmlFor="fixture-role">Secondary user's role</label>
                <div>
                  <select
                    id="fixture-role"
                    value={targetRole}
                    onChange={(e) => setTargetRole(e.target.value)}
                  >
                    <option>Viewer</option>
                    <option>Analyst</option>
                    <option>Operator</option>
                  </select>
                  <button
                    type="button"
                    className="primary-button"
                    disabled={busy || !users.length}
                    onClick={() => void saveRole()}
                  >
                    Save role
                  </button>
                </div>
              </div>
            ) : (
              <div className="panel-note inline">
                Only Admin can manage fixture roles. Changing the browser UI cannot grant
                permission.
              </div>
            )}
            <button
              type="button"
              className="secondary-button"
              onClick={() => void checkPermission()}
            >
              Test approval permission <Icon name="arrow" />
            </button>
            <p className="subtle">
              This check never creates an approval or executes a security action.
            </p>
            {message && (
              <div className="result-message" role="status">
                {message}
              </div>
            )}
          </div>
        </section>
      </div>
      <section className="panel planned">
        <span className="panel-kicker">WORKSPACE HOSTNAMES</span>
        <div>
          <span>
            Console<strong>{policy.consoleHostname}</strong>
          </span>
          <span>
            Disposable test target<strong>{policy.testHostname}</strong>
          </span>
          <span>
            Permitted test namespace<strong>{policy.testPathNamespace}</strong>
          </span>
        </div>
        <p>
          The test hostname remains unprovisioned. Live collection, AI analysis and controlled
          security tests retain separate acceptance gates.
        </p>
      </section>
    </>
  );
}

const element = document.getElementById("root");
if (!element) throw new Error("Missing application root");
createRoot(element).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
