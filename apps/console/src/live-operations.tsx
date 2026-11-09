import type { Session } from "@soc/shared";
import { useEffect, useState } from "react";
import { api } from "./client";

const formatTime = (value: string | null) =>
  value ? new Date(value).toLocaleString(undefined, { timeZoneName: "short" }) : "Awaiting data";
const errorText = (error: unknown) =>
  error instanceof Error ? error.message : "Request unavailable.";

interface EventRow {
  id: string;
  occurred_at: string;
  ray_id: string;
  host: string;
  status: number | null;
  action: string | null;
  source: string | null;
  rule_id: string | null;
  object_key: string;
  outcome: string;
}

export function LogEvidence({ finding }: { finding?: string }) {
  const [dataset, setDataset] = useState("http");
  const [ray, setRay] = useState("");
  const [logs, setLogs] = useState<{ events: EventRow[]; truncated: boolean } | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  async function load() {
    setBusy(true);
    setError("");
    setLogs(null);
    try {
      const query = new URLSearchParams({ dataset });
      if (finding) query.set("finding", finding);
      if (ray.trim()) query.set("ray", ray.trim());
      setLogs(await api(`/api/live/logs?${query}`));
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className={finding ? "live-actions" : "live-panel"} aria-label="Logpush evidence">
      <h3>Logpush evidence</h3>
      <p>
        {finding
          ? "Individual records from this observation window."
          : "Recent records from the last 24 hours. Ray ID search covers retained records."}{" "}
        Coverage follows the Cloudflare job’s filters and sampling.
      </p>
      <form
        className="live-ops-form"
        onSubmit={(event) => {
          event.preventDefault();
          void load();
        }}
      >
        <label>
          Dataset{" "}
          <select
            value={dataset}
            disabled={busy}
            onChange={(event) => {
              setDataset(event.target.value);
              setLogs(null);
            }}
          >
            <option value="http">HTTP Requests</option>
            <option value="firewall">Firewall Events</option>
          </select>
        </label>
        <label>
          Ray ID (optional){" "}
          <input
            value={ray}
            maxLength={16}
            pattern="[a-fA-F0-9]{16}"
            disabled={busy}
            onChange={(event) => {
              setRay(event.target.value);
              setLogs(null);
            }}
          />
        </label>
        <button type="submit" disabled={busy}>
          {busy ? "Loading records…" : "Find records"}
        </button>
      </form>
      {error && <p role="alert">{error}</p>}
      {logs && !logs.events.length && <p>No matching records have been collected.</p>}
      {logs && logs.events.length > 0 && (
        <div className="live-scroll">
          {logs.truncated && <p>Showing the newest 100 matching records.</p>}
          <table>
            <thead>
              <tr>
                <th>Event time</th>
                <th>Hostname</th>
                <th>Ray ID</th>
                <th>HTTP status</th>
                <th>Action / source</th>
                <th>Rule</th>
                <th>Source batch</th>
              </tr>
            </thead>
            <tbody>
              {logs.events.map((row) => (
                <tr key={row.id}>
                  <td>{formatTime(row.occurred_at)}</td>
                  <td>{row.host}</td>
                  <td>{row.ray_id}</td>
                  <td>{row.status ?? "—"}</td>
                  <td>{[row.action, row.source].filter(Boolean).join(" / ") || "—"}</td>
                  <td>{row.rule_id ?? "—"}</td>
                  <td>
                    {row.object_key}
                    {row.outcome === "partial" && " (partial)"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

interface Health {
  analytics: { last_success: string | null; collection_paused_at: string | null } | null;
  sources: Record<
    string,
    { lastObject: string | null; lastSuccess: string | null; errors: number }
  >;
  tasks: {
    task: string;
    last_attempt: string;
    last_success: string | null;
    removed: number;
    error: string | null;
  }[];
  alerts: string[];
}

export function LiveOperations() {
  const [health, setHealth] = useState<Health | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    let active = true;
    async function refresh() {
      try {
        const result = await api<Health>("/api/live/operations");
        if (active) {
          setHealth(result);
          setError("");
        }
      } catch (e) {
        if (active) setError(errorText(e));
      }
    }
    void refresh();
    const timer = setInterval(() => void refresh(), 60000);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, []);
  const retention = health?.tasks.find((task) => task.task === "retention");
  return (
    <>
      <section className="live-panel">
        <h2>Collection and retention health</h2>
        {error && <p role="alert">{error}</p>}
        {!health && !error && <p role="status">Loading operations status…</p>}
        {health && (
          <>
            {health.alerts.length ? (
              <ul className="live-warning" aria-label="Operations alerts">
                {health.alerts.map((alert) => (
                  <li key={alert}>{alert}</li>
                ))}
              </ul>
            ) : (
              <p>No active operations alerts.</p>
            )}
            <dl className="live-health">
              <dt>Analytics</dt>
              <dd>
                {health.analytics?.collection_paused_at ? "Paused · " : "Last success · "}
                {formatTime(health.analytics?.last_success ?? null)}
              </dd>
              {Object.entries(health.sources).map(([name, source]) => (
                <div className="live-health-row" key={name}>
                  <dt>{name === "http" ? "HTTP Logpush" : "Firewall Logpush"}</dt>
                  <dd>
                    {source.lastSuccess
                      ? `Last usable batch · ${formatTime(source.lastSuccess)}`
                      : "Awaiting first usable batch"}
                    {source.lastObject && ` · last processed ${formatTime(source.lastObject)}`}
                    {source.errors > 0 && ` · ${source.errors} incomplete in the last hour`}
                  </dd>
                </div>
              ))}
              <dt>D1 retention</dt>
              <dd>
                {formatTime(retention?.last_success ?? null)} · {retention?.removed ?? 0} expired
                records or reports cleared last run.
              </dd>
            </dl>
            <p>
              Logpush delivery runs independently of the Analytics collection switch. Individual
              records expire after 30 days.
            </p>
          </>
        )}
      </section>
      <LogEvidence />
    </>
  );
}

interface Repair {
  id: string;
  expression: string;
  note: string;
  status: string;
  apply_before: string;
  requested_by: string;
  approved_by: string | null;
  rule_expires_at: string | null;
  rule_id: string | null;
  result: string | null;
}
interface RepairState {
  host: string;
  execution: { apply: boolean; rollback: boolean };
  policyPaused: boolean;
  requiresSecondApprover: boolean;
  maxDurationSeconds: number;
  repairs: Repair[];
  audit: { repair_id: string; actor: string; action: string; at: string }[];
}

export function LiveRepairs({ session }: { session: Session }) {
  const [state, setState] = useState<RepairState | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [path, setPath] = useState("/__soc_test/check");
  const [ip, setIp] = useState("");
  const [note, setNote] = useState("");
  const base = "/api/live/repairs";
  useEffect(() => {
    let active = true;
    void api<RepairState>(base)
      .then((result) => {
        if (active) setState(result);
      })
      .catch((e) => {
        if (active) setError(errorText(e));
      });
    return () => {
      active = false;
    };
  }, []);

  async function submit(
    operation?: string,
    draft?: { path: string; client_ip: string; note: string },
  ) {
    setBusy(true);
    setError("");
    try {
      if (operation !== undefined)
        await api(`${base}${operation}`, { method: "POST", csrf: session.csrfToken, body: draft });
      setState(await api(base));
      if (draft) setNote("");
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="live-panel">
      <h2>Controlled Managed Challenge</h2>
      <p>
        Propose a rule for one exact test path and source IPv4 on{" "}
        <strong>{state?.host ?? "soc-test.d.example.invalid"}</strong>. Review the expression,
        approve, then apply and verify the rule.
      </p>
      {state && (
        <p role="status">
          {state.policyPaused
            ? "Approvals and applications are paused in Live Settings."
            : state.execution.apply
              ? "Test executor enabled for the verified scope."
              : "Apply is disabled until the isolated test host, source IP, and scoped Cloudflare credential are verified."}
        </p>
      )}
      {state && (
        <p>
          Configured rule expiry target is {state.maxDurationSeconds} seconds. Expired rules are
          removed on the scheduled check.
        </p>
      )}
      <form
        className="live-ops-form"
        onSubmit={(event) => {
          event.preventDefault();
          void submit("", { path, client_ip: ip.trim(), note });
        }}
      >
        <label>
          Exact test path{" "}
          <input
            required
            maxLength={76}
            value={path}
            onChange={(event) => setPath(event.target.value)}
          />
        </label>
        <label>
          Source IPv4{" "}
          <input
            required
            maxLength={15}
            value={ip}
            onChange={(event) => setIp(event.target.value)}
          />
        </label>
        <label>
          Test justification{" "}
          <input
            required
            minLength={12}
            maxLength={300}
            value={note}
            onChange={(event) => setNote(event.target.value)}
          />
        </label>
        <button type="submit" disabled={busy || !state}>
          Create proposal
        </button>
        <button type="button" disabled={busy} onClick={() => void submit()}>
          Refresh repair status
        </button>
      </form>
      {error && <p role="alert">{error}</p>}
      {state?.repairs.map((repair) => {
        const unexpired = Date.parse(repair.apply_before) > Date.now();
        const needsDifferentApprover =
          state.requiresSecondApprover && repair.requested_by === session.user.id;
        return (
          <article className="live-actions" key={repair.id}>
            <h3>{repair.status.replaceAll("_", " ")}</h3>
            <p>{repair.note}</p>
            <p>
              <code>{repair.expression}</code>
            </p>
            <p>Approval and apply deadline · {formatTime(repair.apply_before)}.</p>
            {repair.approved_by && <p>Approved by {repair.approved_by}.</p>}
            {repair.rule_expires_at && <p>Rule expiry · {formatTime(repair.rule_expires_at)}.</p>}
            {repair.result && (
              <p>
                Readback result · {repair.result.replaceAll("_", " ")} {repair.rule_id}
              </p>
            )}
            <div className="live-ops-form">
              {repair.status === "pending" && unexpired && (
                <>
                  {needsDifferentApprover && (
                    <span>A different administrator must approve this proposal.</span>
                  )}
                  <button
                    type="button"
                    disabled={busy || state.policyPaused || needsDifferentApprover}
                    onClick={() => void submit(`/${repair.id}/approve`)}
                  >
                    Approve proposal
                  </button>
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => void submit(`/${repair.id}/reject`)}
                  >
                    Reject proposal
                  </button>
                </>
              )}
              {repair.status === "approved" && unexpired && (
                <button
                  type="button"
                  disabled={
                    busy ||
                    !state.execution.apply ||
                    state.policyPaused ||
                    (state.requiresSecondApprover && repair.requested_by === repair.approved_by)
                  }
                  onClick={() => void submit(`/${repair.id}/apply`)}
                >
                  Apply approved rule
                </button>
              )}
              {["verified", "review", "applying", "rolling_back"].includes(repair.status) && (
                <button
                  type="button"
                  disabled={busy || !state.execution.rollback}
                  onClick={() => void submit(`/${repair.id}/rollback`)}
                >
                  Verify and roll back
                </button>
              )}
            </div>
          </article>
        );
      })}
      {state && state.audit.length > 0 && (
        <details>
          <summary>Recent repair audit</summary>
          <ul>
            {state.audit.map((event) => (
              <li key={`${event.repair_id}-${event.at}-${event.action}`}>
                {formatTime(event.at)} · {event.actor} · {event.action.replaceAll("_", " ")} ·{" "}
                {event.repair_id}
              </li>
            ))}
          </ul>
        </details>
      )}
    </section>
  );
}
