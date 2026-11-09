import type { Session } from "@soc/shared";
import { useCallback, useEffect, useRef, useState } from "react";
import {
  type LiveFacts,
  type LiveFinding,
  type LiveFollowUpWindow,
  type LiveInvestigation,
  type LiveObservations,
  type LiveOverview,
  type LivePriority,
  livePriorities,
} from "../../../packages/shared/src/live";
import { api } from "./client";
import { LiveOperations, LiveRepairs, LogEvidence } from "./live-operations";
import { LiveSettings } from "./live-settings";
import { Workbench } from "./workbench";
import "./live.css";

const time = (s: string | null | undefined) =>
  s ? new Date(s).toLocaleString(undefined, { timeZoneName: "short" }) : "Not collected";
const number = (n: number) => n.toLocaleString(undefined, { maximumFractionDigits: 0 });
export function Workspace({ session, onSignOut }: { session: Session; onSignOut: () => void }) {
  const [mode, setMode] = useState<"live" | "simulation">(
    session.liveDataEnabled ? "live" : "simulation",
  );
  return (
    <>
      {session.liveDataEnabled && (
        <nav className="source-switch" aria-label="Data environment">
          <strong>Data source</strong>
          <button type="button" aria-pressed={mode === "live"} onClick={() => setMode("live")}>
            Live · d.example.invalid
          </button>
          <button
            type="button"
            aria-pressed={mode === "simulation"}
            onClick={() => setMode("simulation")}
          >
            Simulation · test data
          </button>
        </nav>
      )}
      {mode === "live" ? (
        <LiveWorkspace session={session} onSignOut={onSignOut} />
      ) : (
        <Workbench session={session} onSignOut={onSignOut} />
      )}
    </>
  );
}
function Evidence({ facts, sha256 }: { facts: LiveFacts; sha256: string }) {
  return (
    <div className="live-evidence">
      <p>
        <strong>Evidence window</strong> {time(facts.start)} → {time(facts.end)}
      </p>
      <p>
        Collected {time(facts.collectedAt)} · Adaptive Analytics estimates · zone-wide · no
        individual request records.
      </p>
      <div className="live-tables">
        <section>
          <h3>Security events</h3>
          <p>
            {facts.security.state === "available"
              ? "Estimated event counts; one request may produce multiple security events."
              : `Unavailable: ${facts.security.error}. Counts are unknown.`}{" "}
            {facts.security.truncated &&
              "Group limit reached; incomplete results. Detection is suppressed."}
          </p>
          {facts.security.state === "available" && (
            <table>
              <thead>
                <tr>
                  <th>Action</th>
                  <th>Source</th>
                  <th>Events ≈</th>
                </tr>
              </thead>
              <tbody>
                {facts.security.groups.map((g) => (
                  <tr key={`${g.action}-${g.source}`}>
                    <td>{g.action}</td>
                    <td>{g.source}</td>
                    <td>{number(g.count)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {facts.security.state === "available" && !facts.security.groups.length && (
            <p>No security events returned for this window.</p>
          )}
        </section>
        <section>
          <h3>HTTP responses</h3>
          <p>
            {facts.http.state === "available"
              ? "Estimated HTTP request counts grouped by edge response status."
              : `Unavailable: ${facts.http.error}. Counts are unknown.`}{" "}
            {facts.http.truncated &&
              "Group limit reached; incomplete results. Detection is suppressed."}
          </p>
          {facts.http.state === "available" && (
            <table>
              <thead>
                <tr>
                  <th>Edge status</th>
                  <th>Requests ≈</th>
                </tr>
              </thead>
              <tbody>
                {facts.http.groups.map((g) => (
                  <tr key={g.status}>
                    <td>{g.status === 0 ? "0 · no HTTP response status" : g.status}</td>
                    <td>{number(g.count)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {facts.http.state === "available" && !facts.http.groups.length && (
            <p>No HTTP requests returned for this window.</p>
          )}
        </section>
      </div>
      <details>
        <summary>Source evidence and SHA-256</summary>
        <p className="live-hash">{sha256}</p>
        <pre>{JSON.stringify(facts, null, 2)}</pre>
      </details>
    </div>
  );
}
function SuggestedActions({ finding }: { finding: LiveFinding }) {
  const [windows, setWindows] = useState<LiveFollowUpWindow[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const isHttp = finding.rule === "http-5xx-v1";
  const errors = finding.evidence.http.groups.filter((group) => group.status >= 500);
  const originDns = isHttp && errors.some((group) => group.status === 530 && group.count > 0);
  const states: Record<LiveFollowUpWindow["state"], string> = {
    threshold_met: "Threshold still met",
    below_threshold: "Below alert threshold",
    insufficient_data: "Insufficient data",
    not_collected: "No stored snapshot",
  };
  async function checkFollowUp() {
    setBusy(true);
    setError("");
    setWindows(null);
    try {
      const result = await api<{ windows: LiveFollowUpWindow[] }>(
        `/api/live/findings/${encodeURIComponent(finding.id)}/follow-up`,
      );
      setWindows(result.windows);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Follow-up check unavailable.");
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="live-actions" aria-label="Suggested actions">
      <h4>Suggested actions</h4>
      {originDns ? (
        <>
          <p>
            HTTP 530 points to an origin hostname resolution problem. Start with the affected
            hostname and the specific Cloudflare error code on the response page.
          </p>
          <ol>
            <li>
              Filter Cloudflare HTTP Analytics to this window and status 530, then check the
              breakdown by hostname.
            </li>
            <li>
              Use the Cloudflare 1xxx code to narrow the cause. Check the intended origin and
              whether its DNS target resolves.
            </li>
            <li>
              After confirming the intended target, correct the affected configuration and retest
              the hostname.
            </li>
          </ol>
          <a
            href="https://developers.cloudflare.com/support/troubleshooting/http-status-codes/cloudflare-5xx-errors/error-530/"
            target="_blank"
            rel="noreferrer"
          >
            Cloudflare error 530 guide
          </a>
        </>
      ) : isHttp ? (
        <ol>
          <li>
            Filter HTTP Analytics to this window and the observed 5xx statuses to locate affected
            hostnames.
          </li>
          <li>
            Compare edge and origin status, check origin health and correlate with recent
            deployments or configuration changes.
          </li>
          <li>
            After correcting the confirmed cause, verify the affected hostname and check subsequent
            error counts.
          </li>
        </ol>
      ) : (
        <>
          <ol>
            <li>
              Open Security Events for this window and filter by the observed block or challenge
              actions and services.
            </li>
            <li>
              Identify the affected hostname and matched rule. Review representative events for
              legitimate traffic or a recurring abuse pattern.
            </li>
            <li>
              Keep effective protections in place. If you confirm a false positive, review a
              narrowly scoped adjustment for the matched rule.
            </li>
          </ol>
          <a
            href="https://developers.cloudflare.com/waf/analytics/security-events/"
            target="_blank"
            rel="noreferrer"
          >
            Cloudflare Security Events guide
          </a>
        </>
      )}
      <p>
        Applying a fix requires a verified target, a confirmed change, and your approval. This
        observation has zone-wide totals.
      </p>
      <button type="button" disabled={busy} onClick={() => void checkFollowUp()}>
        {busy ? "Checking…" : "Check follow-up windows"}
      </button>
      <p>
        Compare the next three five-minute windows against the same threshold using stored
        Analytics.
      </p>
      {error && <p role="alert">{error}</p>}
      {windows && (
        <div aria-live="polite" className="live-scroll">
          <table>
            <thead>
              <tr>
                <th>Window end</th>
                <th>Result</th>
                <th>{isHttp ? "5xx / requests ≈" : "Mitigation events ≈"}</th>
              </tr>
            </thead>
            <tbody>
              {windows.map((window) => (
                <tr key={window.end}>
                  <td>{time(window.end)}</td>
                  <td>{states[window.state]}</td>
                  <td>
                    {window.count === null ? "—" : number(window.count)}
                    {window.total !== null && ` / ${number(window.total)}`}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <p>
            These results describe the follow-up period. Confirm current service health before
            closing the issue.
          </p>
        </div>
      )}
    </section>
  );
}

function Investigation({ id, session }: { id: string; session: Session }) {
  const [analysis, setAnalysis] = useState<LiveInvestigation | null>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");
  const path = `/api/live/findings/${encodeURIComponent(id)}/investigation`;

  useEffect(() => {
    let active = true;
    void api<LiveInvestigation>(path)
      .then((result) => {
        if (active) setAnalysis(result);
      })
      .catch((e) => {
        if (active) setError(e instanceof Error ? e.message : "Investigation unavailable.");
      });
    return () => {
      active = false;
    };
  }, [path]);

  async function load(start: boolean) {
    setPending(true);
    setError("");
    try {
      setAnalysis(
        await api<LiveInvestigation>(
          path,
          start ? { method: "POST", csrf: session.csrfToken } : {},
        ),
      );
    } catch (e) {
      setError(e instanceof Error ? e.message : "Investigation unavailable.");
    } finally {
      setPending(false);
    }
  }
  const cannotStart = analysis?.canStart === false;
  const checkOnly = !analysis || analysis.status === "running" || Boolean(analysis.retryAt);
  const report = analysis?.report;
  return (
    <section className="live-actions" aria-label="AI SOC investigation">
      <h4>AI SOC investigation</h4>
      <p>
        AI SOC reviews this observation and any saved follow-up windows. Results are saved with the
        observation.
      </p>
      {cannotStart && !report && (
        <p role="status">New investigations are unavailable. Check AI usage in Settings.</p>
      )}
      {session.user.role === "Admin" && !report && (
        <button
          type="button"
          disabled={pending || (!checkOnly && Boolean(cannotStart))}
          onClick={() => void load(!checkOnly)}
        >
          {pending ? "Working…" : checkOnly ? "Check investigation status" : "Investigate with AI"}
        </button>
      )}
      {pending && <p role="status">This can take up to 90 seconds.</p>}
      {error && <p role="alert">{error}</p>}
      {analysis?.status === "running" && <p role="status">An investigation is in progress.</p>}
      {analysis?.status === "failed" && (
        <p role="status">
          {analysis.failure === "timeout"
            ? "The investigation timed out."
            : analysis.failure === "invalid_response"
              ? "The model response could not be verified."
              : "The model service could not complete this request."}
          {analysis.retryAt && ` Check status again after ${time(analysis.retryAt)}.`}
        </p>
      )}
      {report && (
        <div aria-live="polite">
          <p>{report.summary}</p>
          <h5>Evidence-backed findings</h5>
          <ul>
            {[...new Map(report.findings.map((finding) => [finding.claim, finding])).values()].map(
              (finding) => (
                <li key={finding.claim}>
                  {finding.claim}{" "}
                  {[...new Set(finding.evidenceRefs)].map((ref) => (
                    <a key={ref} href={`#ai-${ref}-${id}`}>
                      {ref === "observation" ? "Observation evidence" : "Follow-up evidence"}{" "}
                    </a>
                  ))}
                </li>
              ),
            )}
          </ul>
          <h5>Limitations</h5>
          <ul>
            {[...new Set(report.limitations)].map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
          <h5>Next checks</h5>
          <ol>
            {[...new Set(report.nextChecks)].map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ol>
          {analysis.followUp.length > 0 && (
            <section id={`ai-follow-up-${id}`} aria-label="Follow-up evidence">
              <h5>Follow-up evidence used</h5>
              <ul>
                {analysis.followUp.map((window) => (
                  <li key={window.end}>
                    {time(window.end)} · {window.state.replaceAll("_", " ")}
                    {window.count !== null &&
                      ` · ${number(window.count)}${window.total !== null ? ` / ${number(window.total)} HTTP requests` : " mitigation events"}`}
                  </li>
                ))}
              </ul>
            </section>
          )}
        </div>
      )}
    </section>
  );
}

function ObservationDetail({
  id,
  session,
  aiEnabled,
}: {
  id: string;
  session: Session;
  aiEnabled: boolean;
}) {
  const [detail, setDetail] = useState<LiveFinding | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    let active = true;
    void api<LiveFinding>(`/api/live/findings/${encodeURIComponent(id)}`)
      .then((value) => {
        if (active) setDetail(value);
      })
      .catch((e) => {
        if (active) setError(e instanceof Error ? e.message : "Evidence unavailable.");
      });
    return () => {
      active = false;
    };
  }, [id]);
  if (error) return <p role="alert">{error}</p>;
  if (!detail) return <p role="status">Loading evidence…</p>;
  return (
    <>
      {aiEnabled && <Investigation id={id} session={session} />}
      <SuggestedActions finding={detail} />
      <LogEvidence finding={id} />
      <div id={`ai-observation-${id}`}>
        <p>Evidence expires {time(detail.expiresAt)}</p>
        <Evidence facts={detail.evidence} sha256={detail.sha256} />
      </div>
    </>
  );
}

const priorityLabel = { low: "Low", medium: "Medium", high: "High" };
type ObservationFilter = "all" | LivePriority;
const observationFilters: ObservationFilter[] = ["all", ...livePriorities];

function Observations({ overview, session }: { overview: LiveOverview | null; session: Session }) {
  const [priority, setPriority] = useState<ObservationFilter>("all");
  const [pages, setPages] = useState<string[]>([]);
  const [selected, setSelected] = useState("");
  const [result, setResult] = useState<{ url: string; data: LiveObservations } | null>(null);
  const [error, setError] = useState<{ url: string; message: string } | null>(null);
  const params = new URLSearchParams();
  const before = pages.at(-1);
  if (priority !== "all") params.set("priority", priority);
  if (before) params.set("before", before);
  const url = `/api/live/findings?${params}`;

  useEffect(() => {
    if (!overview) return;
    let active = true;
    void api<LiveObservations>(url)
      .then((data) => {
        if (active) {
          setResult({ url, data });
          setError(null);
        }
      })
      .catch((e) => {
        if (active)
          setError({ url, message: e instanceof Error ? e.message : "Observations unavailable." });
      });
    return () => {
      active = false;
    };
  }, [url, overview]);

  if (!overview) return null;
  const counts = result?.data.counts;
  const total = counts && livePriorities.reduce((sum, level) => sum + counts[level], 0);
  const current = result?.url === url ? result.data : null;
  const next = current?.next;
  const message = error?.url === url ? error.message : "";

  return (
    <section className="live-panel">
      <h2>Review suggested</h2>
      <p>
        These are deterministic observations from real aggregates, not confirmed attacks or AI
        conclusions. A logging-only match does not create an observation. No automatic action runs.
      </p>
      <p>
        Thresholds per 5 minutes: block/challenge events ≥ 100; HTTP 5xx ≥ 25 and ≥ 5% of HTTP
        requests. Only complete, available group results are evaluated.
      </p>
      <fieldset className="live-priority-filters" aria-label="Filter observations by priority">
        {observationFilters.map((filter) => {
          const count = filter === "all" ? total : counts?.[filter];
          return (
            <button
              type="button"
              key={filter}
              aria-pressed={priority === filter}
              onClick={() => {
                if (priority === filter) return;
                setPriority(filter);
                setPages([]);
                setSelected("");
              }}
            >
              <span>{filter === "all" ? "All" : priorityLabel[filter]}</span>
              <strong>{count === undefined ? "—" : number(count)}</strong>
            </button>
          );
        })}
      </fieldset>
      {message && <p role="alert">{message}</p>}
      {!current && !message && <p role="status">Loading observations…</p>}
      {current?.findings.length === 0 && (
        <p className="live-empty" role="status">
          {priority === "all"
            ? "No observations match this view."
            : `No ${priorityLabel[priority]} priority observations on this page.`}
        </p>
      )}
      {!!current?.findings.length && (
        <>
          <div className="live-observation-columns" aria-hidden="true">
            <span>Priority</span>
            <span>Date</span>
            <span>Subject</span>
          </div>
          <ul className="live-findings" aria-label="Observations">
            {current.findings.map((finding) => {
              const expanded = selected === finding.id;
              return (
                <li key={finding.id}>
                  <button
                    type="button"
                    className="live-observation-row"
                    id={`toggle-${finding.id}`}
                    aria-expanded={expanded}
                    aria-controls={`detail-${finding.id}`}
                    onClick={() => setSelected(expanded ? "" : finding.id)}
                  >
                    <span className="live-priority" data-priority={finding.severity}>
                      {priorityLabel[finding.severity]}
                    </span>
                    <time dateTime={finding.windowEnd}>{time(finding.windowEnd)}</time>
                    <strong>{finding.title}</strong>
                    <span aria-hidden="true">{expanded ? "−" : "+"}</span>
                  </button>
                  <section
                    className="live-detail"
                    id={`detail-${finding.id}`}
                    aria-labelledby={`toggle-${finding.id}`}
                    hidden={!expanded}
                  >
                    {expanded && (
                      <>
                        <p>{finding.summary}</p>
                        <ObservationDetail
                          id={finding.id}
                          session={session}
                          aiEnabled={overview.aiEnabled}
                        />
                      </>
                    )}
                  </section>
                </li>
              );
            })}
          </ul>
        </>
      )}
      {(before || next) && (
        <nav className="live-observation-pages" aria-label="Observation pages">
          <button
            type="button"
            disabled={!before}
            onClick={() => {
              setPages((history) => history.slice(0, -1));
              setSelected("");
            }}
          >
            Newer
          </button>
          <span>Page {pages.length + 1}</span>
          <button
            type="button"
            disabled={!next}
            onClick={() => {
              if (!next) return;
              setPages((history) => [...history, next]);
              setSelected("");
            }}
          >
            Older
          </button>
        </nav>
      )}
    </section>
  );
}

const livePages = {
  overview: "Overview",
  observations: "Observations",
  coverage: "Collection & coverage",
  operations: "Operations",
  repairs: "Repairs",
  settings: "Settings",
} as const;
type LivePage = keyof typeof livePages;

function LiveWorkspace({ session, onSignOut }: { session: Session; onSignOut: () => void }) {
  const [page, setPage] = useState<LivePage>("overview");
  const [data, setData] = useState<LiveOverview | null>(null),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false);
  const [changing, setChanging] = useState(false);
  const [collectionError, setCollectionError] = useState("");
  const inFlight = useRef(false),
    changingCollection = useRef(false),
    mounted = useRef(false);
  const pausedAt = data?.collector?.collection_paused_at;
  const refresh = useCallback(async () => {
    if (inFlight.current || changingCollection.current) return;
    inFlight.current = true;
    setBusy(true);
    try {
      const next = await api<LiveOverview>("/api/live/overview");
      if (mounted.current) {
        setData(next);
        setError("");
      }
    } catch (e) {
      if (mounted.current) setError(e instanceof Error ? e.message : "Live data unavailable.");
    } finally {
      inFlight.current = false;
      if (mounted.current) setBusy(false);
    }
  }, []);
  useEffect(() => {
    mounted.current = true;
    void refresh();
    return () => {
      mounted.current = false;
    };
  }, [refresh]);
  useEffect(() => {
    if (pausedAt) return;
    const tick = setInterval(() => void refresh(), 60000);
    return () => clearInterval(tick);
  }, [pausedAt, refresh]);

  async function setCollection(enabled: boolean) {
    if (inFlight.current || changingCollection.current) return;
    changingCollection.current = true;
    setChanging(true);
    setCollectionError("");
    try {
      const state = await api<{ collection_paused_at: string | null }>("/api/live/collection", {
        method: "POST",
        body: { enabled },
        csrf: session.csrfToken,
      });
      if (mounted.current)
        setData((current) =>
          current?.collector
            ? { ...current, collector: { ...current.collector, ...state } }
            : current,
        );
    } catch (e) {
      if (mounted.current)
        setCollectionError(e instanceof Error ? e.message : "Could not change collection status.");
    } finally {
      changingCollection.current = false;
      if (mounted.current) {
        setChanging(false);
        void refresh();
      }
    }
  }
  const facts = data?.latest?.facts;
  const http =
    facts?.http.state === "available" ? facts.http.groups.reduce((n, g) => n + g.count, 0) : null;
  const security =
    facts?.security.state === "available"
      ? facts.security.groups.reduce((n, g) => n + g.count, 0)
      : null;
  const partial =
    !!facts &&
    (facts.http.state !== "available" ||
      facts.security.state !== "available" ||
      facts.http.truncated ||
      facts.security.truncated);
  return (
    <div className="live-shell">
      <aside className="live-nav">
        <a className="live-brand" href="/">
          SOC <small>LIVE ANALYTICS</small>
        </a>
        <p>d.example.invalid</p>
        {(Object.keys(livePages) as LivePage[])
          .filter((id) => id !== "repairs" || session.user.role === "Admin")
          .map((id) => (
            <button
              type="button"
              key={id}
              aria-current={page === id ? "page" : undefined}
              onClick={() => setPage(id)}
            >
              {livePages[id]}
            </button>
          ))}
        <div className="live-user">
          <p>{session.user.label}</p>
          <button type="button" onClick={onSignOut}>
            Sign out
          </button>
        </div>
      </aside>
      <main className="live-main">
        <header className="live-heading">
          <div>
            <p className="eyebrow">REAL ZONE · ANALYTICS</p>
            <h1>{page === "overview" ? "Live overview" : livePages[page]}</h1>
          </div>
          <div className="live-heading-actions">
            {data?.collector && session.user.role === "Admin" && (
              <button
                type="button"
                disabled={busy || changing}
                onClick={() => void setCollection(Boolean(pausedAt))}
              >
                {changing
                  ? "Updating collection…"
                  : pausedAt
                    ? "Start collection"
                    : "Stop collection"}
              </button>
            )}
            <button type="button" disabled={busy || changing} onClick={() => void refresh()}>
              {busy ? "Refreshing…" : "Refresh view"}
            </button>
          </div>
        </header>
        <div className="live-notice">
          <strong>Cloudflare Analytics · d.example.invalid</strong>
          {data?.collector && (
            <p role="status">
              {pausedAt
                ? `Collection paused since ${time(pausedAt)}`
                : "Collection on · every 5 minutes"}
            </p>
          )}
          <p>
            Zone-wide HTTP and security event estimates.{" "}
            {pausedAt
              ? "Saved evidence stays available until its normal expiry. Start collection to resume on the next scheduled run."
              : "Each run uses the latest complete five-minute window after a two-minute source delay."}
          </p>
          {collectionError && <p role="alert">{collectionError}</p>}
        </div>
        {error && (
          <div role="alert" className="live-warning">
            {error} {data && "Previously fetched results remain below; they may be out of date."}
          </div>
        )}
        {!pausedAt && data?.collector?.last_error && (
          <div role="status" className="live-warning">
            Collection issue: {data.collector.last_error}. Unavailable data is never replaced with
            test data or zeros.
          </div>
        )}
        {!pausedAt && data?.stale && (
          <div role="status" className="live-warning">
            {facts
              ? "Collection is stale: the latest window ended more than 15 minutes ago."
              : "Waiting for the first successful collection. No live results are available yet."}
          </div>
        )}
        {partial && (
          <div role="status" className="live-warning">
            Partial coverage. Inspect dataset status below; detection is suppressed for unavailable
            or truncated datasets.
          </div>
        )}
        {!data && <p>{busy ? "Loading live data…" : "No live results loaded."}</p>}
        {page === "overview" && data && (
          <>
            <div className="live-metrics">
              <article>
                <span>HTTP requests ≈</span>
                <strong>{http === null ? "Unknown" : number(http)}</strong>
                <small>Latest five-minute window{facts?.http.truncated ? " · partial" : ""}</small>
              </article>
              <article>
                <span>Security events ≈</span>
                <strong>{security === null ? "Unknown" : number(security)}</strong>
                <small>
                  Events, not unique requests{facts?.security.truncated ? " · partial" : ""}
                </small>
              </article>
              <article>
                <span>Observations</span>
                <strong>
                  {data.findings.length}
                  {data.findings.length === 100 ? "+" : ""}
                </strong>
                <small>Rule thresholds met · up to 90 days</small>
              </article>
            </div>
            <section className="live-panel">
              <h2>{pausedAt ? "Last saved evidence" : "Latest collected evidence"}</h2>
              {facts && data.latest ? (
                <Evidence facts={facts} sha256={data.latest.sha256} />
              ) : (
                <p>
                  {pausedAt
                    ? "Collection is paused. No saved evidence is available."
                    : "Waiting for Analytics collection. The existing simulation cases are available in Simulation."}
                </p>
              )}
            </section>
          </>
        )}
        {page === "observations" && <Observations overview={data} session={session} />}
        {page === "operations" && <LiveOperations />}
        {page === "repairs" && session.user.role === "Admin" && <LiveRepairs session={session} />}
        {page === "settings" && <LiveSettings overview={data} session={session} />}
        {page === "coverage" && data && (
          <section className="live-panel">
            <h2>Source and collection health</h2>
            <dl className="live-health">
              <dt>Source</dt>
              <dd>Cloudflare GraphQL: firewallEventsAdaptiveGroups + httpRequestsAdaptiveGroups</dd>
              <dt>Scope</dt>
              <dd>All of d.example.invalid · not limited to soc-test</dd>
              <dt>Last attempt</dt>
              <dd>{time(data.collector?.last_attempt)}</dd>
              <dt>Last successful collection</dt>
              <dd>{time(data.collector?.last_success)}</dd>
              <dt>Latest window end</dt>
              <dd>{time(data.collector?.last_end)}</dd>
              <dt>Gap before latest window</dt>
              <dd>{data.collector?.last_gap_seconds ?? 0} seconds · no automatic backfill</dd>
              <dt>Retention</dt>
              <dd>
                Aggregate snapshots: 30 days. Observation evidence: 90 days from window end. Cleanup
                runs on each collection cycle or hourly while paused.
              </dd>
              <dt>Private request fields</dt>
              <dd>
                Not collected: IPs, identities, paths, query strings, cookies, tokens or request
                bodies.
              </dd>
            </dl>
            <p>
              Only windows listed below were stored. Collection starts at deployment; previous
              traffic and missed windows are not reconstructed. Empty groups mean no results were
              returned, not guaranteed complete traffic visibility. Analytics can arrive late and a
              stored window is not re-fetched.
            </p>
            <h3>Latest 24 stored windows</h3>
            <div className="live-scroll">
              <table>
                <thead>
                  <tr>
                    <th>Window start</th>
                    <th>Window end</th>
                    <th>Security</th>
                    <th>HTTP</th>
                  </tr>
                </thead>
                <tbody>
                  {data.windows.map((w) => (
                    <tr key={w.end}>
                      <td>{time(w.start)}</td>
                      <td>{time(w.end)}</td>
                      <td>{w.securityState}</td>
                      <td>{w.httpState}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        )}
      </main>
    </div>
  );
}
