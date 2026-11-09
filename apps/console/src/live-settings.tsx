import { executableActions, type Session } from "@soc/shared";
import { useCallback, useEffect, useRef, useState } from "react";
import type { LiveAiBudget, LiveOverview } from "../../../packages/shared/src/live";
import {
  type LivePolicy,
  type LivePolicyState,
  livePolicySchema,
} from "../../../packages/shared/src/live-policy";
import { api } from "./client";

const policyPath = "/api/live/settings/policy";
const usd = (value: number) =>
  `$${(value / 1000000).toFixed(value === 0 || value >= 100000 ? 2 : 5)}`;
const models = [
  ["@cf/zai-org/glm-5.3", "GLM 5.3"],
  ["@cf/zai-org/glm-5.3-flash", "GLM 5.3 Flash (planned retirement)"],
] as const;
const modes = [
  ["Observe", "Observe"],
  ["Approve", "Approve"],
  ["Autonomous", "Autonomous (plan only)"],
] as const;
const limits = [
  { key: "monthlyBudgetUsd", label: "Monthly AI budget (USD)", min: 0, max: 50, step: 0.01 },
  {
    key: "investigationDeadlineSeconds",
    label: "Investigation timeout (seconds)",
    min: 1,
    max: 90,
    step: 1,
  },
  {
    key: "maxDurationSeconds",
    label: "Test rule expiry target (seconds)",
    min: 60,
    max: 600,
    step: 1,
  },
] as const;
const planningLimits = [
  {
    key: "maxRequestSharePercent",
    label: "Maximum request share (%)",
    min: 0,
    max: 10,
    step: "any",
  },
  {
    key: "maxEvidenceAgeSeconds",
    label: "Maximum evidence age (seconds)",
    min: 60,
    max: 3600,
    step: 1,
  },
  { key: "maxToolCalls", label: "Maximum tool calls", min: 1, max: 8, step: 1 },
  { key: "triageDeadlineSeconds", label: "Triage timeout (seconds)", min: 1, max: 30, step: 1 },
] as const;

export function LiveSettings({
  overview,
  session,
}: {
  overview: LiveOverview | null;
  session: Session;
}) {
  const [draft, setDraft] = useState<LivePolicyState | null>(null);
  const [budget, setBudget] = useState<LiveAiBudget | null>(null);
  const [budgetError, setBudgetError] = useState("");
  const [error, setError] = useState("");
  const [saved, setSaved] = useState(false);
  const [busy, setBusy] = useState(false);
  const budgetRequest = useRef(0);
  const admin = session.user.role === "Admin";
  const loadPolicy = useCallback(async () => {
    setBusy(true);
    setError("");
    setSaved(false);
    try {
      setDraft(await api<LivePolicyState>(policyPath));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Live policy unavailable.");
    } finally {
      setBusy(false);
    }
  }, []);
  useEffect(() => {
    void loadPolicy();
  }, [loadPolicy]);
  const loadBudget = useCallback(async () => {
    const request = ++budgetRequest.current;
    try {
      const next = await api<LiveAiBudget>("/api/live/settings/ai");
      if (request === budgetRequest.current) {
        setBudget(next);
        setBudgetError("");
      }
    } catch (e) {
      if (request === budgetRequest.current)
        setBudgetError(e instanceof Error ? e.message : "AI usage unavailable.");
    }
  }, []);
  useEffect(() => {
    if (overview) void loadBudget();
  }, [loadBudget, overview]);

  const patch = <K extends keyof LivePolicy>(key: K, value: LivePolicy[K]) => {
    setSaved(false);
    setDraft((current) => current && { ...current, policy: { ...current.policy, [key]: value } });
  };
  async function save() {
    if (!draft || !admin || busy) return;
    setError("");
    setSaved(false);
    if (!livePolicySchema.safeParse(draft.policy).success) {
      setError("Check the live policy values and limits.");
      return;
    }
    setBusy(true);
    try {
      setDraft(
        await api<LivePolicyState>(policyPath, {
          method: "PUT",
          csrf: session.csrfToken,
          body: draft,
        }),
      );
      setSaved(true);
      await loadBudget();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Live policy could not be saved.");
    } finally {
      setBusy(false);
    }
  }
  const policy = draft?.policy;
  const input = (field: (typeof limits)[number] | (typeof planningLimits)[number]) => {
    const value = policy?.[field.key];
    return (
      <label key={field.key}>
        {field.label}
        <input
          type="number"
          required
          min={field.min}
          max={field.max}
          step={field.step}
          value={Number.isFinite(value) ? value : ""}
          onChange={(event) => patch(field.key, event.currentTarget.valueAsNumber)}
        />
      </label>
    );
  };

  return (
    <>
      <section className="live-panel">
        <h2>Live AI usage and budget</h2>
        {budgetError && <p role="alert">{budgetError}</p>}
        {budget ? (
          <>
            <dl className="live-health">
              <dt>Monthly AI usage estimate</dt>
              <dd>{usd(budget.estimatedMicro)}</dd>
              <dt>Monthly AI budget</dt>
              <dd>{usd(budget.limitMicro)}</dd>
            </dl>
            {budget.warning && (
              <p role="status">The monthly budget has reached its 80% warning threshold.</p>
            )}
            {!budget.canInvestigate && (
              <p role="status">The available budget is too low to start another investigation.</p>
            )}
          </>
        ) : (
          !budgetError && <p role="status">Loading AI usage…</p>
        )}
        {overview && !overview.aiEnabled && <p>Workers AI is unavailable in this deployment.</p>}
      </section>
      <section className="live-panel">
        <h2>Live response policy</h2>
        <p>Applies to Live. Repairs require explicit approval and a verified test scope.</p>
        {!policy && busy && <p role="status">Loading live policy…</p>}
        {policy && (
          <form
            onSubmit={(event) => {
              event.preventDefault();
              void save();
            }}
          >
            <fieldset
              className="live-policy-fields"
              disabled={!admin || busy}
              aria-label="Live policy options"
            >
              <div className="live-policy-grid">
                <label>
                  Mode
                  <select
                    value={policy.mode}
                    onChange={(event) => patch("mode", event.target.value as LivePolicy["mode"])}
                  >
                    {modes.map(([id, label]) => (
                      <option key={id} value={id}>
                        {label}
                      </option>
                    ))}
                  </select>
                </label>
                <label>
                  Model provider
                  <select
                    value={policy.provider}
                    onChange={(event) =>
                      patch("provider", event.target.value as LivePolicy["provider"])
                    }
                  >
                    <option value="workers_ai">Workers AI</option>
                    <option value="disabled">Disabled</option>
                  </select>
                </label>
                <label>
                  Investigation model
                  <select
                    value={policy.investigationModel}
                    onChange={(event) =>
                      patch(
                        "investigationModel",
                        event.target.value as LivePolicy["investigationModel"],
                      )
                    }
                  >
                    {models.map(([id, label]) => (
                      <option key={id} value={id}>
                        {label}
                      </option>
                    ))}
                  </select>
                </label>
                {limits.map(input)}
              </div>
              <div className="live-policy-checks">
                <label>
                  <input
                    type="checkbox"
                    checked={policy.requireSecondApprover}
                    onChange={(event) => patch("requireSecondApprover", event.target.checked)}
                  />{" "}
                  Require a different approver
                </label>
                <label>
                  <input
                    type="checkbox"
                    checked={policy.killSwitch}
                    onChange={(event) => patch("killSwitch", event.target.checked)}
                  />{" "}
                  Emergency stop
                </label>
              </div>
              <p>
                Emergency stop pauses new investigations and repair approvals or applications.
                Observe mode pauses repair approvals and applications.
              </p>
              <h3>Planned controls</h3>
              <p>
                These values are saved for future triage, tool use, request impact checks, evidence
                checks, and autonomous actions.
              </p>
              <div className="live-policy-grid">
                <label>
                  Triage model
                  <select
                    value={policy.triageModel}
                    onChange={(event) =>
                      patch("triageModel", event.target.value as LivePolicy["triageModel"])
                    }
                  >
                    {models.map(([id, label]) => (
                      <option key={id} value={id}>
                        {label}
                      </option>
                    ))}
                  </select>
                </label>
                {planningLimits.map(input)}
              </div>
              <h4>Autonomous allowlist</h4>
              <div className="live-policy-checks">
                {executableActions.map((action) => (
                  <label key={action}>
                    <input
                      type="checkbox"
                      checked={policy.autonomousActions.includes(action)}
                      onChange={(event) =>
                        patch(
                          "autonomousActions",
                          event.target.checked
                            ? [...policy.autonomousActions, action]
                            : policy.autonomousActions.filter((item) => item !== action),
                        )
                      }
                    />
                    {action.replaceAll("_", " ")}
                  </label>
                ))}
              </div>
              <button type="submit">{busy ? "Saving…" : "Save live policy"}</button>
            </fieldset>
          </form>
        )}
        {saved && <p role="status">Live policy saved.</p>}
        {error && <p role="alert">{error}</p>}
        {error && (
          <button type="button" disabled={busy} onClick={() => void loadPolicy()}>
            Reload live policy
          </button>
        )}
      </section>
    </>
  );
}
