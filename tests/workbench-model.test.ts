import { defaultWorkbenchPolicy, type Finding } from "@soc/shared";
import { expect, it, vi } from "vitest";
import type { Bindings } from "../apps/api/src/env";
import { modelStep, type Usage } from "../apps/api/src/workbench/model";

const finding: Finding = {
  verdict: "incident",
  severity: "high",
  confidence: 0.8,
  summary: "Suspicious requests need review.",
  findings: [{ claim: "Observed spike", evidenceRefs: ["tool:trusted"] }],
  limitations: [],
  falsePositives: [],
  recommendedAction: "managed_challenge",
};
const evidence = [
  {
    ref: "tool:trusted",
    name: "traffic_trend",
    status: "ok",
    observedAt: new Date().toISOString(),
    data: { requests: 1000 },
  },
];
const usage = (): Usage => ({
  calls: 0,
  inputTokens: 0,
  outputTokens: 0,
  costMicro: 0,
  estimated: false,
  uncertain: false,
});
const policy = { ...defaultWorkbenchPolicy, provider: "workers_ai" as const };
function binding(output: unknown) {
  const run = vi.fn(async () => output);
  const env = {
    SOC_AI_APPROVED: "workers-ai-metadata-only-v1",
    AI_GATEWAY_ID: "example-soc-ai",
    AI: { run },
  } as unknown as Bindings;
  return { env, run };
}
it("real-model adapter pins metadata-only Gateway options, structured output and redaction", async () => {
  const { env, run } = binding({
    choices: [{ message: { content: JSON.stringify({ kind: "final", finding }) } }],
    usage: { prompt_tokens: 100, completion_tokens: 20 },
  });
  const meter = usage();
  const signal = new AbortController().signal;
  const result = await modelStep(
    env,
    policy,
    "waf",
    evidence,
    "Cookie=fixture-secret email@example.com 192.0.2.10",
    true,
    meter,
    signal,
  );
  expect(result.kind).toBe("final");
  if (result.kind === "final") expect(result.finding.recommendedAction).toBe("none");
  const args = run.mock.calls[0] as unknown as [
    string,
    Record<string, unknown>,
    Record<string, unknown>,
  ];
  expect(args[0]).toBe("@cf/zai-org/glm-5.3-flash");
  expect(args[1].response_format).toMatchObject({
    type: "json_schema",
    json_schema: { name: "soc_readonly_step", strict: true },
  });
  expect(args[2]).toMatchObject({
    gateway: { id: "example-soc-ai", skipCache: true, collectLog: true },
    extraHeaders: { "cf-aig-collect-log-payload": "false" },
    signal,
  });
  expect(JSON.stringify(args[1])).not.toMatch(/fixture-secret|email@example|192\.0\.2\.10/);
  expect(meter).toMatchObject({ calls: 1, inputTokens: 100, outputTokens: 20, costMicro: 25 });
});
it("unapproved activation, missing usage and fabricated citations fail closed", async () => {
  const { env, run } = binding({
    response: {
      kind: "final",
      finding: { ...finding, findings: [{ claim: "Invented", evidenceRefs: ["tool:invented"] }] },
    },
    usage: { prompt_tokens: 10, completion_tokens: 10 },
  });
  await expect(
    modelStep(
      { ...env, SOC_AI_APPROVED: "" },
      policy,
      "waf",
      evidence,
      "",
      false,
      usage(),
      new AbortController().signal,
    ),
  ).rejects.toThrow();
  expect(run).not.toHaveBeenCalled();
  await expect(
    modelStep(env, policy, "waf", evidence, "", false, usage(), new AbortController().signal),
  ).rejects.toThrow("fabricated_evidence_reference");
  const missing = binding({ response: { kind: "final", finding } }),
    meter = usage();
  await expect(
    modelStep(missing.env, policy, "waf", evidence, "", false, meter, new AbortController().signal),
  ).rejects.toThrow("model_usage_missing");
  expect(meter.uncertain).toBe(true);
});
