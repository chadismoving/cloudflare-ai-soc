import { expect, it } from "vitest";
import { collectFacts, digest, findings, windowAt } from "../apps/api/src/live/analytics";
import { liveZone } from "../packages/shared/src/live";

const now = Date.parse("2026-11-08T15:59:20.000Z");
function source(security: unknown[], http: unknown[], errors: unknown = null): typeof fetch {
  return (async (url: string | URL | Request, init?: RequestInit) => {
    expect(url).toBe("https://api.cloudflare.com/client/v4/graphql");
    const query = JSON.parse(String(init?.body)).query as string;
    expect(query).toContain(liveZone);
    expect(query).not.toMatch(/clientIP|clientRequest|cookie|userAgent/i);
    const key = query.includes("firewallEvents")
      ? "firewallEventsAdaptiveGroups"
      : "httpRequestsAdaptiveGroups";
    return Response.json({
      data: { viewer: { zones: [{ [key]: key.startsWith("firewall") ? security : http }] } },
      errors,
    });
  }) as typeof fetch;
}
it("collects only bounded, fixed-zone aggregates; log matches alone never imply an attack", async () => {
  const facts = await collectFacts(
    "synthetic-test-credential",
    now,
    source(
      [
        {
          count: 244,
          dimensions: {
            action: "log",
            source: "firewallCustom",
            clientIP: "private-field-must-not-persist",
          },
        },
      ],
      [{ count: 230, dimensions: { edgeResponseStatus: 200 } }],
    ),
  );
  expect(facts).toMatchObject({
    environment: "live",
    zoneId: liveZone,
    estimated: true,
    ...windowAt(now),
  });
  expect(facts.end).toBe("2026-11-08T15:55:00.000Z");
  expect(JSON.stringify(facts)).not.toContain("private-field");
  expect(findings(facts, await digest(JSON.stringify(facts)))).toEqual([]);
});
it("creates evidence-linked observations only when documented thresholds are met", async () => {
  const facts = await collectFacts(
    "synthetic",
    now,
    source(
      [{ count: 100, dimensions: { action: "block", source: "firewallCustom" } }],
      [
        { count: 25, dimensions: { edgeResponseStatus: 503 } },
        { count: 475, dimensions: { edgeResponseStatus: 200 } },
      ],
    ),
  );
  const sha = await digest(JSON.stringify(facts)),
    found = findings(facts, sha);
  expect(found.map((f) => f.rule)).toEqual(["mitigation-volume-v1", "http-5xx-v1"]);
  expect(found[0]).toMatchObject({ evidence: facts, sha256: sha });
  expect(Date.parse(found[0]?.expiresAt || "") - Date.parse(facts.end)).toBe(90 * 86400000);
  const successful = facts.http.groups[1];
  if (!successful) throw new Error("Missing test group");
  successful.count = 476;
  expect(findings(facts, sha).map((f) => f.rule)).toEqual(["mitigation-volume-v1"]);
});
it("treats GraphQL errors and invalid private dimensions as unavailable rather than zero activity", async () => {
  const failed = await collectFacts(
    "synthetic",
    now,
    source([], [], [{ message: "do-not-persist-secret" }]),
  );
  expect(failed.security).toMatchObject({ state: "unavailable", error: "graphql_rejected" });
  expect(JSON.stringify(failed)).not.toContain("do-not-persist-secret");
  expect(findings(failed, "a".repeat(64))).toEqual([]);
  const invalid = await collectFacts(
    "synthetic",
    now,
    source([{ count: -1, dimensions: { action: "block", source: "unknown" } }], []),
  );
  expect(invalid.security.error).toBe("invalid_count");
  expect(invalid.http.state).toBe("available");
});
it("suppresses detection for truncated groups and rejects oversized responses without retaining provider contents", async () => {
  const groups = Array.from({ length: 128 }, (_, i) => ({
    count: 100,
    dimensions: { action: "block", source: `source${i}` },
  }));
  const facts = await collectFacts("synthetic", now, source(groups, []));
  expect(facts.security.truncated).toBe(true);
  expect(findings(facts, "a".repeat(64))).toEqual([]);
  const oversized = (async () => new Response("x".repeat(65537))) as typeof fetch;
  expect((await collectFacts("synthetic", now, oversized)).http.error).toBe("response_too_large");
});
it.each([302, 401, 403, 429, 503])(
  "sanitizes provider HTTP %i without storing response bodies",
  async (status) => {
    const facts = await collectFacts(
      "synthetic",
      now,
      (async () => new Response("provider-private-content", { status })) as typeof fetch,
    );
    expect(facts.security.state).toBe("unavailable");
    expect(JSON.stringify(facts)).not.toContain("provider-private-content");
  },
);
