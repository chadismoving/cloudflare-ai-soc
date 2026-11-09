import {
  type LiveDataset,
  type LiveFacts,
  type LiveFinding,
  liveZone,
} from "../../../../packages/shared/src/live";

const endpoint = "https://api.cloudflare.com/client/v4/graphql";
const groupLimit = { security: 128, http: 64 } as const;
class SourceError extends Error {}
function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new SourceError("invalid_schema");
  return value as Record<string, unknown>;
}
function count(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0 || value > 1e12)
    throw new SourceError("invalid_count");
  return value;
}
function label(value: unknown): string {
  if (typeof value !== "string" || !/^[a-zA-Z][a-zA-Z0-9_-]{0,63}$/.test(value))
    throw new SourceError("invalid_dimension");
  return value;
}
export function windowAt(now: number): { start: string; end: string } {
  const end = Math.floor((now - 120000) / 300000) * 300000;
  return { start: new Date(end - 300000).toISOString(), end: new Date(end).toISOString() };
}
async function boundedJson(response: Response): Promise<unknown> {
  const reader = response.body?.getReader();
  if (!reader) throw new SourceError("empty_response");
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const chunk = await reader.read();
      if (chunk.done) break;
      size += chunk.value.byteLength;
      if (size > 65536) throw new SourceError("response_too_large");
      chunks.push(chunk.value);
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  try {
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw new SourceError("invalid_json");
  }
}
export async function collectFacts(
  token: string,
  now = Date.now(),
  transport: typeof fetch = fetch,
): Promise<LiveFacts> {
  const window = windowAt(now);
  async function dataset(
    kind: "security" | "http",
  ): Promise<LiveDataset<Record<string, string | number>>> {
    try {
      const node =
        kind === "security" ? "firewallEventsAdaptiveGroups" : "httpRequestsAdaptiveGroups";
      const dimensions = kind === "security" ? "action source" : "edgeResponseStatus";
      const query = `{viewer{zones(filter:{zoneTag:"${liveZone}"}){${node}(limit:${groupLimit[kind]},filter:{datetime_geq:"${window.start}",datetime_lt:"${window.end}"},orderBy:[count_DESC]){count dimensions{${dimensions}}}}}}`;
      const response = await transport(endpoint, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ query }),
        redirect: "manual",
        signal: AbortSignal.timeout(10000),
      });
      if (!response.ok)
        throw new SourceError(
          response.status === 401 || response.status === 403
            ? "credential_rejected"
            : response.status === 429
              ? "rate_limited"
              : "provider_unavailable",
        );
      const payload = object(await boundedJson(response));
      if (payload.errors != null && (!Array.isArray(payload.errors) || payload.errors.length > 0))
        throw new SourceError("graphql_rejected");
      const zones = object(object(payload.data).viewer).zones;
      if (!Array.isArray(zones) || zones.length !== 1) throw new SourceError("zone_unavailable");
      const groups = object(zones[0])[node];
      if (!Array.isArray(groups) || groups.length > groupLimit[kind])
        throw new SourceError("invalid_schema");
      const seen = new Set<string>();
      const clean = groups.map((value: unknown) => {
        const group = object(value),
          d = object(group.dimensions),
          n = count(group.count);
        const result =
          kind === "security"
            ? { action: label(d.action), source: label(d.source), count: n }
            : { status: count(d.edgeResponseStatus), count: n };
        if ("status" in result && result.status > 599) throw new SourceError("invalid_dimension");
        const key = JSON.stringify(result, (k, v) => (k === "count" ? undefined : v));
        if (seen.has(key)) throw new SourceError("duplicate_dimension");
        seen.add(key);
        return result;
      });
      return {
        state: "available",
        groups: clean,
        truncated: clean.length === groupLimit[kind],
        error: null,
      };
    } catch (error) {
      return {
        state: "unavailable",
        groups: [],
        truncated: false,
        error: error instanceof SourceError ? error.message : "source_unreachable",
      };
    }
  }
  // Independent, bounded requests allow one unavailable dataset without inventing zeros.
  const [security, http] = await Promise.all([dataset("security"), dataset("http")]);
  return {
    version: 1,
    environment: "live",
    zoneId: liveZone,
    source: "cloudflare-graphql-adaptive",
    ...window,
    collectedAt: new Date(now).toISOString(),
    estimated: true,
    security: security as LiveFacts["security"],
    http: http as LiveFacts["http"],
  };
}
export async function digest(text: string): Promise<string> {
  const bytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(bytes), (b) => b.toString(16).padStart(2, "0")).join("");
}
export function mitigationCount(facts: LiveFacts): number {
  return facts.security.groups
    .filter((g) => ["block", "challenge", "managed_challenge", "jschallenge"].includes(g.action))
    .reduce((total, group) => total + group.count, 0);
}

export function httpErrorCounts(facts: LiveFacts): { failed: number; total: number } {
  return {
    total: facts.http.groups.reduce((total, group) => total + group.count, 0),
    failed: facts.http.groups
      .filter((group) => group.status >= 500 && group.status <= 599)
      .reduce((total, group) => total + group.count, 0),
  };
}

export function findings(facts: LiveFacts, sha256: string): LiveFinding[] {
  const result: LiveFinding[] = [];
  const add = (
    rule: LiveFinding["rule"],
    title: string,
    severity: LiveFinding["severity"],
    summary: string,
  ) =>
    result.push({
      id: `${rule}-${Date.parse(facts.end)}`,
      rule,
      title,
      severity,
      summary,
      evidence: facts,
      sha256,
      expiresAt: new Date(Date.parse(facts.end) + 90 * 86400000).toISOString(),
    });
  if (facts.security.state === "available" && !facts.security.truncated) {
    const n = mitigationCount(facts);
    if (n >= 100)
      add(
        "mitigation-volume-v1",
        "Security mitigations require review",
        "low",
        `${n} estimated security events had a block or challenge action in this five-minute window (threshold: 100). This does not prove an attack or a successful challenge. Logging-only events are excluded.`,
      );
  }
  if (facts.http.state === "available" && !facts.http.truncated) {
    const { failed, total } = httpErrorCounts(facts);
    if (failed >= 25 && failed / total >= 0.05)
      add(
        "http-5xx-v1",
        "Elevated HTTP server errors",
        "medium",
        `${failed} of ${total} estimated HTTP requests returned 5xx in this five-minute window (threshold: at least 25 and 5%). Review service health; this is not evidence of an attack by itself.`,
      );
  }
  return result;
}
