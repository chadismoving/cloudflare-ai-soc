import { pilotRawKeys } from "@soc/shared";
import { z } from "zod";

export const limits = { compressed: 1048576, expanded: 8388608, lines: 10000, line: 65536 };
export const bucketName = "soc-local-simulation-evidence";
export const cloudAccount = "00000000000000000000000000000001";
export const cloudBucket = "example-cloudflare-ai-soc-simulation";
export const cloudLimits = { compressed: 16384, expanded: 32768, lines: 4, line: 8192 };
export const refSchema = z.object({
  environment: z.literal("simulation").optional(),
  account: z.literal("fixture-account"),
  bucket: z.literal(bucketName),
  action: z.enum(["PutObject", "CopyObject", "CompleteMultipartUpload"]),
  object: z.object({
    key: z
      .string()
      .max(240)
      .regex(/^raw\/(http|firewall|notification)\/[a-zA-Z0-9_-]+\.ndjson(?:\.gz)?$/),
    size: z.number().int().nonnegative().max(limits.compressed),
    eTag: z.string().regex(/^[a-f0-9]{32}(?:-\d+)?$/),
  }),
  eventTime: z.iso.datetime(),
});
export const cloudRefSchema = refSchema.extend({
  account: z.literal(cloudAccount),
  bucket: z.literal(cloudBucket),
  object: refSchema.shape.object.extend({
    key: z
      .string()
      .max(240)
      .regex(/^raw\/(http|firewall|notification)\/phase2b-[a-zA-Z0-9_-]+\.ndjson(?:\.gz)?$/),
    size: z.number().int().nonnegative().max(cloudLimits.compressed),
  }),
});
export const cloudHealthRefSchema = cloudRefSchema.extend({
  object: cloudRefSchema.shape.object.extend({ key: z.enum(pilotRawKeys) }),
});
export type Reference = z.infer<typeof refSchema> | z.infer<typeof cloudRefSchema>;
const common = {
  environment: z.literal("simulation").optional(),
  accountId: z.literal("fixture-account").optional(),
  zoneId: z.literal("fixture-zone").optional(),
  fixture: z.literal(true),
  RayID: z.string().regex(/^[a-zA-Z0-9_-]{1,64}$/),
  ClientRequestHost: z.literal("demo.fixture.invalid"),
  ClientRequestPath: z
    .string()
    .max(240)
    .regex(/^\/__soc_test\/[a-zA-Z0-9/_-]*$/),
  ClientIP: z.string().regex(/^client-[a-z0-9-]{1,32}$/),
};
const http = z.object({ ...common, EdgeStartTimestamp: z.iso.datetime() });
const firewall = z.object({
  ...common,
  Datetime: z.iso.datetime(),
  Action: z.enum(["block", "managed_challenge", "skip", "log"]),
  RuleID: z.string().regex(/^[a-zA-Z0-9_-]{1,64}$/),
  Source: z.enum(["waf", "rate_limit"]),
});
export const notificationSchema = z.strictObject({
  fixture: z.literal(true),
  account_id: z.literal("fixture-account"),
  policy_id: z.literal("fixture-waf-policy"),
  alert_type: z.literal("waf_alert"),
  alert_correlation_id: z.string().regex(/^[a-zA-Z0-9_-]{1,64}$/),
  ts: z.iso.datetime(),
  data: z.strictObject({
    zone_id: z.literal("fixture-zone"),
    client: z.string().regex(/^client-[a-z0-9-]{1,32}$/),
  }),
});
export type Candidate = {
  emulatedSource: string;
  category: string;
  time: string;
  client: string;
  path: string;
  identity: string[];
};
export class IngestError extends Error {}
export function fail(reason: string): never {
  throw new IngestError(reason);
}
export function normalize(input: unknown, dataset: string): Candidate {
  if (dataset === "notification") {
    const p = notificationSchema.safeParse(input);
    if (!p.success) return fail("invalid_notification");
    const v = p.data;
    return {
      emulatedSource: "notification",
      category: "waf",
      time: v.ts,
      client: v.data.client,
      path: "notification",
      identity: [v.policy_id, v.alert_correlation_id, v.ts],
    };
  }
  if (dataset === "http") {
    const p = http.safeParse(input);
    if (!p.success) return fail("invalid_http_record");
    const v = p.data;
    return {
      emulatedSource: "http_requests",
      category: "http",
      time: v.EdgeStartTimestamp,
      client: v.ClientIP,
      path: v.ClientRequestPath,
      identity: [
        v.RayID,
        v.EdgeStartTimestamp,
        v.ClientRequestHost,
        v.ClientRequestPath,
        v.ClientIP,
      ],
    };
  }
  const p = firewall.safeParse(input);
  if (dataset !== "firewall" || !p.success) return fail("invalid_firewall_record");
  const v = p.data;
  return {
    emulatedSource: "firewall_events",
    category: v.Source === "rate_limit" ? "rate_limit" : "waf",
    time: v.Datetime,
    client: v.ClientIP,
    path: v.ClientRequestPath,
    identity: [
      v.RayID,
      v.Datetime,
      v.Action,
      v.RuleID,
      v.Source,
      v.ClientRequestHost,
      v.ClientRequestPath,
      v.ClientIP,
    ],
  };
}
export async function hash(value: string | Uint8Array): Promise<string> {
  const bytes = typeof value === "string" ? new TextEncoder().encode(value) : new Uint8Array(value);
  return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)), (v) =>
    v.toString(16).padStart(2, "0"),
  ).join("");
}
export const dateAfter = (iso: string, days: number) =>
  new Date(Date.parse(iso) + days * 86400000).toISOString();
