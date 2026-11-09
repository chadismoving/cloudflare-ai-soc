import { z } from "zod";

export * from "./workbench";

export const roles = ["Viewer", "Analyst", "Operator", "Admin"] as const;
export const roleSchema = z.enum(roles);
export type Role = z.infer<typeof roleSchema>;
export type Permission = "read" | "investigate" | "approve" | "manage";
export type DataEnvironment = "live" | "simulation";

const rank: Record<Permission, number> = { read: 0, investigate: 1, approve: 2, manage: 3 };
const roleRank: Record<Role, number> = { Viewer: 0, Analyst: 1, Operator: 2, Admin: 3 };
export function permits(role: Role, permission: Permission, zoneGrant?: Permission): boolean {
  return (
    roleRank[role] >= rank[permission] &&
    (zoneGrant === undefined || rank[zoneGrant] >= rank[permission])
  );
}

export const policy = {
  mode: "Approve",
  executionEnabled: false,
  autonomousEnabled: false,
  aiMonthlyBudgetUsd: 50,
  aiWarningUsd: 40,
  triageDeadlineSeconds: 30,
  investigationDeadlineSeconds: 90,
  rawRetentionDays: 30,
  evidenceRetentionDays: 90,
  triageModel: "@cf/zai-org/glm-5.3-flash",
  investigationModel: "@cf/zai-org/glm-5.3",
  consoleHostname: "soc.d.example.invalid",
  testHostname: "soc-test.d.example.invalid",
  testPathNamespace: "/__soc_test/*",
} as const;

export const roleChangeSchema = z.strictObject({
  role: z.enum(["Viewer", "Analyst", "Operator"]),
  version: z.number().int().nonnegative(),
});

export const incidentSchema = z.object({
  id: z.string(),
  environment: z.literal("simulation"),
  zone_id: z.string(),
  title: z.string(),
  category: z.string(),
  severity: z.enum(["info", "low", "medium", "high", "critical"]),
  status: z.string(),
  first_seen: z.string(),
  last_seen: z.string(),
  summary: z.string(),
  confidence: z.number().nullable(),
});
export type Incident = z.infer<typeof incidentSchema>;

export interface Session {
  user: { id: string; role: Role; label: string };
  zoneGrants: Array<{ zoneId: string; permission: Permission }>;
  csrfToken: string;
  environment: "simulation";
  authMode: "signed-local-fixture" | "cloudflare-access";
  simulationIngestionEnabled?: boolean;
  simulationHealthEnabled?: boolean;
  liveConnectorsEnabled: boolean;
  liveDataEnabled?: boolean;
  executionEnabled: false;
  workbenchEnabled?: boolean;
}

export interface AuditRecord {
  id: string;
  actor_id: string | null;
  operation: string;
  target_id: string;
  details_json: string;
  created_at: string;
}

export function evidenceKey(input: {
  environment: DataEnvironment;
  kind: "raw" | "cases" | "tool-snapshots";
  date: string;
  id: string;
}): string {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(input.date) || !/^[a-zA-Z0-9_-]{1,128}$/.test(input.id)) {
    throw new Error("Invalid evidence identity");
  }
  return `${input.environment}/${input.kind}/${input.date}/${input.id}.json`;
}

export interface IngestionCoverage {
  simulation: true;
  scope: "local-raw" | "cloud-pilot-20261029";
  checkedAt: string;
  scanComplete: boolean;
  scannedObjects: number;
  excludedObjects: number;
  objects: Array<{
    key: string;
    uploadedAt: string;
    ageSeconds: number;
    status: string;
  }>;
}

export const simulationHealthProfile = "phase2b-health-v1";
export const pilotRawPrefix = "raw/firewall/phase2b-fixture-";
export const pilotRawKeys = [
  `${pilotRawPrefix}main.ndjson.gz`,
  `${pilotRawPrefix}duplicate.ndjson`,
  `${pilotRawPrefix}partial.ndjson`,
] as const;
