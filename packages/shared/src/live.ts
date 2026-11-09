export const liveZone = "00000000000000000000000000000002";
export const liveAccount = "00000000000000000000000000000001";
export const liveProfile = "zone-analytics-readonly-v1";
export type DatasetState = "available" | "unavailable";
export interface LiveDataset<T> {
  state: DatasetState;
  groups: T[];
  truncated: boolean;
  error: string | null;
}
export interface LiveFacts {
  version: 1;
  environment: "live";
  zoneId: typeof liveZone;
  source: "cloudflare-graphql-adaptive";
  start: string;
  end: string;
  collectedAt: string;
  estimated: true;
  security: LiveDataset<{ action: string; source: string; count: number }>;
  http: LiveDataset<{ status: number; count: number }>;
}
export const livePriorities = ["low", "medium", "high"] as const;
export type LivePriority = (typeof livePriorities)[number];

export interface LiveFinding {
  id: string;
  rule: "mitigation-volume-v1" | "http-5xx-v1";
  title: string;
  severity: LivePriority;
  summary: string;
  evidence: LiveFacts;
  sha256: string;
  expiresAt: string;
}
export interface LiveObservations {
  counts: Record<LivePriority, number>;
  findings: (Pick<LiveFinding, "id" | "title" | "severity" | "summary"> & { windowEnd: string })[];
  next: string | null;
}
export interface LiveFollowUpWindow {
  end: string;
  state: "threshold_met" | "below_threshold" | "insufficient_data" | "not_collected";
  count: number | null;
  total: number | null;
}
export const liveInvestigationModel = "@cf/zai-org/glm-5.3";
export type LiveEvidenceRef = "observation" | "follow-up";
export interface LiveInvestigationReport {
  summary: string;
  findings: { claim: string; evidenceRefs: LiveEvidenceRef[] }[];
  limitations: string[];
  nextChecks: string[];
}
export interface LiveInvestigation {
  status: "ready" | "running" | "complete" | "failed";
  report: LiveInvestigationReport | null;
  followUp: LiveFollowUpWindow[];
  startedAt: string | null;
  retryAt: string | null;
  model: string;
  costMicro: number | null;
  usageKnown: boolean;
  failure: "timeout" | "invalid_response" | "provider_unavailable" | null;
  canStart: boolean;
  budget: { usedMicro: number; limitMicro: number; reservationMicro: number };
}
export interface LiveAiBudget {
  estimatedMicro: number;
  limitMicro: number;
  warning: boolean;
  canInvestigate: boolean;
}
export interface LiveOverview {
  environment: "live";
  zoneId: typeof liveZone;
  zoneName: "d.example.invalid";
  source: "cloudflare-graphql-adaptive";
  collector: {
    last_attempt: string | null;
    last_success: string | null;
    last_error: string | null;
    last_end: string | null;
    last_gap_seconds: number;
    collection_paused_at: string | null;
  } | null;
  latest: { facts: LiveFacts; sha256: string } | null;
  windows: {
    start: string;
    end: string;
    collectedAt: string;
    securityState: string;
    httpState: string;
  }[];
  findings: Omit<LiveFinding, "evidence">[];
  stale: boolean;
  aiEnabled: boolean;
  executionEnabled: false;
}
