import { type DataEnvironment, type Permission, permits } from "@soc/shared";
import type { Principal } from "./auth";
import { type Bindings, isAccessMode } from "./env";
import { HttpError } from "./http";

export interface ReadContext {
  environment: "simulation";
  db: D1Database;
  evidence: R2Bucket;
  executor: "mock-only";
  keyPrefix: string;
}

export function readContext(env: Bindings, requested?: string | null): ReadContext {
  if (
    (!(env.APP_ENV === "local" && env.AUTH_MODE === "fixture") && !isAccessMode(env)) ||
    (requested && requested !== "simulation")
  ) {
    throw new HttpError(
      403,
      "environment_unavailable",
      "Live connectors are unavailable in this foundation.",
    );
  }
  return {
    environment: "simulation",
    db: env.SIMULATION_DB,
    evidence: env.SIMULATION_EVIDENCE,
    executor: "mock-only",
    keyPrefix: isAccessMode(env) ? "cases/" : "simulation/",
  };
}

export function assertZone(
  principal: Principal,
  zoneId: string,
  permission: Permission = "read",
): void {
  const grant = principal.grants.find((v) => v.zoneId === zoneId);
  if (!grant || !permits(principal.role, permission, grant.permission))
    throw new HttpError(403, "zone_forbidden", "No permission for this zone.");
}

export function evidenceBinding(
  context: ReadContext,
  environment: DataEnvironment,
  key: string,
): R2Bucket {
  if (
    environment !== context.environment ||
    !key.startsWith(context.keyPrefix) ||
    key.includes("..") ||
    key.includes("\\")
  ) {
    throw new HttpError(403, "evidence_scope_rejected", "Evidence belongs to another environment.");
  }
  return context.evidence;
}
