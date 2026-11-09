import { simulationHealthProfile } from "@soc/shared";
import {
  cloudHealthRefSchema,
  cloudLimits,
  cloudRefSchema,
  fail,
  limits,
  refSchema,
} from "./schema";

export interface Env {
  APP_ENV: string;
  DATA_ENVIRONMENT: string;
  CLOUD_SIMULATION_PROFILE?: string;
  LOCAL_INGEST_SECRET?: string;
  LOCAL_R2_RETENTION_WRITES?: string;
  SIMULATION_DB: D1Database;
  SIMULATION_STORE: R2Bucket;
  INGEST_QUEUE?: Queue;
}
export function cloudEnabled(env: Env) {
  return (
    env.APP_ENV === "cloud-simulation" &&
    env.DATA_ENVIRONMENT === "simulation" &&
    ["phase2b-v1", simulationHealthProfile, "phase2b-retention-v1"].includes(
      env.CLOUD_SIMULATION_PROFILE || "",
    ) &&
    !env.LOCAL_INGEST_SECRET
  );
}
export function localEnabled(env: Env) {
  return (
    env.APP_ENV === "local" &&
    env.DATA_ENVIRONMENT === "simulation" &&
    typeof env.LOCAL_INGEST_SECRET === "string" &&
    env.LOCAL_INGEST_SECRET.length >= 32
  );
}
export function timingEnabled(env: Env) {
  return localEnabled(env) || (cloudEnabled(env) && env.CLOUD_SIMULATION_PROFILE !== "phase2b-v1");
}
export function retentionWritesEnabled(env: Env) {
  return (
    (cloudEnabled(env) && env.CLOUD_SIMULATION_PROFILE === "phase2b-retention-v1") ||
    (localEnabled(env) && env.LOCAL_R2_RETENTION_WRITES === "v1")
  );
}
export function profile(env: Env) {
  if (cloudEnabled(env))
    return {
      cloud: true,
      prefix: "",
      schema: env.CLOUD_SIMULATION_PROFILE !== "phase2b-v1" ? cloudHealthRefSchema : cloudRefSchema,
      limits: cloudLimits,
      queue: "example-soc-ingest-simulation",
      dlq: "example-soc-ingest-simulation-dlq",
    };
  if (localEnabled(env))
    return {
      cloud: false,
      prefix: "simulation/",
      schema: refSchema,
      limits,
      queue: "soc-local-ingest",
      dlq: "soc-local-ingest-dlq",
    };
  return fail("runtime_rejected");
}
export interface Usage {
  preparedStatements: number;
  r2Operations: number;
  elapsedMs: number;
}
// Conservative statement budget: db.batch counts as one invocation query at Cloudflare,
// while this budget counts every prepared statement. This is not invoice accounting.
export function metered(env: Env) {
  const usage: Usage = { preparedStatements: 0, r2Operations: 0, elapsedMs: 0 };
  const started = performance.now();
  const bounded = cloudEnabled(env);
  const db = new Proxy(env.SIMULATION_DB, {
    get(target, key) {
      const value = Reflect.get(target, key, target);
      if (typeof value !== "function") return value;
      return (...args: unknown[]) => {
        if (key === "prepare") {
          usage.preparedStatements++;
          if (bounded && usage.preparedStatements > 40) fail("statement_budget_exceeded");
        }
        return Reflect.apply(value, target, args);
      };
    },
  });
  const store = new Proxy(env.SIMULATION_STORE, {
    get(target, key) {
      const value = Reflect.get(target, key, target);
      if (typeof value !== "function") return value;
      return (...args: unknown[]) => {
        usage.r2Operations++;
        if (bounded && usage.r2Operations > 10) fail("object_budget_exceeded");
        return Reflect.apply(value, target, args);
      };
    },
  });
  return {
    env: { ...env, SIMULATION_DB: db, SIMULATION_STORE: store },
    usage,
    snapshot: () => ({ ...usage, elapsedMs: Math.round(performance.now() - started) }),
  };
}
