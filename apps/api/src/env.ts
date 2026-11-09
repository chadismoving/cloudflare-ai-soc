export interface Bindings
  extends Omit<
    WranglerBindings,
    "APP_ENV" | "AUTH_MODE" | "APP_ORIGIN" | "ACCESS_ISSUER" | "ACCESS_AUDIENCE" | "SOC_FEATURES"
  > {
  APP_ENV: string;
  AUTH_MODE: string;
  APP_ORIGIN: string;
  ACCESS_ISSUER: string;
  ACCESS_AUDIENCE: string;
  LOCAL_ACCESS_PRIVATE_JWK?: string;
  LOCAL_ACCESS_JWKS?: string;
  OWNER_EMAIL?: string;
  OWNER_SUBJECT_SHA256?: string;
  SESSION_CSRF_SECRET: string;
  SIMULATION_INGEST_READS?: string;
  SOC_FEATURES?: string;
  SOC_MAINTENANCE_PROFILE?: string;
  SOC_AI_APPROVED?: string;
  AI_GATEWAY_ID?: string;
  AI?: Pick<Ai, "run">;
  LIVE_DB?: D1Database;
  LIVE_PROFILE?: string;
  LIVE_AI_MODE?: string;
  LIVE_AI_MODEL?: string;
  LIVE_REPAIR?: Fetcher;
}

export const approvedAccess = {
  origin: "https://soc.d.example.invalid",
  issuer: "https://access-team.example.invalid",
  audience: "0000000000000000000000000000000000000000000000000000000000000001",
} as const;

export function isLocalFixture(request: Request, env: Bindings): boolean {
  let configured: URL;
  try {
    configured = new URL(env.APP_ORIGIN);
  } catch {
    return false;
  }
  return (
    env.APP_ENV === "local" &&
    env.AUTH_MODE === "fixture" &&
    configured.protocol === "http:" &&
    configured.hostname === "127.0.0.1" &&
    new URL(request.url).origin === configured.origin &&
    env.ACCESS_ISSUER === `${configured.origin}/__local/access` &&
    env.ACCESS_AUDIENCE === "soc-local-fixture"
  );
}

export function isAccessRuntime(request: Request, env: Bindings): boolean {
  return (
    env.APP_ENV === "production" &&
    env.AUTH_MODE === "access" &&
    env.APP_ORIGIN === approvedAccess.origin &&
    new URL(request.url).origin === approvedAccess.origin &&
    env.ACCESS_ISSUER === approvedAccess.issuer &&
    env.ACCESS_AUDIENCE === approvedAccess.audience &&
    !!env.OWNER_EMAIL &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(env.OWNER_EMAIL) &&
    /^[a-f0-9]{64}$/.test(env.OWNER_SUBJECT_SHA256 || "") &&
    typeof env.SESSION_CSRF_SECRET === "string" &&
    env.SESSION_CSRF_SECRET.length >= 32
  );
}

export function isAccessMode(env: Bindings): boolean {
  return env.APP_ENV === "production" && env.AUTH_MODE === "access";
}
