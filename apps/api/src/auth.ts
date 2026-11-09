import { accessKeys, type HumanIdentity, verifyHumanJwt } from "@soc/shared/access";

export { accessKeys, verifyHumanJwt } from "@soc/shared/access";

import { type Permission, type Role, roleSchema } from "@soc/shared";
import { createLocalJWKSet, importJWK, type JWK, SignJWT } from "jose";
import { type Bindings, isAccessMode } from "./env";
import { HttpError } from "./http";

export interface Principal {
  id: string;
  role: Role;
  token: string;
  grants: Array<{ zoneId: string; permission: Permission }>;
}

const cookieName = "soc_fixture_session";
function tokenFrom(request: Request, access: boolean): string {
  const header = request.headers.get("Cf-Access-Jwt-Assertion");
  if (access) {
    if (!header || header.length > 16384)
      throw new HttpError(401, "authentication_required", "A valid Access session is required.");
    return header;
  }
  const cookie = request.headers
    .get("Cookie")
    ?.split(";")
    .map((v) => v.trim())
    .find((v) => v.startsWith(`${cookieName}=`))
    ?.slice(cookieName.length + 1);
  if (header && cookie && header !== cookie)
    throw new HttpError(401, "ambiguous_identity", "Conflicting identity assertions.");
  const token = header || cookie;
  if (!token || token.length > 16384)
    throw new HttpError(401, "authentication_required", "Sign in with a local fixture identity.");
  return token;
}

const remoteKeys = new Map<string, ReturnType<typeof accessKeys>>();

export async function authenticate(request: Request, env: Bindings): Promise<Principal> {
  const access = isAccessMode(env);
  const token = tokenFrom(request, access);
  let identity: HumanIdentity;
  try {
    identity = await verifyHumanJwt(token, {
      issuer: env.ACCESS_ISSUER,
      audience: env.ACCESS_AUDIENCE,
      keys: access
        ? trustedKeys(env.ACCESS_ISSUER)
        : createLocalJWKSet(JSON.parse(env.LOCAL_ACCESS_JWKS || "")),
    });
  } catch {
    throw new HttpError(401, "invalid_identity", "Identity assertion is invalid or expired.");
  }
  let subject = identity.subject;
  if (access) {
    const digest = Array.from(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(subject))),
      (v) => v.toString(16).padStart(2, "0"),
    ).join("");
    if (identity.email !== env.OWNER_EMAIL?.toLowerCase() || digest !== env.OWNER_SUBJECT_SHA256)
      throw new HttpError(403, "identity_not_allowed", "This identity is not allowlisted.");
    subject = `sha256:${digest}`;
  }
  const user = await env.APP_DB.prepare(
    "SELECT id, email, role, active FROM users WHERE access_subject = ?",
  )
    .bind(subject)
    .first<{ id: string; email: string; role: string; active: number }>();
  if (
    user?.active !== 1 ||
    user.email !== identity.email ||
    !roleSchema.safeParse(user.role).success
  ) {
    throw new HttpError(403, "identity_not_allowed", "This identity is not allowlisted.");
  }
  const result = await env.APP_DB.prepare(
    "SELECT za.zone_id, za.permission FROM zone_access za JOIN zones z ON z.id = za.zone_id WHERE za.user_id = ? AND z.enabled = 1 AND (z.environment = 'simulation' OR (z.environment = 'live' AND z.id = '00000000000000000000000000000002' AND ? = 1))",
  )
    .bind(user.id, env.LIVE_PROFILE === "zone-analytics-readonly-v1" && env.LIVE_DB ? 1 : 0)
    .all<{ zone_id: string; permission: Permission }>();
  return {
    id: user.id,
    role: roleSchema.parse(user.role),
    token,
    grants: result.results.map((v) => ({ zoneId: v.zone_id, permission: v.permission })),
  };
}

function trustedKeys(issuer: string): ReturnType<typeof accessKeys> {
  let keys = remoteKeys.get(issuer);
  if (!keys) {
    keys = accessKeys(issuer);
    remoteKeys.set(issuer, keys);
  }
  return keys;
}

export function requireOrigin(request: Request, env: Bindings): void {
  if (request.headers.get("Origin") !== env.APP_ORIGIN)
    throw new HttpError(403, "origin_rejected", "A same-origin browser request is required.");
}

export async function csrfToken(principal: Principal, env: Bindings): Promise<string> {
  if (!env.SESSION_CSRF_SECRET || env.SESSION_CSRF_SECRET.length < 32)
    throw new Error("Missing CSRF secret");
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(env.SESSION_CSRF_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signed = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(principal.token));
  return btoa(String.fromCharCode(...new Uint8Array(signed)))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

export async function requireCsrf(
  request: Request,
  principal: Principal,
  env: Bindings,
): Promise<void> {
  requireOrigin(request, env);
  const expected = await csrfToken(principal, env);
  const supplied = request.headers.get("X-CSRF-Token") || "";
  let difference = supplied.length ^ expected.length;
  for (let i = 0; i < expected.length; i++)
    difference |= expected.charCodeAt(i) ^ (supplied.charCodeAt(i) || 0);
  if (difference !== 0)
    throw new HttpError(403, "csrf_rejected", "Refresh your session before trying again.");
}

export async function fixtureSession(persona: "admin" | "viewer", env: Bindings): Promise<string> {
  const jwk = JSON.parse(env.LOCAL_ACCESS_PRIVATE_JWK || "") as JWK;
  const key = await importJWK(jwk, "RS256");
  return new SignJWT({ email: `${persona}@fixture.invalid` })
    .setProtectedHeader({ alg: "RS256", kid: jwk.kid || "local-fixture" })
    .setIssuer(env.ACCESS_ISSUER)
    .setAudience(env.ACCESS_AUDIENCE)
    .setSubject(`fixture-${persona}`)
    .setIssuedAt()
    .setExpirationTime("15m")
    .sign(key);
}

export function sessionCookie(token: string): string {
  return `${cookieName}=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${token ? 900 : 0}`;
}
