import { createRemoteJWKSet, type JWTVerifyGetKey, jwtVerify } from "jose";

export interface HumanIdentity {
  subject: string;
  email: string;
}
export function accessKeys(issuer: string): JWTVerifyGetKey {
  const url = new URL(issuer);
  if (
    url.protocol !== "https:" ||
    url.pathname !== "/" ||
    url.search ||
    url.hash ||
    url.username ||
    url.password
  ) {
    throw new Error("Access issuer must be a pinned HTTPS origin");
  }
  return createRemoteJWKSet(new URL("/cdn-cgi/access/certs", url), {
    timeoutDuration: 5000,
    cooldownDuration: 30000,
  });
}

export async function verifyHumanJwt(
  token: string,
  options: {
    issuer: string;
    audience: string;
    keys: JWTVerifyGetKey;
  },
): Promise<HumanIdentity> {
  const { payload } = await jwtVerify(token, options.keys, {
    issuer: options.issuer,
    audience: options.audience,
    algorithms: ["RS256"],
    requiredClaims: ["iss", "aud", "sub", "iat", "exp"],
    clockTolerance: 2,
  });
  if (
    typeof payload.iat !== "number" ||
    payload.iat > Date.now() / 1000 + 2 ||
    typeof payload.exp !== "number" ||
    payload.exp <= payload.iat
  )
    throw new Error("Invalid issue/expiry interval");
  if (
    !payload.sub ||
    payload.sub.length > 128 ||
    typeof payload.email !== "string" ||
    payload.email.length > 254 ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(payload.email) ||
    payload.common_name !== undefined ||
    payload.email_verified === false
  ) {
    throw new Error("A verified human subject and email are required");
  }
  return { subject: payload.sub, email: payload.email.toLowerCase() };
}
