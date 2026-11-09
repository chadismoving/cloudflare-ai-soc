import { accessKeys, type HumanIdentity, verifyHumanJwt } from "@soc/shared/access";
import type { JWTVerifyGetKey } from "jose";

export interface ProbeBindings {
  APP_ENV: string;
  ALLOWED_ORIGIN: string;
  ACCESS_ISSUER: string;
  ACCESS_AUDIENCE: string;
  SUBJECT_BINDING_MODE: string;
  OWNER_EMAIL?: string;
  OWNER_SUBJECT_SHA256?: string;
}

const origin = "https://soc.d.example.invalid";
const issuer = "https://access-team.example.invalid";
const securityHeaders = {
  "Cache-Control": "no-store",
  "Content-Security-Policy":
    "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Strict-Transport-Security": "max-age=31536000",
};

function reply(request: Request, status: number, body: Record<string, unknown>): Response {
  return new Response(request.method === "HEAD" ? null : JSON.stringify(body), {
    status,
    headers: { ...securityHeaders, "Content-Type": "application/json; charset=utf-8" },
  });
}

export async function subjectFingerprint(subject: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(subject));
  return Array.from(new Uint8Array(digest), (v) => v.toString(16).padStart(2, "0")).join("");
}

// Injection is only a test seam. The exported Worker always uses trusted remote Access JWKS.
export function createProbeHandler(resolveKeys: (issuer: string) => JWTVerifyGetKey = accessKeys) {
  const resolvers = new Map<string, JWTVerifyGetKey>();
  return async (request: Request, env: ProbeBindings): Promise<Response> => {
    const ownerEmail = env.OWNER_EMAIL?.trim().toLowerCase();
    const mode = env.SUBJECT_BINDING_MODE;
    if (
      env.APP_ENV !== "access-probe" ||
      env.ALLOWED_ORIGIN !== origin ||
      env.ACCESS_ISSUER !== issuer ||
      !env.ACCESS_AUDIENCE?.trim() ||
      env.ACCESS_AUDIENCE.length > 1024 ||
      /\s/.test(env.ACCESS_AUDIENCE) ||
      !ownerEmail ||
      ownerEmail.length > 254 ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(ownerEmail) ||
      !["enroll", "pinned"].includes(mode) ||
      (mode === "pinned" && !/^[a-f0-9]{64}$/.test(env.OWNER_SUBJECT_SHA256 || ""))
    )
      return reply(request, 503, { status: "configuration_required" });

    if (new URL(request.url).origin !== origin)
      return reply(request, 403, { status: "hostname_denied" });
    // Never use CF_Authorization or local fixture cookies as an authentication fallback.
    const token = request.headers.get("Cf-Access-Jwt-Assertion");
    if (!token || token.length > 16384)
      return reply(request, 401, { status: "authentication_required" });
    let identity: HumanIdentity;
    try {
      let keys = resolvers.get(issuer);
      if (!keys) {
        keys = resolveKeys(issuer);
        resolvers.set(issuer, keys);
      }
      identity = await verifyHumanJwt(token, { issuer, audience: env.ACCESS_AUDIENCE, keys });
    } catch {
      // No JWT/claim/error reflection, and no application logging of sensitive headers.
      return reply(request, 401, { status: "invalid_identity" });
    }
    if (identity.email !== ownerEmail)
      return reply(request, 403, { status: "identity_not_allowed" });
    const fingerprint = await subjectFingerprint(identity.subject);
    if (mode === "pinned" && fingerprint !== env.OWNER_SUBJECT_SHA256)
      return reply(request, 403, { status: "subject_not_allowed" });
    if (!["GET", "HEAD"].includes(request.method))
      return reply(request, 405, { status: "read_only_probe" });
    if (!["/", "/api/session"].includes(new URL(request.url).pathname))
      return reply(request, 404, { status: "not_found" });
    return reply(request, 200, {
      status:
        mode === "pinned" ? "identity_verified_and_pinned" : "owner_verified_subject_unconfirmed",
      identity: "designated owner (masked)",
      subjectFingerprint: fingerprint,
      role: null,
      consoleAdmission: false,
      enrollmentOnly: mode === "enroll",
      message:
        mode === "enroll"
          ? "Review this subject fingerprint before enabling pinned mode. No role is granted."
          : "Access probe verified. The SOC console is not deployed by this probe.",
      dataConnected: false,
      executionEnabled: false,
    });
  };
}

const fetch = createProbeHandler();
export default { fetch };
