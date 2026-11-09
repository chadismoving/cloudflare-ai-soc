import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import { accessKeys, verifyHumanJwt } from "../apps/api/src/auth";

const issuer = "https://access.fixture.invalid";
const audience = "fixture-audience";
let pair: Awaited<ReturnType<typeof generateKeyPair>>;
let rotated: Awaited<ReturnType<typeof generateKeyPair>>;
let keys: ReturnType<typeof createLocalJWKSet>;
beforeAll(async () => {
  pair = await generateKeyPair("RS256", { extractable: true });
  rotated = await generateKeyPair("RS256", { extractable: true });
  keys = createLocalJWKSet({
    keys: [
      { ...(await exportJWK(pair.publicKey)), kid: "first", alg: "RS256" },
      { ...(await exportJWK(rotated.publicKey)), kid: "rotated", alg: "RS256" },
    ],
  });
});
async function token(
  overrides: {
    issuer?: string;
    audience?: string;
    subject?: string;
    payload?: Record<string, unknown>;
    expires?: number;
    nbf?: number;
    kid?: string;
    key?: CryptoKey;
    omitExpiry?: boolean;
  } = {},
) {
  let jwt = new SignJWT(overrides.payload ?? { email: "owner@fixture.invalid" })
    .setProtectedHeader({ alg: "RS256", kid: overrides.kid || "first" })
    .setIssuer(overrides.issuer || issuer)
    .setAudience(overrides.audience || audience)
    .setSubject(overrides.subject ?? "human-subject")
    .setIssuedAt();
  if (!overrides.omitExpiry)
    jwt = jwt.setExpirationTime(overrides.expires ?? Math.floor(Date.now() / 1000) + 600);
  if (overrides.nbf) jwt = jwt.setNotBefore(overrides.nbf);
  return jwt.sign(overrides.key || pair.privateKey);
}
const verify = (value: string) => verifyHumanJwt(value, { issuer, audience, keys });

describe("Access JWT verification with cryptographic fixtures", () => {
  it("verifies the signature, issuer, audience, expiry and human identity", async () => {
    await expect(verify(await token())).resolves.toEqual({
      subject: "human-subject",
      email: "owner@fixture.invalid",
    });
  });
  it("accepts a rotated key from the trusted JWKS", async () => {
    await expect(
      verify(await token({ kid: "rotated", key: rotated.privateKey })),
    ).resolves.toHaveProperty("subject", "human-subject");
  });
  it.each([
    ["wrong issuer", { issuer: "https://attacker.fixture.invalid" }],
    ["wrong audience", { audience: "another-app" }],
    ["expired token", { expires: 1 }],
    ["not yet valid", { nbf: Math.floor(Date.now() / 1000) + 300 }],
    ["missing expiry", { omitExpiry: true }],
    ["unknown key", { kid: "unknown" }],
    ["empty human subject", { subject: "" }],
    ["service identity", { payload: { common_name: "service.fixture.invalid" } }],
    ["no email", { payload: {} }],
    [
      "unverified email claim",
      { payload: { email: "owner@fixture.invalid", email_verified: false } },
    ],
  ])("rejects %s", async (_label, overrides) => {
    await expect(verify(await token(overrides))).rejects.toThrow();
  });
  it("rejects a valid-looking JWT signed by another key", async () => {
    const other = await generateKeyPair("RS256");
    await expect(verify(await token({ key: other.privateKey }))).rejects.toThrow();
  });
  it("rejects an algorithm substitution", async () => {
    const jwt = await new SignJWT({ email: "owner@fixture.invalid" })
      .setProtectedHeader({ alg: "HS256", kid: "first" })
      .setIssuer(issuer)
      .setAudience(audience)
      .setSubject("human-subject")
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(new TextEncoder().encode("not-an-access-rsa-key-012345678901234567890"));
    await expect(verify(jwt)).rejects.toThrow();
  });
  it("does not discover issuer/key URLs from token content", () => {
    expect(() => accessKeys("http://access.fixture.invalid")).toThrow();
    expect(() => accessKeys("https://access.fixture.invalid/untrusted-path")).toThrow();
    expect(() => accessKeys("https://user:password@access.fixture.invalid")).toThrow();
  });
});
