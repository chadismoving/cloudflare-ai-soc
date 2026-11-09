import { randomBytes } from "node:crypto";
import { exportJWK, generateKeyPair } from "jose";

export async function fixtureEnvironment() {
  const { privateKey, publicKey } = await generateKeyPair("RS256", {
    modulusLength: 2048,
    extractable: true,
  });
  return {
    LOCAL_ACCESS_PRIVATE_JWK: JSON.stringify({
      ...(await exportJWK(privateKey)),
      kid: "local-fixture",
      alg: "RS256",
    }),
    LOCAL_ACCESS_JWKS: JSON.stringify({
      keys: [{ ...(await exportJWK(publicKey)), kid: "local-fixture", alg: "RS256", use: "sig" }],
    }),
    SESSION_CSRF_SECRET: randomBytes(32).toString("hex"),
  };
}

export function serializeFixtureEnvironment(entries) {
  return `${Object.entries(entries)
    .map(([key, value]) => {
      if (
        !/^[A-Z_]+$/.test(key) ||
        typeof value !== "string" ||
        value.includes("'") ||
        value.includes("\n")
      )
        throw new Error("Unsafe fixture environment value");
      return `${key}='${value}'`;
    })
    .join("\n")}\n`;
}
