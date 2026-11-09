import { parseEnv } from "node:util";
import { createLocalJWKSet, importJWK, jwtVerify, SignJWT } from "jose";
import { expect, it } from "vitest";
import { fixtureEnvironment, serializeFixtureEnvironment } from "../scripts/fixture-env.mjs";

it("round-trips generated fixture keys through a real dotenv parser and signs a verifiable JWT", async () => {
  const values = await fixtureEnvironment();
  const decoded = parseEnv(serializeFixtureEnvironment(values));
  const privateKey = await importJWK(JSON.parse(decoded.LOCAL_ACCESS_PRIVATE_JWK || "{}"), "RS256");
  const jwt = await new SignJWT({ fixture: true })
    .setProtectedHeader({ alg: "RS256", kid: "local-fixture" })
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(privateKey);
  const { payload } = await jwtVerify(
    jwt,
    createLocalJWKSet(JSON.parse(decoded.LOCAL_ACCESS_JWKS || "{}")),
    { algorithms: ["RS256"] },
  );
  expect(payload.fixture).toBe(true);
  expect(decoded.SESSION_CSRF_SECRET?.length).toBe(64);
});
