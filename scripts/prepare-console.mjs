import { createHash, randomBytes } from "node:crypto";
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const sql = (value) => `'${value.replaceAll("'", "''")}'`;

export function ownerBootstrap(identity) {
  if (
    identity.verified_login !== true ||
    typeof identity.intended_owner_email !== "string" ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(identity.intended_owner_email) ||
    !/^[a-f0-9]{64}$/.test(identity.subject_sha256 || "") ||
    !identity.subject_confirmation
  )
    throw new Error("A verified, explicitly confirmed owner identity is required.");
  const email = identity.intended_owner_email.toLowerCase();
  const subject = `sha256:${identity.subject_sha256}`;
  return `-- Private owner bootstrap. Apply only after reviewed schema/migration checks.
-- INSERT OR IGNORE never overwrites an existing identity or changes its role.
INSERT OR IGNORE INTO users VALUES
 ('soc-owner',${sql(subject)},${sql(email)},'Admin',1,0,strftime('%Y-%m-%dT%H:%M:%fZ','now'));
INSERT OR IGNORE INTO zones VALUES ('fixture-zone','fixture-account','demo.fixture.invalid',1,'simulation');
INSERT OR IGNORE INTO zone_access
 SELECT 'soc-owner','fixture-zone','manage'
 WHERE EXISTS (SELECT 1 FROM users WHERE id='soc-owner' AND access_subject=${sql(subject)} AND email=${sql(email)} AND role='Admin' AND active=1)
 AND EXISTS (SELECT 1 FROM zones WHERE id='fixture-zone' AND account_id='fixture-account' AND hostname='demo.fixture.invalid' AND environment='simulation' AND enabled=1);
INSERT OR IGNORE INTO audit_trail (id,actor_id,operation,target_id,details_json,created_at,expires_at)
 SELECT 'owner-bootstrap-v1','soc-owner','rbac.owner.provisioned','soc-owner',
 '{"source":"owner-confirmed bootstrap","subjectPinned":true}',
 strftime('%Y-%m-%dT%H:%M:%fZ','now'),strftime('%Y-%m-%dT%H:%M:%fZ','now','+90 days')
 WHERE EXISTS (SELECT 1 FROM users WHERE id='soc-owner' AND access_subject=${sql(subject)} AND email=${sql(email)} AND role='Admin' AND active=1);
`;
}

export function simulationBootstrap(source, bytes) {
  const digest = createHash("sha256").update(bytes).digest("hex");
  return source
    .replaceAll("__EVIDENCE_SHA256__", digest)
    .replaceAll("simulation/cases/fixture/evidence-001.json", "cases/fixture/evidence-001.json");
}

async function prepare() {
  const identityPath = process.argv[2];
  if (!identityPath)
    throw new Error(
      "Supply the protected verified-owner JSON path; never an email or token argument.",
    );
  const identity = JSON.parse(await readFile(identityPath, "utf8"));
  const bootstrap = ownerBootstrap(identity);
  const folder = `${root}.local/console-candidate`;
  await mkdir(folder, { recursive: true, mode: 0o700 });
  await chmod(folder, 0o700);
  const writePrivate = async (name, value) => {
    await writeFile(`${folder}/${name}`, value, { mode: 0o600 });
    await chmod(`${folder}/${name}`, 0o600);
  };
  await writePrivate("control-seed.sql", bootstrap);
  const evidence = await readFile(`${root}simulations/fixtures/evidence-001.json`);
  await writePrivate(
    "simulation-seed.sql",
    simulationBootstrap(
      await readFile(`${root}infrastructure/seeds/simulation.sql`, "utf8"),
      evidence,
    ),
  );
  // Preserve any prepared CSRF secret so re-running preparation does not rotate credentials.
  let csrf;
  try {
    csrf = JSON.parse(await readFile(`${folder}/secrets.json`, "utf8")).SESSION_CSRF_SECRET;
    if (typeof csrf !== "string" || csrf.length < 32)
      throw new Error("Invalid existing CSRF secret");
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
    csrf = randomBytes(32).toString("hex");
  }
  await writePrivate(
    "secrets.json",
    `${JSON.stringify(
      {
        OWNER_EMAIL: identity.intended_owner_email.toLowerCase(),
        OWNER_SUBJECT_SHA256: identity.subject_sha256,
        SESSION_CSRF_SECRET: csrf,
      },
      null,
      2,
    )}\n`,
  );
  const config = JSON.parse(
    await readFile(`${root}apps/api/wrangler.production.review.jsonc`, "utf8"),
  );
  config.main = `${root}apps/api/src/index.ts`;
  config.assets.directory = `${root}apps/console/dist`;
  for (const db of config.d1_databases) db.migrations_dir = `${root}infrastructure/migrations`;
  config.account_id = "00000000000000000000000000000001";
  config.routes = [{ pattern: "soc.d.example.invalid", custom_domain: true }];
  await writePrivate("wrangler.jsonc", `${JSON.stringify(config, null, 2)}\n`);
  console.log(
    "Private console candidate prepared. No Cloudflare calls, migrations, uploads or deployment performed.",
  );
}

if (process.argv[1] === fileURLToPath(import.meta.url)) await prepare();
