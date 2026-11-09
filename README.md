# Cloudflare AI SOC

Cloudflare AI SOC is a TypeScript security operations console and Worker runtime. The local workbench lets you replay synthetic incidents, inspect evidence, run investigations, and exercise approvals and rule rollback with a simulated executor.

The source also includes Live Analytics observations, priority filters, a Logpush ingestion Worker, configurable investigation policy, and an approval-based repair flow for an isolated test hostname. Cloud configuration examples use reserved hostnames and placeholder resource IDs. [Deployment configuration](docs/deployment-configuration.md)

## Run locally

Use Node.js 26 or newer and npm 11 or newer.

```sh
npm ci
npm run dev
```

Open the loopback address printed by the server. Sign in with the **Admin fixture**, then open **Simulation & Evaluation** to run the 12 scenarios. The server uses synthetic identities and data. It keeps local state and generated fixture keys under the ignored `.local/` directory.

## Check the project

```sh
npm run check
```

This runs lint, TypeScript checks, offline Worker builds, integration tests and a source credential scan. Tests use local Miniflare storage and need permission to open loopback sockets. GitHub Actions runs the same checks on pushes and pull requests.

| Directory           | Contents                                                           |
| ------------------- | ------------------------------------------------------------------ |
| `apps/console`      | React console for Simulation and Live                              |
| `apps/api`          | Authenticated API, investigation policy and controlled test repair |
| `apps/ingest`       | Logpush and fixture ingestion, retention and recovery              |
| `apps/access-probe` | Cloudflare Access login verification probe                         |
| `packages/shared`   | Schemas and shared policy types                                    |
| `infrastructure`    | Migrations and synthetic seed data                                 |

The [design specification](cloudflare-ai-soc-master-spec.md) describes the original goals and acceptance criteria.
