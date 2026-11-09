# Deployment configuration

Use the `*.review.jsonc` files as offline build examples. The example domain is `d.example.invalid`. The application validates the console origin, Access issuer and audience, zone ID and ingestion bindings against matching values in source, migrations and configuration.

For your own installation, prepare private configuration for the target environment. Review and update the matching allowlists and migration constraints together with your Worker bindings. Provision separate control, simulation and live D1 databases, private R2 buckets, and separate ingestion queues. Configure Access and set the owner email, owner subject fingerprint and session CSRF secret through Worker secrets. Use a scoped read credential for the Analytics collector. Keep real values and generated deployment artifacts in ignored local storage.

The example repair profile starts disabled. Its scope is a separate test hostname, an exact test path and a single source IPv4. Enable a controlled test only after checking that scope, the Cloudflare rule target and the rollback path. The fixed R2 cleanup allowlist is empty in this snapshot. Prepare and review an explicit allowlist for your environment if you use the cleanup Worker.

The default local commands run without a Cloudflare account. GitHub Actions uses offline builds and simulated data.
