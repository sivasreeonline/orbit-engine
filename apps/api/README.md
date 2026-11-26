# Sky High Coding Judge API

Cloudflare Worker control plane for the coding judge. The API is intentionally
fail-closed until Sky High identity integration and the execution pipeline are
configured.

## Local development

Requirements: Node.js 24.x and npm 11.x.

~~~powershell
cd apps/api
npm install
npm run dev
~~~

The first npm install generates package-lock.json. Commit that lockfile on the
feature branch; after it exists, CI should use npm ci instead of npm install.

Useful checks:

~~~powershell
npm run typecheck
npm test
npx wrangler deploy --dry-run
npm audit --audit-level=high
~~~

## Database migrations

Migrations are ordered SQL files under migrations/. Apply them using a
database-owner/migration connection, never the restricted application role.

PowerShell example (keep the URL in a local environment variable; do not put it
in source control or paste it into chat):

~~~powershell
$env:DATABASE_URL = "<your migration database URL>"
psql $env:DATABASE_URL -v ON_ERROR_STOP=1 -f .\migrations\0001_problem_catalog.sql
psql $env:DATABASE_URL -v ON_ERROR_STOP=1 -f .\migrations\0002_seed_two_sum.sql
~~~

The scripts are transaction-wrapped. The seed uses stable IDs and guards so it
can be re-applied in a development database.

### Least-privilege API database role

Create a dedicated runtime role through the database administration channel and
grant it:

~~~sql
GRANT USAGE ON SCHEMA public TO sky_high_api;
GRANT SELECT ON problems, problem_versions TO sky_high_api;
GRANT SELECT ON public_problem_test_cases TO sky_high_api;
REVOKE ALL ON problem_test_cases FROM sky_high_api;
~~~

The student-facing repository reads the public_problem_test_cases security
barrier view. The view exposes only PUBLIC fixtures. Do not grant the Worker
runtime role direct access to the underlying problem_test_cases table or to
hidden input/expected-output artifacts.

Published problem versions and their test fixtures are immutable. A correction
must create a new version; attempts and source snapshots will pin a version ID.

## Current safety boundaries

- /healthz is a liveness check and does not require database or identity access.
- /readyz checks database connectivity.
- Problem-catalog routes require a real authenticated Sky High principal with
  both user and tenant IDs.
- UnconfiguredAuthenticator intentionally fails closed. Do not replace it with
  mock headers, a hard-coded user, or client-supplied tenant IDs.
- Run and Submit are still connected only to the frontend mock adapter. No
  student source is executed by this Worker.
- The Go runner's UnconfiguredExecutor also fails closed. Real execution
  requires the separately reviewed M0 Linux sandbox proof.
- Judge0 is excluded.
- No live database credentials, Hyperdrive IDs, API tokens or deployment
  secrets belong in this repository.

## Deployment status

wrangler.jsonc currently contains a placeholder Hyperdrive configuration ID.
Provision the actual Hyperdrive configuration and bind it through the Cloudflare
environment before deployment. A successful dry-run is not proof that a live
database or identity provider is connected.
