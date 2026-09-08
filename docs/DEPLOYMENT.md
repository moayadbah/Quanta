# Deploy Quanta on Vercel for free

Use the existing `moayadbah/Quanta` repository. Keep the project on Vercel Hobby and
choose a free PostgreSQL plan. This setup serves the full Python application, not a
static screenshot of the demo.

## Provisioned deployment targets

Continue with these existing resources. Do not create a duplicate project or use
`min-taht`.

| Service | Resource | Free plan |
| --- | --- | --- |
| GitHub | `moayadbah/Quanta`, branch `main` | Public repository |
| Vercel | `quanta` in `moayadbahs-projects` | Hobby |
| Supabase | `quanta` in `The-Underdog` | Free |

Vercel project ID: `prj_D2nwzmDjmr4xJahr2rRbDewqdCiB`.
Vercel team ID: `team_n3QHkd0FXRngDlIy0xpH7ueN`.
Production domain: `https://quanta-moayadbahs-projects.vercel.app`.

Supabase project reference: `sktxismylxomhrpnmult`.
Organization ID: `ntppzxoqbwlkzoxbuwib`. Region: Frankfurt (`eu-central-1`).
The `initialize_quanta_private_storage` migration has installed all ten application
tables in the private `quanta` schema. RLS is enabled on every table; `anon`,
`authenticated`, and `service_role` have no table access. This was verified directly
on September 8, 2026, along with a rolled-back atomic quota update. The security
advisor's informational "RLS Enabled No Policy" notices are expected for this
server-only schema; do not add browser policies to silence them.

Provisioning these resources does not configure the application's runtime secrets.
Complete the connection string, OAuth app and trusted scanner snapshot steps below,
then run the production checks before describing hosted scanning as available.

## Architecture

The FastAPI function handles authentication, private results and PR operations. A
new scan runs in a disposable Vercel Sandbox microVM. The VM can contact GitHub during
acquisition; its external firewall changes to deny-all before parsing. OAuth tokens,
database credentials and Vercel credentials never enter the scanner.

PostgreSQL stores jobs, sessions, quota reservations and compressed artifacts. Nothing
on the function's temporary disk is treated as durable scan storage. At most two hosted
scans run concurrently. A scan has a 180-second microVM deadline and a function budget
of 300 seconds. Output is capped at 4 MB total per scan. New work consumes a quota slot
even if it fails; pinned cache hits reuse existing work without a new compute charge.

The browser starts a durable queued job through `/run`, then polls its status. The
`/run` request stays active while the isolated scan completes; it does not depend on an
untracked background thread. Reopening a queued scan resumes it. An interrupted running
scan expires after 260 seconds rather than spending another quota slot automatically.
Results become inaccessible after seven days; cleanup removes expired database rows.

## One-time setup

1. Import the repository into a **Hobby** Vercel project. Root directory is the repository
   root; framework is FastAPI. `pyproject.toml` selects `api.index:app`. Python is pinned
   to 3.12. Keep the checked-in function duration. Use one stable production domain for
   GitHub sign-in; arbitrary preview domains are not OAuth callback destinations.
2. Use the **Supabase Free `quanta`** project listed above. In **Connect**, choose **Transaction
   pooler** (port 6543) and use its PostgreSQL connection URL, including `sslmode=require`,
   as `QUANTA_CLOUD__DATABASE_URL`. Enter the database password in that URL, with special
   characters URL-encoded. A Supabase project URL or publishable/anon/service-role key
   is not a PostgreSQL connection string. Use Vercel's encrypted environment settings.
   Quanta disables prepared statements for the transaction pooler and creates its tables
   in a private `quanta` schema at startup under a database lock. It revokes Data API role
   grants and enables RLS with no browser policies. Keep `quanta` out of Supabase's exposed
   schemas; the browser accesses data only through Quanta's authenticated API. Connect as
   the schema owner (the project's `postgres` database user for initial setup).
3. Register a GitHub OAuth app for Quanta. Set its homepage to the production URL and its
   callback to exactly `https://quanta-moayadbahs-projects.vercel.app/auth/callback`. Disable wildcard callback
   matching. The application requests `read:user public_repo`; no private-repository
   scope is requested. `public_repo` permits public repository writes and is broader
   than a per-repository GitHub App permission. The privacy page states this clearly.
4. Configure `QUANTA_AUTH__GITHUB_CLIENT_ID`, `QUANTA_AUTH__GITHUB_CLIENT_SECRET`, and
   `QUANTA_AUTH__PUBLIC_URL` in Vercel. Generate a Fernet key locally and set it as
   `QUANTA_AUTH__ENCRYPTION_KEY`. Keep secrets in Vercel's environment settings, never
   the repository or chat. Rotating the encryption key invalidates existing sessions.
5. Create one trusted scanner snapshot from a tested, pushed Quanta commit:

   ```bash
   vercel link
   vercel env pull
   # Supply the documented Vercel SDK credentials in your shell.
   # Either VERCEL_OIDC_TOKEN, or VERCEL_TOKEN + VERCEL_PROJECT_ID + VERCEL_TEAM_ID.
   uv run python scripts/prepare_vercel.py --commit FULL_TESTED_COMMIT_SHA
   ```

   `vercel env pull` writes a file; export its relevant variables in your shell before
   running Python. The builder installs only the pinned Quanta runtime, checks the real
   sample, and snapshots it. Credentials authenticate SDK requests and are not copied
   into the VM. Save the returned snapshot ID as `QUANTA_CLOUD__SANDBOX_SNAPSHOT`.
6. Set `QUANTA_CLOUD__ENABLED=true`, redeploy, then test the production URL. Vercel's SDK
   uses the function's OIDC identity automatically. You do not need to give each visitor
   a Vercel credential. Keep snapshot and function code at the same Quanta version.

Without complete configuration the homepage and sample remain usable. Hosted scans
fail closed. OAuth is unavailable without durable storage; a public deployment never
uses local development's unsigned scan path.

### What the GitHub connections do

Connecting Supabase to GitHub links source-control workflows. It does not supply a
PostgreSQL password to Vercel or register the OAuth app used by Quanta's visitors.
Quanta uses Supabase as its database and handles GitHub OAuth on its own backend so it
can retain the provider permission needed for reviewed draft pull requests. Supabase
Auth, Storage, Edge Functions and paid branching are not required for this setup.

If PostgreSQL was used with a Quanta revision before private-schema support, its tables
are in `public`. Back up and explicitly migrate those Quanta tables into `quanta` before
upgrading that installation. Startup does not move or read unrelated `public` tables.
Local SQLite installations are unchanged.

## Free limits

The defaults are deliberately small: three new scans per user per UTC day and fifty
shared new scans per calendar month. Hosted repositories are limited to 10 MB GitHub
reported size, 1,000 Python files, and 20 MB of accepted source. Snapshot setup consumes
some hosting usage too, so reuse one snapshot and delete superseded snapshots after
verification. With one vCPU and a 180-second ceiling, fifty full-length scans consume at
most 2.5 CPU-hours, plus setup and service overhead. Other applications in the same
Vercel account may also consume its allowance.

Vercel documents five included Sandbox CPU-hours per month on Hobby and pauses creation
when its quota is exhausted. This is why the deployment must stay on Hobby. On paid
plans, usage can be billed. Keep the database on its free plan as well. Application
limits do not replace the providers' plan and account settings.

Supabase Free allows 500 MB of database data and enters read-only mode above that limit.
The app's 4 MB output cap and 50 monthly scans bound new raw result data to 200 MB per
month before compression; seven-day retention reduces live result storage. Database
metadata, indexes, dead tuples and other projects' data still count. Keep the project on
Free, leave autovacuum enabled, and check Supabase's database-size report before opening
the service widely. Free projects can pause after inactivity and may need resuming.

## Before sharing the URL

- Confirm `/auth/session` reports `required: true`, `configured: true` and no user token.
- Confirm `/api/v1/workspace` reports `hosted: true` and `scan_available: true`.
- Sign in with GitHub, scan a small public Python repository, then reload during progress.
- Select one supported change, inspect the diff, acknowledge its compatibility impact,
  and open a draft PR in a repository you control. Verify only the selected source changed.
- Retry the same PR operation and confirm the same PR is returned.
- Check the production layout on desktop and mobile, including Arabic and keyboard navigation.

These live checks require the real OAuth app, database and Vercel project. Mocked
integration tests cannot establish that those account settings are correct.

## Operational notes

Do not add runtime secrets to the trusted snapshot or scanner settings. Do not install
or execute scanned repository dependencies or tests. A user should run their repository
CI after reviewing the draft PR. A moved default branch, changed source blob, symlink,
unrelated fork or edited Quanta branch is refused, never force-pushed.

For each release, create the new scanner snapshot from that release's tested commit,
update the snapshot environment value, deploy the matching function revision and remove
the superseded snapshot after checking the deployment. Do not let snapshots accumulate.

References checked September 2026:
[FastAPI](https://vercel.com/docs/frameworks/backend/fastapi),
[Sandbox Python SDK](https://vercel.com/docs/sandbox/python-sdk-reference),
[Sandbox pricing](https://vercel.com/docs/sandbox/pricing),
[Sandbox authentication](https://vercel.com/docs/sandbox/concepts/authentication),
[Supabase connections](https://supabase.com/docs/guides/database/connecting-to-postgres),
[Supabase Data API security](https://supabase.com/docs/guides/api/securing-your-api),
[Supabase database limits](https://supabase.com/docs/guides/platform/database-size),
[GitHub OAuth](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps).
