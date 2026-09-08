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
Public production domain: `https://quanta-gilt-mu.vercel.app`.
The additional `quanta-moayadbahs-projects.vercel.app` alias requires Vercel sign-in;
use the public production domain for visitors and OAuth callbacks.

Supabase project reference: `sktxismylxomhrpnmult`.
Organization ID: `ntppzxoqbwlkzoxbuwib`. Region: Frankfurt (`eu-central-1`).
The `initialize_quanta_private_storage` migration has installed all ten application
tables in the private `quanta` schema. RLS is enabled on every table; `anon`,
`authenticated`, and `service_role` have no table access. This was verified directly
on September 8, 2026, along with a rolled-back atomic quota update. The security
advisor's informational "RLS Enabled No Policy" notices are expected for this
server-only schema; do not add browser policies to silence them.

The GitHub OAuth application **Quanta** is registered under `moayadbah`, application
ID `3844194`, with the public production homepage and the exact `/auth/callback`
redirect. Wildcard matching and device flow are disabled.

The production database connection, GitHub OAuth flow, isolated scans and reviewed
draft pull requests are operational. The OAuth secret, encryption key and database
URL are stored as production-only Vercel Secrets. The existing Vercel project is now
connected to this GitHub repository's `main` branch.

### Verified release and acceptance checks

Runtime/scanner release: `8bee37bd3e75a3ba61f5d726d84e4a21f26c5e77`.
Production deployment: `dpl_fCaxn3v7mCUi11K29wRQ3N2wm5qQ`.
Trusted snapshot: `snap_VbtCFKMhw5SwE8X8pbXHns7d0Bne`.
Retained, stopped builder: `lavender-massive-hoverfly-Msqw56`.
Later documentation-only commits can deploy the same runtime without rebuilding this
snapshot; rebuild it when scanner/runtime code or its pinned dependencies change.

Verified on September 8, 2026:

- `/auth/session` reports `required: true` and `configured: true`; real GitHub sign-in
  returns to the workspace as `@moayadbah`, with the session persisted in PostgreSQL.
- `/api/v1/workspace` reports `hosted: true` and `scan_available: true`.
- Scan `9c9dedcd-f72c-4fe2-a8f4-0a897af21f65` analyzed `moayadbah/Quanta` at the release
  commit: 132 Python files, 44 cryptographic call sites and one reviewable change.
  Reloading during execution recovered the same job. The database records one attempt,
  five durable artifacts and one scan quota charge (2 daily and 49 monthly scans left).
- [Draft PR #5](https://github.com/moayadbah/Quanta/pull/5) was created through the live
  application after reviewing the exact diff and acknowledging compatibility impact.
  GitHub confirms one changed file and one SHA-1-to-SHA-256 replacement. Retrying the same
  reviewed operation returned PR #5. It is labeled **do not merge** because the selected
  file is an intentionally weak test fixture used for this acceptance check.
- Production desktop layout and keyboard review focus/Escape behavior passed. The same
  application assets were checked in a preview with a 375-pixel content viewport,
  including English, Arabic RTL, selection and the review dialog; neither the page nor
  dialog had horizontal overflow. Code diffs retain their own horizontal scrolling.
- [Release CI](https://github.com/moayadbah/Quanta/actions/runs/34210093901) passed.
  No production HTTP 5xx logs were recorded during the live checks. The database occupied
  about 11.1 MB after acceptance; the security advisor reports only the expected ten
  informational RLS-without-policy notices for the private schema.

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
   the dedicated schema owner `quanta_app`, using pooler username
   `quanta_app.sktxismylxomhrpnmult`. This login owns only Quanta's application schema
   and tables, has database `CONNECT` and `CREATE` privileges for startup, and has no
   superuser, role-management, database-creation or global RLS-bypass privilege.
3. Use the registered GitHub OAuth app for Quanta listed above. Its homepage must be the
   public production URL and its callback exactly `https://quanta-gilt-mu.vercel.app/auth/callback`.
   Disable wildcard callback
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
   running Python. The builder verifies the checkout SHA, installs only the pinned Quanta
   runtime into the sandbox's root `.venv`, checks the real sample, and snapshots it.
   Current Sandbox images place Git checkouts in a repository-named child directory;
   the script handles this separately from the runtime working directory. Credentials
   authenticate SDK requests and are not copied into the VM. Save the returned snapshot
   ID as `QUANTA_CLOUD__SANDBOX_SNAPSHOT` and retain the printed builder sandbox name.
   The builder is stopped after snapshot creation. Do not destroy it while its snapshot
   is deployed: destroying a sandbox also removes its snapshots.
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
update the snapshot environment value, deploy the matching function revision and destroy
the superseded builder after checking the deployment. This also removes its snapshots.
Do not let stopped builders and snapshots accumulate.

References checked September 2026:
[FastAPI](https://vercel.com/docs/frameworks/backend/fastapi),
[Sandbox Python SDK](https://vercel.com/docs/sandbox/python-sdk-reference),
[Sandbox pricing](https://vercel.com/docs/sandbox/pricing),
[Sandbox authentication](https://vercel.com/docs/sandbox/concepts/authentication),
[Supabase connections](https://supabase.com/docs/guides/database/connecting-to-postgres),
[Supabase Data API security](https://supabase.com/docs/guides/api/securing-your-api),
[Supabase database limits](https://supabase.com/docs/guides/platform/database-size),
[GitHub OAuth](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps).
