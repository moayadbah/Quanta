# ADR-026: Publish a focused web product

Status: accepted by product owner, September 2026.

The owner explicitly changed the goal from a research artifact to a published project.
The benchmark freeze and comparison-engine gates in ADR-024 no longer apply to product
implementation. Existing research tools and historical records remain optional; their
results are not marketed as empirical validation of the product.

The release path is GitHub sign-in, a public Python repository scan, reviewable hash
upgrades, and an explicit draft pull request. Hosting must stay free, with usage limits.
We retain Python/FastAPI and the no-build frontend. The new home page provides an English
and Arabic product workflow, responsive layouts, an honest working sample and an
original Sadu-inspired geometric accent. The prior walkthrough is preserved at
`/guide.html` as educational material.

Supported proposals are deliberately narrow: replace qualified MD5/SHA-1 calls in
`hashlib` and `cryptography` with SHA-256. Aliases are resolved with LibCST metadata;
shadowed names, explicit non-security hashes and unsupported migrations are skipped.
Every proposal states that digest values and lengths change. Users select changes,
review a server-produced diff and acknowledge compatibility before a draft PR is opened.
Syntax is parsed, target tests are never run, and there is no automatic merging.

Source needed for proposals is retained in bounded private artifacts for seven days.
This supersedes the earlier claim that only non-source reports survive cleanup. Full
clones are still deleted. Hosted OAuth uses encrypted tokens and opaque sessions; scan
access is checked per account. No OAuth, database or hosting secret reaches the scanner.

Vercel Functions serve the control plane. Vercel Sandbox provides a disposable microVM
per scan with an external network policy; PostgreSQL replaces local SQLite in hosting.
The database also holds small compressed artifacts to avoid a separate storage account.
Atomic usage reservations and claims bound cost and concurrency. Provider quotas remain
an independent boundary, so the deployment must remain on the free plans.

Integration with the live OAuth application and hosting account is a deployment gate,
not a research gate. The UI exposes actual availability and does not claim a real scan
or PR succeeded when those services are not configured.
