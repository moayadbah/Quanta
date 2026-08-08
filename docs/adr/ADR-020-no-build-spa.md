# ADR-020 — Hand-written SPA instead of a Next.js static export

**Status:** Accepted
**Date:** 2026-08-08
**Amends §3.3 and ADR-011 of the Technical Documentation.**

## Context

§3.3 selects Next.js with `output: 'export'`, built into `src/quanta/web/static/` and
served by FastAPI. The reasoning given is that "modern web frontend" is a stated
requirement and Next.js is the recognised default, and that static export avoids a Node
runtime in production.

The requirement the frontend actually has to meet is three screens — submit, progress,
report — plus a pipeline view. §3.3 says as much: *"Three screens: submit, progress,
report. That is the whole requirement."*

Two facts weigh against Next.js for this build:

1. **The artifact is a demonstration.** It will be run on a laptop in front of an
   audience. A build step is a thing that can fail at that moment: a missing
   `node_modules`, a stale export, a Node version drift. `quanta serve` with committed
   static files has no such failure mode.
2. **Static export already forfeits most of what Next.js provides.** §3.3 correctly notes
   SSR and ISR "would buy nothing" here. What remains is routing and JSX for three
   screens, against the cost of a package manager, a lockfile, a toolchain and a build
   output that must be regenerated whenever the UI changes.

## Decision

Serve a hand-written single-page app from `src/quanta/web/static/` — `index.html`,
`app.js`, `app.css`. No Node, no build step, no `node_modules`. The directory is
**committed source**, not a build output, and its entry was removed from `.gitignore`.

JavaScript and CSS are **separate files rather than inline**, specifically so the
Content-Security-Policy can omit `'unsafe-inline'` — an inline-script allowance forfeits
most of what CSP provides. `tests/security/test_web_headers.py` asserts both the served
policy and the absence of inline handlers in the source.

## Consequences

- The demo starts with one command and cannot fail to build.
- "Next.js is the recognised default" is no longer available as a talking point. The
  frontend is defensible on its own terms — three screens, no framework needed — but a
  reviewer expecting the documented stack should be pointed at this ADR.
- No component model. If the UI grows much past the current four views, this becomes the
  wrong trade and the revisit trigger applies.
- Browser support is whatever the hand-written code targets; it uses `EventSource`,
  `fetch` and standard DOM APIs, all long-stable.

## Revisit trigger

The frontend grows beyond roughly half a dozen views, needs client-side routing, or gains
a second developer working on it concurrently — at which point a component framework earns
its cost, and §3.3's original choice should be restored.
