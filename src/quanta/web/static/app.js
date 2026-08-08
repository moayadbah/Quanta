/* Quanta demo SPA (ADR-020).
 *
 * Hand-written, no framework, no build step. Three screens driven by one SSE stream.
 *
 * Everything rendered here comes from a repository someone else controls — file paths,
 * module names, error details. So this file never assigns to innerHTML. Text goes in via
 * textContent, which cannot introduce markup. That is the same T5 control the Jinja2
 * report applies with autoescaping, enforced here by construction.
 */

"use strict";

const $ = (id) => document.getElementById(id);
const api = (path, opts) => fetch(`/api/v1${path}`, opts);

const STEP_ORDER = [];
let current = { jobId: null, source: null, cached: false, repo: "" };

/* ── DOM helpers ──────────────────────────────────────────────────────────── */

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

function show(screen) {
  for (const id of ["screen-submit", "screen-pipeline", "screen-result"]) {
    $(id).classList.toggle("hidden", id !== screen);
  }
  window.scrollTo({ top: 0, behavior: "smooth" });
}

/* ── Boot ─────────────────────────────────────────────────────────────────── */

async function boot() {
  wireControls();
  await Promise.all([loadAbout(), loadExamples()]);
}

async function loadAbout() {
  try {
    const about = await (await api("/about")).json();
    const list = $("not-claims");
    clear(list);
    for (const claim of about.does_not_claim) list.appendChild(el("li", null, claim));
    $("footer-version").textContent =
      `Quanta ${about.version} · ruleset ${about.crypto_ruleset_version}`;
  } catch {
    /* The explainer is decoration; its absence must not block an analysis. */
  }
}

async function loadExamples() {
  const container = $("example-list");
  clear(container);
  let examples = [];
  try {
    examples = (await (await api("/examples")).json()).examples;
  } catch {
    return;
  }

  if (!examples.length) {
    container.appendChild(
      el("div", "muted small", "No cached examples are installed. Live analysis still works.")
    );
    return;
  }

  for (const example of examples) {
    const card = el("button", "example ghost");
    card.type = "button";

    const top = el("div", "example-repo", example.repo);
    const badge = el("span", "tag", "cached");
    top.appendChild(document.createTextNode(" "));
    top.appendChild(badge);

    card.appendChild(top);
    card.appendChild(el("div", `example-score ${scoreClass(example.agility_score)}`,
      example.agility_score.toFixed(1)));
    card.appendChild(el("div", "example-blurb", example.blurb));
    card.addEventListener("click", () => replay(example.slug, example.repo));
    container.appendChild(card);
  }
}

function wireControls() {
  $("about-toggle").addEventListener("click", () => $("about").classList.toggle("hidden"));

  $("submit-form").addEventListener("submit", (event) => {
    event.preventDefault();
    startLive($("repo-url").value.trim());
  });

  const reset = () => {
    if (current.source) current.source.close();
    current = { jobId: null, source: null, cached: false, repo: "" };
    show("screen-submit");
  };
  $("cancel-run").addEventListener("click", reset);
  $("new-run").addEventListener("click", reset);

  for (const tab of document.querySelectorAll(".tab")) {
    tab.addEventListener("click", () => {
      for (const other of document.querySelectorAll(".tab")) {
        other.classList.toggle("active", other === tab);
      }
      for (const name of ["deductions", "trace", "report"]) {
        $(`tab-${name}`).classList.toggle("hidden", name !== tab.dataset.tab);
      }
    });
  }
}

/* ── Starting a run ───────────────────────────────────────────────────────── */

function showSubmitError(code, detail) {
  const box = $("submit-error");
  clear(box);
  box.appendChild(el("span", "code", code));
  box.appendChild(document.createTextNode(` — ${detail || "request refused"}`));
  box.classList.remove("hidden");
}

async function startLive(url) {
  if (!url) return;
  $("submit-error").classList.add("hidden");
  const button = document.querySelector("#submit-form .primary");
  button.disabled = true;

  try {
    const response = await api("/analyses", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ repo_url: url }),
    });
    const body = await response.json();

    if (!response.ok) {
      // The server speaks RFC 9457 problem+json with a stable error_code (§5.2.4).
      showSubmitError(body.error_code || `HTTP_${response.status}`, body.detail);
      return;
    }
    beginRun(body.job_id, url.replace(/^https?:\/\/github\.com\//, ""), false);
  } catch (err) {
    showSubmitError("NETWORK", "could not reach the Quanta service");
  } finally {
    button.disabled = false;
  }
}

async function replay(slug, repo) {
  const response = await api(`/examples/${encodeURIComponent(slug)}/replay`, { method: "POST" });
  const body = await response.json();
  if (!response.ok) {
    showSubmitError(body.error_code || "REPLAY_FAILED", body.detail);
    return;
  }
  beginRun(body.job_id, repo, true);
}

function beginRun(jobId, repo, cached) {
  current = { jobId, source: null, cached, repo };

  $("pipeline-repo").textContent = repo;
  const sub = $("pipeline-sub");
  clear(sub);
  sub.appendChild(document.createTextNode(
    cached ? "Replaying a pre-computed run from committed artifacts — no network in use"
           : "Live analysis — cloning at a pinned commit"
  ));

  clear($("steps"));
  STEP_ORDER.length = 0;
  $("progress-bar").style.width = "0%";
  show("screen-pipeline");

  const source = new EventSource(`/api/v1/analyses/${jobId}/events`);
  current.source = source;

  source.addEventListener("plan", (event) => renderPlan(JSON.parse(event.data)));
  source.addEventListener("step", (event) => renderStep(JSON.parse(event.data)));
  source.addEventListener("done", () => { source.close(); showResult(jobId); });

  // The server names its failure event "failed" rather than "error": EventSource already
  // dispatches a built-in "error" for transport problems, and the two would be
  // indistinguishable on this listener.
  source.addEventListener("failed", (event) => {
    source.close();
    const payload = JSON.parse(event.data);
    show("screen-submit");
    showSubmitError(payload.error_code || "INTERNAL", payload.detail);
  });

  source.addEventListener("error", () => {
    // Transport-level only. EventSource reconnects on its own, resuming from
    // Last-Event-ID; give up only once it has genuinely closed.
    if (source.readyState === EventSource.CLOSED) {
      show("screen-submit");
      showSubmitError("CONNECTION_LOST", "the event stream closed before the analysis finished");
    }
  });
}

/* ── Pipeline rendering ───────────────────────────────────────────────────── */

function renderPlan(plan) {
  const list = $("steps");
  clear(list);
  STEP_ORDER.length = 0;

  for (const step of plan.steps) {
    STEP_ORDER.push(step.id);
    list.appendChild(buildStep({ id: step.id, title: step.title, status: "pending" }));
  }
}

const ICONS = { pending: "", running: "*", done: "✓", failed: "!", skipped: "–" };

function buildStep(step) {
  const item = el("li", `step step-${step.status}`);
  item.dataset.stepId = step.id;

  const head = el("button", "step-head");
  head.type = "button";
  head.appendChild(el("span", "step-icon", ICONS[step.status] || ""));

  const label = el("span");
  label.appendChild(el("span", "step-title", step.title));
  if (step.summary) {
    label.appendChild(document.createElement("br"));
    label.appendChild(el("span", "step-summary", step.summary));
  }
  head.appendChild(label);

  const meta = el("span", "step-meta");
  if (step.duration_ms) meta.appendChild(el("span", "step-ms", `${step.duration_ms} ms`));
  if (step.evidence && step.evidence.length) meta.appendChild(el("span", "chev", "▶"));
  head.appendChild(meta);
  item.appendChild(head);

  if (step.evidence && step.evidence.length) {
    const body = el("div", "step-body hidden");
    for (const row of step.evidence) {
      const line = el("div", `ev${row.ok === true ? " ev-ok" : row.ok === false ? " ev-no" : ""}`);
      line.appendChild(el("span", "ev-label", row.label));
      line.appendChild(el("span", "ev-value", row.value));
      body.appendChild(line);
    }
    item.appendChild(body);
    head.addEventListener("click", () => {
      body.classList.toggle("hidden");
      item.classList.toggle("step-open");
    });
  }
  return item;
}

function renderStep(step) {
  for (const list of [$("steps"), $("result-steps")]) {
    const existing = list.querySelector(`[data-step-id="${CSS.escape(step.id)}"]`);
    const fresh = buildStep(step);
    if (existing) list.replaceChild(fresh, existing);
    else if (list === $("steps")) list.appendChild(fresh);
  }

  if (step.status === "done" || step.status === "failed") {
    const index = STEP_ORDER.indexOf(step.id);
    const total = STEP_ORDER.length || 9;
    $("progress-bar").style.width = `${Math.round(((index + 1) / total) * 100)}%`;
  }

  // Auto-expand the running step so a viewer sees evidence without hunting for it.
  if (step.status === "running") {
    const node = $("steps").querySelector(`[data-step-id="${CSS.escape(step.id)}"]`);
    if (node) node.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }
}

/* ── Result rendering ─────────────────────────────────────────────────────── */

function scoreClass(value) {
  if (value >= 70) return "score-high";
  if (value >= 40) return "score-mid";
  return "score-low";
}

function scoreLabel(value) {
  if (value >= 70) return "Agile — a swap is a small, local change";
  if (value >= 40) return "Moderate — some restructuring needed";
  return "Rigid — an algorithm change touches many places";
}

const FORMULAS = {
  call_sites: "1 / (1 + log10(1 + n))",
  isolation_layer: "1 / (1 + minimum node cut)",
  selection_source: "config / (config + literals)",
  propagation_depth: "1 − (ancestors / modules)",
};

const FACTOR_TITLES = {
  call_sites: "Call sites",
  isolation_layer: "Isolation layer",
  selection_source: "Algorithm selection",
  propagation_depth: "Propagation depth",
};

async function showResult(jobId) {
  const [score, trace] = await Promise.all([
    (await api(`/analyses/${jobId}/score`)).json(),
    (await api(`/analyses/${jobId}/trace`)).json(),
  ]);

  $("result-repo").textContent = score.provenance.repo;
  const sub = $("result-sub");
  clear(sub);
  sub.appendChild(document.createTextNode(
    `commit ${score.provenance.commit_sha.slice(0, 12)} · ruleset ${score.provenance.crypto_ruleset_version} · ` +
    `${score.coverage.files_scanned} files scanned` +
    (current.cached ? " · cached replay" : "")
  ));

  $("score-value").textContent = score.agility_score.toFixed(1);
  $("score-value").className = `score-value ${scoreClass(score.agility_score)}`;
  $("score-label").textContent = scoreLabel(score.agility_score);
  $("score-label").className = `score-label ${scoreClass(score.agility_score)}`;

  const rows = $("factor-rows");
  clear(rows);
  // score.json has sorted keys (NFR-03 canonical form), which is alphabetical rather
  // than the order §5.3.3 presents the factors in. Render the documented order.
  const ordered = ["call_sites", "isolation_layer", "selection_source", "propagation_depth"]
    .filter((key) => key in score.factors)
    .map((key) => [key, score.factors[key]]);
  for (const [key, factor] of ordered) {
    const tr = el("tr");
    tr.appendChild(el("td", null, FACTOR_TITLES[key] || key));
    tr.appendChild(el("td", "mono", String(factor.raw)));
    tr.appendChild(el("td", "mono muted small", FORMULAS[key] || ""));
    tr.appendChild(el("td", "num", factor.normalised.toFixed(2)));
    tr.appendChild(el("td", "num", factor.weight.toFixed(2)));
    tr.appendChild(el("td", "num", factor.contribution.toFixed(2)));
    rows.appendChild(tr);
  }

  renderDeductions(score);

  clear($("result-steps"));
  for (const step of trace.steps) $("result-steps").appendChild(buildStep(step));

  $("report-frame").src = `/api/v1/analyses/${jobId}/report`;
  $("dl-report").href = `/api/v1/analyses/${jobId}/report`;
  $("dl-score").href = `/api/v1/analyses/${jobId}/score`;
  $("dl-cdg").href = `/api/v1/analyses/${jobId}/cdg`;
  $("dl-meta").href = `/api/v1/analyses/${jobId}/meta`;

  show("screen-result");
}

function renderDeductions(score) {
  const container = $("deductions");
  clear(container);

  if (!score.deductions.length) {
    container.appendChild(el("p", "muted",
      "No deductions — no cryptographic call sites were detected in this repository."));
  }

  for (const deduction of score.deductions) {
    const box = el("div", "deduction");
    const head = el("div", "deduction-head");
    head.appendChild(el("span", null, FACTOR_TITLES[deduction.factor] || deduction.factor));
    head.appendChild(el("span", "deduction-points", `−${deduction.points.toFixed(2)}`));
    box.appendChild(head);
    box.appendChild(el("div", null, deduction.reason));

    const cites = el("div", "cites");
    for (const citation of deduction.citations) cites.appendChild(el("span", "cite", citation));
    box.appendChild(cites);
    container.appendChild(box);
  }

  const recs = $("recommendations");
  clear(recs);
  if (score.recommendations.length) {
    recs.appendChild(el("h3", null, "What would improve it"));
    for (const rec of score.recommendations) {
      const box = el("div", "rec");
      box.appendChild(el("div", null, rec.action));
      const gain = rec.estimated_score_gain > 0
        ? ` · recovers at most ${rec.estimated_score_gain.toFixed(1)} points`
        : "";
      box.appendChild(el("div", "muted small",
        `Affects ${rec.affected_sites} site${rec.affected_sites === 1 ? "" : "s"}${gain}`));
      recs.appendChild(box);
    }
  }
}

boot();
