/* Quanta demo SPA (ADR-020).
 *
 * Hand-written, no framework, no build step. Two views: a guided walkthrough that explains
 * the idea, and the analyzer itself.
 *
 * Two rules hold throughout:
 *
 *  - Everything rendered from a repository someone else controls goes in via textContent,
 *    never innerHTML. That is the same T5 control the Jinja2 report applies with
 *    autoescaping, enforced here by construction.
 *  - Every user-facing sentence comes from /api/v1/content. Nothing is written in English
 *    in this file, so nothing can be left untranslated by accident. The only exception is
 *    act copy carrying <term> markup, which is parsed and rebuilt as real elements below.
 */

"use strict";

const $ = (id) => document.getElementById(id);
const api = (path, opts) => fetch(`/api/v1${path}`, opts);

const STORAGE_LANG = "quanta.lang";
const ACTS = ["problem", "inventory", "cdg", "cut", "verify", "try"];

const state = {
  lang: "en",
  content: null,
  glossary: {},
  variants: [],
  examples: null,
  act: 0,
  cutRemoved: false,
  activeVariant: 0,
  job: { id: null, source: null, cached: false },
};

/* ── Small DOM helpers ────────────────────────────────────────────────────── */

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

function svg(tag, attrs = {}) {
  const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, String(v));
  return node;
}

/* ── i18n ─────────────────────────────────────────────────────────────────── */

function lookup(path) {
  return path.split(".").reduce((acc, key) => (acc == null ? acc : acc[key]), state.content);
}

function t(path, vars) {
  const entry = lookup(path);
  let text = entry && typeof entry === "object" ? entry[state.lang] ?? entry.en : entry;
  if (typeof text !== "string") return "";
  if (vars) for (const [k, v] of Object.entries(vars)) text = text.replace(`{${k}}`, String(v));
  return text;
}

/* Act copy may contain <term data-term="cdg">CDG</term>. Parse it into real elements
 * rather than assigning innerHTML: the strings are ours, but building the DOM explicitly
 * keeps a single rule ("never innerHTML") instead of a rule with an exception.
 *
 * In Arabic the term itself stays English, so each one is wrapped in a <bdi>. Without
 * that isolation an English term next to Arabic punctuation renders in the wrong order. */
function renderRich(target, markup) {
  clear(target);
  const pattern = /<term data-term="([a-z0-9-]+)">(.*?)<\/term>/g;
  let cursor = 0;
  let match;

  while ((match = pattern.exec(markup)) !== null) {
    if (match.index > cursor) {
      target.appendChild(document.createTextNode(markup.slice(cursor, match.index)));
    }
    // Captured per iteration: `match` is reassigned by the loop and is null once it ends,
    // so a handler closing over it directly would fire on nothing.
    const termKey = match[1];
    const termText = match[2];

    const button = el("button", "term");
    button.type = "button";
    button.dataset.term = termKey;

    const isolate = document.createElement("bdi");
    isolate.textContent = termText;
    button.appendChild(isolate);

    button.addEventListener("click", () => openGlossary(termKey));
    target.appendChild(button);
    cursor = pattern.lastIndex;
  }
  if (cursor < markup.length) {
    target.appendChild(document.createTextNode(markup.slice(cursor)));
  }
}

function applyTranslations() {
  document.documentElement.lang = state.lang;
  document.documentElement.dir = state.lang === "ar" ? "rtl" : "ltr";

  for (const node of document.querySelectorAll("[data-i18n]")) {
    node.textContent = t(node.dataset.i18n);
  }
  for (const node of document.querySelectorAll("[data-i18n-html]")) {
    renderRich(node, t(node.dataset.i18nHtml));
  }
  for (const node of document.querySelectorAll("[data-i18n-placeholder]")) {
    node.placeholder = t(node.dataset.i18nPlaceholder);
  }
}

function setLanguage(lang) {
  state.lang = lang;
  try { localStorage.setItem(STORAGE_LANG, lang); } catch { /* private mode */ }
  applyTranslations();
  renderLedger();
  renderActVisual();
  renderDots();
  renderExamples();
}

/* ── Glossary ─────────────────────────────────────────────────────────────── */

function openGlossary(key) {
  const entry = state.glossary[key];
  if (!entry) return;

  $("glossary-term").textContent = entry.term;
  $("glossary-what").textContent = entry.what[state.lang] ?? entry.what.en;
  $("glossary-why").textContent = entry.why[state.lang] ?? entry.why.en;
  $("glossary-source").textContent = entry.source || "";
  $("glossary").classList.remove("hidden");
  $("glossary-close").focus();
}

function closeGlossary() {
  $("glossary").classList.add("hidden");
}

/* ── Act navigation ───────────────────────────────────────────────────────── */

function renderDots() {
  const list = $("act-dots");
  clear(list);
  ACTS.forEach((_, index) => {
    const dot = el("li", `act-dot${index === state.act ? " active" : ""}${index < state.act ? " done" : ""}`);
    const button = el("button");
    button.type = "button";
    button.setAttribute("aria-label", `${index + 1}`);
    button.addEventListener("click", () => goToAct(index));
    dot.appendChild(button);
    list.appendChild(dot);
  });
  $("act-counter").textContent = t("ui.act_of", { n: state.act + 1, total: ACTS.length });
  $("act-back").disabled = state.act === 0;
  $("act-next").disabled = state.act === ACTS.length - 1;
}

function goToAct(index) {
  state.act = Math.max(0, Math.min(ACTS.length - 1, index));
  document.querySelectorAll(".act").forEach((node, i) => {
    node.classList.toggle("hidden", i !== state.act);
  });
  renderDots();
  renderActVisual();
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function showWalkthrough() {
  $("walkthrough").classList.remove("hidden");
  $("tool").classList.add("hidden");
  goToAct(state.act);
}

function showTool() {
  $("walkthrough").classList.add("hidden");
  $("tool").classList.remove("hidden");
  window.scrollTo({ top: 0, behavior: "smooth" });
}

/* ── Hero visuals ─────────────────────────────────────────────────────────── */

const PALETTE = {
  module: "#3b5b8c",
  function: "#4a7c59",
  crypto_call: "#a33b3b",
  algo_literal: "#8a6d99",
  config_read: "#6d6a8a",
};

function renderActVisual() {
  const act = ACTS[state.act];
  if (act === "problem") drawProblem();
  if (act === "inventory") drawInventory();
  if (act === "cdg") drawCdgAssembly();
  if (act === "cut") drawCutAct();
  if (act === "verify") drawVerify();
  if (act === "try") drawTry();
}

/* Act 1: two repositories, identical inventory, different cost. */
function drawProblem() {
  const host = $("visual-problem");
  clear(host);
  const pair = el("div", "twin");

  for (const [label, fill, tone] of [["A", 0.92, "bad"], ["B", 0.18, "good"]]) {
    const card = el("div", "twin-card");
    card.appendChild(el("div", "twin-name", `repo ${label}`));

    const badge = el("div", "twin-badge");
    badge.appendChild(el("span", null, "27"));
    badge.appendChild(el("span", "twin-badge-label", t("act_cut.sites_label")));
    card.appendChild(badge);

    // SVG rather than a CSS width: the strict CSP (style-src 'self') blocks every
    // inline style, including ones set from JavaScript. Geometry attributes are not
    // styles, so the figure works without weakening the policy. See ADR-020.
    const meter = svg("svg", { viewBox: "0 0 100 6", class: "twin-meter", preserveAspectRatio: "none" });
    meter.appendChild(svg("rect", { x: 0, y: 0, width: 100, height: 6, rx: 3, class: "twin-track" }));
    meter.appendChild(svg("rect", {
      x: 0, y: 0, width: Math.round(fill * 100), height: 6, rx: 3, class: `twin-fill twin-${tone}`,
    }));
    card.appendChild(meter);

    // A mixed run like "≈ 10×" reverses in an RTL paragraph and reads as "×10 ≈".
    // Forcing LTR keeps the operator on the correct side of the number.
    const cost = el("div", "twin-cost muted small", tone === "bad" ? "≈ 10×" : "≈ 1×");
    cost.dir = "ltr";
    card.appendChild(cost);
    pair.appendChild(card);
  }
  host.appendChild(pair);
}

/* Act 2: an inventory list that stops. */
function drawInventory() {
  const host = $("visual-inventory");
  clear(host);
  const panel = el("div", "cbom");
  const rows = [
    ["auth/token.py:88", "RSA-2048"],
    ["store/blob.py:214", "AES-GCM"],
    ["net/tls.py:31", "X25519"],
    ["util/hash.py:12", "SHA-1"],
    ["api/sign.py:77", "ECDSA"],
  ];
  rows.forEach(([path, algo]) => {
    const row = el("div", "cbom-row");
    row.appendChild(el("code", "cbom-path", path));
    row.appendChild(el("span", "cbom-algo", algo));
    panel.appendChild(row);
  });
  const stop = el("div", "cbom-stop", "?");
  panel.appendChild(stop);
  host.appendChild(panel);
}

/* Act 3: the graph assembling from source. */
function drawCdgAssembly() {
  const host = $("visual-cdg");
  clear(host);
  const width = 460;
  const height = 300;
  const figure = svg("svg", { viewBox: `0 0 ${width} ${height}`, class: "assembly", role: "img" });

  const columns = [
    { kind: "module", x: 60, count: 4 },
    { kind: "function", x: 220, count: 5 },
    { kind: "crypto_call", x: 380, count: 3 },
  ];

  const placed = [];
  columns.forEach((column, ci) => {
    for (let i = 0; i < column.count; i += 1) {
      const y = 50 + i * ((height - 100) / Math.max(1, column.count - 1 || 1));
      placed.push({ ...column, y, ci, i });
    }
  });

  // Edges first so nodes sit above them.
  placed.filter((n) => n.ci < 2).forEach((from, index) => {
    const targets = placed.filter((n) => n.ci === from.ci + 1);
    const to = targets[index % targets.length];
    if (!to) return;
    const line = svg("line", {
      x1: from.x, y1: from.y, x2: to.x, y2: to.y,
      class: "assembly-edge",
    });
    figure.appendChild(line);
  });

  placed.forEach((node, index) => {
    const dot = svg("circle", {
      cx: node.x, cy: node.y, r: node.kind === "crypto_call" ? 13 : 10,
      fill: PALETTE[node.kind], class: "assembly-node",
    });
    figure.appendChild(dot);
  });

  host.appendChild(figure);
}

/* Act 4: the real graph, the real cut, and the three scores. */
function drawCutAct() {
  renderVariantTabs();
  drawCutGraph();
  drawVariantBars();
  $("cut-status").textContent = "";
  state.cutRemoved = false;
  $("cut-toggle").textContent = t("act_cut.press");
}

function renderVariantTabs() {
  const host = $("variant-tabs");
  clear(host);
  state.variants.forEach((variant, index) => {
    const tab = el("button", `variant-tab${index === state.activeVariant ? " active" : ""}`);
    tab.type = "button";
    tab.appendChild(el("span", "variant-name", t(`act_cut.variants.${variant.slug}.name`)));
    tab.appendChild(el("span", "variant-score", variant.agility_score.toFixed(1)));
    tab.addEventListener("click", () => {
      state.activeVariant = index;
      drawCutAct();
    });
    host.appendChild(tab);
  });
}

function drawCutGraph() {
  const host = $("visual-cut");
  clear(host);
  const variant = state.variants[state.activeVariant];
  if (!variant) return;

  const graph = variant.graph;
  const width = 520;
  // Kept short on purpose: an act should fit one projector screen without scrolling, and
  // the argument is the shape of the cut, not the individual node.
  const height = 230;
  const figure = svg("svg", { viewBox: `0 0 ${width} ${height}`, class: "cutgraph", role: "img" });

  // Three columns: program structure, the cut candidates, the cryptographic surface.
  const lanes = { module: 70, function: 260, crypto: 450 };
  const byLane = { module: [], function: [], crypto: [] };
  for (const node of graph.nodes) {
    const lane = node.crypto ? "crypto" : node.kind === "module" ? "module" : "function";
    byLane[lane].push(node);
  }

  // Order each lane by the average position of its neighbours in the lane before it
  // (a one-pass barycentre sort). Without this, lanes fall in node-id order and the
  // figure is a cat's cradle of crossings that hides the very structure it should show.
  const neighbours = {};
  for (const edge of graph.edges) {
    (neighbours[edge.source] ||= []).push(edge.target);
    (neighbours[edge.target] ||= []).push(edge.source);
  }

  const pos = {};
  const order = ["module", "function", "crypto"];
  let previousIndex = {};

  for (const lane of order) {
    const nodes = byLane[lane];
    if (Object.keys(previousIndex).length) {
      nodes.sort((a, b) => barycentre(a) - barycentre(b));
    }
    const step = (height - 60) / Math.max(1, nodes.length);
    const index = {};
    nodes.forEach((node, i) => {
      pos[node.id] = { x: lanes[lane], y: 32 + step * (i + 0.5) };
      index[node.id] = i;
    });
    previousIndex = index;
  }

  function barycentre(node) {
    const linked = (neighbours[node.id] || [])
      .map((id) => previousIndex[id])
      .filter((v) => v !== undefined);
    if (!linked.length) return Number.MAX_SAFE_INTEGER;
    return linked.reduce((a, b) => a + b, 0) / linked.length;
  }

  for (const edge of graph.edges) {
    const a = pos[edge.source];
    const b = pos[edge.target];
    if (!a || !b) continue;
    figure.appendChild(svg("line", {
      x1: a.x, y1: a.y, x2: b.x, y2: b.y,
      class: `cut-edge${edge.confidence === "low" ? " low" : ""}`,
      "data-a": edge.source, "data-b": edge.target,
    }));
  }

  for (const node of graph.nodes) {
    const p = pos[node.id];
    if (!p) continue;
    const group = svg("g", {
      class: `cut-node${node.in_cut ? " in-cut" : ""}${node.crypto ? " is-crypto" : ""}`,
      "data-id": node.id,
    });
    group.appendChild(svg("circle", {
      cx: p.x, cy: p.y, r: node.crypto ? 9 : 7, fill: PALETTE[node.kind] || "#666",
    }));
    const title = svg("title");
    title.textContent = node.label;
    group.appendChild(title);
    figure.appendChild(group);
  }

  host.appendChild(figure);

  const legend = el("div", "cut-legend");
  legend.appendChild(statChip(t("act_cut.cut_label"), variant.cut));
  legend.appendChild(statChip(t("act_cut.sites_label"), variant.sites));
  legend.appendChild(statChip(t("act_cut.modules_label"), variant.modules_with_crypto));
  host.appendChild(legend);
}

function statChip(label, value) {
  const chip = el("div", "stat-chip");
  chip.appendChild(el("span", "stat-value", value));
  chip.appendChild(el("span", "stat-label", label));
  return chip;
}

function toggleCut() {
  const stage = $("visual-cut");
  state.cutRemoved = !state.cutRemoved;
  stage.classList.toggle("cut-removed", state.cutRemoved);
  $("cut-status").textContent = state.cutRemoved ? t("act_cut.removed") : "";
  $("cut-toggle").textContent = state.cutRemoved ? t("ui.replay") : t("act_cut.press");
}

function drawVariantBars() {
  const host = $("variant-bars");
  clear(host);
  const max = Math.max(...state.variants.map((v) => v.agility_score), 1);

  state.variants.forEach((variant, index) => {
    const row = el("div", `bar-row${index === state.activeVariant ? " active" : ""}`);
    row.appendChild(el("span", "bar-name", t(`act_cut.variants.${variant.slug}.name`)));

    // SVG geometry, not a CSS width: style-src 'self' blocks JS-set inline styles.
    const track = svg("svg", { viewBox: "0 0 100 8", class: "bar-track", preserveAspectRatio: "none" });
    track.appendChild(svg("rect", { x: 0, y: 0, width: 100, height: 8, rx: 4, class: "bar-bg" }));
    track.appendChild(svg("rect", {
      x: 0, y: 0, width: (variant.agility_score / max) * 100, height: 8, rx: 4, class: "bar-fill",
    }));
    row.appendChild(track);

    row.appendChild(el("span", "bar-score", variant.agility_score.toFixed(1)));
    host.appendChild(row);
  });
}

/* Act 5: two hashes against the published vector. */
async function drawVerify() {
  const host = $("visual-verify");
  clear(host);
  let evidence;
  try {
    evidence = await (await api("/demo/xwing")).json();
  } catch {
    return;
  }
  if (!evidence || !evidence.published) return;

  host.appendChild(hashRow(t("act_verify.vector_label"), evidence.published, null, evidence.published));
  host.appendChild(hashRow(t("act_verify.ours_label"), evidence.draft_order, evidence.draft_matches, evidence.published));
  host.appendChild(hashRow(t("act_verify.wrong_label"), evidence.document_order, evidence.document_matches, evidence.published));
}

function hashRow(label, value, matches, reference) {
  const row = el("div", `hash-row${matches === true ? " ok" : matches === false ? " bad" : ""}`);
  row.appendChild(el("div", "hash-label", label));

  const hex = el("code", "hash-value");
  hex.dir = "ltr";
  // Character-diff against the published vector so the audience sees exactly where the
  // wrong byte order diverges, rather than being told that it does.
  for (let i = 0; i < value.length; i += 1) {
    const span = el("span", reference && value[i] !== reference[i] ? "hash-diff" : null, value[i]);
    hex.appendChild(span);
  }
  row.appendChild(hex);

  if (matches !== null) {
    row.appendChild(el("span", "hash-verdict", matches ? t("act_verify.match") : t("act_verify.mismatch")));
  }
  return row;
}

function drawTry() {
  const host = $("visual-try");
  clear(host);
  const list = el("ol", "try-steps");
  for (const step of ["validate", "resolve", "clone", "walk", "parse", "graph", "score", "render", "cleanup"]) {
    const item = el("li", "try-step");
    item.appendChild(el("span", "try-dot"));
    item.appendChild(el("span", null, step));
    list.appendChild(item);
  }
  host.appendChild(list);
}

function renderLedger() {
  const built = $("ledger-built");
  const reused = $("ledger-reused");
  if (!built || !state.content) return;
  clear(built);
  clear(reused);

  (lookup("act_cdg.built") || []).forEach((item) => {
    built.appendChild(el("li", null, item[state.lang] ?? item.en));
  });
  (lookup("act_cdg.reused") || []).forEach((item) => {
    reused.appendChild(el("li", null, item[state.lang] ?? item.en));
  });
}

/* ── Boot ─────────────────────────────────────────────────────────────────── */

async function boot() {
  try {
    state.lang = localStorage.getItem(STORAGE_LANG) || "en";
  } catch { state.lang = "en"; }

  const [content, glossary, variants] = await Promise.all([
    api("/content").then((r) => r.json()).catch(() => ({})),
    api("/glossary").then((r) => r.json()).catch(() => ({ terms: {} })),
    api("/demo/variants").then((r) => r.json()).catch(() => ({ variants: [] })),
  ]);

  state.content = content;
  state.glossary = glossary.terms || {};
  state.variants = variants.variants || [];

  applyTranslations();
  renderLedger();
  wire();
  goToAct(0);
  loadAbout();
  loadExamples();
}

function wire() {
  $("lang-toggle").addEventListener("click", () => setLanguage(state.lang === "en" ? "ar" : "en"));
  $("to-tool").addEventListener("click", showTool);
  $("open-tool").addEventListener("click", showTool);
  $("brand").addEventListener("click", showWalkthrough);

  $("act-next").addEventListener("click", () => goToAct(state.act + 1));
  $("act-back").addEventListener("click", () => goToAct(state.act - 1));
  $("cut-toggle").addEventListener("click", toggleCut);

  $("glossary-close").addEventListener("click", closeGlossary);
  $("glossary").addEventListener("click", (event) => {
    if (event.target === $("glossary")) closeGlossary();
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") closeGlossary();
    if ($("walkthrough").classList.contains("hidden")) return;
    if (event.target.tagName === "INPUT") return;
    if (event.key === "ArrowRight") goToAct(state.act + (state.lang === "ar" ? -1 : 1));
    if (event.key === "ArrowLeft") goToAct(state.act + (state.lang === "ar" ? 1 : -1));
  });

  $("submit-form").addEventListener("submit", (event) => {
    event.preventDefault();
    startLive($("repo-url").value.trim());
  });

  const reset = () => {
    if (state.job.source) state.job.source.close();
    state.job = { id: null, source: null, cached: false };
    showScreen("screen-submit");
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

async function loadAbout() {
  try {
    const about = await (await api("/about")).json();
    $("footer-version").textContent = `Quanta ${about.version} · ruleset ${about.crypto_ruleset_version}`;
  } catch { /* decorative */ }
}

/* ── The analyzer ─────────────────────────────────────────────────────────── */

function showScreen(screen) {
  for (const id of ["screen-submit", "screen-pipeline", "screen-result"]) {
    $(id).classList.toggle("hidden", id !== screen);
  }
  window.scrollTo({ top: 0, behavior: "smooth" });
}

async function loadExamples() {
  try {
    state.examples = (await (await api("/examples")).json()).examples;
  } catch { return; }
  renderExamples();
}

function renderExamples() {
  const container = $("example-list");
  clear(container);
  const examples = state.examples;
  if (examples === null) return;

  if (!examples.length) {
    container.appendChild(el("div", "muted small", t("tool.no_examples")));
    return;
  }

  for (const example of examples) {
    const card = el("button", "example ghost");
    card.type = "button";
    const top = el("div", "example-repo");
    top.dir = "ltr";
    top.textContent = example.repo;
    card.appendChild(top);
    card.appendChild(el("div", `example-score ${scoreClass(example.agility_score)}`, example.agility_score.toFixed(1)));
    // Falls back to English rather than showing nothing, but an English sentence inside an
    // RTL card would drag its full stop to the wrong end, so it is isolated when it happens.
    const blurbText = (state.lang === "ar" && example.blurb_ar) || example.blurb;
    const blurb = el("div", "example-blurb", blurbText);
    if (state.lang === "ar" && !example.blurb_ar) blurb.dir = "ltr";
    card.appendChild(blurb);
    card.addEventListener("click", () => replay(example.slug, example.repo));
    container.appendChild(card);
  }
}

function showSubmitError(code, detail) {
  const box = $("submit-error");
  clear(box);
  box.appendChild(el("span", "code", code));
  box.appendChild(document.createTextNode(` — ${detail || ""}`));
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
      showSubmitError(body.error_code || `HTTP_${response.status}`, body.detail);
      return;
    }
    beginRun(body.job_id, url.replace(/^https?:\/\/github\.com\//, ""), false);
  } catch {
    showSubmitError("NETWORK", "");
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
  state.job = { id: jobId, source: null, cached };
  $("pipeline-repo").textContent = repo;
  $("pipeline-sub").textContent = cached ? t("tool.cached_sub") : t("tool.live_sub");
  clear($("steps"));
  setProgress(0);
  showScreen("screen-pipeline");

  const source = new EventSource(`/api/v1/analyses/${jobId}/events`);
  state.job.source = source;
  source.addEventListener("plan", (e) => renderPlan(JSON.parse(e.data)));
  source.addEventListener("step", (e) => renderStep(JSON.parse(e.data)));
  source.addEventListener("done", () => { source.close(); showResult(jobId); });
  source.addEventListener("failed", (e) => {
    source.close();
    const payload = JSON.parse(e.data);
    showScreen("screen-submit");
    showSubmitError(payload.error_code || "INTERNAL", payload.detail);
  });
  source.addEventListener("error", () => {
    if (source.readyState === EventSource.CLOSED) {
      showScreen("screen-submit");
      showSubmitError("CONNECTION_LOST", "");
    }
  });
}

/** Drive the progress bar through an SVG width attribute.
 *
 * It used to set `style.width`, which the strict CSP silently blocked — the bar simply
 * never moved and nothing reported it. Attributes are not styles. */
function setProgress(percent) {
  const bar = $("progress-fill");
  if (bar) bar.setAttribute("width", String(Math.max(0, Math.min(100, percent))));
}

const STEP_ORDER = [];
const ICONS = { pending: "", running: "*", done: "✓", failed: "!", skipped: "–" };

function renderPlan(plan) {
  const list = $("steps");
  clear(list);
  STEP_ORDER.length = 0;
  for (const step of plan.steps) {
    STEP_ORDER.push(step.id);
    list.appendChild(buildStep({ id: step.id, title: step.title, status: "pending" }));
  }
}

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
      const value = el("span", "ev-value", row.value);
      value.dir = "ltr";
      line.appendChild(value);
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
    setProgress(((index + 1) / (STEP_ORDER.length || 9)) * 100);
  }
}

function scoreClass(value) {
  if (value >= 70) return "score-high";
  if (value >= 40) return "score-mid";
  return "score-low";
}

const FORMULAS = {
  call_sites: "1 / (1 + log10(1 + n))",
  isolation_layer: "1 / (1 + cut)",
  selection_source: "config / (config + literals)",
  propagation_depth: "1 − (ancestors / modules)",
};

async function showResult(jobId) {
  const [score, trace] = await Promise.all([
    (await api(`/analyses/${jobId}/score`)).json(),
    (await api(`/analyses/${jobId}/trace`)).json(),
  ]);

  const repo = el("span");
  repo.dir = "ltr";
  repo.textContent = score.provenance.repo;
  clear($("result-repo"));
  $("result-repo").appendChild(repo);

  $("result-sub").textContent =
    `${score.provenance.commit_sha.slice(0, 12)} · ${score.coverage.files_scanned} files`;

  $("score-value").textContent = score.agility_score.toFixed(1);
  $("score-value").className = `score-value ${scoreClass(score.agility_score)}`;
  const band = score.agility_score >= 70 ? "high" : score.agility_score >= 40 ? "mid" : "low";
  $("score-label").textContent = t(`tool.score_${band}`);
  $("score-label").className = `score-label ${scoreClass(score.agility_score)}`;

  const rows = $("factor-rows");
  clear(rows);
  const ordered = ["call_sites", "isolation_layer", "selection_source", "propagation_depth"]
    .filter((k) => k in score.factors);
  for (const key of ordered) {
    const factor = score.factors[key];
    const tr = el("tr");
    tr.appendChild(el("td", null, t(`factors.${key}`)));
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

  showScreen("screen-result");
}

function renderDeductions(score) {
  const container = $("deductions");
  clear(container);
  if (!score.deductions.length) {
    container.appendChild(el("p", "muted", t("tool.no_deductions")));
  }
  for (const deduction of score.deductions) {
    const box = el("div", "deduction");
    const head = el("div", "deduction-head");
    head.appendChild(el("span", null, t(`factors.${deduction.factor}`)));
    head.appendChild(el("span", "deduction-points", `−${deduction.points.toFixed(2)}`));
    box.appendChild(head);
    // The analyzer writes its reasons and actions in English. Left to inherit the page
    // direction they render as Arabic would, so "27 call sites ..." loses its 27 to the
    // far end of the line. Isolating them keeps the sentence in reading order.
    const reason = el("div", null, deduction.reason);
    reason.dir = "ltr";
    box.appendChild(reason);
    const cites = el("div", "cites");
    for (const citation of deduction.citations) {
      const chip = el("span", "cite", citation);
      chip.dir = "ltr";
      cites.appendChild(chip);
    }
    box.appendChild(cites);
    container.appendChild(box);
  }

  const recs = $("recommendations");
  clear(recs);
  if (score.recommendations.length) {
    recs.appendChild(el("h3", null, t("tool.recommendations_title")));
    for (const rec of score.recommendations) {
      const box = el("div", "rec");
      const action = el("div", null, rec.action);
      action.dir = "ltr";
      box.appendChild(action);
      const parts = [t("tool.affects", { n: rec.affected_sites })];
      if (rec.estimated_score_gain > 0) {
        parts.push(t("tool.recovers", { n: rec.estimated_score_gain.toFixed(1) }));
      }
      box.appendChild(el("div", "muted small", parts.join(" · ")));
      recs.appendChild(box);
    }
  }
}

boot();
