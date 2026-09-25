/** The product: scan a repository, watch it run, then read what was found, the proposed
 * changes and the post-quantum readiness.
 *
 * The run view follows the deployment pages developers already know: four stages with
 * one status line, detail folded under each stage, and the result on top when it is done.
 * No summary appears before the evidence it summarises.
 */
import { apply, loadContent, numberText, onLanguage, t, tk } from "./i18n.mjs";
import { badge, el, fill, icon, mountChrome, tag, track } from "./chrome.mjs";
import { AnalysisWatcher } from "./progress.mjs";
import { normalizeRepositoryUrl } from "./repository.mjs";
import { requestJson } from "./request.mjs";
import { loadAccount } from "./account.mjs";

const $ = (id) => document.getElementById(id);
const JOB_ID = /^[a-f0-9-]{36}$/;
const STAGES = [
  { id: "fetch", steps: ["validate", "resolve", "clone"] },
  { id: "scan", steps: ["walk", "parse"] },
  { id: "analyse", steps: ["graph", "score", "render"] },
  { id: "cleanup", steps: ["cleanup"] },
];
const TABS = ["readiness", "findings", "changes", "report"];
const STATUSES = ["vulnerable", "weak", "review", "pq", "safe"];
const STATUS_KIND = { vulnerable: "bad", weak: "warn", review: "warn", pq: "ok", safe: "plain" };
const VERDICT_RING = { at_risk: "bad", in_transition: "warn", ready: "ok", no_crypto: "none", no_source: "none" };

const state = {
  session: null,
  workspace: null,
  examples: [],
  job: null,
  watcher: null,
  review: null,
  ticker: null,
};

function newJob(id) {
  return {
    id,
    repo: "",
    sha: "",
    cached: false,
    status: "queued",
    done: false,
    failed: null,
    steps: new Map(),
    findings: new Map(),
    feedback: {},
    openReason: null,
    proposals: new Map(),
    selected: new Set(),
    fixes: null,
    score: null,
    disputes: null,
    readiness: null,
    sources: {},
    parse: null,
    truncated: false,
    startedAt: Date.now(),
    finishedAt: null,
    tab: "findings",
    tabChosen: false,
    filter: "all",
    openStages: new Set(),
    openEvidence: new Set(),
  };
}

/* API ------------------------------------------------------------------------------------ */
async function api(path, { method = "GET", body } = {}) {
  const options = { method, credentials: "same-origin", headers: { Accept: "application/json" } };
  if (method !== "GET") {
    options.headers["Content-Type"] = "application/json";
    options.headers["X-CSRF-Token"] = state.session?.csrf_token || "";
    if (body !== undefined) options.body = JSON.stringify(body);
  }
  let response;
  let data;
  try {
    ({ response, data } = await requestJson(path, options, method === "GET" ? 30000 : 0));
  } catch (cause) {
    const error = new Error(t(cause.code === "INVALID_RESPONSE" ? "error.unavailable" : "error.connection"));
    error.code = "NETWORK";
    throw error;
  }
  if (!response.ok) {
    const code = data?.error_code || "INTERNAL";
    const error = new Error(tk(`error.${code}`, "error.generic"));
    error.code = code;
    throw error;
  }
  return data;
}

function showError(id, error) {
  const node = $(id);
  node.textContent = error ? error.message || String(error) : "";
  node.hidden = !error;
}

function repoName(url) {
  return String(url || "").replace("https://github.com/", "");
}

function realSha(sha) {
  return sha && !/^0+$/.test(sha);
}

/* Home: two doors when signed out; the dashboard when signed in ------------------------------ */
function signedIn() {
  return Boolean(state.session?.user);
}

function localMode() {
  // A local installation scans without sign-in; the hosted one requires it.
  return Boolean(state.session && !state.session.required);
}

function firstName(name) {
  return String(name || "").trim().split(/\s+/)[0] || "";
}

function renderAccount() {
  const session = state.session;
  const signed = signedIn();
  $("account-chip").hidden = !signed;
  if (signed) $("account-chip").textContent = session.user.login;
  $("signin").hidden = signed || !session?.configured;
  $("menu-signin").hidden = signed || !session?.configured;
  $("signout").hidden = !signed;
  const doors = Boolean(session) && !signed && !localMode();
  $("doors").hidden = !doors;
  $("dashboard").hidden = !session || doors;
  $("door-signin").hidden = !session?.configured;
  $("door-signin-note").hidden = Boolean(session?.configured);
  $("run-banner-signin").hidden = signed || !session?.configured;
  $("scan-auth").hidden = true;
  renderWelcome();
}

function renderWelcome() {
  const me = state.me;
  const signed = signedIn();
  $("welcome-title").textContent = signed
    ? t("ws.welcome", { name: firstName(me?.name) || state.session.user.login })
    : t("ws.scan_title");
  const avatar = $("avatar");
  avatar.hidden = !(signed && me?.avatar_url);
  if (!avatar.hidden) {
    avatar.src = `${me.avatar_url}${me.avatar_url.includes("?") ? "&" : "?"}s=96`;
    avatar.alt = t("ws.avatar_alt", { login: state.session.user.login });
  }
  renderRepos();
}

function renderRepos() {
  const block = $("repos-block");
  block.hidden = !signedIn();
  if (block.hidden) return;
  const repos = state.me?.repos;
  $("repos-note").textContent = repos?.length ? t("ws.repos_note", { n: repos.length }) : "";
  if (!repos) {
    fill($("repos"), el("p", { class: "small", text: t("ws.repos_loading") }));
    return;
  }
  if (!repos.length) {
    fill($("repos"), el("p", { class: "small", text: t("ws.repos_none") }));
    return;
  }
  fill($("repos"),
    ...repos.map((repo) =>
      el("div", { class: "item repo" },
        el("span", { class: "title", text: repo.full_name }),
        el("span", { class: "meta" },
          repo.language ? el("span", { class: "lang", text: repo.language }) : null,
          repo.pushed_at ? el("span", { text: t("ws.updated", { date: repo.pushed_at.slice(0, 10) }) }) : null,
          repo.description ? el("span", { class: "desc", text: repo.description }) : null,
        ),
        el("span", { class: "side" },
          el("button", {
            type: "button",
            class: "btn sm",
            "aria-label": t("ws.scan_repo_label", { repo: repo.full_name }),
            onclick: () => scanRepo(repo.full_name),
            text: t("ws.scan_button"),
          }),
        ),
      ),
    ),
  );
}

async function loadMe() {
  if (!signedIn()) return;
  try {
    state.me = await api("/api/v1/me");
  } catch {
    state.me = { name: state.session.user.login, avatar_url: "", repos: [] };
  }
  renderWelcome();
}

function jobBadge(status) {
  const kind = status === "succeeded" ? "ok" : status === "failed" || status === "timeout" ? "bad" : status === "running" ? "live" : "";
  return badge(t(`status.job.${status}`), kind);
}

function renderWorkspace() {
  const ws = state.workspace;
  if (!ws) return;
  const usage = ws.usage;
  $("scan-limits").textContent = usage
    ? t("ws.limits_used", { used: usage.daily_used, limit: usage.daily_limit, mb: ws.limits.repo_mb })
    : t("ws.limits", { limit: ws.limits.daily, mb: ws.limits.repo_mb });
  $("history-block").hidden = !ws.jobs.length;
  $("history-note").textContent = signedIn() ? t("ws.history_note", { days: ws.retention_days }) : "";
  fill($("history"),
    ...ws.jobs.map((job) =>
      el("button", { type: "button", class: "item", onclick: () => openJob(job.job_id) },
        el("span", { class: "title", text: repoName(job.repo_url) }),
        el("span", { class: "meta", text: new Date(job.created_at * 1000).toISOString().slice(0, 16).replace("T", " ") }),
        el("span", { class: "side" }, jobBadge(job.status)),
      ),
    ),
  );
  $("scan-submit").disabled = !ws.scan_available;
}

async function refreshWorkspace() {
  state.workspace = await api("/api/v1/workspace");
  renderWorkspace();
}

function scanRepo(fullName) {
  $("repo-url").value = fullName;
  $("scan-form").requestSubmit();
}

/* Starting runs ----------------------------------------------------------------------------- */
async function startScan(event) {
  event.preventDefault();
  showError("scan-error", null);
  const url = normalizeRepositoryUrl($("repo-url").value);
  if (!url) {
    showError("scan-error", new Error(t("ws.url_invalid")));
    return;
  }
  $("repo-url").value = repoName(url);
  if (state.session?.required && !state.session.user) {
    if (!state.session.configured) {
      showError("scan-error", new Error(t("ws.signin_unavailable")));
      return;
    }
    try { sessionStorage.setItem("quanta-pending-repo", url); } catch { /* private mode */ }
    location.assign("/auth/login");
    return;
  }
  $("scan-submit").disabled = true;
  try {
    const job = await api("/api/v1/analyses", { method: "POST", body: { repo_url: url } });
    await openJob(job.job_id);
    refreshWorkspace().catch(() => {});
  } catch (error) {
    showError("scan-error", error);
  } finally {
    $("scan-submit").disabled = !(state.workspace?.scan_available ?? true);
  }
}

async function startSample() {
  showError("scan-error", null);
  try {
    const job = await api("/api/v1/sample/replay", { method: "POST", body: {} });
    history.replaceState(null, "", "#sample");
    await openJob(job.job_id, { keepHash: true });
  } catch (error) {
    showError("scan-error", error);
  }
}

function showHome() {
  state.watcher?.stop();
  clearInterval(state.ticker);
  state.job = null;
  history.replaceState(null, "", location.pathname);
  $("run-view").hidden = true;
  $("home-view").hidden = false;
  window.scrollTo({ top: 0 });
}

async function openJob(id, { keepHash = false } = {}) {
  if (!JOB_ID.test(id)) return;
  state.watcher?.stop();
  clearInterval(state.ticker);
  state.review = null;
  const job = newJob(id);
  state.job = job;
  if (!keepHash) history.replaceState(null, "", `#analysis/${id}`);
  let status;
  try {
    status = await api(`/api/v1/analyses/${id}`);
  } catch (error) {
    showError("scan-error", error);
    return;
  }
  if (state.job !== job) return;
  $("home-view").hidden = true;
  $("run-view").hidden = false;
  window.scrollTo({ top: 0 });
  job.repo = repoName(status.repo_url);
  job.cached = Boolean(status.cached);
  job.status = status.status;
  fill($("proposals"));
  fill($("refusals"));
  renderRun();
  state.ticker = setInterval(() => { if (!job.done && !job.failed) renderHead(); }, 1000);
  let hostedRun = false;
  state.watcher = new AnalysisWatcher(id, {
    plan: (data) => {
      for (const step of data.steps) if (!job.steps.has(step.id)) job.steps.set(step.id, { id: step.id, status: "pending" });
      renderStages();
    },
    step: (step) => {
      job.steps.set(step.id, step);
      if (step.id === "resolve" && step.status === "done") {
        const pinned = (step.evidence || []).find((e) => e.label === "Head commit");
        if (pinned) job.sha = pinned.value;
      }
      job.status = job.status === "queued" ? "running" : job.status;
      renderHead();
      renderStages();
    },
    status: (data) => {
      job.status = data.status || job.status;
      if (data.status === "queued" && state.workspace?.hosted && !hostedRun) {
        hostedRun = true;
        api(`/api/v1/analyses/${id}/run`, { method: "POST", body: {} }).catch((error) => showError("scan-error", error));
      }
      renderHead();
    },
    progress: () => renderHead(),
    parseProgress: (data) => {
      job.parse = data;
      renderHead();
      renderStages();
    },
    findings: (batch) => {
      const list = job.findings.get(batch.file) || [];
      list.push(...batch.items);
      job.findings.set(batch.file, list);
      renderCounts();
      if (job.tab === "findings") renderFindings();
    },
    proposals: (file) => {
      job.proposals.set(file.path, file.changes);
      renderCounts();
      if (job.tab === "changes") renderProposals();
    },
    truncated: () => {
      job.truncated = true;
      renderHead();
    },
    done: () => finish(job),
    failure: (data) => {
      job.failed = data || {};
      job.status = "failed";
      job.finishedAt = Date.now();
      renderHead();
      renderStages();
    },
  }).start();
}

/* Head: title, badge, facts, one status line -------------------------------------------------- */
function elapsed(job) {
  const steps = [...job.steps.values()];
  const measured = steps.reduce((n, s) => n + (s.duration_ms || 0), 0);
  if (job.done || job.cached) return measured / 1000;
  return Math.max(measured, (job.finishedAt || Date.now()) - job.startedAt) / 1000;
}

function currentStep(job) {
  return [...job.steps.values()].find((s) => s.status === "running");
}

function findingsCount(job) {
  let n = 0;
  for (const list of job.findings.values()) n += list.length;
  return n;
}

function statusText(job) {
  if (job.failed) return tk(`error.${job.failed.error_code}`, "error.analysis_failed");
  if (job.done) return t("live.done", { seconds: numberText(elapsed(job), 1), n: findingsCount(job) });
  const step = currentStep(job);
  if (!step) return t(job.status === "queued" ? "live.queued" : "live.starting");
  if (step.id === "parse" && job.parse) {
    return t("live.parse_progress", { done: numberText(job.parse.done), total: numberText(job.parse.total), n: findingsCount(job) });
  }
  return tk(`live.${step.id}`, "live.working");
}

function renderHead() {
  const job = state.job;
  if (!job) return;
  $("run-banner").hidden = !job.cached;
  $("run-repo").textContent = job.repo;
  const status = job.failed ? "failed" : job.done ? "succeeded" : job.status === "queued" ? "queued" : "running";
  fill($("run-badge"), jobBadge(status));
  fill($("run-facts"),
    realSha(job.sha) ? el("span", {}, t("facts.commit"), " ", el("span", { class: "ltr", text: job.sha.slice(0, 12) })) : null,
    el("span", { text: t("facts.duration", { seconds: numberText(elapsed(job), 1) }) }),
    fileCount(job) ? el("span", { text: t("facts.files", { n: numberText(fileCount(job)) }) }) : null,
    job.cached ? el("span", { text: t("facts.recorded") }) : null,
    job.truncated ? el("span", { text: t("ws.stream_truncated") }) : null,
  );
  $("statusline").classList.toggle("idle", Boolean(job.done || job.failed));
  $("status-text").textContent = statusText(job);
}

/* Stages: four rows, each folding its steps and their evidence --------------------------------- */
function stageState(job, stage) {
  const steps = stage.steps.map((id) => job.steps.get(id)).filter(Boolean);
  if (steps.some((s) => s.status === "failed")) return "failed";
  if (steps.length && steps.every((s) => s.status === "done" || s.status === "skipped")) return "done";
  if (steps.some((s) => s.status === "running" || s.status === "done")) return "running";
  if (job.failed) return "pending";
  return "pending";
}

function stateIcon(status) {
  const node = el("span", { class: `state-icon ${status}`, "aria-label": t(`status.step.${status === "failed" ? "failed" : status}`) });
  if (status === "done") node.append(icon("check"));
  if (status === "failed") node.append(icon("cross"));
  return node;
}

function fileCount(job) {
  if (job.parse) return job.parse.total;
  const walk = job.steps.get("walk");
  const accepted = (walk?.evidence || []).find((e) => e.label === "Accepted for analysis");
  return accepted ? Number(String(accepted.value).replace(/,/g, "")) : null;
}

function stageSummary(job, stage, status) {
  if (status === "pending") return t("stage.waiting");
  if (stage.id === "fetch") return realSha(job.sha) ? t("stage.fetch_pinned", { sha: job.sha.slice(0, 12) }) : t(`stage.fetch_${status === "done" ? "done" : "running"}`);
  if (stage.id === "scan") {
    const n = findingsCount(job);
    const files = fileCount(job);
    if (status === "done") return files ? t("stage.scan_done", { files: numberText(files), n }) : t("stage.scan_done_findings", { n });
    return job.parse ? t("stage.scan_running", { done: numberText(job.parse.done), total: numberText(job.parse.total), n }) : t("live.walk");
  }
  return t(`stage.${stage.id}_${status === "done" ? "done" : "running"}`);
}

function evidenceRows(step) {
  const seen = new Set();
  return (step.evidence || []).filter((e) => {
    const key = `${e.label}|${e.value}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function renderStages() {
  const job = state.job;
  if (!job) return;
  fill($("stages"),
    ...STAGES.filter((stage) => !(job.done || job.cached) || stage.steps.some((id) => job.steps.has(id))).map((stage) => {
      const status = stageState(job, stage);
      const steps = stage.steps.map((id) => job.steps.get(id)).filter(Boolean);
      const ms = steps.reduce((n, s) => n + (s.status === "done" ? s.duration_ms || 0 : 0), 0);
      const details = el("details", { class: "stage", open: job.openStages.has(stage.id) },
        el("summary", {},
          stateIcon(status),
          el("span", { class: "name" }, el("span", { text: t(`stage.${stage.id}`) }), el("span", { class: "small", text: stageSummary(job, stage, status) })),
          el("span", { class: "time", text: status === "done" ? t("unit.seconds", { s: numberText(ms / 1000, 1) }) : "" }),
          icon("chevron", "chev"),
        ),
        el("div", { class: "stage-body" },
          el("div", { class: "substeps" },
            ...steps.flatMap((step) => {
              const rows = evidenceRows(step);
              const open = job.openEvidence.has(step.id);
              // The score's evidence is a summary: it waits for the finished result.
              const withheld = step.id === "score" && !job.done;
              return [
                el("div", { class: "substep" },
                  el("span", { class: `dot ${step.status === "done" ? "ok" : step.status === "running" ? "info" : step.status === "failed" ? "bad" : ""}` }),
                  el("span", {}, t(`step.${step.id}`), " ",
                    rows.length && !withheld
                      ? el("button", {
                          type: "button",
                          class: "evidence-toggle",
                          "aria-expanded": String(open),
                          onclick: () => {
                            if (open) job.openEvidence.delete(step.id);
                            else job.openEvidence.add(step.id);
                            renderStages();
                          },
                          text: t(open ? "stage.hide_evidence" : "stage.show_evidence", { n: rows.length }),
                        })
                      : null,
                  ),
                  el("span", { class: "time", text: step.status === "done" && step.duration_ms != null ? t("unit.ms", { ms: numberText(step.duration_ms) }) : t(`status.step.${step.status}`) }),
                ),
                open && !withheld
                  ? el("div", { class: "evidence" },
                      ...rows.map((e) =>
                        el("div", { class: "kv" },
                          el("span", { class: "k" }, tk(`ev.${e.label}`, "ev.raw", { label: e.label })),
                          el("span", { class: "v", text: e.value }),
                        ),
                      ),
                    )
                  : null,
              ];
            }),
          ),
        ),
      );
      details.addEventListener("toggle", () => {
        if (details.open) job.openStages.add(stage.id);
        else job.openStages.delete(stage.id);
      });
      return details;
    }),
  );
}

/* Result: readiness first --------------------------------------------------------------------- */
function renderResult() {
  const job = state.job;
  const node = $("result");
  if (!job.done) {
    node.hidden = true;
    return;
  }
  node.hidden = false;
  const r = job.readiness;
  if (!r) {
    fill(node, el("p", { class: "body", text: t("result.no_readiness") }));
    return;
  }
  const lines = [t(`verdict.${r.verdict}.body`)];
  if (r.overdue.length) lines.push(t("result.overdue", { n: r.overdue.length }));
  if (r.earliest_year) lines.push(t("result.earliest", { year: r.earliest_year }));
  if (r.complete === false) lines.push(t("result.partial", { n: numberText(r.source_unread) }));
  // A library that is the cryptography (python-ecdsa, python-rsa) is told so plainly.
  const implemented = [...new Set([...job.findings.values()].flat()
    .filter((f) => f.form === "implementation" && f.role === "source").map((f) => f.algorithm))].sort();
  fill(node,
    el("div", { class: "verdict" }, el("span", { class: `ring ${VERDICT_RING[r.verdict]}` }), el("h2", { class: "h1", text: t(`verdict.${r.verdict}`) })),
    el("p", { class: "body", text: lines.join(" ") }),
    implemented.length ? el("p", { class: "notice", text: t("result.implements", { algorithms: implemented.join(", ") }) }) : null,
    r.counts.sites ? el("p", { class: "small", text: t("result.sites", { n: numberText(r.counts.sites) }) }) : null,
    r.counts.sites
      ? el("div", { class: "tally" },
          ...STATUSES.map((s) =>
            el("div", {},
              el("span", { class: "n", text: numberText(r.counts[s] || 0) }),
              el("span", { class: "k" }, el("span", { class: `dot ${STATUS_KIND[s] === "plain" ? "" : STATUS_KIND[s]}` }), t(`st.${s}`)),
            ),
          ),
        )
      : null,
  );
}

/* Tabs ------------------------------------------------------------------------------------------ */
function selectTab(name, chosen = true) {
  const job = state.job;
  if (!job) return;
  job.tab = name;
  if (chosen) job.tabChosen = true;
  for (const tab of TABS) {
    $(`tab-${tab}`).setAttribute("aria-selected", String(tab === name));
    $(`panel-${tab}`).hidden = tab !== name;
  }
  renderPanel();
}

function renderCounts() {
  const job = state.job;
  if (!job) return;
  const n = findingsCount(job);
  $("count-findings").textContent = n ? numberText(n) : "";
  // One entry per finding that needs action: patches, guided sites and refusals.
  const patches = [...job.proposals.values()].reduce((m, c) => m + c.length, 0);
  const guided = (job.fixes?.guides || []).reduce((m, g) => m + g.sites.length, 0);
  const changes = patches + guided + (job.fixes?.skipped || []).length;
  $("count-changes").textContent = changes ? numberText(changes) : "";
}

function renderPanel() {
  const job = state.job;
  if (!job) return;
  if (job.tab === "readiness") renderReadiness();
  if (job.tab === "findings") renderFindings();
  if (job.tab === "changes") renderProposals();
  if (job.tab === "report") renderReport();
}

/* Readiness tab ---------------------------------------------------------------------------------- */
function sourceLinks(ids) {
  return el("div", { class: "sources" },
    ...ids.map((id) => {
      const source = state.job.sources[id];
      if (!source) return null;
      return el("a", { href: source.url, target: "_blank", rel: "noopener noreferrer" },
        el("span", { class: "link", text: t(`src.${id}`) }),
        source.status === "draft" ? badge(t("src.status.draft"), "warn") : null,
        icon("external", "arrow"),
      );
    }),
  );
}

function renderReadiness() {
  const job = state.job;
  const panel = $("panel-readiness");
  if (!job.done) {
    fill(panel, el("p", { class: "small", text: t("readiness.waiting") }));
    return;
  }
  const r = job.readiness;
  if (!r) {
    fill(panel, el("p", { class: "small", text: t("result.no_readiness") }));
    return;
  }
  const rank = (m) => (m.in_force ? 0 : m.year ?? 9999);
  const milestones = r.milestones.filter((m) => m.state === "overdue" || m.state === "due").sort((a, b) => rank(a) - rank(b) || a.id.localeCompare(b.id));
  const clear = r.milestones.filter((m) => m.state === "clear").length;
  const met = r.milestones.filter((m) => m.state === "met").length;
  const stateKind = { overdue: "bad", due: "warn", clear: "plain", met: "ok" };
  fill(panel,
    el("div", { class: "block" },
      el("h3", { class: "h4", text: t("readiness.actions_title") }),
      r.actions.length
        ? el("div", { class: "actions-list" },
            ...r.actions.map((a, i) =>
              el("details", { class: "action" },
                el("summary", {},
                  el("span", { class: "rank", text: String(i + 1) }),
                  el("span", { class: "what" }, el("span", { class: "h4", text: t(`action.${a.id}.title`) }), el("span", { class: "small", text: t(`action.${a.id}.body`) })),
                  el("span", { class: "when" },
                    a.in_force ? badge(t("ready.in_force"), "bad") : a.by ? badge(t(a.by <= r.reference_year ? "ready.overdue_since" : "ready.by", { year: a.by }), a.by <= r.reference_year ? "bad" : "warn") : badge(t("ready.no_date"), "plain"),
                    el("span", { class: "small", text: t("ready.sites", { n: a.sites }) }),
                  ),
                  icon("chevron", "chev"),
                ),
                el("div", { class: "detail" },
                  el("div", { class: "cites" }, ...a.citations.slice(0, 40).map((c) => tag(c)), a.citations.length > 40 ? el("span", { class: "small", text: t("ready.more", { n: a.citations.length - 40 }) }) : null),
                  sourceLinks(a.sources),
                ),
              ),
            ),
          )
        : el("p", { class: "small", text: t("readiness.nothing") }),
    ),
    el("div", { class: "block" },
      el("h3", { class: "h4", text: t("readiness.deadlines_title") }),
      el("div", { class: "table-scroll" },
        el("table", { class: "deadlines" },
          el("thead", {}, el("tr", {}, ...["fw", "rule", "year", "sites", "state"].map((c) => el("th", { text: t(`readiness.col.${c}`) })))),
          el("tbody", {},
            ...milestones.map((m) =>
              el("tr", {},
                el("td", { class: "fwname", text: t(`fw.${m.framework}`) }),
                el("td", { class: "rule" }, el("div", { text: t(`ms.${m.id}`) }), sourceLinks([m.source])),
                el("td", { class: "num", text: m.in_force ? (m.year ? t("readiness.after", { year: m.year }) : t("readiness.in_force")) : m.year ?? t("readiness.any_date") }),
                el("td", { class: "num", text: numberText(m.sites) }),
                el("td", {}, badge(t(`ms.state.${m.state}`), stateKind[m.state])),
              ),
            ),
          ),
        ),
      ),
      el("p", { class: "small", text: t("readiness.others", { clear, met }) }),
      el("p", { class: "small", text: t("readiness.note", { checked: r.checked }) }),
    ),
  );
}

/* Findings tab ---------------------------------------------------------------------------------- */
function findingStatus(f) {
  return f.readiness?.status || (f.weak ? "weak" : f.quantum_vulnerable ? "vulnerable" : "safe");
}

function shipped(f) {
  return f.role === "source";
}

function counted(f) {
  // Readiness counts call sites; an algorithm argument belongs to its call.
  return f.kind === "crypto_call";
}

function changeEntries(job) {
  const entries = new Map();
  const fixes = job.fixes;
  if (!fixes) return entries;
  for (const file of fixes.files || []) for (const c of file.changes) entries.set(`${file.path}:${c.line}`, "patch");
  for (const g of fixes.guides || []) for (const s of g.sites) entries.set(`${s.path}:${s.line}`, "guide");
  for (const s of fixes.skipped || []) entries.set(`${s.path}:${s.line}`, "refused");
  return entries;
}

function renderFindings() {
  const job = state.job;
  const panel = $("panel-findings");
  const all = [...job.findings.values()].flat();
  if (!all.length) {
    fill(panel, el("p", { class: "small", text: t(job.done ? "inv.none" : "inv.waiting") }));
    return;
  }
  const inShipped = all.filter(shipped);
  const inOther = all.filter((f) => !shipped(f));
  if (!job.scope) job.scope = inShipped.length || !inOther.length ? "shipped" : "other";
  const scoped = job.scope === "shipped" ? inShipped : inOther;
  const counts = Object.fromEntries(STATUSES.map((s) => [s, 0]));
  for (const f of scoped) if (counted(f)) counts[findingStatus(f)] += 1;
  const sites = scoped.filter(counted).length;
  const scopes = el("div", { class: "segmented", role: "group", "aria-label": t("inv.scope_label") },
    ...[["shipped", inShipped], ["other", inOther]].map(([key, list]) =>
      el("button", {
        type: "button",
        "aria-pressed": String(job.scope === key),
        onclick: () => { job.scope = key; job.filter = "all"; renderFindings(); },
        text: t(`inv.scope_${key}`, { n: numberText(list.filter(counted).length) }),
      }),
    ),
  );
  const filters = el("div", { class: "filters", role: "group", "aria-label": t("inv.filter_label") },
    ...["all", ...STATUSES].filter((s) => s === "all" || counts[s]).map((s) =>
      el("button", {
        type: "button",
        class: "filter",
        "aria-pressed": String(job.filter === s),
        onclick: () => { job.filter = s; renderFindings(); },
        text: `${t(s === "all" ? "inv.all" : `st.${s}`)} ${numberText(s === "all" ? sites : counts[s])}`,
      }),
    ),
  );
  const entries = changeEntries(job);
  const files = [...job.findings.entries()]
    .map(([file, items]) => [file, items.filter((f) => (job.scope === "shipped") === shipped(f) && (job.filter === "all" || findingStatus(f) === job.filter))])
    .filter(([, items]) => items.length);
  fill(panel,
    el("div", { class: "findings-head" }, scopes, filters),
    el("p", { class: "small", text: t(job.scope === "shipped" ? "inv.scope_shipped_note" : "inv.scope_other_note") }),
    el("div", {},
      ...files.map(([file, items], index) =>
        el("details", { class: "file", open: index < 12 || files.length < 20 },
          el("summary", {}, el("span", { text: file }), el("span", { class: "n", text: numberText(items.filter(counted).length) })),
          ...items.map((f) => findingNode(f, entries)),
        ),
      ),
    ),
  );
}

function findingNode(finding, entries) {
  const status = findingStatus(finding);
  const algorithms = finding.algorithms?.length ? finding.algorithms : finding.algorithm ? [finding.algorithm] : [];
  const entry = entries.get(`${finding.file}:${finding.line}`);
  return el("div", { class: "finding", id: `f-${finding.id}` },
    el("div", { class: "head" },
      el("span", { class: "line", text: `L${finding.line}` }),
      el("span", { class: "name", text: finding.name }),
      ...algorithms.map((a) => tag(a)),
      badge(t(`st.${status}`), STATUS_KIND[status]),
      finding.form === "implementation" ? badge(t("inv.implementation"), "bad") : null,
      finding.kind === "algo_literal" ? badge(t("inv.argument"), "plain") : null,
    ),
    entry
      ? el("button", { type: "button", class: "entry-link", onclick: () => selectTab("changes"), text: t(`inv.entry_${entry}`) })
      : el("span"),
    finding.snippet ? el("div", { class: "code inline" }, el("span", { class: "ln", text: finding.snippet })) : null,
  );
}

/* Changes tab ------------------------------------------------------------------------------------- */
function sourceLinksFor(ids) {
  return sourceLinks(ids.filter((id) => state.job.sources[id]));
}

function renderProposals() {
  const job = state.job;
  const files = [...job.proposals.entries()];
  const total = files.reduce((n, [, changes]) => n + changes.length, 0);
  const guides = job.fixes?.guides || [];
  const refusals = job.fixes?.skipped || [];
  const guided = guides.reduce((n, g) => n + g.sites.length, 0);
  fill($("changes-summary"),
    job.done
      ? el("p", { class: "body", text: t("edits.summary", { patches: numberText(total), guided: numberText(guided), refused: numberText(refusals.length) }) })
      : el("p", { class: "small", text: t("edits.waiting") }),
  );
  fill($("proposals"),
    total ? el("h3", { class: "h4", text: t("edits.patches_title", { n: numberText(total) }) }) : null,
    total ? el("p", { class: "small", text: t("edits.lede") }) : null,
    ...files.flatMap(([path, changes]) =>
      changes.map((change) => {
        const box = el("input", { type: "checkbox", id: `c-${change.id}`, checked: job.selected.has(change.id) });
        box.addEventListener("change", () => {
          if (box.checked) job.selected.add(change.id);
          else job.selected.delete(change.id);
          renderSelection();
        });
        // The preview comes from the patch's own offsets, never from searching the line.
        const before = change.line_before || change.before;
        const after = change.line_after || change.after;
        return el("div", { class: "proposal" },
          el("label", { for: `c-${change.id}` }, box, el("span", { text: `${path}:${change.line}` })),
          el("div", { class: "code inline" },
            el("span", { class: "ln del", text: `- ${before}` }),
            el("span", { class: "ln add", text: `+ ${after}` }),
          ),
          el("div", { class: "actions" }, badge(tk(`rule.${change.rule}`, "rule.other"), "info"), el("span", { class: "small", text: t("edits.note") })),
        );
      }),
    ),
    !total && job.done ? el("p", { class: "small", text: t("edits.no_patches") }) : null,
  );
  fill($("guides"),
    guides.length ? el("h3", { class: "h4", text: t("edits.guides_title", { n: numberText(guided) }) }) : null,
    guides.length ? el("p", { class: "small", text: t("edits.guides_lede") }) : null,
    ...guides.map((g) =>
      el("details", { class: "guide-card" },
        el("summary", {},
          el("span", { class: "what" },
            el("span", { class: "h4", text: tk(`guide.${g.id}.title`, "guide.other.title") }),
            el("span", { class: "small", text: t("edits.guide_target", { to: g.to }) }),
          ),
          badge(t("edits.guide_sites", { n: numberText(g.sites.length) }), "info"),
          icon("chevron", "chev"),
        ),
        el("div", { class: "detail" },
          el("p", { class: "body", text: tk(`guide.${g.id}.body`, "guide.other.body") }),
          el("div", { class: "code" }, ...g.example.replace(/\n$/, "").split("\n").map((line) => el("span", { class: "ln", text: line || " " }))),
          el("div", { class: "cites" }, ...g.sites.slice(0, 60).map((s) => tag(`${s.path}:${s.line}`)), g.sites.length > 60 ? el("span", { class: "small", text: t("ready.more", { n: g.sites.length - 60 }) }) : null),
          sourceLinksFor(g.sources || []),
        ),
      ),
    ),
  );
  fill($("refusals"),
    refusals.length ? el("h3", { class: "h4", text: t("edits.refusals_title", { n: refusals.length }) }) : null,
    ...refusals.map((skip) =>
      el("div", { class: "refusal" },
        el("div", { class: "where", text: `${skip.path}:${skip.line}` }),
        el("div", {}, badge(tk(`refusal.${skip.code}.title`, "refusal.other.title"), "warn")),
        el("p", { class: "small", text: tk(`refusal.${skip.code}.body`, "refusal.other.body") }),
      ),
    ),
  );
  $("selectionbar").hidden = total === 0;
  renderSelection();
}

function renderSelection() {
  const job = state.job;
  const n = job.selected.size;
  $("selection-note").textContent = n ? t("edits.selected", { n }) : t("edits.select_hint");
  $("review-open").disabled = n === 0 || !job.done;
}

/* Finish: load the canonical artifacts ---------------------------------------------------------- */
async function finish(job) {
  if (state.job !== job) return;
  const [score, fixes, findings, readiness] = await Promise.all([
    api(`/api/v1/analyses/${job.id}/score`),
    api(`/api/v1/analyses/${job.id}/fixes`),
    api(`/api/v1/analyses/${job.id}/findings`),
    api(`/api/v1/analyses/${job.id}/readiness`).catch(() => ({ readiness: null, sources: {} })),
  ]);
  if (state.job !== job) return;
  job.done = true;
  job.status = "succeeded";
  job.finishedAt = Date.now();
  job.score = score;
  job.fixes = fixes;
  job.readiness = readiness.readiness;
  job.sources = readiness.sources || {};
  job.sha = score.provenance.commit_sha;
  // The artifact is the source of truth: a truncated stream never leaves the view short.
  job.findings = new Map();
  for (const f of findings.findings) {
    const list = job.findings.get(f.file) || [];
    list.push(f);
    job.findings.set(f.file, list);
  }
  job.proposals = new Map(fixes.files.map((f) => [f.path, f.changes]));
  renderRun();
  if (!job.tabChosen) selectTab("readiness", false);
  refreshWorkspace().catch(() => {});
}

function renderRun() {
  renderHead();
  renderStages();
  renderResult();
  renderCounts();
  selectTab(state.job.tab, false);
}

/* Report tab --------------------------------------------------------------------------------------- */
const FACTORS = ["call_sites", "isolation_layer", "selection_source", "propagation_depth"];

function renderReport() {
  const job = state.job;
  const panel = $("panel-report");
  const score = job.score;
  if (!score) {
    fill(panel, el("p", { class: "small", text: t("report.waiting") }));
    return;
  }
  const base = `/api/v1/analyses/${job.id}`;
  const parts = [
    el("div", { class: "block report-lead" },
      el("h3", { class: "h3", text: t("report.document_title") }),
      el("p", { class: "body", text: t("report.document_lede") }),
      el("div", { class: "actions" },
        el("a", { class: "btn primary", href: `${base}/report.pdf`, download: "" }, t("report.export_pdf")),
        el("a", { class: "btn", href: `${base}/report`, target: "_blank", rel: "noopener" }, t("report.open_html"), icon("external", "arrow")),
      ),
    ),
    el("h3", { class: "h4", text: t("report.score_title") }),
  ];
  if (score.status === "scored") {
    parts.push(
      el("div", { class: "block" },
        el("div", { class: "scoreline" },
          el("div", { class: "score" }, numberText(score.agility_score, 1), el("small", { text: t("report.out_of") })),
          el("div", {}, el("p", { class: "h4", text: t("report.scored_title") }), el("p", { class: "small", text: t("report.scored_lede") })),
        ),
        ...FACTORS.map((name) => {
          const factor = score.factors[name];
          const deductions = (score.deductions || []).filter((d) => d.factor === name);
          const lost = deductions.reduce((n, d) => n + d.points, 0);
          return el("div", { class: "factor" },
            el("div", {},
              el("div", { class: "h4", text: t(`factor.${name}.name`) }),
              el("div", { class: "why", text: t(`factor.${name}.why`, factor.inputs) }),
              deductions.length ? el("div", { class: "cites" }, ...deductions.flatMap((d) => d.citations.slice(0, 8)).map((c) => tag(c))) : null,
            ),
            track([{ start: 0, width: factor.normalised * 100, cls: "pass" }]),
            el("div", { class: "pts", text: lost ? `-${numberText(lost, 2)}` : `+${numberText(factor.contribution, 2)}` }),
          );
        }),
      ),
    );
    const recs = score.recommendations || [];
    if (recs.length) {
      parts.push(
        el("div", { class: "block" },
          el("h3", { class: "h4", text: t("report.next") }),
          ...recs.map((r) =>
            el("div", { class: "finding" },
              el("span", { class: "body fg", text: tk(`rec.${r.pattern}`, "rec.other", { n: r.affected_sites }) }),
              badge(r.estimated_score_gain ? t("report.gain", { gain: numberText(r.estimated_score_gain, 1) }) : t("report.no_gain"), r.estimated_score_gain ? "info" : "plain"),
            ),
          ),
          el("p", { class: "small", text: t("report.gain_note") }),
        ),
      );
    }
  } else if (score.status === "refused") {
    const refusal = score.refusal || {};
    const values = refusal.values || {};
    parts.push(
      el("div", { class: "block" },
        el("p", { class: "h4", text: t("report.withheld_title") }),
        el("p", { class: "body", text: tk(`gate.${refusal.code}`, "gate.other", { ...values, pct: values.coverage_ratio != null ? Math.round(values.coverage_ratio * 100) : "" }) }),
        el("p", { class: "small", text: t("report.withheld_why") }),
      ),
    );
  } else {
    parts.push(el("div", { class: "block" }, el("p", { class: "h4", text: t("report.no_crypto") }), el("p", { class: "small", text: t("report.no_crypto_note") })));
  }
  if (score.coverage) {
    parts.push(el("p", { class: "small", text: t("report.coverage", { matched: score.coverage.crypto_api_calls_matched, total: score.coverage.crypto_api_calls_matched + score.coverage.crypto_api_calls_unmatched }) }));
  }
  parts.push(
    el("div", { class: "block" },
      el("h3", { class: "h4", text: t("report.downloads") }),
      el("div", { class: "downloads" },
        ...[["readiness", "readiness.json"], ["findings", "findings.json"], ["fixes", "fixes.json"], ["score", "score.json"], ["cdg", "cdg.json"], ["meta", "meta.json"]].map(([path, name]) =>
          el("a", { class: "btn sm", href: `${base}/${path}`, target: "_blank", rel: "noopener", text: name }),
        ),
      ),
    ),
    el("div", { class: "block" },
      el("h3", { class: "h4", text: t("report.cli") }),
      el("div", { class: "code" },
        realSha(job.sha) ? el("span", { class: "ln", text: `git clone https://github.com/${job.repo} && git -C ${job.repo.split("/")[1]} checkout ${job.sha}` }) : null,
        el("span", { class: "ln", text: `quanta analyze ${job.repo.split("/")[1]} --out out/` }),
      ),
    ),
  );
  fill(panel, ...parts);
}

/* Review and pull request ------------------------------------------------------------------------- */
function renderDiff(files) {
  const lines = [];
  for (const file of files) {
    for (const raw of file.diff.split("\n")) {
      if (!raw) continue;
      const kind = raw.startsWith("+++") || raw.startsWith("---") ? "file" : raw.startsWith("@@") ? "hunk" : raw.startsWith("+") ? "add" : raw.startsWith("-") ? "del" : "";
      lines.push(el("span", { class: `ln ${kind}`, text: raw }));
    }
  }
  fill($("diff"), ...lines);
}

async function openReview() {
  const job = state.job;
  showError("review-error", null);
  $("pr-link").hidden = true;
  try {
    const result = await api(`/api/v1/analyses/${job.id}/review`, { method: "POST", body: { selected: [...job.selected] } });
    state.review = { ...result, selected: [...job.selected].sort() };
  } catch (error) {
    showError("scan-error", error);
    return;
  }
  renderDiff(state.review.files);
  renderReviewText();
  $("ack-compat").checked = false;
  $("review").showModal();
  renderPrButton();
}

function renderReviewText() {
  $("review-validation").textContent = t(state.job?.cached ? "review.cached" : "review.validation");
  $("ack-compat-text").textContent = t("review.compat");
}

function prAllowed() {
  const job = state.job;
  return Boolean(state.review && !job.cached && $("ack-compat").checked && state.session?.user);
}

function renderPrButton() {
  $("pr-open").disabled = !prAllowed();
  if (state.review && !state.session?.user && !state.job.cached) showError("review-error", new Error(t("review.signin")));
}

async function openPullRequest() {
  const job = state.job;
  const review = state.review;
  $("pr-open").disabled = true;
  showError("review-error", null);
  try {
    const result = await api(`/api/v1/analyses/${job.id}/pull-request`, {
      method: "POST",
      body: { selected: review.selected, digest: review.digest, acknowledge_compatibility: $("ack-compat").checked },
    });
    if (!/^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/pull\/\d+$/.test(result.url)) throw new Error(t("review.bad_link"));
    $("pr-link").href = result.url;
    $("pr-link").hidden = false;
  } catch (error) {
    showError("review-error", error);
  } finally {
    renderPrButton();
  }
}

/* Boot -------------------------------------------------------------------------------------------- */
function rerender() {
  apply();
  renderAccount();
  renderWorkspace();
  if (state.job) renderRun();
  if (state.review && $("review").open) renderReviewText();
}

function route() {
  const hash = location.hash.slice(1);
  if (hash === "sample") return startSample();
  if (hash.startsWith("analysis/")) return openJob(hash.slice("analysis/".length), { keepHash: true });
  return null;
}

async function main() {
  await loadContent();
  mountChrome();
  onLanguage(rerender);
  $("scan-form").addEventListener("submit", startScan);
  $("door-sample").addEventListener("click", startSample);
  $("dash-sample").addEventListener("click", startSample);
  $("back").addEventListener("click", showHome);
  for (const tab of TABS) $(`tab-${tab}`).addEventListener("click", () => selectTab(tab));
  $("tabs").addEventListener("keydown", (event) => {
    if (!state.job || !["ArrowLeft", "ArrowRight"].includes(event.key)) return;
    const rtl = document.documentElement.dir === "rtl";
    const step = (event.key === "ArrowRight") !== rtl ? 1 : -1;
    const next = TABS[(TABS.indexOf(state.job.tab) + step + TABS.length) % TABS.length];
    selectTab(next);
    $(`tab-${next}`).focus();
  });
  $("review-open").addEventListener("click", openReview);
  $("review-close").addEventListener("click", () => $("review").close());
  $("ack-compat").addEventListener("change", renderPrButton);
  $("pr-open").addEventListener("click", openPullRequest);
  $("signout").addEventListener("click", async () => {
    try {
      await api("/auth/logout", { method: "POST", body: {} });
      location.assign("/");
    } catch (error) {
      showError("scan-error", error);
    }
  });
  rerender();
  await loadAccount({
    read: { session: () => api("/auth/session"), workspace: () => api("/api/v1/workspace") },
    loaded: (kind, value) => {
      state[kind] = value;
      renderAccount();
      renderWorkspace();
    },
    failed: (kind, error) => showError("scan-error", error),
    retrying: () => {},
  });
  await loadMe();
  let pending = null;
  try { pending = sessionStorage.getItem("quanta-pending-repo"); sessionStorage.removeItem("quanta-pending-repo"); } catch { /* private mode */ }
  if (pending && state.session?.user) {
    $("repo-url").value = repoName(pending);
    $("scan-form").requestSubmit();
    return;
  }
  await route();
}

main();
