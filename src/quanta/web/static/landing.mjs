import { apply, loadContent, onLanguage, t } from "./i18n.mjs";
import { badge, el, fill, icon, mountChrome, observeReveals, tag } from "./chrome.mjs";

const $ = (id) => document.getElementById(id);
const data = { sample: null, standards: null, evidence: null, mark: null, figure: null };
const FIRST_YEAR = 2026;
const LAST_YEAR = 2035;
const FRAMEWORK_ORDER = ["nist", "nsa", "nca", "eu", "uk", "us"];

async function getJson(path) {
  const response = await fetch(path, { credentials: "same-origin", headers: { Accept: "application/json" } });
  if (!response.ok) throw new Error(path);
  return response.json();
}

/* Hero: the horizon photograph, re-drawn as a field of hex digits -------------------------
   The photo fades in faint first; the digits resolve over it. Drawn once per size. */
const RAMP = " .:-=+*0123456789abcdef";

function drawAscii() {
  const canvas = $("hero-ascii");
  const image = $("hero-image");
  const media = $("hero-media");
  if (!canvas || !image || !image.complete || !image.naturalWidth) return;
  const rect = media.getBoundingClientRect();
  if (!rect.width || !rect.height) return;
  const ratio = Math.min(window.devicePixelRatio || 1, 2);
  const cell = rect.width < 700 ? 7 : 9;
  const cols = Math.ceil(rect.width / cell);
  const rows = Math.ceil(rect.height / cell);
  const sample = document.createElement("canvas");
  sample.width = cols;
  sample.height = rows;
  const sctx = sample.getContext("2d", { willReadFrequently: true });
  const scale = Math.max(cols / image.naturalWidth, rows / image.naturalHeight);
  const w = image.naturalWidth * scale;
  const h = image.naturalHeight * scale;
  if (document.documentElement.dir === "rtl") {
    sctx.translate(cols, 0);
    sctx.scale(-1, 1);
  }
  sctx.drawImage(image, (cols - w) / 2, (rows - h) * 0.45, w, h);
  const pixels = sctx.getImageData(0, 0, cols, rows).data;
  canvas.width = Math.round(rect.width * ratio);
  canvas.height = Math.round(rect.height * ratio);
  const ctx = canvas.getContext("2d");
  ctx.scale(ratio, ratio);
  ctx.clearRect(0, 0, rect.width, rect.height);
  ctx.font = `500 ${cell + 1}px "Geist Mono", monospace`;
  ctx.textBaseline = "top";
  for (let y = 0; y < rows; y++) {
    for (let x = 0; x < cols; x++) {
      const i = (y * cols + x) * 4;
      const r = pixels[i], g = pixels[i + 1], b = pixels[i + 2];
      const light = (0.2126 * r + 0.7152 * g + 0.0722 * b) / 255;
      if (light < 0.06) continue;
      ctx.fillStyle = `rgb(${r},${g},${b})`;
      ctx.fillText(RAMP[Math.min(RAMP.length - 1, Math.floor(light * RAMP.length))], x * cell, y * cell);
    }
  }
  requestAnimationFrame(() => {
    canvas.classList.add("ready");
    media.classList.add("has-ascii");
  });
}

function mountHero() {
  const image = $("hero-image");
  const media = $("hero-media");
  if (!image || !media) return;
  const start = () => {
    media.classList.add("photo");
    document.fonts.ready.then(() => setTimeout(drawAscii, 250));
  };
  if (image.complete && image.naturalWidth) start();
  else image.addEventListener("load", start, { once: true });
  let timer;
  let width = window.innerWidth;
  window.addEventListener("resize", () => {
    if (window.innerWidth === width) return;
    width = window.innerWidth;
    clearTimeout(timer);
    timer = setTimeout(drawAscii, 200);
  });
}

/* Three answers: small views of the real sample ---------------------------------------------- */
const STATUS_DOT = { vulnerable: "bad", weak: "warn", review: "warn", pq: "ok", safe: "" };

function shortName(name) {
  return name.split(".").slice(-2).join(".");
}

function renderShots() {
  const sample = data.sample;
  if (!sample) return;
  const shipped = sample.findings.filter((f) => f.role === "source");
  fill($("shot-find"),
    ...shipped.slice(0, 6).map((f) =>
      el("div", { class: "shot-row" },
        el("span", { class: `dot ${STATUS_DOT[f.readiness?.status] || ""}` }),
        el("span", { class: "where", text: `${f.file}:${f.line}` }),
        el("span", { class: "grow" }),
        f.algorithm ? tag(f.algorithm) : el("span", { class: "where", text: shortName(f.name) }),
      ),
    ),
    el("p", { class: "small", text: t("product.find_foot", { n: shipped.length }) }),
  );

  const file = sample.fixes.files[0];
  if (file) {
    const change = file.changes[0];
    // The patch's own preview, built from exact offsets; never a search-and-replace.
    const before = (change.line_before || change.before).trim();
    const after = (change.line_after || change.after).trim();
    fill($("shot-change"),
      el("div", { class: "shot-row" }, el("span", { class: "where", text: `${file.path}:${change.line}` })),
      el("div", { class: "code inline" },
        el("span", { class: "ln del", text: `- ${before}` }),
        el("span", { class: "ln add", text: `+ ${after}` }),
      ),
      sample.fixes.skipped.length ? el("p", { class: "small", text: t("product.change_foot", { n: sample.fixes.skipped.length }) }) : null,
    );
  }

  const readiness = sample.readiness;
  if (readiness) {
    const ring = { at_risk: "bad", in_transition: "warn", ready: "ok", no_crypto: "none", no_source: "none" }[readiness.verdict];
    fill($("shot-ready"),
      el("div", { class: "shot-verdict" }, el("span", { class: `dot ${ring}` }), t(`verdict.${readiness.verdict}`)),
      readiness.earliest_year ? el("p", { class: "shot-sub", text: t("ready.earliest", { year: readiness.earliest_year }) }) : null,
      ...readiness.actions.slice(0, 3).map((a, i) =>
        el("div", { class: "shot-row readable" },
          el("span", { class: "where", text: String(i + 1) }),
          el("span", { class: "grow text", text: t(`action.${a.id}.short`) }),
          a.in_force ? badge(t("ready.in_force"), "bad") : a.by ? badge(t(a.by <= readiness.reference_year ? "ready.overdue_since" : "ready.by", { year: a.by }), a.by <= readiness.reference_year ? "bad" : "plain") : null,
        ),
      ),
    );
  }
}

/* Deadlines: every published milestone, one click from its source ---------------------------- */
function columnOf(m) {
  // Rules already in force sit together, labelled with the year they took effect; a rule
  // with no date (the NCA draft) gets its own column instead of being filed under "now".
  if (m.in_force || (m.year !== null && m.year < FIRST_YEAR)) return "inforce";
  if (m.year === null) return "undated";
  return String(m.year);
}

function groups() {
  const map = new Map();
  for (const m of data.standards.milestones) {
    if (m.applies.includes("inventory")) continue;
    const column = columnOf(m);
    const key = `${m.framework}|${column}`;
    if (!map.has(key)) map.set(key, { framework: m.framework, column, items: [] });
    map.get(key).items.push(m);
  }
  return map;
}

function markLabel(group) {
  if (group.column === "undated") return t("readiness.any_date");
  if (group.column === "inforce") return t("readiness.in_force");
  return group.column;
}

function renderTimeline() {
  if (!data.standards) return;
  const byKey = groups();
  const columns = ["inforce"];
  for (let y = FIRST_YEAR; y <= LAST_YEAR; y++) columns.push(String(y));
  columns.push("undated");
  const heading = { inforce: t("readiness.col_inforce"), undated: t("readiness.col_undated") };
  const cells = [el("div", { class: "year" })];
  for (const c of columns) cells.push(el("div", { class: `year ${heading[c] ? "wide" : ""}`, text: heading[c] || c }));
  for (const fw of FRAMEWORK_ORDER) {
    cells.push(el("div", { class: "fw", text: t(`fw.${fw}`) }));
    for (const c of columns) {
      const group = byKey.get(`${fw}|${c}`);
      const cell = el("div", { class: `cell ${c === "inforce" ? "past" : ""}` });
      if (group) {
        const key = `${fw}|${c}`;
        const label = markLabel(group);
        cell.append(
          el("button", {
            type: "button",
            class: `mark ${c === "inforce" ? "past" : ""} ${c === "undated" ? "hybrid" : ""}`,
            "aria-pressed": String(data.mark === key),
            "aria-label": t("readiness.mark_label", { framework: t(`fw.${fw}`), when: label }),
            onclick: () => selectMark(key),
            text: label,
          }),
        );
      }
      cells.push(cell);
    }
  }
  fill($("timeline"), ...cells);
  renderSource();
}

function selectMark(key) {
  data.mark = key;
  renderTimeline();
}

function whenLabel(m) {
  if (m.in_force) return m.year ? t("readiness.after", { year: m.year }) : t("readiness.in_force");
  return m.year === null ? t("readiness.any_date") : String(m.year);
}

function renderSource() {
  const group = groups().get(data.mark);
  const panel = $("source-panel");
  if (!group) {
    fill(panel, el("p", { class: "small", text: t("readiness.pick") }));
    return;
  }
  const sources = [...new Set(group.items.map((m) => m.source))];
  fill(panel,
    el("p", { class: "h4", text: t(`fw.${group.framework}`) }),
    ...group.items.map((m) =>
      el("div", { class: "rule-row" },
        badge(
          whenLabel(m),
          m.in_force ? "bad" : m.year === null ? "ok" : "info",
        ),
        el("span", { class: "body fg", text: t(`ms.${m.id}`) }),
      ),
    ),
    // One line per source; the full title, status and date open on click.
    ...sources.map((id) => {
      const source = data.standards.sources[id];
      return el("details", { class: "source-more" },
        el("summary", {},
          el("span", { class: "small fg", text: t("readiness.source_line", { title: t(`src.${id}`) }) }),
          el("a", { class: "link small", href: source.url, target: "_blank", rel: "noopener noreferrer", onclick: (e) => e.stopPropagation() }, t("readiness.read_source"), " ", icon("external", "arrow")),
        ),
        el("p", { class: "small", text: t("readiness.source_detail", { publisher: source.publisher, status: t(`src.status.${source.status}`), date: source.date }) }),
      );
    }),
  );
}

/* The figure as it is written in the reader's language (fig.<id>.format, "{n}" is the
   number): "$5,007", "77h" and "94.6%" in English; in Arabic the number stays left to
   right and a unit word follows it ("77 ساعة", "5,007 دولار"), while a glued sign such as
   "٪" stays attached to the digits. */
function figureValue(figure) {
  const [before, after = ""] = t(`fig.${figure.id}.format`).split("{n}");
  const word = after.startsWith(" ") ? after.trim() : "";
  const glued = word ? "" : after;
  return el("span", { class: "value" },
    el("span", { class: "n" }, before, figure.value, glued ? el("span", { class: "unit", text: glued }) : null),
    word ? el("span", { class: "unit word", text: word }) : null,
  );
}

/* Numbers: each figure opens its source and method -------------------------------------------- */
function renderFigures() {
  const evidence = data.evidence;
  if (!evidence) return;
  fill($("figures"),
    ...evidence.figures.map((figure) =>
      el("button", {
        type: "button",
        class: "figure reveal in",
        "aria-expanded": String(data.figure === figure.id),
        "aria-controls": "figure-detail",
        onclick: () => {
          data.figure = data.figure === figure.id ? null : figure.id;
          renderFigures();
        },
      },
        figureValue(figure),
        el("span", { class: "label", text: t(`fig.${figure.id}.label`, figure.values) }),
        el("span", { class: "how" }, t("numbers.how"), icon("chevron", "chev")),
      ),
    ),
  );
  const detail = $("figure-detail");
  const figure = evidence.figures.find((f) => f.id === data.figure);
  detail.hidden = !figure;
  if (!figure) return;
  fill(detail,
    el("p", { class: "h4", text: t(`fig.${figure.id}.label`, figure.values) }),
    el("dl", {},
      el("dt", { text: t("numbers.measured") }), el("dd", { text: t(`fig.${figure.id}.measured`, figure.values) }),
      el("dt", { text: t("numbers.method") }), el("dd", { text: t(`fig.${figure.id}.method`, figure.values) }),
      el("dt", { text: t("numbers.source") }),
      el("dd", {},
        ...figure.sources.map((s) =>
          s.url
            ? el("div", {}, el("a", { class: "link", href: s.url, target: "_blank", rel: "noopener noreferrer", text: t(`fig.src.${s.id}`) }))
            : el("div", {}, el("span", { text: t(`fig.src.${s.id}`) }), " ", el("code", { class: "small ltr", text: s.path })),
        ),
      ),
      figure.values.limit ? el("dt", { text: t("numbers.limit") }) : null,
      figure.values.limit ? el("dd", { text: t(`fig.${figure.id}.limit`, figure.values) }) : null,
    ),
  );
}

function renderAll() {
  apply();
  renderShots();
  renderTimeline();
  renderFigures();
}

async function main() {
  // The page arrived with its text (assets.py): start the picture and the scroll fades now,
  // and let the strings, the sample and the standards fill in behind their skeletons.
  mountHero();
  observeReveals();
  await loadContent();
  mountChrome();
  onLanguage(() => {
    renderAll();
    drawAscii();
  });
  const [sample, standards, evidence] = await Promise.allSettled([
    getJson("/api/v1/sample"),
    getJson("/api/v1/standards"),
    getJson(new URL("./evidence.json", import.meta.url).href),
  ]);
  if (sample.status === "fulfilled") data.sample = sample.value;
  if (standards.status === "fulfilled") data.standards = standards.value;
  if (evidence.status === "fulfilled") data.evidence = evidence.value;
  data.mark = "nist|2030";
  renderAll();
  observeReveals();
}

main().catch(() => {
  document.documentElement.classList.remove("js");
  document.documentElement.classList.add("no-js");
});
