import { apply, loadContent, onLanguage, t } from "./i18n.mjs";
import { badge, el, fill, icon, mountChrome, observeReveals, tag } from "./chrome.mjs";

const $ = (id) => document.getElementById(id);
const data = { sample: null, standards: null, evidence: null, mark: null, figure: null, engine: "v9" };
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

/* Numbers: the previous engine and v9 on the same repositories, one panel -------------------
   Both tabs show the same six cards. Choosing v9 moves the top three numbers from the
   previous engine's value to v9's and lights them; the bottom three, which did not change,
   step back under a light shade. Each number names both of its values (data-v5, data-v9),
   so the move and the language switch never disagree. */
const reduceMotion = () => window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
const NUM_MS = 1800;
const calm = (k) => (1 - Math.cos(Math.PI * k)) / 2;

function side(figure) {
  return data.engine === "v9" || !figure.previous
    ? { value: figure.value, values: figure.values, sources: figure.sources }
    : { value: figure.previous.value, values: figure.previous.values, sources: figure.previous.sources || figure.sources };
}

/* A number that knows both engines' values. Its decimals and thousands commas come from
   how the evidence writes it ("95.0", "5,007"). */
function both(v5, v9) {
  return el("span", { class: "eng-num", "data-v5": String(v5), "data-v9": String(v9), text: String(data.engine === "v9" ? v9 : v5) });
}

/* Text with one number in it: the "{n}" of a string becomes a number that knows both values. */
function withNumber(key, v5, v9, values = {}) {
  const [before, after = ""] = t(key, values).split("{n}");
  return [before, both(v5, v9), after];
}

/* The figure as it is written in the reader's language (fig.<id>.format, "{n}" is the
   number): "$5,007", "77h" and "95.0%" in English; in Arabic the number stays left to
   right and a unit word follows it ("77 ساعة", "5,007 دولار"), while a glued sign such as
   "٪" stays attached to the digits. */
function figureValue(figure) {
  const [before, after = ""] = t(`fig.${figure.id}.format`).split("{n}");
  const word = after.startsWith(" ") ? after.trim() : "";
  const glued = word ? "" : after;
  return el("span", { class: "value" },
    el("span", { class: "n" }, before, both(figure.previous?.value ?? figure.value, figure.value), glued ? el("span", { class: "unit", text: glued }) : null),
    word ? el("span", { class: "unit word", text: word }) : null,
  );
}

const asFigure = (figure, value) => t(`fig.${figure.id}.format`).replace("{n}", value);
const plain = (value) => Number(String(value).replace(/,/g, ""));
const points = (a, b) => (plain(a) - plain(b)).toFixed(1);

/* What only v9 adds under a card: the previous engine's figure and the gain. */
function comparison(figure, inside) {
  const was = (text, gain) => el("div", { class: "eng-was" }, text, gain ? [" ", t("numbers.arrow"), " ", el("em", { text: gain })] : null);
  const lines = [];
  const prev = figure.previous;
  if (figure.id === "other" || figure.id === "pktls") {
    lines.push(was(t("numbers.was", { was: asFigure(figure, prev.value) }), t("numbers.points", { n: points(figure.value, prev.value) })));
  }
  if (figure.id === "pktls") {
    const [before, after = ""] = t("numbers.latest").split("{n}");
    lines.push(el("div", { class: "eng-extra" }, before, el("b", { text: asFigure(figure, figure.values.latest) }), after));
  }
  if (figure.id === "precision") {
    lines.push(was(t("numbers.was", { was: prev.values.found }), t("numbers.calls", { n: figure.values.found - prev.values.found })));
  }
  if (inside) lines.push(was(t("numbers.scan_was", { n: inside.previous.value })));
  return lines.length ? el("div", { class: "eng-v9only" }, el("div", {}, ...lines)) : null;
}

function renderFigures() {
  const evidence = data.evidence;
  if (!evidence) return;
  const inside = Object.fromEntries(evidence.figures.filter((f) => f.inside).map((f) => [f.inside, f]));
  fill($("figures"),
    ...evidence.figures.filter((f) => !f.inside).map((figure) => {
      const changed = figure.previous && figure.previous.value !== figure.value;
      const sub = inside[figure.id];
      return el("button", {
        type: "button",
        class: `figure reveal in ${changed ? "up" : "same"}`,
        "aria-expanded": String(data.figure === figure.id),
        "aria-controls": "figure-detail",
        "data-figure": figure.id,
        onclick: () => {
          data.figure = data.figure === figure.id ? null : figure.id;
          $("figures").querySelectorAll(".figure").forEach((b) => b.setAttribute("aria-expanded", String(b.dataset.figure === data.figure)));
          renderDetail();
        },
      },
        figureValue(figure),
        el("span", { class: "label" },
          t(`fig.${figure.id}.label`, side(figure).values),
          figure.id === "precision" ? [" ", ...withNumber("numbers.results", figure.previous.values.total, figure.values.total)] : null,
        ),
        sub ? el("span", { class: "eng-sub" }, ...withNumber("numbers.scan", sub.previous.value, sub.value)) : null,
        comparison(figure, sub),
        el("span", { class: "how" }, t("numbers.how"), icon("chevron", "chev")),
      );
    }),
  );
  fill($("numbers-scope"), ...withNumber("numbers.scope", evidence.scope.previous, evidence.scope.value));
  renderDetail();
}

function sourceList(sources) {
  return el("dd", {},
    ...sources.map((s) =>
      s.url
        ? el("div", {}, el("a", { class: "link", href: s.url, target: "_blank", rel: "noopener noreferrer", text: t(`fig.src.${s.id}`) }))
        : el("div", {}, el("span", { text: t(`fig.src.${s.id}`) }), " ", el("code", { class: "small ltr", text: s.path })),
    ),
  );
}

/* A figure opens its source and method, for the engine the panel shows. */
function renderDetail() {
  const evidence = data.evidence;
  const detail = $("figure-detail");
  const figure = evidence?.figures.find((f) => f.id === data.figure);
  detail.hidden = !figure;
  if (!figure) return;
  const { values, sources } = side(figure);
  const inside = evidence.figures.find((f) => f.inside === figure.id);
  const scan = inside ? side(inside) : null;
  fill(detail,
    el("p", { class: "h4", text: t(`fig.${figure.id}.label`, values) }),
    el("dl", {},
      el("dt", { text: t("numbers.measured") }), el("dd", { text: t(`fig.${figure.id}.measured`, values) }),
      el("dt", { text: t("numbers.method") }), el("dd", { text: t(`fig.${figure.id}.method`, values) }),
      el("dt", { text: t("numbers.source") }), sourceList(sources),
      values.limit ? el("dt", { text: t("numbers.limit") }) : null,
      values.limit ? el("dd", { text: t(`fig.${figure.id}.limit`, values) }) : null,
      scan ? el("dt", { text: t("numbers.scan_title") }) : null,
      scan ? el("dd", { text: `${t(`fig.${inside.id}.measured`, scan.values)} ${t(`fig.${inside.id}.method`, scan.values)}` }) : null,
    ),
  );
}

function moveNumbers(ver, animate) {
  $("p-engine").querySelectorAll(".eng-num").forEach((node) => {
    const target = node.dataset[ver];
    const digits = (target.split(".")[1] || "").length;
    const commas = target.includes(",");
    const to = plain(target);
    const from = plain(node.textContent);
    const write = (v) => {
      node.textContent = commas ? Math.round(v).toLocaleString("en-US") : v.toFixed(digits);
    };
    cancelAnimationFrame(node.raf);
    if (!animate || reduceMotion() || from === to) {
      node.textContent = target;
      return;
    }
    const t0 = performance.now();
    const step = (now) => {
      const k = Math.min(1, (now - t0) / NUM_MS);
      if (k < 1) {
        write(from + (to - from) * calm(k));
        node.raf = requestAnimationFrame(step);
      } else node.textContent = target;
    };
    node.raf = requestAnimationFrame(step);
  });
}

function setEngine(ver, animate) {
  data.engine = ver;
  const panel = $("p-engine");
  panel.classList.toggle("is-v9", ver === "v9");
  panel.classList.toggle("is-v5", ver === "v5");
  panel.setAttribute("aria-labelledby", `t-${ver}`);
  moveNumbers(ver, animate);
  renderDetail();
  if (animate && ver === "v9" && !reduceMotion()) {
    setTimeout(() => panel.querySelectorAll(".figure.up .value").forEach((v) => {
      v.classList.remove("pop");
      void v.offsetWidth;
      v.classList.add("pop");
    }), NUM_MS - 300);
  }
}

/* Coming next opens like the demo video at 0:20: the scene fades, a beam rises, lies flat and
   runs out to both edges, and the horizon draws itself in hex digits outward from it, over
   every card; then it opens from its middle onto coming next. Leaving, the page collapses into
   the horizon line. The timings up to the drop are the video's, with the click at 0. */
const clamp = (x, a = 0, b = 1) => Math.min(b, Math.max(a, x));
const lerp = (a, b, k) => a + (b - a) * k;
const seg = (x, a, b) => clamp((x - a) / (b - a));
const EASE = {
  outCubic: (x) => 1 - Math.pow(1 - x, 3),
  inCubic: (x) => x * x * x,
  inOutCubic: (x) => (x < 0.5 ? 4 * x * x * x : 1 - Math.pow(-2 * x + 2, 3) / 2),
  outExpo: (x) => (x >= 1 ? 1 : 1 - Math.pow(2, -10 * x)),
  inExpo: (x) => (x <= 0 ? 0 : Math.pow(2, 10 * x - 10)),
};
const hash = (i, salt = 0) => {
  let x = Math.imul(i ^ 0x9e3779b9, 0x85ebca6b) ^ Math.imul(salt + 0x632be5ab, 0xc2b2ae35);
  x ^= x >>> 16; x = Math.imul(x, 0x7feb352d); x ^= x >>> 15; x = Math.imul(x, 0x846ca68b); x ^= x >>> 16;
  return (x >>> 0) / 4294967296;
};
const HEX = "0123456789abcdef";
const T = { out: 0.26, lineTurn: 0.16, drop: 0.38, lineFade: [0.46, 1.0], field: [0.38, 1.18], photoIn: [0.48, 1.3], swap: 1.0, open: [1.3, 1.9] };

// The horizon photograph, turned so the limb lies nearly flat, re-drawn as hex digits (the
// video's Horizon), sized to the stage: u turns the video's 1920-wide geometry into this width.
class Horizon {
  constructor(img, W, H, { limb, zoom = 1.75, theta = 0.303, cell = 22 }) {
    Object.assign(this, { img, W, H, limb, zoom, theta, cell, u: Math.max(W, 900) / 1920 });
    this.cols = Math.ceil(W / cell);
    this.rows = Math.ceil(H / cell);
    const c = document.createElement("canvas");
    c.width = this.cols;
    c.height = this.rows;
    const x = c.getContext("2d", { willReadFrequently: true });
    x.fillStyle = "#000";
    x.fillRect(0, 0, this.cols, this.rows);
    x.imageSmoothingEnabled = true;
    x.imageSmoothingQuality = "high";
    this.place(x, this.cols / W);
    x.drawImage(img, 0, 0);
    const d = x.getImageData(0, 0, this.cols, this.rows).data;
    const n = this.cols * this.rows;
    this.r = new Float32Array(n); this.g = new Float32Array(n); this.b = new Float32Array(n); this.L = new Float32Array(n);
    for (let i = 0; i < n; i++) {
      this.r[i] = d[4 * i]; this.g[i] = d[4 * i + 1]; this.b[i] = d[4 * i + 2];
      this.L[i] = (0.2126 * this.r[i] + 0.7152 * this.g[i] + 0.0722 * this.b[i]) / 255;
    }
  }

  place(ctx, k) {
    ctx.setTransform(k, 0, 0, k, 0, 0);
    ctx.translate(this.W / 2, this.limb);
    ctx.rotate(-this.theta);
    ctx.scale(this.zoom * this.u, this.zoom * this.u);
    ctx.translate(-960, -628); // a point on the limb in the photograph
  }

  draw(ctx, now, { start, spread, photo }) {
    const { cell: c, cols, rows } = this;
    ctx.fillStyle = "#000";
    ctx.fillRect(0, 0, this.W, this.H);
    if (photo > 0) {
      ctx.save();
      ctx.globalAlpha = photo;
      const base = ctx.getTransform();
      this.place(ctx, 1);
      ctx.setTransform(base.multiply(ctx.getTransform()));
      ctx.drawImage(this.img, 0, 0);
      ctx.restore();
    }
    ctx.font = `500 ${c + 1}px "Geist Mono", monospace`;
    ctx.textBaseline = "top";
    const frame = Math.round(now * 30);
    for (let y = 0; y < rows; y++) {
      const dist = Math.abs(y * c + c / 2 - this.limb) / (640 * this.u);
      for (let x = 0; x < cols; x++) {
        const i = y * cols + x;
        const L = this.L[i];
        const age = now - (start + spread * Math.pow(dist, 0.8) + 0.22 * hash(i, 7));
        if (age < 0) continue;
        // Where the photograph is dark, faint blue digits, so the field covers every card.
        const dark = L < 0.06;
        let ch, r = dark ? 34 : this.r[i], g = dark ? 78 : this.g[i], b = dark ? 140 : this.b[i];
        if (age < 0.16) {
          ch = HEX[(hash(i, frame) * 16) | 0];
          const w = 0.6 * (1 - age / 0.16);
          r = lerp(r, 255, w); g = lerp(g, 255, w); b = lerp(b, 255, w);
        } else ch = dark ? HEX[(hash(i, 3) * 16) | 0] : RAMP[Math.min(RAMP.length - 1, Math.floor(L * RAMP.length))];
        ctx.fillStyle = `rgba(${r | 0},${g | 0},${b | 0},${(clamp(age / 0.1) * (dark ? 0.55 : 1)).toFixed(3)})`;
        ctx.fillText(ch, x * c, y * c);
      }
    }
  }
}

/* The video's beam: a 2 px line, white at its middle and blue towards its ends, with a near
   and a far glow; thick widens it on the drop. Drawn, not styled, so the page's style policy
   cannot drop it. */
function drawLine(ctx, cx, cy, len, turn, thick, alpha) {
  if (alpha <= 0 || len <= 0) return;
  ctx.save();
  ctx.globalAlpha = alpha;
  ctx.translate(cx, cy);
  ctx.rotate((turn * Math.PI) / 2);
  const g = ctx.createLinearGradient(0, -len / 2, 0, len / 2);
  g.addColorStop(0, "rgba(191,224,255,0)");
  g.addColorStop(0.12, "#bfe0ff");
  g.addColorStop(0.5, "#ffffff");
  g.addColorStop(0.88, "#bfe0ff");
  g.addColorStop(1, "rgba(191,224,255,0)");
  ctx.fillStyle = g;
  const w = 2 * thick;
  for (const [blur, color] of [[80, "rgba(82,168,255,0.3)"], [20, "rgba(82,168,255,0.6)"], [0, "transparent"]]) {
    ctx.shadowBlur = blur;
    ctx.shadowColor = color;
    ctx.fillRect(-w / 2, -len / 2, w, len);
  }
  ctx.restore();
}

/* The blue bloom on the drop: an ellipse of light centred on the limb. */
function drawBloom(ctx, cx, cy, rx, ry, alpha) {
  if (alpha <= 0) return;
  ctx.save();
  ctx.globalAlpha = alpha;
  ctx.translate(cx, cy);
  ctx.scale(1, ry / rx);
  const g = ctx.createRadialGradient(0, 0, 0, 0, 0, rx);
  g.addColorStop(0, "rgba(170,215,255,0.55)");
  g.addColorStop(0.45, "rgba(82,168,255,0.12)");
  g.addColorStop(0.72, "rgba(0,0,0,0)");
  ctx.fillStyle = g;
  ctx.fillRect(-rx, -rx, 2 * rx, 2 * rx);
  ctx.restore();
}

const engines = { current: null, run: 0, horizon: null, img: null, back: null, front: null };

function horizonParts() {
  if (engines.back) return;
  engines.img = new Image();
  engines.img.src = new URL("./brand/horizon-hero.webp", import.meta.url).href;
  engines.back = el("canvas", { class: "eng-hz", "aria-hidden": "true" });
  engines.front = el("canvas", { class: "eng-light", "aria-hidden": "true" });
}

/* A canvas drawn at the screen's density; the page's CSS gives it the stage's width, and its
   height follows from its proportions. */
function sized(canvas, W, H) {
  const dpr = Math.min(2, window.devicePixelRatio || 1);
  canvas.width = Math.round(W * dpr);
  canvas.height = Math.round(H * dpr);
  const ctx = canvas.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  return ctx;
}

// The limb sits in the middle of the part of the stage on screen, where the horizon opens.
function limbOnScreen(box) {
  const top = Math.max(box.top, 0);
  const bottom = Math.min(box.bottom, window.innerHeight);
  return Math.round(top + 0.5 * Math.max(0, bottom - top) - box.top);
}

/* The horizon opens from its line: a band with soft edges, cut out of the drawing and widening
   until it clears the stage, while what is left fades. */
function openFrom(ctx, W, H, L, k) {
  if (k <= 0) return;
  const soft = 90;
  const half = k * (Math.max(L, H - L) + soft);
  const span = 2 * (half + soft);
  ctx.save();
  ctx.globalCompositeOperation = "destination-out";
  const g = ctx.createLinearGradient(0, L - half - soft, 0, L + half + soft);
  g.addColorStop(0, "rgba(0,0,0,0)");
  g.addColorStop(soft / span, "#000");
  g.addColorStop(1 - soft / span, "#000");
  g.addColorStop(1, "rgba(0,0,0,0)");
  ctx.fillStyle = g;
  ctx.fillRect(0, L - half - soft, W, span);
  ctx.fillStyle = `rgba(0,0,0,${EASE.inCubic(k).toFixed(3)})`;
  ctx.fillRect(0, 0, W, H);
  ctx.restore();
}

function frames(paint, until) {
  const id = ++engines.run;
  const t0 = performance.now();
  return new Promise((done) => {
    const tick = (now) => {
      if (id !== engines.run) return done(false);
      const s = (now - t0) / 1000;
      paint(Math.min(s, until));
      if (s < until) requestAnimationFrame(tick);
      else done(true);
    };
    requestAnimationFrame(tick);
  });
}

const PLAYING = ["leaving", "rising", "collapsing"];
function settle(...nodes) {
  for (const node of nodes) node.classList.remove(...PLAYING);
}

/* Into coming next: the scene fades, drops and blurs; the beam rises, turns flat and runs out
   to both edges; a blue bloom; the horizon draws outward from the line until it covers every
   card, the new scene rises under it, and the horizon opens from its middle and is gone. */
async function intoNext() {
  horizonParts();
  await engines.img.decode().catch(() => {});
  const stage = document.querySelector(".eng-stage");
  const engine = $("p-engine");
  const next = $("p-next");
  const { back, front } = engines;
  settle(engine, next, back);
  const box = stage.getBoundingClientRect();
  const W = Math.round(box.width);
  const H = Math.round(box.height);
  const horizon = new Horizon(engines.img, W, H, { limb: limbOnScreen(box) });
  engines.horizon = horizon;
  const bctx = sized(back, W, H);
  const fctx = sized(front, W, H);
  const { limb: L, u } = horizon;
  stage.prepend(back);
  stage.append(front);
  engine.classList.add("leaving");
  let swapped = false;
  const ok = await frames((s) => {
    fctx.clearRect(0, 0, W, H);
    if (s < T.lineFade[1] + 0.05) {
      const g = EASE.outCubic(seg(s, 0, T.lineTurn));
      const turn = EASE.inOutCubic(seg(s, T.lineTurn, T.drop - 0.02));
      const len = lerp(lerp(0, 320 * u * 1.6, g), W * 1.36, EASE.inExpo(seg(s, T.lineTurn + 0.04, T.drop)));
      const fade = 1 - EASE.inOutCubic(seg(s, T.lineFade[0], T.lineFade[1]));
      drawLine(fctx, W / 2, L, len, turn, 1 + 1.4 * clamp(1 - Math.abs(s - T.drop) / 0.14), fade);
    }
    const bloom = clamp(1 - Math.abs(s - T.drop) / 0.1) * (s < T.drop ? 0.6 : 1) * clamp(1 - (s - T.drop) / 0.34);
    drawBloom(fctx, W / 2, L, 1400 * u, 260 * u * 1.6, bloom);
    if (s >= T.drop - 0.02) {
      const photo = 0.42 * EASE.outCubic(seg(s, T.photoIn[0], T.photoIn[1]));
      const push = 1 + 0.035 * seg(s, T.drop, T.drop + 5);
      bctx.save();
      bctx.translate(W / 2, L);
      bctx.scale(push, push);
      bctx.translate(-W / 2, -L);
      horizon.draw(bctx, s, { start: T.field[0], spread: T.field[1] - T.field[0], photo });
      bctx.restore();
      openFrom(bctx, W, H, L, EASE.inOutCubic(seg(s, T.open[0], T.open[1])));
    }
    if (s >= T.swap && !swapped) {
      swapped = true;
      engine.classList.remove("on", "leaving");
      next.classList.add("on", "rising");
    }
  }, T.open[1]);
  if (!ok) return;
  front.remove();
  back.remove();
  settle(next);
}

/* Out of coming next: the page collapses into the horizon line, the line flares and fades
   (the video's T7), and the numbers rise in its place. */
async function outOfNext(ver) {
  horizonParts();
  const stage = document.querySelector(".eng-stage");
  const engine = $("p-engine");
  const next = $("p-next");
  const { back, front } = engines;
  settle(engine, next, back);
  const box = stage.getBoundingClientRect();
  const W = Math.round(box.width);
  const H = Math.round(box.height);
  const L = engines.horizon ? Math.min(engines.horizon.limb, H) : limbOnScreen(box);
  const fctx = sized(front, W, H);
  stage.append(front);
  next.classList.add("collapsing");
  if (back.isConnected) back.classList.add("collapsing");
  let swapped = false;
  const ok = await frames((s) => {
    fctx.clearRect(0, 0, W, H);
    const flare = Math.min(EASE.outCubic(seg(s, 0.1, 0.3)) * 1.2, 1) * (1 - EASE.inOutCubic(seg(s, 0.4, 0.9)));
    drawLine(fctx, W / 2, L, W * 1.36, 1, 1 + 1.2 * clamp(1 - Math.abs(s - 0.3) / 0.16), flare);
    if (s >= 0.32 && !swapped) {
      swapped = true;
      next.classList.remove("on", "collapsing");
      engine.classList.add("on", "rising");
      setEngine(ver, false);
    }
  }, 0.95);
  if (!ok) return;
  front.remove();
  back.remove();
  settle(engine, back);
}

function showEngine(id, animate) {
  document.querySelectorAll(".eng-tab").forEach((tab) => tab.setAttribute("aria-selected", String(tab.dataset.tab === id)));
  const toNext = id === "next";
  const wasNext = engines.current === "next";
  engines.current = id;
  if (animate && !reduceMotion() && toNext !== wasNext) {
    if (toNext) intoNext();
    else outOfNext(id);
    return;
  }
  engines.run++;
  const engine = $("p-engine");
  const next = $("p-next");
  settle(engine, next);
  engines.front?.remove();
  engines.back?.remove();
  engine.classList.toggle("on", !toNext);
  next.classList.toggle("on", toNext);
  if (!toNext) setEngine(id, animate);
}

function mountEngines() {
  document.querySelectorAll(".eng-tab").forEach((tab) => tab.addEventListener("click", () => {
    if (tab.dataset.tab !== engines.current) showEngine(tab.dataset.tab, true);
  }));
  showEngine("v9", false);
}

function renderAll() {
  apply();
  renderShots();
  renderTimeline();
  renderFigures();
}

async function main() {
  // The page arrived with its text (assets.py): start the scroll fades now, and let the
  // strings, the sample and the standards fill in behind their skeletons.
  observeReveals();
  await loadContent();
  mountChrome();
  mountHero();
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
  mountEngines();
  observeReveals();
}

main().catch(() => {
  document.documentElement.classList.remove("js");
  document.documentElement.classList.add("no-js");
});
