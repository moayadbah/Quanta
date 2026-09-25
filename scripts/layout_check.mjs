// Layout check: every page and state, English and Arabic, phone to desktop.
//
//   node scripts/layout_check.mjs --base http://localhost:8767 --local http://localhost:8766 --out out/layout
//
// Drives headless Chrome over the DevTools protocol (Node 22, no dependencies). For each
// state, language and viewport it records failures for:
//   * header: the site header overlaps or crowds the first heading (24 px on the home hero,
//     16 px elsewhere);
//   * overflow: an element leaves the screen outside a scroll container, or text spills out
//     of its own box;
//   * scroll: the page scrolls sideways;
//   * target: a control smaller than 44 x 44 px (links inside running text are exempt);
// and writes, per state, a screenshot plus one with every glyph made transparent, and the
// text boxes with their colours. scripts/layout_contrast.py measures each text box against
// the pixels actually behind it (canvas, photograph and gradients included).
import { spawn } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const args = Object.fromEntries(
  process.argv.slice(2).reduce((pairs, arg, i, all) => (arg.startsWith("--") ? [...pairs, [arg.slice(2), all[i + 1]]] : pairs), []),
);
const BASE = args.base || "http://localhost:8767";
const LOCAL = args.local || "";
const OUT = args.out || "out/layout";
const LANGS = (args.langs || "en,ar").split(",");
const CHROME = args.chrome || "C:/Program Files/Google/Chrome/Application/chrome.exe";
export const SIZES = [
  [320, 568], [360, 780], [375, 812], [390, 844], [414, 896], [768, 1024], [1024, 768], [1440, 900], [844, 390],
];
const sizes = args.sizes ? SIZES.filter(([w, h]) => args.sizes.split(",").includes(`${w}x${h}`)) : SIZES;
mkdirSync(OUT, { recursive: true });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function browser() {
  const port = 9400 + Math.floor(Math.random() * 400);
  const profile = join(OUT, `profile-${port}`);
  const proc = spawn(CHROME, ["--headless=new", "--disable-gpu", "--hide-scrollbars", `--remote-debugging-port=${port}`, `--user-data-dir=${profile}`, "about:blank"], { stdio: "ignore" });
  let targets;
  for (let i = 0; i < 60 && !targets; i++) {
    try { targets = await (await fetch(`http://127.0.0.1:${port}/json`)).json(); } catch { await sleep(200); }
  }
  const ws = new WebSocket(targets.find((t) => t.type === "page").webSocketDebuggerUrl);
  await new Promise((r) => ws.addEventListener("open", r));
  let id = 0;
  const pending = new Map();
  ws.addEventListener("message", (m) => {
    const msg = JSON.parse(m.data);
    if (msg.id && pending.has(msg.id)) { pending.get(msg.id)(msg); pending.delete(msg.id); }
  });
  const send = (method, params = {}) => new Promise((r) => { const n = ++id; pending.set(n, r); ws.send(JSON.stringify({ id: n, method, params })); });
  const evaluate = async (expression) => (await send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true })).result?.result?.value;
  await send("Page.enable");
  // The test browser alone ignores the page's CSP, so it may inject the "hide text" sheet.
  await send("Page.setBypassCSP", { enabled: true });
  return { send, evaluate, close: () => { ws.close(); proc.kill(); } };
}

// Runs inside the page: the four geometric checks, and the text boxes for contrast.
const PROBE = String.raw`(() => {
  const vw = document.documentElement.clientWidth;
  const fails = [];
  const visible = (el) => {
    const s = getComputedStyle(el);
    if (s.visibility === "hidden" || s.display === "none" || Number(s.opacity) === 0) return false;
    const r = el.getBoundingClientRect();
    if (!r.width || !r.height) return false;
    if (el.closest("[hidden], details:not([open]) > :not(summary), dialog:not([open]), .skip")) return false;
    return true;
  };
  const name = (el) => (el.id ? "#" + el.id : el.tagName.toLowerCase() + (el.className && typeof el.className === "string" ? "." + el.className.trim().split(/\s+/).slice(0, 2).join(".") : "")) + ' "' + (el.textContent || el.getAttribute("aria-label") || "").trim().slice(0, 30) + '"';
  if (document.documentElement.scrollWidth > vw + 1) fails.push({ kind: "scroll", detail: "page is " + document.documentElement.scrollWidth + "px wide for " + vw + "px" });
  const header = document.querySelector(".site-header");
  const first = document.querySelector("#hero-title") || [...document.querySelectorAll("main h1, main .h1, main h2")].find(visible);
  if (header && first && visible(first)) {
    const gap = first.getBoundingClientRect().top - header.getBoundingClientRect().bottom;
    const need = first.id === "hero-title" ? 24 : 16;
    if (gap < need) fails.push({ kind: "header", detail: name(first) + " is " + Math.round(gap) + "px below the header (needs " + need + ")" });
  }
  const clips = (el) => {
    for (let p = el.parentElement; p && p !== document.body; p = p.parentElement) {
      const s = getComputedStyle(p);
      if (s.overflowX !== "visible" || s.position === "fixed" && p.classList.contains("hero")) return p;
    }
    return null;
  };
  for (const el of document.body.querySelectorAll("*")) {
    if (!visible(el) || el.matches("canvas, .hero-media, .hero-media *, .hero-scrim, svg *, .sk")) continue;
    const r = el.getBoundingClientRect();
    if ((r.right > vw + 1 || r.left < -1) && !clips(el)) fails.push({ kind: "overflow", detail: name(el) + " spans " + Math.round(r.left) + " to " + Math.round(r.right) });
    const hasText = [...el.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim());
    const s = getComputedStyle(el);
    if (hasText && el.clientWidth > 0 && s.overflowX === "visible" && s.display !== "inline" && el.scrollWidth > el.clientWidth + 1 && !el.matches("td, th, pre, code") && !clips(el))
      fails.push({ kind: "overflow", detail: "text spills out of " + name(el) + " (" + el.scrollWidth + " > " + el.clientWidth + ")" });
    // Text taller than a box of fixed height (a wrapped label in a pill) spills downwards.
    const self = el.getBoundingClientRect();
    const range = document.createRange();
    range.selectNodeContents(el);
    const content = range.getBoundingClientRect();
    // Glyphs of tightly set headings poke a few pixels out of their line box; a wrapped
    // line escaping its box overshoots by most of a line, so that is the threshold.
    const slack = 0.4 * parseFloat(s.fontSize);
    if (hasText && s.display !== "inline" && s.overflowY === "visible" && content.height > 0 && (content.bottom > self.bottom + slack || content.top < self.top - slack))
      fails.push({ kind: "overflow", detail: "text spills vertically out of " + name(el) + " (" + Math.round(content.height) + " > " + Math.round(self.height) + ")" });
  }
  const controls = "a[href], button, input:not([type=hidden]), select, textarea, summary, [role=button], [role=tab]";
  for (const el of document.querySelectorAll(controls)) {
    if (!visible(el)) continue;
    const s = getComputedStyle(el);
    const inText = s.display === "inline" && el.closest("p, li, dd, td, .small, .body, .lede, .note, .source-detail");
    if (inText) continue;
    let r = el.getBoundingClientRect();
    // A checkbox counts with the label that toggles it.
    if (el.matches("input[type=checkbox], input[type=radio]") && el.closest("label")) r = el.closest("label").getBoundingClientRect();
    if (r.width < 44 - 0.5 || r.height < 44 - 0.5) fails.push({ kind: "target", detail: name(el) + " is " + Math.round(r.width) + "x" + Math.round(r.height) });
  }
  const texts = [];
  // With a modal open, only its own text is in front of the reader.
  const scope = document.querySelector("dialog[open]") || document.body;
  for (const el of scope.querySelectorAll("*")) {
    if (!visible(el) || el.closest("svg, canvas, .sk, pre, .diff, [disabled], [aria-disabled=true]")) continue;
    if (![...el.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim())) continue;
    const s = getComputedStyle(el);
    const range = document.createRange();
    const rects = [];
    for (const node of el.childNodes) {
      if (node.nodeType !== 3 || !node.textContent.trim()) continue;
      range.selectNodeContents(node);
      rects.push(...range.getClientRects());
    }
    for (const rect of rects) {
      if (rect.width < 2 || rect.height < 2) continue;
      // Only text a reader sees whole: inside the screen and not covered by anything on top
      // (the fixed header, a sticky bar), which is what is actually in front of the reader.
      if (rect.top < 0 || rect.bottom > innerHeight) continue;
      const hit = document.elementFromPoint(Math.min(innerWidth - 1, rect.left + rect.width / 2), rect.top + rect.height / 2);
      if (!hit || !(hit === el || el.contains(hit) || hit.contains(el))) continue;
      texts.push({ name: name(el), x: rect.left, y: rect.top, w: rect.width, h: rect.height, color: s.color, size: parseFloat(s.fontSize), weight: Number(s.fontWeight) || 400 });
    }
  }
  return { fails, texts, height: Math.ceil(document.documentElement.scrollHeight), width: vw };
})()`;

const HIDE_TEXT = `(() => { const s = document.createElement("style"); s.id = "hide-text"; s.textContent = "*, *::before, *::after { color: transparent !important; text-shadow: none !important; caret-color: transparent !important; -webkit-text-fill-color: transparent !important; } ::placeholder { color: transparent !important; } svg { visibility: hidden !important; }"; document.head.append(s); return true; })()`;
const SETTLE = `(async () => {
  document.querySelectorAll(".reveal").forEach((e) => e.classList.add("in"));
  await document.fonts.ready;
  // The hex field behind the hero is drawn once the page is idle: measure with it present.
  for (let i = 0; i < 40 && document.querySelector(".hero-ascii:not(.ready)"); i++) await new Promise((r) => setTimeout(r, 150));
  await new Promise((r) => setTimeout(r, 900));
  return true;
})()`;

async function shoot(page, file) {
  const shot = await page.send("Page.captureScreenshot", { format: "png" });
  writeFileSync(file, Buffer.from(shot.result.data, "base64"));
}

const TEXTS = PROBE.replace("return { fails, texts,", "return { texts,");
const SCREENS = 8;

// Geometry once for the whole page; contrast screen by screen at real scroll positions, so
// the fixed header and the full-height hero sit exactly where a reader sees them.
async function measure(page, label) {
  await page.evaluate(SETTLE);
  await page.evaluate(`document.documentElement.style.scrollBehavior = "auto"; window.scrollTo(0, 0); true`);
  const result = await page.evaluate(PROBE);
  const screens = [];
  const view = await page.evaluate("innerHeight");
  for (let i = 0; i < SCREENS && i * view < result.height; i++) {
    await page.evaluate(`window.scrollTo(0, ${i * view}); true`);
    await sleep(250);
    const { texts } = await page.evaluate(TEXTS);
    await shoot(page, join(OUT, `${label}.${i}.png`));
    await page.evaluate(HIDE_TEXT);
    await sleep(60);
    await shoot(page, join(OUT, `${label}.${i}.bg.png`));
    await page.evaluate(`document.getElementById("hide-text").remove(); true`);
    screens.push({ index: i, texts });
  }
  await page.evaluate(`window.scrollTo(0, 0); true`);
  writeFileSync(join(OUT, `${label}.json`), JSON.stringify({ label, fails: result.fails, screens, height: result.height, width: result.width }));
  return result.fails;
}

async function open(page, url, [w, h]) {
  await page.send("Emulation.setDeviceMetricsOverride", { width: w, height: h, deviceScaleFactor: 1, mobile: w < 768 || h < 500 });
  await page.send("Emulation.setTouchEmulationEnabled", { enabled: w < 1024 || h < 500 });
  await page.send("Page.navigate", { url });
  for (let i = 0; i < 40; i++) {
    await sleep(250);
    if ((await page.evaluate("document.readyState")) === "complete") break;
  }
  await sleep(1200);
}

const STATES = [
  { id: "home", url: (l) => `${BASE}/?lang=${l}` },
  { id: "menu", url: (l) => `${BASE}/?lang=${l}`, phone: true, act: `document.getElementById("menu-open")?.click(); true` },
  { id: "privacy", url: (l) => `${BASE}/privacy.html?lang=${l}` },
  { id: "signin", url: (l) => `${BASE}/workspace.html?lang=${l}` },
  ...(LOCAL ? [{ id: "dashboard", url: (l) => `${LOCAL}/workspace.html?lang=${l}` }] : []),
  { id: "run", url: (l) => `${BASE}/workspace.html?lang=${l}#sample`, run: true },
];
const TABS = ["readiness", "findings", "changes", "report"];

const summary = [];
const page = await browser();
for (const lang of LANGS) {
  for (const size of sizes) {
    const tag = `${size[0]}x${size[1]}`;
    for (const state of STATES) {
      if (state.phone && size[0] >= 768) continue;
      await open(page, state.url(lang), size);
      if (state.act) { await page.evaluate(state.act); await sleep(500); }
      if (!state.run) {
        const fails = await measure(page, `${state.id}-${lang}-${tag}`);
        summary.push({ state: state.id, lang, size: tag, fails });
        continue;
      }
      // The recorded sample: wait until the run is done, then every tab and the report.
      let finished = false;
      for (let i = 0; i < 120 && !finished; i++) {
        await sleep(500);
        finished = await page.evaluate(`!!document.querySelector("#result .verdict")`);
      }
      if (!finished) {
        // A run that never shows its result is itself a failure, never a pass by omission.
        summary.push({ state: "run", lang, size: tag, fails: [{ kind: "load", detail: "the sample run did not finish" }] });
        continue;
      }
      await sleep(800);
      for (const tab of TABS) {
        await page.evaluate(`document.getElementById("tab-${tab}").click(); true`);
        await sleep(600);
        const fails = await measure(page, `run-${tab}-${lang}-${tag}`);
        summary.push({ state: `run-${tab}`, lang, size: tag, fails });
      }
      const report = await page.evaluate(`document.querySelector(".report-lead a[href*='/report']:not([href$='.pdf'])")?.href || [...document.querySelectorAll("a")].map(a => a.href).find(h => /\\/report(\\?|$)/.test(h))`);
      if (report) {
        await open(page, report.split("?")[0] + `?lang=${lang}`, size);
        const fails = await measure(page, `report-${lang}-${tag}`);
        summary.push({ state: "report", lang, size: tag, fails });
      }
    }
    console.log(lang, tag, summary.filter((s) => s.lang === lang && s.size === tag).reduce((n, s) => n + s.fails.length, 0), "geometry failures");
  }
}
page.close();
writeFileSync(join(OUT, "geometry.json"), JSON.stringify(summary, null, 1));
const total = summary.reduce((n, s) => n + s.fails.length, 0);
console.log(`states checked: ${summary.length}, geometry failures: ${total}`);
process.exit(0);
