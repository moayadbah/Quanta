const $ = (id) => document.getElementById(id);
const english = Object.fromEntries(
  [...document.querySelectorAll("[data-i18n]")].map((el) => [
    el.dataset.i18n,
    el.textContent,
  ]),
);
const arabic = {
  skip: "انتقل إلى مساحة العمل",
  workspace: "مساحة العمل",
  approach: "طريقتنا",
  signin: "الدخول عبر GitHub",
  signout: "تسجيل الخروج",
  eyebrow: "رؤية أوضح للتشفير في مشروعك",
  hero1: "افهم تشفيرك.",
  hero2: "اختر خطوتك القادمة.",
  intro:
    "اكتشف مواضع التشفير في الكود، وافهم ما يعتمد عليها، وحوّل التعديل الذي تختاره إلى طلب دمج.",
  start: "استكشف مستودعك",
  sample: "جرّب فحصاً توضيحياً",
  heroNote: "مفتوح المصدر. يبدأ بـ Python. لا يُنفّذ الكود الخاص بك.",
  specimen: "تعديل واحد. رؤية كاملة.",
  yourWorkspace: "مساحة عملك",
  workspaceTitle: "ابدأ برؤية أوضح.",
  publicPython: "مستودعات Python العامة",
  repoLabel: "مستودع GitHub",
  scanHelp: "كل ما تحتاجه رابط مستودع عام.",
  scan: "افحص المستودع",
  signinNote:
    "سجّل الدخول عبر GitHub لفحص المستودعات وحفظ نتائجك في مكان واحد. الوصول إلى المستودعات العامة فقط.",
  freeAccess: "استخدام مجاني",
  limited: "بحدود استخدام",
  scansToday: "عمليات فحص / يوم",
  allowanceNote: "الحصة الشهرية المشتركة تتيح بقاء Quanta مجانياً للجميع.",
  quotaDefault: "50 فحصاً مشتركاً شهرياً · التوقيت العالمي UTC",
  scanning: "الفحص جارٍ",
  looking: "نتعرّف على مستودعك.",
  scanDetail: "نثبّت نسخة الكود، ونتتبّع المصدر، ونجهّز تقريرك.",
  scanComplete: "اكتمل الفحص",
  download: "تنزيل بيانات التقرير",
  fullReport: "التقرير الكامل ↗",
  agility: "مرونة التشفير",
  scoreNote: "مدى سهولة تغيير البنية. هذه ليست درجة أمان.",
  files: "ملفات Python فُحصت",
  sites: "مواضع استدعاء التشفير",
  fixesAvailable: "تعديلات قابلة للمراجعة",
  fixesTab: "التعديلات المقترحة",
  findingsTab: "ملاحظات البنية",
  factorsTab: "تفاصيل الدرجة",
  fixTitle: "تعديلات محددة. بمراجعة متأنية.",
  fixIntro:
    "اختر تحسينات التجزئة التي تريد مراجعتها. تحقق من التوافق قبل دمج أي تعديل.",
  review: "راجع التعديلات المختارة",
  validation:
    "تم التحقق من صياغة Python. لا تُشغّل اختبارات المستودع أثناء الفحص.",
  factorIntro:
    "أربع إشارات بنيوية تشكّل الدرجة. القيم الأعلى تعني مرونة أكبر، وليس تشفيراً أقوى.",
  recent: "عمليات الفحص الأخيرة",
  retention: "تُحفظ النتائج لمدة 7 أيام",
  emptyTitle: "رؤيتك القادمة تبدأ هنا.",
  emptyDescription: "أدخل رابط مستودع أعلاه، أو استكشف الأداة بمثال عملي.",
  sampleArrow: "استكشف المثال ↗",
  approachEyebrow: "من الفهم إلى العمل",
  approachTitle: "خطوة مدروسة إلى الأمام.",
  approachDescription: "أدلة مفيدة. تعديلات محددة. وأنت تقرر ما يُنشر.",
  principle1: "اكتشف الروابط.",
  principle1Body:
    "اعثر على استدعاءات التشفير والكود الذي يعتمد عليها، مع مراجع للملفات والأسطر يمكنك تتبّعها.",
  principle2: "راجع كل تعديل.",
  principle2Body:
    "اطّلع على الفروقات الفعلية لتحسينات التجزئة المدعومة. ترحيل المفاتيح والشهادات والبروتوكولات يحتاج قراراً مدروساً.",
  principle3: "حوّله إلى طلب دمج.",
  principle3Body:
    "افتح مسودة طلب دمج للتعديلات التي راجعتها. شغّل اختباراتك، وتحقق من التوافق، ثم ادمج عندما تكون جاهزاً.",
  closing: "لنمنح الكود المعقّد شيئاً من الوضوح.",
  source: "استكشف المصدر ↗",
  footer: "وضوح، بعناية.",
  privacy: "الخصوصية",
  reviewEyebrow: "تعديلاتك، قبل النشر",
  reviewTitle: "ألقِ نظرة أقرب.",
  compatibilityTitle: "تحقق من التوافق قبل الدمج.",
  compatibilityBody:
    "يغيّر SHA-256 قيم التجزئة وطولها. راجع القيم المخزنة والتوقيعات والبروتوكولات وبيانات الاختبار والأنظمة التي تستخدمها. هذه ليست طريقة لتجزئة كلمات المرور.",
  acknowledge: "راجعت الفروقات وأفهم أثرها على التوافق.",
  openPr: "افتح مسودة طلب دمج ↗",
  viewPr: "عرض طلب الدمج ↗",
};
const state = {
  lang: "en",
  session: null,
  workspace: null,
  result: null,
  id: null,
  selected: new Set(),
  review: null,
  generation: 0,
  polling: null,
  runs: new Set(),
  loading: false,
  reviewVersion: 0,
};
try {
  state.lang = localStorage.getItem("quanta-language") === "ar" ? "ar" : "en";
} catch {}
const tr = (en, ar) => (state.lang === "ar" ? ar : en);
const node = (tag, cls, text) => {
  const el = document.createElement(tag);
  if (cls) el.className = cls;
  if (text !== undefined) el.textContent = text;
  return el;
};
const show = (id, visible = true) => {
  $(id).hidden = !visible;
};
function error(message, id = "error") {
  $(id).textContent = message;
  show(id, Boolean(message));
}
function language() {
  document.documentElement.lang = state.lang;
  document.documentElement.dir = state.lang === "ar" ? "rtl" : "ltr";
  document.querySelectorAll("[data-i18n]").forEach((el) => {
    el.textContent =
      (state.lang === "ar" ? arabic : english)[el.dataset.i18n] ||
      english[el.dataset.i18n];
  });
  $("language").textContent = state.lang === "ar" ? "EN" : "عربي";
  $("language").ariaLabel =
    state.lang === "ar" ? "Switch to English" : "التبديل إلى العربية";
  $("close-review").ariaLabel = tr("Close review", "إغلاق المراجعة");
  if (state.session) renderAccount();
  if (state.workspace) renderWorkspace();
  if (state.result) renderResult();
  if (state.review) renderReview();
}
async function api(path, body) {
  const options = {
    credentials: "same-origin",
    headers: { Accept: "application/json" },
  };
  if (body !== undefined) {
    options.method = "POST";
    options.headers["Content-Type"] = "application/json";
    options.headers["X-CSRF-Token"] = state.session?.csrf_token || "";
    options.body = JSON.stringify(body);
  }
  let response;
  try {
    response = await fetch(path, options);
  } catch {
    throw new Error(
      tr(
        "Connection interrupted. Please try again.",
        "انقطع الاتصال. حاول مجدداً.",
      ),
    );
  }
  let data;
  try {
    data = await response.json();
  } catch {
    throw new Error(
      tr(
        "The service is unavailable. Please try again shortly.",
        "الخدمة غير متاحة. حاول بعد قليل.",
      ),
    );
  }
  if (!response.ok) {
    const err = new Error(
      data.detail ||
        tr("Something went wrong. Please try again.", "حدث خطأ. حاول مجدداً."),
    );
    err.code = data.error_code;
    throw err;
  }
  return data;
}
function renderAccount() {
  const session = state.session;
  const signed = Boolean(session.user);
  show("nav-signin", !signed);
  show("signout", signed);
  show("signin-note", !signed && session.required);
  $("account-label").textContent = signed
    ? "@" + session.user.login
    : tr("Public Python repositories", "مستودعات Python العامة");
  const label = state.loading
    ? tr("Starting scan…", "بدء الفحص…")
    : !signed && session.required
      ? tr("Sign in to scan ↗", "سجّل الدخول للفحص ↗")
      : tr("Scan repository ↗", "افحص المستودع ↗");
  $("scan-button").textContent = label;
  $("scan-button").disabled = state.loading;
}
function renderWorkspace() {
  const { usage, limits, jobs, scan_available } = state.workspace;
  $("daily-left").textContent = usage
    ? Math.max(0, usage.daily_limit - usage.daily_used)
    : limits.daily;
  $("quota-fill").style.width =
    (usage
      ? Math.min(100, (100 * usage.monthly_used) / usage.monthly_limit)
      : 0) + "%";
  $("quota-label").textContent = usage
    ? tr(
        `${Math.max(0, usage.monthly_limit - usage.monthly_used)} of ${usage.monthly_limit} shared scans left this month`,
        `${Math.max(0, usage.monthly_limit - usage.monthly_used)} من ${usage.monthly_limit} فحصاً متبقية هذا الشهر`,
      )
    : tr(
        `${limits.monthly} shared scans per month · resets in UTC`,
        `${limits.monthly} فحصاً مشتركاً شهرياً · التوقيت العالمي UTC`,
      );
  if (state.session?.required && !scan_available) {
    $("service-notice").textContent = tr(
      "Live scanning is temporarily unavailable. You can explore the complete review flow with the sample below.",
      "الفحص المباشر غير متاح مؤقتاً. يمكنك تجربة مسار المراجعة الكامل بالمثال أدناه.",
    );
    show("service-notice");
  } else show("service-notice", false);
  show("history-section", jobs.length > 0);
  $("history-list").replaceChildren();
  jobs.forEach((job) => {
    const row = node("button", "history-row");
    row.type = "button";
    const repo = node(
      "span",
      "history-repo",
      job.repo_url.replace("https://github.com/", ""),
    );
    repo.dir = "ltr";
    row.append(
      repo,
      node("span", "history-state", statusLabel(job.status)),
      node(
        "span",
        "history-date",
        new Date(job.created_at * 1000).toLocaleDateString(
          state.lang === "ar" ? "ar-SA" : "en",
          { month: "short", day: "numeric" },
        ),
      ),
      node("span", "history-arrow", "↗"),
    );
    row.addEventListener("click", () => openJob(job.job_id));
    $("history-list").append(row);
  });
}
function statusLabel(status) {
  return (
    {
      queued: tr("Queued", "في الانتظار"),
      running: tr("Scanning", "جارٍ الفحص"),
      succeeded: tr("Complete", "مكتمل"),
      failed: tr("Failed", "لم يكتمل"),
      timeout: tr("Timed out", "انتهت المهلة"),
    }[status] || status
  );
}
async function refreshWorkspace() {
  state.workspace = await api("/api/v1/workspace");
  renderWorkspace();
}
function progress(data) {
  $("activity-status").textContent = statusLabel(data.status || "running");
  const phases = {
    acquire: tr("Getting a fresh copy of your code.", "نجلب نسخة من الكود."),
    clone: tr("Getting a fresh copy of your code.", "نجلب نسخة من الكود."),
    analyze: tr(
      "Following the cryptography through your code.",
      "نتتبّع التشفير في الكود.",
    ),
    parse: tr("Reading the Python source.", "نقرأ ملفات Python."),
    graph: tr("Connecting the dependencies.", "نربط الاعتماديات."),
    score: tr("Measuring architectural flexibility.", "نقيس مرونة البنية."),
    render: tr("Preparing your results.", "نجهّز نتائجك."),
  };
  $("activity-title").textContent =
    data.status === "queued"
      ? tr("Your scan is in the queue.", "فحصك في قائمة الانتظار.")
      : phases[data.phase] ||
        tr("Getting to know your repository.", "نتعرّف على مستودعك.");
  const pct = Math.min(100, Math.max(0, data.progress || 0));
  $("progress-label").textContent = pct + "%";
  $("progress-fill").style.width = pct + "%";
}
function resetResult(id) {
  state.generation++;
  clearTimeout(state.polling);
  state.id = id;
  state.result = null;
  state.selected.clear();
  state.review = null;
  state.reviewVersion++;
  show("results", false);
  show("empty-workspace", false);
  error("");
}
async function startScan(event) {
  event.preventDefault();
  if (state.loading) return;
  const url = $("repo-url").value.trim();
  if (
    !/^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/?$/.test(url)
  ) {
    error(
      tr(
        "Use a public GitHub repository URL, like https://github.com/owner/repository.",
        "استخدم رابط مستودع GitHub عام مثل https://github.com/owner/repository.",
      ),
    );
    return;
  }
  if (!state.session?.user && state.session?.required) {
    if (!state.session.configured) {
      error(
        tr(
          "GitHub sign-in is temporarily unavailable. Try the sample scan.",
          "الدخول عبر GitHub غير متاح مؤقتاً. جرّب المثال.",
        ),
      );
      return;
    }
    try {
      sessionStorage.setItem("quanta-pending-repo", url);
    } catch {}
    location.assign("/auth/login");
    return;
  }
  state.loading = true;
  renderAccount();
  error("");
  try {
    const job = await api("/api/v1/analyses", { repo_url: url });
    await openJob(job.job_id);
    await refreshWorkspace();
  } catch (err) {
    error(err.message);
  } finally {
    state.loading = false;
    renderAccount();
  }
}
async function openJob(id) {
  if (!/^[a-f0-9-]{36}$/.test(id)) return;
  resetResult(id);
  history.replaceState(null, "", `#analysis/${id}`);
  show("activity");
  progress({ status: "queued" });
  const generation = state.generation;
  const tick = async () => {
    try {
      const data = await api(`/api/v1/analyses/${id}`);
      if (generation !== state.generation) return;
      if (data.status === "succeeded") {
        await loadResult(id, generation);
        return;
      }
      if (["failed", "timeout"].includes(data.status)) {
        show("activity", false);
        error(
          data.detail ||
            tr(
              "This scan could not finish. Try a smaller repository.",
              "لم يكتمل الفحص. جرّب مستودعاً أصغر.",
            ),
        );
        refreshWorkspace().catch(() => {});
        return;
      }
      progress(data);
      if (
        data.status === "queued" &&
        state.workspace?.hosted &&
        !state.runs.has(id)
      ) {
        state.runs.add(id);
        api(`/api/v1/analyses/${id}/run`, {})
          .catch((err) => {
            if (generation === state.generation) error(err.message);
          })
          .finally(() => state.runs.delete(id));
      }
    } catch (err) {
      if (generation !== state.generation) return;
      if (["AUTH_REQUIRED", "REPO_NOT_FOUND"].includes(err.code)) {
        show("activity", false);
        error(err.message);
        return;
      }
      $("activity-detail").textContent = tr(
        "Connection interrupted. Reconnecting to your saved scan…",
        "انقطع الاتصال. نعيد الاتصال بفحصك المحفوظ…",
      );
    }
    if (generation === state.generation) state.polling = setTimeout(tick, 3000);
  };
  await tick();
  $("workspace").scrollIntoView({ behavior: "smooth", block: "start" });
}
async function loadResult(id, generation) {
  const [score, meta, fixes] = await Promise.all([
    api(`/api/v1/analyses/${id}/score`),
    api(`/api/v1/analyses/${id}/meta`),
    api(`/api/v1/analyses/${id}/fixes`),
  ]);
  if (generation !== state.generation) return;
  state.result = {
    score,
    meta,
    fixes,
    sample: false,
    repo: score.provenance.repo,
  };
  show("activity", false);
  renderResult();
  refreshWorkspace().catch(() => {});
}
async function sample() {
  resetResult("sample");
  const generation = state.generation;
  show("activity");
  progress({ status: "running" });
  history.replaceState(null, "", "#sample");
  try {
    const result = await api("/api/v1/sample");
    if (generation !== state.generation) return;
    state.result = result;
    show("activity", false);
    renderResult();
    $("results").scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (err) {
    show("activity", false);
    error(err.message);
  }
}
function renderResult() {
  const result = state.result;
  if (!result) return;
  show("results");
  show("empty-workspace", false);
  $("result-kind").textContent = result.sample
    ? tr(
        "WORKING SAMPLE · NO LIVE REPOSITORY",
        "مثال عملي · ليس مستودعاً مباشراً",
      )
    : tr("SCAN COMPLETE", "اكتمل الفحص");
  $("result-title").textContent = result.repo;
  $("result-provenance").textContent = result.sample
    ? tr(
        "An intentionally simple Python project. All figures are computed by the real analyzer.",
        "مشروع Python توضيحي. جميع النتائج محسوبة بالمحلّل الفعلي.",
      )
    : tr("Commit ", "النسخة ") +
      result.score.provenance.commit_sha.slice(0, 12) +
      " · " +
      result.meta.files_scanned +
      " " +
      tr("files scanned", "ملفات مفحوصة");
  $("score").textContent = Number(result.score.agility_score).toFixed(1);
  $("files-scanned").textContent = result.meta.files_scanned;
  $("sites-detected").textContent = result.meta.sites_detected;
  const count = result.fixes.files.reduce(
    (sum, file) => sum + file.changes.length,
    0,
  );
  $("fix-count").textContent = count;
  show("full-report", !result.sample);
  $("full-report").href = result.sample
    ? "#"
    : `/api/v1/analyses/${state.id}/report`;
  const partial =
    result.score.coverage.truncated ||
    result.score.coverage.files_unparseable ||
    result.fixes.limited;
  show("coverage-note", Boolean(partial));
  $("coverage-note").textContent = tr(
    "Partial coverage: some files or proposals were skipped because of size or parsing limits. Review the downloaded report for details.",
    "تغطية جزئية: تم تجاوز بعض الملفات أو المقترحات بسبب حدود الحجم أو التحليل. راجع التقرير المنزّل للتفاصيل.",
  );
  renderFixes();
  renderFindings();
  renderFactors();
}
function renderFixes() {
  const container = $("fix-list");
  container.replaceChildren();
  for (const file of state.result.fixes.files) {
    const group = node("div", "fix-file");
    group.append(node("div", "file-title", file.path));
    for (const change of file.changes) {
      const row = node("label", "fix-row");
      const input = node("input");
      input.type = "checkbox";
      input.value = change.id;
      input.checked = state.selected.has(change.id);
      input.addEventListener("change", () => {
        input.checked
          ? state.selected.add(change.id)
          : state.selected.delete(change.id);
        state.review = null;
        state.reviewVersion++;
        $("review-button").disabled = !state.selected.size;
      });
      const copy = node("div");
      copy.append(
        node("strong", "", tr("Upgrade to SHA-256", "الترقية إلى SHA-256")),
      );
      const code = node("div", "fix-code");
      code.append(
        document.createTextNode(change.before + " → "),
        node("span", "", change.after),
      );
      copy.append(code);
      row.append(input, copy, node("span", "fix-line", "L" + change.line));
      group.append(row);
    }
    container.append(group);
  }
  if (!state.result.fixes.files.length)
    container.append(
      node(
        "div",
        "empty-fixes",
        tr(
          "No supported hash upgrades were found. This does not mean the repository is secure or quantum-ready. Explore the architecture findings for other next steps.",
          "لم نعثر على تحسينات تجزئة مدعومة. هذا لا يعني أن المستودع آمن أو جاهز للحوسبة الكمية. راجع ملاحظات البنية لخطوات أخرى.",
        ),
      ),
    );
  $("review-button").disabled = !state.selected.size;
}
function renderFindings() {
  const list = $("finding-list");
  list.replaceChildren();
  for (const finding of state.result.score.deductions) {
    const item = node("article", "finding");
    item.append(node("p", "", finding.reason));
    const citations = node("div", "citations");
    for (const citation of finding.citations.slice(0, 10)) {
      const match = citation.match(/^(.+):(\d+)$/);
      const link = node(state.result.sample ? "span" : "a", "", citation);
      if (!state.result.sample && match) {
        link.href = `https://github.com/${state.result.repo}/blob/${state.result.score.provenance.commit_sha}/${match[1].split("/").map(encodeURIComponent).join("/")}#L${match[2]}`;
        link.target = "_blank";
        link.rel = "noopener";
      }
      citations.append(link);
    }
    item.append(citations);
    list.append(item);
  }
  if (!state.result.score.deductions.length)
    list.append(
      node(
        "p",
        "empty-fixes",
        tr(
          "No architecture deductions were recorded for the scanned files. This is not a security certification.",
          "لم تُسجّل خصومات بنيوية للملفات المفحوصة. هذه ليست شهادة أمان.",
        ),
      ),
    );
}
function renderFactors() {
  const names = {
    call_sites: tr("Crypto concentration", "تركيز التشفير"),
    isolation_layer: tr("Isolation", "العزل"),
    selection_source: tr("Configuration", "الإعدادات"),
    propagation_depth: tr("Change propagation", "انتشار التغيير"),
  };
  const list = $("factor-list");
  list.replaceChildren();
  for (const [key, factor] of Object.entries(state.result.score.factors)) {
    const row = node("div", "factor-row");
    const label = node("div", "factor-name", names[key] || key);
    label.append(
      node(
        "span",
        "",
        `${Math.round(factor.weight * 100)}% ` +
          tr("of total score", "من الدرجة الكلية"),
      ),
    );
    const bar = node("div", "factor-bar");
    const fill = node("div");
    fill.style.width = factor.normalised * 100 + "%";
    bar.append(fill);
    row.append(
      label,
      bar,
      node("span", "factor-value", Math.round(factor.normalised * 100) + "%"),
    );
    list.append(row);
  }
}
async function prepareReview() {
  const version = ++state.reviewVersion;
  const id = state.id;
  const selected = [...state.selected];
  $("review-button").disabled = true;
  error("");
  try {
    const result = await api(
      id === "sample"
        ? "/api/v1/sample/review"
        : `/api/v1/analyses/${id}/review`,
      { selected },
    );
    if (version !== state.reviewVersion || id !== state.id) return;
    state.review = result;
    $("review-ack").checked = false;
    show("pr-link", false);
    show("open-pr");
    error("", "review-error");
    renderReview();
    $("review-dialog").showModal();
  } catch (err) {
    error(err.message);
  } finally {
    $("review-button").disabled = !state.selected.size;
  }
}
function renderReview() {
  const list = $("diff-list");
  list.replaceChildren();
  for (const file of state.review.files) {
    const item = node("div", "diff-file");
    item.append(node("div", "file-title", file.path));
    const pre = node("pre");
    for (const line of file.diff.split("\n")) {
      const cls =
        line.startsWith("+++") ||
        line.startsWith("---") ||
        line.startsWith("@@")
          ? "diff-meta"
          : line.startsWith("+")
            ? "diff-plus"
            : line.startsWith("-")
              ? "diff-minus"
              : "";
      pre.append(node("span", "diff-line " + cls, line));
    }
    item.append(pre);
    list.append(item);
  }
  $("open-pr").disabled = !$("review-ack").checked || state.id === "sample";
  if (state.id === "sample")
    error(
      tr(
        "This is a sample. Scan a public repository to open a real pull request.",
        "هذا مثال توضيحي. افحص مستودعاً عاماً لفتح طلب دمج فعلي.",
      ),
      "review-error",
    );
}
async function openPr() {
  if (!state.review || !$("review-ack").checked || state.id === "sample")
    return;
  $("open-pr").disabled = true;
  $("close-review").disabled = true;
  error("", "review-error");
  const review = state.review,
    id = state.id;
  $("open-pr").textContent = tr("Preparing pull request…", "نجهّز طلب الدمج…");
  try {
    const result = await api(`/api/v1/analyses/${id}/pull-request`, {
      selected: review.selected,
      digest: review.digest,
    });
    if (state.id !== id || state.review !== review) return;
    if (
      !/^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/pull\/\d+$/.test(
        result.url,
      )
    )
      throw new Error(
        tr(
          "The pull request link could not be verified.",
          "تعذّر التحقق من رابط طلب الدمج.",
        ),
      );
    $("pr-link").href = result.url;
    show("pr-link");
    show("open-pr", false);
  } catch (err) {
    error(err.message, "review-error");
  } finally {
    $("open-pr").disabled = !$("review-ack").checked;
    $("close-review").disabled = false;
    $("open-pr").textContent = tr(
      "Open draft pull request ↗",
      "افتح مسودة طلب دمج ↗",
    );
  }
}
function download() {
  if (!state.result) return;
  const blob = new Blob([JSON.stringify(state.result, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const a = node("a");
  a.href = url;
  a.download = "quanta-report.json";
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
$("language").addEventListener("click", () => {
  state.lang = state.lang === "en" ? "ar" : "en";
  try {
    localStorage.setItem("quanta-language", state.lang);
  } catch {}
  language();
});
$("scan-form").addEventListener("submit", startScan);
document
  .querySelectorAll(".sample-button")
  .forEach((button) => button.addEventListener("click", sample));
$("review-button").addEventListener("click", prepareReview);
$("close-review").addEventListener("click", () => $("review-dialog").close());
$("review-ack").addEventListener("change", () => {
  $("open-pr").disabled = !$("review-ack").checked || state.id === "sample";
});
$("open-pr").addEventListener("click", openPr);
$("download").addEventListener("click", download);
$("nav-signin").addEventListener("click", (event) => {
  if (state.session && !state.session.configured) {
    event.preventDefault();
    error(
      tr(
        "GitHub sign-in is temporarily unavailable. Try the sample scan.",
        "الدخول عبر GitHub غير متاح مؤقتاً. جرّب المثال.",
      ),
    );
    $("workspace").scrollIntoView({ behavior: "smooth" });
  }
});
$("signout").addEventListener("click", async () => {
  try {
    await api("/auth/logout", {});
    location.assign("/");
  } catch (err) {
    error(err.message);
  }
});
const tabs = [...document.querySelectorAll("[role=tab]")];
function activateTab(tab) {
  tabs.forEach((other) => {
    const selected = other === tab;
    other.setAttribute("aria-selected", String(selected));
    other.tabIndex = selected ? 0 : -1;
    show(other.dataset.tab, selected);
  });
}
tabs.forEach((tab, index) => {
  tab.tabIndex = index === 0 ? 0 : -1;
  tab.addEventListener("click", () => activateTab(tab));
  tab.addEventListener("keydown", (event) => {
    if (["ArrowRight", "ArrowLeft", "Home", "End"].includes(event.key)) {
      event.preventDefault();
      let next =
        event.key === "Home"
          ? 0
          : event.key === "End"
            ? tabs.length - 1
            : (index + (event.key === "ArrowRight" ? 1 : -1) + tabs.length) %
              tabs.length;
      activateTab(tabs[next]);
      tabs[next].focus();
    }
  });
});
async function init() {
  language();
  try {
    const [session, workspace] = await Promise.all([
      api("/auth/session"),
      api("/api/v1/workspace"),
    ]);
    state.session = session;
    state.workspace = workspace;
    renderAccount();
    renderWorkspace();
    try {
      const pending = sessionStorage.getItem("quanta-pending-repo");
      if (pending) {
        $("repo-url").value = pending;
        sessionStorage.removeItem("quanta-pending-repo");
      }
    } catch {}
    const match = location.hash.match(/^#analysis\/([a-f0-9-]{36})$/);
    if (match) await openJob(match[1]);
    else if (location.hash === "#sample") await sample();
  } catch (err) {
    error(err.message);
  }
}
init();
