// LiteLLM-Schwachstellen: lädt vulnerabilities.json und bietet Versions-Check,
// Volltextsuche, Filter, Sortierung und Detailansicht. Inhalte werden nur per
// textContent eingefügt (nie innerHTML), Links nur für http(s)-URLs erzeugt.

const DATA_URL = "vulnerabilities.json";
const PAGE_SIZE = 100;
// Gleiche Felder wie "vulnerabilities.py search"
const SEARCH_FIELDS = ["id", "title", "description", "aliases", "cves", "weakness", "references", "cvssVector"];
const SEVERITY_ORDER = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };
const COLUMNS = ["published", "id", "severity", "title", "fix"];

const $ = (sel) => document.querySelector(sel);
const form = $("#filters");
const rows = $("#rows");
const moreBtn = $("#more");
const collator = new Intl.Collator("de", { numeric: true, sensitivity: "base" });

const state = {
  all: [],
  filtered: [],
  sortKey: "published",
  sortDir: -1,
  shown: PAGE_SIZE,
  expanded: new Set(),
};

// ---------------------------------------------------------------------------
// Versionen (vereinfachtes PEP 440, wie version_key in vulnerabilities.py)
// ---------------------------------------------------------------------------

const VERSION_RE = /^v?(\d+(?:\.\d+)*)(?:[-_.]?(a|b|c|rc|alpha|beta|pre|preview)[-_.]?(\d*))?(?:[-_.]?(post|rev|r)[-_.]?(\d*))?(?:[-_.]?(dev)[-_.]?(\d*))?(?:\+.*)?$/i;
const PRE_RANK = { a: 1, alpha: 1, b: 2, beta: 2, c: 3, rc: 3, pre: 3, preview: 3 };

// Schlüssel als Zahlenliste: dev < a < b < rc < final < post; null = nicht auswertbar
function versionKey(v) {
  const m = VERSION_RE.exec(String(v ?? "").trim());
  if (!m) return null;
  const [, release, pre, preN, post, postN, dev, devN] = m;
  const nums = release.split(".").map(Number);
  while (nums.length > 1 && nums.at(-1) === 0) nums.pop();
  const phase = pre ? PRE_RANK[pre.toLowerCase()] : (dev && !post ? 0 : 4);
  return { nums, rest: [phase, pre ? Number(preN || 0) : 0, post ? Number(postN || 0) + 1 : 0, dev ? 0 : 1, Number(devN || 0)] };
}

function compareKeys(x, y) {
  const len = Math.max(x.nums.length, y.nums.length);
  for (let i = 0; i < len; i++) {
    // Fehlende Stellen sind kleiner (Python-Tupelvergleich), Nullen am Ende sind schon entfernt
    if (x.nums[i] === undefined) return -1;
    if (y.nums[i] === undefined) return 1;
    if (x.nums[i] !== y.nums[i]) return x.nums[i] - y.nums[i];
  }
  for (let i = 0; i < x.rest.length; i++) if (x.rest[i] !== y.rest[i]) return x.rest[i] - y.rest[i];
  return 0;
}

function affects(a, version, key) {
  if ((a.versions ?? []).includes(version)) return true;
  return (a.ranges ?? []).some((r) => {
    const lo = versionKey(r.introduced || "0");
    if (!lo || compareKeys(key, lo) < 0) return false;
    if (r.fixed) {
      const hi = versionKey(r.fixed);
      return !!hi && compareKeys(key, hi) < 0;
    }
    if (r.lastAffected) {
      const hi = versionKey(r.lastAffected);
      return !!hi && compareKeys(key, hi) <= 0;
    }
    return true;
  });
}

// ---------------------------------------------------------------------------
// Laden
// ---------------------------------------------------------------------------

async function load() {
  try {
    const resp = await fetch(DATA_URL, { cache: "no-cache" });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    init(await resp.json());
  } catch (err) {
    $("#meta").textContent = `Laden von ${DATA_URL} fehlgeschlagen: ${err.message}`;
    $("#fallback").hidden = false;
  }
}

$("#fallback input").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  try {
    init(JSON.parse(await file.text()));
    $("#fallback").hidden = true;
  } catch (err) {
    $("#meta").textContent = `Datei ungültig: ${err.message}`;
  }
});

// Zelle Fix: Schadcode, Fix-Versionen oder nur letzte betroffene Version
function fixCell(a) {
  if (a.kind === "malicious") return { kind: "malicious", text: "Release meiden" };
  const fixes = a.fixes ?? [];
  if (fixes.length) return { kind: "fixed", text: fixes.join(", ") + (a.unfixed ? " (+ ohne Fix)" : "") };
  const last = (a.ranges ?? []).map((r) => r.lastAffected).filter(Boolean).at(-1);
  return { kind: "none", text: last ? `keiner (betroffen bis ${last})` : "kein Fix angegeben" };
}

// Absteigend sortiert: Schadcode, ohne Fix, dann höchste Fix-Version
const FIX_RANK = { fixed: 0, none: 1, malicious: 2 };

function init(data) {
  if (!data || !Array.isArray(data.vulnerabilities)) {
    throw new Error("Schlüssel 'vulnerabilities' fehlt");
  }
  state.all = data.vulnerabilities.map((a) => ({
    a,
    text: SEARCH_FIELDS.map((k) => (Array.isArray(a[k]) ? a[k].join(" ") : String(a[k] ?? ""))).join("\n").toLowerCase(),
    sev: SEVERITY_ORDER[String(a.severity).toUpperCase()] ?? -1,
    fix: fixCell(a),
  }));

  const newest = state.all.reduce((m, e) => (String(e.a.published) > m ? String(e.a.published) : m), "");
  const latest = data.latestVersion ? ` · neueste PyPI-Version ${data.latestVersion}` : "";
  $("#meta").textContent = `${state.all.length} Einträge · neuester vom ${newest || "?"}${latest} · Quelle: osv.dev (PyPI litellm)`;

  const bad = [...new Set(state.all.filter((e) => e.a.kind === "malicious").flatMap((e) => e.a.versions?.length
    ? e.a.versions
    : (e.a.ranges ?? []).flatMap((r) => [r.introduced, r.lastAffected]).filter(Boolean)))]
    .sort((x, y) => collator.compare(x, y));
  if (bad.length) {
    $("#malware-versions").replaceChildren(...bad.flatMap((v, i) => [i ? ", " : "", el("code", { textContent: v })]));
    $("#malware").hidden = false;
  }

  readUrl();
  apply();
}

// ---------------------------------------------------------------------------
// Filtern / Sortieren
// ---------------------------------------------------------------------------

// Suchbegriffe trennen; "mehrere Wörter" in Anführungszeichen bleiben zusammen
function parseTerms(q) {
  return [...q.toLowerCase().matchAll(/"([^"]+)"|(\S+)/g)].map((m) => m[1] ?? m[2]);
}

function sortValue(entry, key) {
  if (key === "severity") return String(entry.sev);
  if (key === "fix") return `${FIX_RANK[entry.fix.kind]} ${entry.a.fixes?.at(-1) ?? ""}`;
  return String(entry.a[key] ?? "");
}

function apply() {
  const f = Object.fromEntries(new FormData(form));
  const terms = parseTerms(f.q ?? "");
  const minSev = f.severity ? SEVERITY_ORDER[f.severity] : -1;
  const version = String(f.version ?? "").trim();
  const vkey = version ? versionKey(version) : null;

  state.filtered = state.all.filter(({ a, text, sev, fix }) => {
    if (f.kind && a.kind !== f.kind) return false;
    if (sev < minSev) return false;
    // ISO-Daten (YYYY-MM-DD) lassen sich als Strings vergleichen
    if (f.since && String(a.published ?? "") < f.since) return false;
    if (f.until && String(a.published ?? "") > f.until) return false;
    if (f.unfixed === "on" && fix.kind !== "none" && !a.unfixed) return false;
    if (vkey && !affects(a, version, vkey)) return false;
    return terms.every((t) => text.includes(t));
  });

  const check = $("#check");
  check.hidden = !version;
  if (version && !vkey) {
    check.className = "";
    check.textContent = `Version „${version}“ nicht auswertbar (erwartet z. B. 1.82.7 oder 1.83.0rc1).`;
  } else if (vkey) {
    const n = state.filtered.length;
    const malicious = state.filtered.some((e) => e.a.kind === "malicious");
    check.className = n ? "hit" : "ok";
    check.textContent = n
      ? `litellm ${version} ist von ${n} Einträgen betroffen${malicious ? " — darunter SCHADCODE: System als kompromittiert behandeln" : ""}.`
      : `litellm ${version}: keine bekannten Einträge (bei den übrigen Filtern).`;
  }

  const { sortKey, sortDir } = state;
  state.filtered.sort((x, y) =>
    collator.compare(sortValue(x, sortKey), sortValue(y, sortKey)) * sortDir ||
    collator.compare(String(y.a.id), String(x.a.id)));

  state.shown = PAGE_SIZE;
  render();
  writeUrl();
}

// ---------------------------------------------------------------------------
// Darstellung
// ---------------------------------------------------------------------------

function el(tag, props = {}, ...children) {
  const node = Object.assign(document.createElement(tag), props);
  node.append(...children.filter((c) => c != null));
  return node;
}

function link(href, text = href) {
  // Nur http(s) verlinken — alles andere bleibt Text
  if (!/^https?:\/\//i.test(String(href))) return document.createTextNode(String(text));
  return el("a", { href, target: "_blank", rel: "noopener noreferrer", textContent: text });
}

function sevBadge(severity) {
  const s = String(severity ?? "").toUpperCase();
  return el("span", { className: `sev sev-${s in SEVERITY_ORDER ? s : "NONE"}`, textContent: s || "?" });
}

function buildRow({ a, fix }) {
  const tr = el("tr", { className: "row", tabIndex: 0 },
    el("td", { textContent: a.published ?? "" }),
    el("td", {}, link(a.url, a.id)),
    el("td", {}, sevBadge(a.severity)),
    el("td", {}, a.title ?? "", a.kind === "malicious" ? el("span", { className: "kind", textContent: "SCHADCODE" }) : null),
    el("td", { className: `fix fix-${fix.kind}`, textContent: fix.text }),
  );
  tr.dataset.id = a.id;
  tr.setAttribute("aria-expanded", "false");
  return tr;
}

function rangesTable(a) {
  const head = el("tr", {}, ...["betroffen ab", "betroffen bis", "Fix"].map((t) => el("th", { textContent: t })));
  const body = (a.ranges ?? []).map((r) => el("tr", {},
    el("td", { textContent: !r.introduced || r.introduced === "0" ? "allen Versionen" : r.introduced }),
    el("td", { textContent: r.fixed ? `< ${r.fixed}` : r.lastAffected ? `≤ ${r.lastAffected}` : "offen" }),
    r.fixed
      ? el("td", { textContent: r.fixed })
      : el("td", { className: "nofix", textContent: "keiner angegeben" })));
  return el("table", {}, el("thead", {}, head), el("tbody", {}, ...body));
}

function buildDetail({ a }) {
  const dl = el("dl");
  const add = (label, value, className = "") => {
    if (value == null || value === "" || (Array.isArray(value) && !value.length)) return;
    dl.append(el("dt", { textContent: label }),
      value instanceof Node ? el("dd", {}, value) : el("dd", { className, textContent: Array.isArray(value) ? value.join(", ") : value }));
  };
  add("Beschreibung", a.description, "text");
  add("Betroffene Releases", a.versions);
  add("Versionsbereiche", a.ranges?.length ? rangesTable(a) : null);
  add("CVSS", a.cvssVector);
  add("CVE", a.cves);
  add("Aliase", a.aliases?.length ? el("span", {}, ...a.aliases.flatMap((id, i) =>
    [i ? ", " : "", link(`https://osv.dev/vulnerability/${encodeURIComponent(id)}`, id)])) : null);
  add("CWE", a.weakness);
  add("Geändert", a.modified);
  add("Referenzen", a.references?.length ? el("ul", {}, ...a.references.map((r) => el("li", {}, link(r)))) : null);
  return el("tr", { className: "detail" }, el("td", { colSpan: COLUMNS.length }, dl));
}

function render() {
  const frag = document.createDocumentFragment();
  for (const entry of state.filtered.slice(0, state.shown)) {
    const tr = buildRow(entry);
    frag.append(tr);
    if (state.expanded.has(tr.dataset.id)) {
      tr.setAttribute("aria-expanded", "true");
      frag.append(buildDetail(entry));
    }
  }
  rows.replaceChildren(frag);

  for (const th of document.querySelectorAll("thead th")) {
    const active = th.dataset.key === state.sortKey;
    th.setAttribute("aria-sort", active ? (state.sortDir > 0 ? "ascending" : "descending") : "none");
  }

  const total = state.filtered.length;
  const shown = Math.min(state.shown, total);
  $("#status").textContent = `${total} von ${state.all.length} Einträgen` + (shown < total ? ` · ${shown} angezeigt` : "");
  const remaining = total - shown;
  moreBtn.hidden = remaining <= 0;
  moreBtn.textContent = `Weitere ${Math.min(PAGE_SIZE, remaining)} anzeigen (${remaining} übrig)`;
}

function toggleRow(tr) {
  const id = tr.dataset.id;
  const entry = state.filtered.find((e) => String(e.a.id) === id);
  if (!entry) return;
  if (state.expanded.delete(id)) {
    tr.setAttribute("aria-expanded", "false");
    if (tr.nextElementSibling?.classList.contains("detail")) tr.nextElementSibling.remove();
  } else {
    state.expanded.add(id);
    tr.setAttribute("aria-expanded", "true");
    tr.after(buildDetail(entry));
  }
}

// ---------------------------------------------------------------------------
// URL-Zustand (Filter und Sortierung teilbar per Link)
// ---------------------------------------------------------------------------

function writeUrl() {
  const params = new URLSearchParams();
  for (const [k, val] of new FormData(form)) if (val) params.set(k, val);
  if (state.sortKey !== "published" || state.sortDir !== -1) {
    params.set("sort", state.sortKey);
    params.set("dir", state.sortDir > 0 ? "asc" : "desc");
  }
  const qs = params.toString();
  history.replaceState(null, "", qs ? `?${qs}` : location.pathname);
}

function readUrl() {
  const params = new URLSearchParams(location.search);
  for (const field of form.elements) {
    if (!field.name || !params.has(field.name)) continue;
    if (field.type === "checkbox") field.checked = params.get(field.name) === "on";
    else field.value = params.get(field.name);
  }
  if (COLUMNS.includes(params.get("sort"))) {
    state.sortKey = params.get("sort");
    state.sortDir = params.get("dir") === "asc" ? 1 : -1;
  }
}

// ---------------------------------------------------------------------------
// Ereignisse
// ---------------------------------------------------------------------------

let debounce;
form.addEventListener("input", () => {
  clearTimeout(debounce);
  debounce = setTimeout(apply, 150);
});
form.addEventListener("submit", (e) => e.preventDefault());
// reset-Event feuert, bevor die Felder geleert sind
form.addEventListener("reset", () => setTimeout(apply));

document.querySelector("thead").addEventListener("click", (e) => {
  const th = e.target.closest("th[data-key]");
  if (!th) return;
  const key = th.dataset.key;
  // Neue Spalte: Datum, Severity und Fix absteigend, Textspalten aufsteigend beginnen
  state.sortDir = key === state.sortKey ? -state.sortDir : (["published", "severity", "fix"].includes(key) ? -1 : 1);
  state.sortKey = key;
  apply();
});

rows.addEventListener("click", (e) => {
  if (e.target.closest("a")) return;
  const tr = e.target.closest("tr.row");
  if (tr) toggleRow(tr);
});
rows.addEventListener("keydown", (e) => {
  if ((e.key === "Enter" || e.key === " ") && e.target.matches("tr.row")) {
    e.preventDefault();
    toggleRow(e.target);
  }
});

moreBtn.addEventListener("click", () => {
  state.shown += PAGE_SIZE;
  render();
});

load();
