// Node.js-Schwachstellen: lädt vulnerabilities.json und bietet Filter,
// Volltextsuche, Sortierung und Detailansicht. Inhalte werden nur per
// textContent eingefügt (nie innerHTML), Links nur für http(s)-URLs erzeugt.

const DATA_URL = "vulnerabilities.json";
const PAGE_SIZE = 100;
// Gleiche Felder wie "vulnerabilities.py search"
const SEARCH_FIELDS = ["id", "title", "description", "vulnerable", "patched", "affectedLines", "reportedBy", "nswg"];
const SEVERITY_ORDER = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };
const COLUMNS = ["published", "id", "severity", "lines", "title", "patched"];

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

// "22.x" → [22], "0.12.x" → [0, 12] — für numerische Sortierung der Release-Linien
const lineKey = (line) => line.replace(/\.x$/, "").split(".").map(Number);
const compareLines = (a, b) => {
  const x = lineKey(a), y = lineKey(b);
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    if ((x[i] ?? -1) !== (y[i] ?? -1)) return (x[i] ?? -1) - (y[i] ?? -1);
  }
  return 0;
};

// Semver-Bereich der Security WG ("^22.23.2 || ^24.18.1") oder sonst die Releases
// aus dem Blogpost — als Versionsliste, höchste zuerst
function patchedVersions(v) {
  const versions = v.patched
    ? String(v.patched).split(/\s*\|\|\s*/).map((s) => s.replace(/^[\^~>=v\s]+/, "").trim()).filter(Boolean)
    : (v.releases ?? []);
  return [...new Set(versions)].sort(collator.compare).reverse();
}

function init(data) {
  if (!data || !Array.isArray(data.vulnerabilities)) {
    throw new Error("Schlüssel 'vulnerabilities' fehlt");
  }
  state.all = data.vulnerabilities.map((v) => {
    const lines = Array.isArray(v.affectedLines) ? v.affectedLines : [];
    return {
      v,
      lines,
      // Höchste betroffene Linie zuerst, damit Sortieren nach "Release-Linien" sinnvoll ist
      linesSort: [...lines].sort(compareLines).reverse().map((l) => lineKey(l).map((n) => String(n).padStart(3, "0")).join(".")).join(" "),
      text: SEARCH_FIELDS.map((k) => (Array.isArray(v[k]) ? v[k].join(" ") : String(v[k] ?? "")))
        .concat(String(v.post?.title ?? "")).join("\n").toLowerCase(),
      sev: SEVERITY_ORDER[String(v.severity).toUpperCase()] ?? -1,
      patchedText: patchedVersions(v).join(", "),
    };
  });

  const newest = state.all.reduce((m, e) => (String(e.v.published ?? "") > m ? String(e.v.published) : m), "");
  $("#meta").textContent = `${state.all.length} Einträge · neueste vom ${newest || "?"} · Quellen: nodejs.org Blog, Node.js Security WG`;

  const lines = [...new Set(state.all.flatMap((e) => e.lines))].sort(compareLines).reverse();
  const select = form.elements.line;
  select.replaceChildren(select.options[0], ...lines.map((l) => new Option(l)));

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
  if (key === "lines") return entry.linesSort;
  if (key === "patched") return entry.patchedText;
  return String(entry.v[key] ?? "");
}

function apply() {
  const f = Object.fromEntries(new FormData(form));
  const terms = parseTerms(f.q ?? "");
  const minSev = f.severity ? SEVERITY_ORDER[f.severity] : -1;

  state.filtered = state.all.filter(({ v, lines, text, sev }) => {
    if (f.line && !lines.includes(f.line)) return false;
    if (sev < minSev) return false;
    // ISO-Daten (YYYY-MM-DD) lassen sich als Strings vergleichen
    if (f.since && String(v.published ?? "") < f.since) return false;
    if (f.until && String(v.published ?? "") > f.until) return false;
    return terms.every((t) => text.includes(t));
  });

  const { sortKey, sortDir } = state;
  state.filtered.sort((x, y) =>
    collator.compare(sortValue(x, sortKey), sortValue(y, sortKey)) * sortDir ||
    collator.compare(String(y.v.id), String(x.v.id)));

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

function cveLink(id) {
  return /^CVE-\d{4}-\d+$/i.test(id) ? link(`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(id)}`, id) : document.createTextNode(id);
}

function sevBadge(severity) {
  const s = String(severity ?? "").toUpperCase();
  return el("span", { className: `sev sev-${s in SEVERITY_ORDER ? s : "NONE"}`, textContent: s || "?" });
}

function buildRow({ v, lines, patchedText }) {
  const tr = el("tr", { className: "row", tabIndex: 0 },
    el("td", { textContent: v.published || "?" }),
    el("td", {}, cveLink(String(v.id ?? ""))),
    el("td", {}, sevBadge(v.severity)),
    el("td", { textContent: lines.join(", ") }),
    el("td", { textContent: v.title ?? "" }),
    el("td", { textContent: patchedText }),
  );
  tr.dataset.id = v.id;
  tr.setAttribute("aria-expanded", "false");
  return tr;
}

function buildDetail({ v }) {
  const dl = el("dl");
  const add = (label, value, className = "") => {
    if (value == null || value === "" || (Array.isArray(value) && !value.length)) return;
    dl.append(el("dt", { textContent: label }),
      value instanceof Node ? el("dd", {}, value) : el("dd", { className, textContent: Array.isArray(value) ? value.join(", ") : value }));
  };
  // Markdown-Hervorhebungen aus den Blogposts für die Textanzeige entfernen
  add("Beschreibung", String(v.description ?? "").replace(/\*\*/g, ""), "text");
  add("Verwundbar", v.vulnerable);
  add("Gepatcht", v.patched);
  add("Releases im Post", v.releases);
  add("CVSS", [v.cvss, v.cvssScore].filter(Boolean).join(" · "));
  add("Gemeldet von", v.reportedBy);
  add("Security WG", v.nswg);
  add("Quellen", v.sources);
  add("Blogpost", v.post?.url ? link(v.post.url, v.post.title || v.post.url) : null);
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
  const entry = state.filtered.find((e) => String(e.v.id) === id);
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
  // Neue Spalte: Datum, Severity und Versionen absteigend, Textspalten aufsteigend beginnen
  state.sortDir = key === state.sortKey ? -state.sortDir : (["published", "severity", "lines", "patched"].includes(key) ? -1 : 1);
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
