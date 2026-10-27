// Apache Hadoop CVEs: lädt cves.json und bietet Filter nach Release-Linie,
// Volltextsuche, Sortierung und Detailansicht. Inhalte werden nur per
// textContent eingefügt (nie innerHTML), Links nur für http(s)-URLs erzeugt.

const DATA_URL = "cves.json";
const PAGE_SIZE = 100;
// Gleiche Felder wie "cves.py search"
const SEARCH_FIELDS = [
  "id", "title", "description", "impact", "advice", "affectedText",
  "fixedText", "reporter", "references", "cvssVector", "weakness",
];
const SEVERITY_ORDER = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };
const LINES = ["2.x", "3.x"];
const COLUMNS = ["published", "id", "severity", "title", ...LINES];

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

// Zelle je Linie: nicht betroffen, unbekannt, Fix-Versionen oder kein Fix
function lineCell(a, line) {
  const status = a.lines?.[line];
  if (!status) return a.affectedUnknown ? { kind: "unknown", text: "?" } : { kind: "none", text: "–" };
  if (!status.fixes?.length) return { kind: "nofix", text: "kein Fix" };
  return { kind: "fixed", text: status.fixes.join(", ") };
}

// Absteigend sortiert stehen "kein Fix" zuerst, dann Fixes (höchste Version), dann unbekannt, nicht betroffen
const LINE_RANK = { none: 0, unknown: 1, fixed: 2, nofix: 3 };

function init(data) {
  if (!data || !Array.isArray(data.cves)) {
    throw new Error("Schlüssel 'cves' fehlt");
  }
  state.all = data.cves.map((a) => {
    const cells = Object.fromEntries(LINES.map((l) => [l, lineCell(a, l)]));
    return {
      a,
      text: SEARCH_FIELDS.map((k) => (Array.isArray(a[k]) ? a[k].join(" ") : String(a[k] ?? ""))).join("\n").toLowerCase(),
      sev: SEVERITY_ORDER[String(a.severity).toUpperCase()] ?? -1,
      cells,
    };
  });

  const newest = state.all.reduce((m, e) => (String(e.a.published) > m ? String(e.a.published) : m), "");
  $("#meta").textContent = `${state.all.length} CVEs · neuester vom ${newest || "?"} · Quelle: hadoop.apache.org/cve_list.html`;

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
  if (LINES.includes(key)) {
    const cell = entry.cells[key];
    return `${LINE_RANK[cell.kind]} ${cell.kind === "fixed" ? entry.a.lines[key].fixes.at(-1) : ""}`;
  }
  return String(entry.a[key] ?? "");
}

function apply() {
  const f = Object.fromEntries(new FormData(form));
  const terms = parseTerms(f.q ?? "");
  const minSev = f.severity ? SEVERITY_ORDER[f.severity] : -1;

  state.filtered = state.all.filter(({ a, text, sev, cells }) => {
    if (f.line && !a.lines?.[f.line]) return false;
    if (sev < minSev) return false;
    // ISO-Daten (YYYY-MM-DD) lassen sich als Strings vergleichen
    if (f.since && String(a.published ?? "") < f.since) return false;
    if (f.until && String(a.published ?? "") > f.until) return false;
    // Ohne gewählte Linie: irgendeine betroffene Linie ohne Fix
    if (f.unfixed === "on" && !(f.line ? [f.line] : LINES).some((l) => cells[l].kind === "nofix")) return false;
    return terms.every((t) => text.includes(t));
  });

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

function buildRow({ a, cells }) {
  const tr = el("tr", { className: "row", tabIndex: 0 },
    el("td", { textContent: a.published ?? "" }),
    el("td", {}, link(a.url, a.id)),
    el("td", {}, sevBadge(a.severity)),
    el("td", { textContent: a.title ?? "" }),
    ...LINES.map((l) => el("td", { className: `line line-${cells[l].kind}`, textContent: cells[l].text })),
  );
  tr.dataset.id = a.id;
  tr.setAttribute("aria-expanded", "false");
  return tr;
}

function linesTable(a) {
  const head = el("tr", {}, ...["Linie", "betroffen", "Fix in der Linie"].map((t) => el("th", { textContent: t })));
  const body = Object.entries(a.lines ?? {}).map(([line, s]) => el("tr", {},
    el("td", { textContent: line }),
    el("td", { textContent: (s.affected ?? []).join(", ") }),
    s.fixes?.length
      ? el("td", { textContent: s.fixes.join(", ") })
      : el("td", { className: "nofix", textContent: "kein Fix — Upgrade auf neuere Linie" })));
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
  add("Betroffen (Quelle)", a.affectedText);
  add("Gefixt in (Quelle)", a.fixedText);
  add("Linien", Object.keys(a.lines ?? {}).length ? linesTable(a) : null);
  add("Impact", a.impact, "text");
  add("Advice", a.advice, "text");
  add("Reporter", a.reporter);
  add("Gemeldet", a.reported);
  add("Angekündigt", a.announced);
  const score = [a.cvssScore, a.cvssVector].filter((v) => v != null && v !== "").join(" ");
  add("CVSS", score ? `${score}${a.scoreSource ? ` (${a.scoreSource})` : ""}` : (a.scoreSource ? `Einstufung: ${a.scoreSource}` : ""));
  add("CWE", a.weakness);
  add("Referenzen", a.references?.length ? el("ul", {}, ...a.references.map((r) => el("li", {}, link(r)))) : null);
  add("hadoop.apache.org", link(a.url));
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
  $("#status").textContent = `${total} von ${state.all.length} CVEs` + (shown < total ? ` · ${shown} angezeigt` : "");
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
  // Neue Spalte: Datum, Severity und Linien absteigend, Textspalten aufsteigend beginnen
  state.sortDir = key === state.sortKey ? -state.sortDir : (["published", "severity", ...LINES].includes(key) ? -1 : 1);
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
