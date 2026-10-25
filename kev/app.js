// KEV-Katalog: lädt known_exploited_vulnerabilities.json und bietet Filter,
// Volltextsuche, Sortierung und Detailansicht. Feed-Inhalte werden nur per
// textContent eingefügt (nie innerHTML), Links nur für http(s)-URLs erzeugt.

const DATA_URL = "known_exploited_vulnerabilities.json";
const PAGE_SIZE = 100;
// Gleiche Felder wie "catalog.py search"
const SEARCH_FIELDS = [
  "cveID", "vendorProject", "product", "vulnerabilityName",
  "shortDescription", "requiredAction", "notes", "cwes",
];
const COLUMNS = ["dateAdded", "cveID", "vendorProject", "product", "vulnerabilityName", "dueDate", "ransomware"];

const $ = (sel) => document.querySelector(sel);
const form = $("#filters");
const rows = $("#rows");
const moreBtn = $("#more");
const collator = new Intl.Collator("de", { numeric: true, sensitivity: "base" });
const today = new Date().toISOString().slice(0, 10);

const state = {
  all: [],
  filtered: [],
  sortKey: "dateAdded",
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

function init(data) {
  if (!data || !Array.isArray(data.vulnerabilities)) {
    throw new Error("Schlüssel 'vulnerabilities' fehlt");
  }
  state.all = data.vulnerabilities.map((v) => ({
    v,
    text: SEARCH_FIELDS.map((k) => (Array.isArray(v[k]) ? v[k].join(" ") : String(v[k] ?? ""))).join("\n").toLowerCase(),
    ransomware: String(v.knownRansomwareCampaignUse ?? "").toLowerCase() === "known",
  }));

  $("#meta").textContent =
    `Version ${data.catalogVersion ?? "?"} vom ${String(data.dateReleased ?? "?").slice(0, 10)} · ${state.all.length} Einträge`;

  const vendors = [...new Set(state.all.map((e) => e.v.vendorProject).filter(Boolean))].sort(collator.compare);
  $("#vendors").replaceChildren(...vendors.map((name) => new Option(name)));

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
  return key === "ransomware" ? (entry.ransomware ? "1" : "0") : String(entry.v[key] ?? "");
}

function apply() {
  const f = Object.fromEntries(new FormData(form));
  const terms = parseTerms(f.q ?? "");
  const vendor = (f.vendor ?? "").trim().toLowerCase();
  const product = (f.product ?? "").trim().toLowerCase();
  const rwOnly = f.rw === "on";

  state.filtered = state.all.filter(({ v, text, ransomware }) => {
    if (vendor && !String(v.vendorProject ?? "").toLowerCase().includes(vendor)) return false;
    if (product && !String(v.product ?? "").toLowerCase().includes(product)) return false;
    // ISO-Daten (YYYY-MM-DD) lassen sich als Strings vergleichen
    if (f.since && String(v.dateAdded ?? "") < f.since) return false;
    if (f.until && String(v.dateAdded ?? "") > f.until) return false;
    if (rwOnly && !ransomware) return false;
    return terms.every((t) => text.includes(t));
  });

  const { sortKey, sortDir } = state;
  state.filtered.sort((a, b) =>
    collator.compare(sortValue(a, sortKey), sortValue(b, sortKey)) * sortDir ||
    collator.compare(String(b.v.cveID), String(a.v.cveID)));

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

function nvdLink(cve) {
  return el("a", {
    href: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}`,
    target: "_blank",
    rel: "noopener noreferrer",
    textContent: cve,
  });
}

function buildRow({ v, ransomware }) {
  const cve = String(v.cveID ?? "");
  const due = String(v.dueDate ?? "");
  const tr = el("tr", { className: "row", tabIndex: 0 },
    el("td", { textContent: v.dateAdded ?? "" }),
    el("td", {}, nvdLink(cve)),
    el("td", { textContent: v.vendorProject ?? "" }),
    el("td", { textContent: v.product ?? "" }),
    el("td", { textContent: v.vulnerabilityName ?? "" }),
    el("td", { textContent: due, className: due >= today ? "due-open" : "", title: due >= today ? "Frist läuft noch" : "" }),
    el("td", {}, ransomware ? el("span", { className: "badge", textContent: "R", title: "Bekannte Ransomware-Nutzung" }) : null),
  );
  tr.dataset.cve = cve;
  tr.setAttribute("aria-expanded", "false");
  return tr;
}

// "Text: https://… ; https://…" → Liste aus Beschriftung + Link
function notesList(notes) {
  const items = String(notes).split(/\s*;\s*/).filter(Boolean).map((part) => {
    const m = part.match(/^(.*?)\s*(https?:\/\/\S+)$/);
    if (!m) return el("li", { textContent: part });
    const label = m[1].replace(/:\s*$/, "");
    return el("li", {}, label ? `${label}: ` : null,
      el("a", { href: m[2], target: "_blank", rel: "noopener noreferrer", textContent: m[2] }));
  });
  return el("ul", {}, ...items);
}

function buildDetail({ v }) {
  const dl = el("dl");
  const add = (label, value) => {
    if (value == null || value === "" || (Array.isArray(value) && !value.length)) return;
    dl.append(el("dt", { textContent: label }),
      value instanceof Node ? el("dd", {}, value) : el("dd", { textContent: Array.isArray(value) ? value.join(", ") : value }));
  };
  add("Beschreibung", v.shortDescription);
  add("Maßnahme", v.requiredAction);
  add("CWE", v.cwes);
  add("Ransomware", v.knownRansomwareCampaignUse);
  add("Forensik-Triage", v.forensicTriage);
  add("Hinweise", v.notes ? notesList(v.notes) : null);
  return el("tr", { className: "detail" }, el("td", { colSpan: COLUMNS.length }, dl));
}

function render() {
  const frag = document.createDocumentFragment();
  for (const entry of state.filtered.slice(0, state.shown)) {
    const tr = buildRow(entry);
    frag.append(tr);
    if (state.expanded.has(tr.dataset.cve)) {
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
  const cve = tr.dataset.cve;
  const entry = state.filtered.find((e) => String(e.v.cveID) === cve);
  if (!entry) return;
  if (state.expanded.delete(cve)) {
    tr.setAttribute("aria-expanded", "false");
    if (tr.nextElementSibling?.classList.contains("detail")) tr.nextElementSibling.remove();
  } else {
    state.expanded.add(cve);
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
  if (state.sortKey !== "dateAdded" || state.sortDir !== -1) {
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
  // Neue Spalte: Datumsspalten absteigend, Textspalten aufsteigend beginnen
  state.sortDir = key === state.sortKey ? -state.sortDir : (["dateAdded", "dueDate", "ransomware"].includes(key) ? -1 : 1);
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
