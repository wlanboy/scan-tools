"use strict";

const state = {
  rows: [],          // eine Zeile pro (Release, CVE)
  grouped: [],       // eine Zeile pro CVE
  sortKey: "version",
  sortDir: "desc",
};

const $ = (sel) => document.querySelector(sel);

// ---------------------------------------------------------------------------
// Hilfsfunktionen
// ---------------------------------------------------------------------------

function versionParts(v) {
  return v.split(".").map(Number);
}

function compareVersions(a, b) {
  const pa = versionParts(a), pb = versionParts(b);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d) return d;
  }
  return 0;
}

function compareCves(a, b) {
  const [, ya, na] = a.split("-").map(Number);
  const [, yb, nb] = b.split("-").map(Number);
  return ya - yb || na - nb;
}

function severityOf(sev, cvss) {
  const s = (sev || "").toLowerCase();
  if (s === "critical") return "critical";
  if (s === "high") return "high";
  if (s === "medium" || s === "moderate") return "medium";
  if (s === "low") return "low";
  const score = parseFloat(cvss);
  if (isNaN(score)) return "";
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  return score > 0 ? "low" : "";
}

const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, "": 0 };

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else node.setAttribute(k, v);
  }
  for (const c of children) {
    if (c != null) node.append(c);
  }
  return node;
}

function link(href, text) {
  return el("a", { href, target: "_blank", rel: "noopener" }, text);
}

// ---------------------------------------------------------------------------
// Daten aufbereiten
// ---------------------------------------------------------------------------

function buildRows(releases) {
  const rows = [];
  for (const rel of releases) {
    for (const c of rel.cves) {
      rows.push({
        version: rel.version,
        minor: rel.version.split(".").slice(0, 2).join("."),
        releaseUrl: rel.url,
        cve: c.cve,
        cvss: c.cvss,
        severity: severityOf(c.severity, c.cvss),
        description: c.description,
        source: c.source,
        via: c.via_bulletin || "Release Notes",
      });
    }
  }
  return rows;
}

function buildGrouped(rows) {
  const map = new Map();
  for (const r of rows) {
    let g = map.get(r.cve);
    if (!g) {
      g = { ...r, versions: [] };
      map.set(r.cve, g);
    }
    g.versions.push({ version: r.version, url: r.releaseUrl, minor: r.minor });
    if (!g.cvss && r.cvss) {
      g.cvss = r.cvss;
      g.severity = r.severity;
    }
    if (r.description.length > g.description.length) g.description = r.description;
  }
  for (const g of map.values()) {
    g.versions.sort((a, b) => compareVersions(a.version, b.version));
    g.version = g.versions[0].version; // Sortierung nach ältestem Fix
  }
  return [...map.values()];
}

// ---------------------------------------------------------------------------
// Filtern, Sortieren, Rendern
// ---------------------------------------------------------------------------

function currentRows() {
  const grouped = $("#group").checked;
  const minor = $("#minor").value;
  const terms = $("#search").value.toLowerCase().split(/\s+/).filter(Boolean);

  let rows = grouped ? state.grouped : state.rows;

  if (minor) {
    rows = grouped
      ? rows.filter((r) => r.versions.some((v) => v.minor === minor))
      : rows.filter((r) => r.minor === minor);
  }

  if (terms.length) {
    rows = rows.filter((r) => {
      const versions = grouped ? r.versions.map((v) => v.version).join(" ") : r.version;
      const hay = [versions, r.cve, r.cvss, r.severity, r.via, r.description].join(" ").toLowerCase();
      return terms.every((t) => hay.includes(t));
    });
  }

  const th = document.querySelector(`th[data-key="${state.sortKey}"]`);
  const type = th ? th.dataset.type : "";
  const key = state.sortKey;
  const dir = state.sortDir === "asc" ? 1 : -1;

  const cmp = (a, b) => {
    switch (type) {
      case "version": return compareVersions(a.version, b.version);
      case "cve": return compareCves(a.cve, b.cve);
      case "number": return (parseFloat(a[key]) || 0) - (parseFloat(b[key]) || 0);
    }
    if (key === "severity") return SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
    return String(a[key]).localeCompare(String(b[key]));
  };

  // Sekundär immer nach CVE, damit gleiche Werte stabil gruppiert bleiben
  return [...rows].sort((a, b) => dir * cmp(a, b) || compareCves(b.cve, a.cve));
}

function render() {
  const grouped = $("#group").checked;
  const rows = currentRows();
  const tbody = $("#table tbody");
  tbody.replaceChildren();

  for (const r of rows) {
    const versionCell = grouped
      ? el("td", {}, el("div", { class: "versions" },
          ...r.versions.map((v) => link(v.url, v.version))))
      : el("td", { class: "nowrap" }, link(r.releaseUrl, r.version));

    const sev = r.severity || "none";
    tbody.append(el("tr", {},
      versionCell,
      el("td", { class: "nowrap mono" }, link(`https://nvd.nist.gov/vuln/detail/${r.cve}`, r.cve)),
      el("td", { class: "nowrap" }, r.cvss || "–"),
      el("td", {}, el("span", { class: `badge sev-${sev}` }, r.severity || "n/a")),
      el("td", { class: "desc" }, r.description),
      el("td", { class: "nowrap" }, link(r.source, r.via)),
    ));
  }

  const total = grouped ? state.grouped.length : state.rows.length;
  $("#count").textContent = `${rows.length} von ${total} ${grouped ? "CVEs" : "Einträgen"}`;

  document.querySelectorAll("th").forEach((th) => {
    th.classList.remove("asc", "desc");
    if (th.dataset.key === state.sortKey) th.classList.add(state.sortDir);
  });
  document.querySelector('th[data-key="version"]').textContent = grouped ? "Gefixt in" : "Version";
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

function init(releases) {
  state.rows = buildRows(releases);
  state.grouped = buildGrouped(state.rows);

  const minors = [...new Set(releases.map((r) => r.version.split(".").slice(0, 2).join(".")))]
    .sort(compareVersions).reverse();
  const select = $("#minor");
  for (const m of minors) select.append(el("option", { value: m }, `Istio ${m}.x`));

  const newest = releases.map((r) => r.version).sort(compareVersions).pop();
  const oldest = releases.map((r) => r.version).sort(compareVersions)[0];
  $("#summary").textContent =
    `${state.grouped.length} eindeutige CVEs in ${releases.length} Releases (${oldest} – ${newest})`;

  document.querySelectorAll("th:not(.nosort)").forEach((th) => {
    th.addEventListener("click", () => {
      const key = th.dataset.key;
      if (state.sortKey === key) {
        state.sortDir = state.sortDir === "asc" ? "desc" : "asc";
      } else {
        state.sortKey = key;
        state.sortDir = th.dataset.type ? "desc" : "asc";
      }
      render();
    });
  });

  $("#search").addEventListener("input", render);
  $("#minor").addEventListener("change", render);
  $("#group").addEventListener("change", render);

  render();
}

fetch("istio-cves.json", { cache: "no-store" })
  .then((r) => {
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  })
  .then(init)
  .catch((err) => {
    $("#summary").textContent = "";
    const e = $("#error");
    e.hidden = false;
    e.textContent =
      `istio-cves.json konnte nicht geladen werden (${err.message}). ` +
      "Erst istio/update.sh ausführen und die Seite über einen Webserver öffnen, " +
      "z.B. python3 -m http.server -d istio 8000";
  });
