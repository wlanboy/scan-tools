"use strict";

const KEYS = ["critical", "high", "medium", "low", "none"];
const NAMES = ["Critical", "High", "Medium", "Low", "Ohne Bewertung"];
const UNITS = { week: "Woche", month: "Monat", year: "Jahr" };
const DAY = 864e5;

const $ = (sel) => document.querySelector(sel);
const num = new Intl.NumberFormat("de-DE").format;
const iso = (t) => new Date(t).toISOString().slice(0, 10);
const DMY = { day: "2-digit", month: "2-digit", year: "numeric" };
const de = (t, opts) =>new Date(t).toLocaleDateString("de-DE", { timeZone: "UTC", ...opts });

let days = {};   // "YYYY-MM-DD" -> [critical, high, medium, low, none]
const on = KEYS.map(() => true);   // per Klick auf die Legende ein-/ausgeblendet

// [Jahr, KW] nach ISO 8601: die Woche gehört zum Jahr ihres Donnerstags
function isoWeek(t) {
  const d = new Date(t);
  d.setUTCDate(d.getUTCDate() + 3 - (d.getUTCDay() + 6) % 7);
  const year = d.getUTCFullYear();
  return [year, 1 + Math.floor((d - Date.UTC(year, 0, 1)) / DAY / 7)];
}

function bucketStart(t, mode) {
  const day = iso(t);
  if (mode === "year") return Date.parse(day.slice(0, 4) + "-01-01");
  if (mode === "month") return Date.parse(day.slice(0, 7) + "-01");
  return t - (new Date(t).getUTCDay() + 6) % 7 * DAY;  // Montag
}

// Tage von..bis zu Wochen, Monaten oder Jahren zusammenfassen, leere Zeiträume inklusive
function buckets(from, to, mode) {
  const map = new Map();
  for (let t = from; t <= to; t += DAY) {
    const day = iso(t);
    const start = bucketStart(t, mode);
    let b = map.get(start);
    if (!b) map.set(start, b = { start, counts: [0, 0, 0, 0, 0], days: 0 });
    (days[day] || []).forEach((n, i) => { b.counts[i] += n; });
    b.days++;
  }
  return [...map.values()];
}

function label(b, mode, long) {
  if (mode === "year") return String(new Date(b.start).getUTCFullYear());
  if (mode === "month") return de(b.start, { month: "short", year: "numeric" });
  const [y, w] = isoWeek(b.start);
  return long ? `KW ${w}/${y} (${de(b.start, { day: "2-digit", month: "2-digit" })}–${de(b.start + 6 * DAY, DMY)})`
              : `KW ${w}/${String(y).slice(2)}`;
}

function daysInBucket(b, mode) {
  const d = new Date(b.start), y = d.getUTCFullYear(), m = d.getUTCMonth();
  const next = mode === "year" ? Date.UTC(y + 1, 0, 1) : mode === "month" ? Date.UTC(y, m + 1, 1) : b.start + 7 * DAY;
  return Math.round((next - b.start) / DAY);
}

function niceStep(max) {
  const raw = max / 4, p = 10 ** Math.floor(Math.log10(raw));
  return [1, 2, 5, 10].map((m) => m * p).find((s) => s >= raw);
}

function render() {
  const mode = $("#interval").value;
  let from = Date.parse($("#from").value), to = Date.parse($("#to").value);
  if (isNaN(from) || isNaN(to)) return;
  if (from > to) [from, to] = [to, from];

  const list = buckets(from, to, mode);
  const totals = list.map((b) => b.counts.reduce((a, n, j) => a + (on[j] ? n : 0), 0));
  const sum = totals.reduce((a, n) => a + n, 0);
  const top = Math.max(1, ...totals);
  const step = niceStep(top), yMax = Math.ceil(top / step) * step;

  let grid = "";
  for (let v = 0; v <= yMax; v += step) {
    grid += `<div class="grid" style="bottom:${v / yMax * 100}%"><span>${num(v)}</span></div>`;
  }

  const bars = list.map((b, i) => {
    const partial = b.days < daysInBucket(b, mode) ? " (unvollständig)" : "";
    const tip = [label(b, mode, true) + partial, `Gesamt: ${num(totals[i])}`,
      ...KEYS.map((k, j) => `${NAMES[j]}: ${num(b.counts[j])}`)].join("&#10;");
    const segs = KEYS.map((k, j) => on[j] && b.counts[j] ? `<i class="${k}" style="flex-grow:${b.counts[j]}"></i>` : "").join("");
    return `<div class="col${partial && " partial"}" title="${tip}"><div class="bar" style="height:${totals[i] / yMax * 100}%">${segs}</div></div>`;
  });
  $("#plot").innerHTML = `${grid}<div class="bars">${bars.join("")}</div>`;

  // Nur so viele Achsenbeschriftungen wie in die Breite passen
  const every = Math.ceil(list.length / Math.max(2, Math.floor($("#plot").clientWidth / 90)));
  $("#xaxis").innerHTML = list.map((b, i) => `<span>${i % every ? "" : label(b, mode)}</span>`).join("");

  const perKey = KEYS.map((k, j) => list.reduce((a, b) => a + b.counts[j], 0));
  $("#legend").innerHTML = KEYS.map((k, j) =>
    `<li><button type="button" data-i="${j}" aria-pressed="${on[j]}"><i class="${k}"></i>${NAMES[j]} <b>${num(perKey[j])}</b></button></li>`
  ).join("");

  const filter = on.every(Boolean) ? "" : ` (${NAMES.filter((n, j) => on[j]).join(", ")})`;
  $("#summary").textContent = `${num(sum)} CVEs${filter} vom ${de(from, DMY)} bis ${de(to, DMY)} · Ø ${num(Math.round(sum / list.length))} pro ${UNITS[mode]}`;

  $("#head").innerHTML = `<tr><th>Zeitraum</th>${NAMES.map((n, j) => on[j] ? `<th>${n}</th>` : "").join("")}<th>Gesamt</th></tr>`;
  $("#rows").innerHTML = list.map((b, i) =>
    `<tr><td>${label(b, mode, true)}</td>${b.counts.map((n, j) => on[j] ? `<td>${num(n)}</td>` : "").join("")}<td>${num(totals[i])}</td></tr>`
  ).reverse().join("");
}

fetch("cve-counts.json")
  .then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); })
  .then((data) => {
    days = data.days;
    const keys = Object.keys(days).sort();
    const first = keys[0], last = keys[keys.length - 1];
    for (const id of ["#from", "#to"]) Object.assign($(id), { min: first, max: last });
    $("#to").value = last;
    $("#from").value = first;
    document.title += ` (Stand ${de(Date.parse(data.updated))})`;
    for (const id of ["#interval", "#from", "#to"]) $(id).addEventListener("change", render);
    $("#legend").addEventListener("click", (e) => {
      const btn = e.target.closest("button");
      if (!btn) return;
      const j = +btn.dataset.i;
      if (on[j] && on.filter(Boolean).length === 1) return;  // mindestens eine Severity bleibt sichtbar
      on[j] = !on[j];
      render();
    });
    addEventListener("resize", render);
    render();
  })
  .catch((err) => {
    $("#summary").textContent = "";
    Object.assign($("#error"), { hidden: false, textContent: `cve-counts.json konnte nicht geladen werden: ${err.message}` });
  });
