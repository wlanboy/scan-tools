// Prüft, ob Node.js den kompromittierten eMudhra-Intermediates noch vertraut.
// Aufruf: node check.mjs (Node 18+). Exit-Code 1 = verwundbar.
const hosts = ['dv-g3b', 'dv-g3b-aaa', 'dv-g3b-noct', 'dv-g3b-aaa-noct'];

console.log(`node ${process.version}, NODE_OPTIONS=${process.env.NODE_OPTIONS ?? ''}`);
let vulnerable = false;
for (const h of hosts) {
  const url = `https://${h}-emudhra.we-have-a-problem.com/`;
  try {
    const r = await fetch(url, { signal: AbortSignal.timeout(10000) });
    console.log('VULNERABEL', r.status, url);
    vulnerable = true;
  } catch (e) {
    console.log('ok        ', url, e.cause?.code ?? e.name);
  }
}
process.exit(vulnerable ? 1 : 0);
