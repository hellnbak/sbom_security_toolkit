export function fuzz(data) {
  if (data.length > 250000) return;
  let doc;
  try { doc = JSON.parse(data.toString('utf8')); } catch { return; }
  if (!doc || typeof doc !== 'object') return;
  if (doc.spdxVersion && !String(doc.spdxVersion).startsWith('SPDX-')) return;
  const ids = new Set();
  const packages = Array.isArray(doc.packages) ? doc.packages.slice(0, 5000) : [];
  for (const p of packages) {
    if (!p || typeof p !== 'object') continue;
    if (typeof p.SPDXID === 'string') ids.add(p.SPDXID.slice(0, 512));
    for (const k of ['name', 'versionInfo', 'licenseConcluded', 'licenseDeclared']) {
      if (typeof p[k] === 'string') Buffer.from(p[k], 'utf8');
    }
  }
  Array.from(ids).sort();
}
