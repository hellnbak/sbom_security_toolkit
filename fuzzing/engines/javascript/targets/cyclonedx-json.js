export function fuzz(data) {
  if (data.length > 250000) return;
  let doc;
  try { doc = JSON.parse(data.toString('utf8')); } catch { return; }
  if (!doc || typeof doc !== 'object') return;
  if (doc.bomFormat && doc.bomFormat !== 'CycloneDX') return;
  const components = Array.isArray(doc.components) ? doc.components.slice(0, 5000) : [];
  for (const c of components) {
    if (!c || typeof c !== 'object') continue;
    for (const k of ['type', 'name', 'version', 'purl', 'bom-ref']) {
      if (typeof c[k] === 'string') Buffer.from(c[k], 'utf8').toString('utf8');
    }
  }
  const deps = Array.isArray(doc.dependencies) ? doc.dependencies.slice(0, 5000) : [];
  for (const d of deps) {
    if (!d || typeof d !== 'object') continue;
    if (Array.isArray(d.dependsOn)) d.dependsOn.slice(0, 250).join('|');
  }
}
