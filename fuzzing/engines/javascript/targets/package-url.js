export function fuzz(data) {
  if (data.length > 8192) return;
  const text = data.toString('utf8').trim();
  if (!text.startsWith('pkg:')) return;
  try {
    const url = new URL(text.replace(/^pkg:/, 'pkg://'));
    decodeURIComponent(url.pathname);
    for (const [k, v] of url.searchParams.entries()) {
      decodeURIComponent(k); decodeURIComponent(v);
    }
  } catch {
    // Invalid purls are expected.
  }
}
