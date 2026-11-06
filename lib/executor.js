// Specialist executor agents — one function per vulnerability class. Every call goes through
// safety.checkScope + safety.gate first, so these never run outside the approved target.
// Payloads are deliberately non-destructive: detection markers and read requests, no data loss.

const safety = require('./safety');

async function safeRequest(url, opts) {
  if (!safety.checkScope(url)) { safety.audit('executor', url, 'blocked: out of scope'); return null; }
  await safety.gate();
  const t0 = Date.now();
  try {
    const res = await fetch(url, opts);
    const text = await res.text().catch(() => '');
    const latency = Date.now() - t0;
    safety.recordLatency(latency);
    safety.audit('executor', `${opts?.method || 'GET'} ${url}`, `status ${res.status}, ${latency}ms`);
    return { status: res.status, text, headers: res.headers };
  } catch (e) {
    safety.recordLatency(Date.now() - t0);
    safety.audit('executor', url, `request failed (${e.code || e.message})`);
    return null;
  }
}

function concreteUrl(origin, normalizedPath, id = '1') {
  return origin + normalizedPath.replace(':id', id);
}

const TESTS = {
  async 'security-headers'(origin, ep) {
    const r = await safeRequest(concreteUrl(origin, ep.path));
    if (!r) return null;
    const required = ['x-content-type-options', 'x-frame-options'];
    const missing = required.filter(h => !r.headers.has(h));
    if (!missing.length) return null;
    return { request: `GET ${ep.path}`, evidence: `Response is missing: ${missing.join(', ')}.`, raw: null };
  },

  async idor(origin, ep) {
    // Request a resource that belongs to a different tenant and see if it's returned anyway.
    const url = concreteUrl(origin, ep.path, '2');
    const r = await safeRequest(url, { headers: { 'x-agency': 'AGENCY_A' } });
    if (!r || r.status >= 400) return null;
    if (/agencyB|passport/i.test(r.text)) {
      return { request: `GET ${url} (as Agency A)`, evidence: `HTTP ${r.status}\n${r.text.slice(0, 300)}`, raw: r.text };
    }
    return null;
  },

  async reflection(origin, ep) {
    const marker = '<kestrel-mark>';
    const url = `${concreteUrl(origin, ep.path)}?q=${encodeURIComponent(marker)}`;
    const r = await safeRequest(url);
    if (!r) return null;
    if (r.text.includes(marker)) {
      return { request: `GET ${url}`, evidence: `Marker reflected unescaped in response:\n${r.text.slice(0, 300)}`, raw: r.text };
    }
    return null;
  },

  async 'verbose-error'(origin, ep) {
    const url = `${concreteUrl(origin, ep.path)}?x=notanumber`;
    const r = await safeRequest(url);
    if (!r) return null;
    if (/at [\w.]+\s*\(|\.js:\d+|Error:/.test(r.text)) {
      return { request: `GET ${url}`, evidence: `Stack trace returned to the client:\n${r.text.slice(0, 400)}`, raw: r.text };
    }
    return null;
  },

  async 'double-spend'(origin, ep) {
    const url = concreteUrl(origin, ep.path);
    const body = JSON.stringify({ bookingId: 1 });
    const opts = { method: 'POST', headers: { 'Content-Type': 'application/json' }, body };
    const r1 = await safeRequest(url, opts);
    const r2 = await safeRequest(url, opts);
    if (!r1 || !r2) return null;
    try {
      const j1 = JSON.parse(r1.text), j2 = JSON.parse(r2.text);
      if (j1.refundId && j2.refundId && j1.refundId !== j2.refundId) {
        return { request: `POST ${ep.path} x2 (same booking)`, evidence: `Call 1: ${r1.text}\nCall 2: ${r2.text}`, raw: r2.text };
      }
    } catch { /* not JSON, no finding */ }
    return null;
  },

  async 'exposure-check'(origin, ep) {
    const url = concreteUrl(origin, ep.path);
    const r = await safeRequest(url);
    if (!r || r.status >= 400) return null;
    if (/passport|api_key|password|secret|ssn/i.test(r.text)) {
      return { request: `GET ${url} (no auth)`, evidence: `HTTP ${r.status}\n${r.text.slice(0, 300)}`, raw: r.text };
    }
    return null;
  },
};

async function runTest(testName, origin, endpoint) {
  const fn = TESTS[testName];
  if (!fn) return null;
  const result = await fn(origin, endpoint);
  if (!result) return null;
  return { testName, endpoint, ...result, time: new Date().toLocaleTimeString('en-GB') };
}

module.exports = { runTest, safeRequest, concreteUrl, TESTS: Object.keys(TESTS) };
