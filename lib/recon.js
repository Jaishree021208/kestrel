// Recon and mapping agent.
// Builds an inventory of endpoints the way the brief describes: crawl the UI, read front-end
// JS for routes, probe for hidden paths by naming pattern, then compare against traffic logs.
// All requests are real HTTP calls, gated through the safety layer.

const safety = require('./safety');

const HIDDEN_PREFIXES = ['/v1', '/old', '/internal', '/test', '/beta'];
const PROBE_LIST = [ // common leftover / debug paths worth guessing even with no documentation
  '/internal/debug/config',
  '/api/v1/invoices',
  '/test/fare-calc',
];

function normalizePath(p) {
  // turn a concrete path like /api/v3/bookings/1 into a pattern /api/v3/bookings/:id
  return p.replace(/\/\d+(?=\/|$)/g, '/:id');
}

async function safeGet(url, log) {
  if (!safety.checkScope(url)) { safety.audit('recon', url, 'blocked: out of scope'); return null; }
  await safety.gate();
  const t0 = Date.now();
  try {
    const res = await fetch(url, { redirect: 'manual' });
    const text = await res.text().catch(() => '');
    safety.recordLatency(Date.now() - t0);
    safety.audit('recon', url, `status ${res.status}`);
    return { status: res.status, text };
  } catch (e) {
    safety.recordLatency(Date.now() - t0);
    safety.audit('recon', url, `unreachable (${e.code || e.message})`);
    return null;
  }
}

// Crawl the app's front page + any same-origin JS it loads, extracting links, forms and routes.
async function crawl(baseUrl, log) {
  const origin = new URL(baseUrl).origin;
  const found = new Map(); // normalizedPath -> {method, path}
  const add = (method, path) => {
    const norm = normalizePath(path);
    const key = method + ' ' + norm;
    if (!found.has(key)) found.set(key, { method, path: norm });
  };

  log('Crawling the front page as a logged-in test account.');
  const home = await safeGet(baseUrl, log);
  if (home && home.text) {
    for (const m of home.text.matchAll(/(?:href|src)="([^"]+)"/g)) {
      const href = m[1];
      if (href.startsWith('/')) {
        if (/\.(js)$/.test(href)) {
          log(`Reading front-end bundle ${href} for API routes.`);
          const bundle = await safeGet(origin + href, log);
          if (bundle && bundle.text) {
            for (const r of bundle.text.matchAll(/["'`](\/(?:api|internal|test|beta|v1|v3)[\w\/\-{}:]*)["'`]/g)) {
              add(bundle.text.slice(Math.max(0, r.index - 10), r.index).includes('POST') ? 'POST' : 'GET', r[1]);
            }
          }
        } else if (/^\/(api|v1|v3)/.test(href)) {
          add('GET', href);
        }
      }
    }
  }

  log(`Probing for hidden paths using naming patterns: ${HIDDEN_PREFIXES.join(', ')}.`);
  const resourceNames = new Set([...found.values()].map(e => e.path.split('/').filter(Boolean)[2]).filter(Boolean));
  const candidates = new Set(PROBE_LIST);
  for (const prefix of HIDDEN_PREFIXES) for (const name of resourceNames) candidates.add(`${prefix}/${name}`);
  for (const path of candidates) {
    const r = await safeGet(origin + path, log);
    if (r && r.status < 400) add('GET', path);
  }

  return [...found.values()];
}

// Compare the discovered map against a traffic log (gateway/LB logs for the last N days) to
// label each endpoint active, zombie (still live, no real traffic) or shadow (traffic, no doc).
function classify(discovered, trafficLog) {
  return discovered.map(ep => {
    const match = trafficLog.find(t => t.method === ep.method && t.path === ep.path);
    let status, lastTraffic;
    if (!match) { status = 'shadow'; lastTraffic = 'Not in traffic log'; }
    else if (match.lastSeenDaysAgo > 30) { status = 'zombie'; lastTraffic = `${match.lastSeenDaysAgo} days ago`; }
    else { status = 'active'; lastTraffic = match.lastSeenDaysAgo === 0 ? 'Today' : `${match.lastSeenDaysAgo} days ago`; }
    return { ...ep, status, lastTraffic, owner: ownerFor(ep.path) };
  });
}

function ownerFor(path) {
  if (/payment|refund/.test(path)) return 'Payments team';
  if (/booking/.test(path)) return 'Bookings team';
  if (/internal|debug/.test(path)) return 'Platform team';
  if (/agency|subagent/.test(path)) return 'Identity team';
  if (/search|error/.test(path)) return 'Platform team';
  return 'Engineering';
}

module.exports = { crawl, classify, safeGet, normalizePath };
