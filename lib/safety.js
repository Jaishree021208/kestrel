// Safety layer — the brief's "Rules of Engagement" as code.
// Every outbound request from the executor goes through gate() and checkScope() first.

const state = {
  allowlist: ['localhost', '127.0.0.1'], // hosts Kestrel is permitted to test. Nothing else, ever.
  paused: false,
  maxRps: 4,
  minRps: 1,
  latencyWindow: [], // last few real round-trip times, used to detect strain
  lastGate: 0,
};

let auditLog = []; // newest first
const listeners = new Set();
function onAudit(fn) { listeners.add(fn); return () => listeners.delete(fn); }

function audit(agent, request, decision) {
  const entry = { time: new Date().toLocaleTimeString('en-GB'), agent, request, decision };
  auditLog.unshift(entry);
  auditLog = auditLog.slice(0, 80);
  for (const fn of listeners) fn(entry);
  return entry;
}

function checkScope(urlStr) {
  let hostname;
  try { hostname = new URL(urlStr).hostname; } catch { return false; }
  return state.allowlist.includes(hostname);
}

function addToAllowlist(hostname) {
  if (!state.allowlist.includes(hostname)) state.allowlist.push(hostname);
  audit('safety', hostname, 'added to allowlist');
}

const sleep = ms => new Promise(r => setTimeout(r, ms));

// Paces real outbound requests to state.maxRps, and blocks entirely while paused.
async function gate() {
  while (state.paused) await sleep(200);
  const minGapMs = 1000 / state.maxRps;
  const wait = Math.max(0, state.lastGate + minGapMs - Date.now());
  if (wait > 0) await sleep(wait);
  state.lastGate = Date.now();
}

// Feeds real measured latency back in. If the target is straining, Kestrel backs itself off —
// this is driven by actual response times, not a fixed timer.
function recordLatency(ms) {
  state.latencyWindow.push(ms);
  state.latencyWindow = state.latencyWindow.slice(-5);
  const avg = state.latencyWindow.reduce((a, b) => a + b, 0) / state.latencyWindow.length;
  if (avg > 400 && state.maxRps > state.minRps) {
    const from = state.maxRps;
    state.maxRps = Math.max(state.minRps, Math.floor(state.maxRps / 2));
    audit('safety', `avg latency ${Math.round(avg)}ms`, `backed off ${from} -> ${state.maxRps} req/s`);
  }
  return avg;
}

function setPaused(p) { state.paused = p; audit('orchestrator', 'all agents', p ? 'paused' : 'resumed'); }
function setMaxRps(r) { state.maxRps = Math.max(1, Math.min(20, r)); }
function getAudit() { return auditLog; }
function reset() {
  state.paused = false;
  state.maxRps = 4;
  state.latencyWindow = [];
  auditLog = [];
}

module.exports = { state, audit, checkScope, addToAllowlist, gate, recordLatency, setPaused, setMaxRps, getAudit, reset, onAudit };
