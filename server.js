// Kestrel backend — orchestrates real recon, planning, execution, verification, triage and
// reporting against a target the user has explicitly added to the scope allowlist.
// Nothing here is simulated: recon.crawl and executor tests make real HTTP requests.

const express = require('express');
const path = require('path');
const fs = require('fs');
const safety = require('./lib/safety');
const recon = require('./lib/recon');
const { plan, REQUIRES_APPROVAL } = require('./lib/planner');
const { runTest } = require('./lib/executor');
const { verify } = require('./lib/verifier');
const triage = require('./lib/triage');
const reporter = require('./lib/reporter');

// Starts the sandbox target in this same process, on its own port, so a single deployed
// service still has something safe to scan — "localhost:4000" then means "this container",
// not the visitor's own machine. Set ENABLE_SANDBOX=false to skip this (e.g. if you've
// swapped in a real target and run the sandbox separately).
if (process.env.ENABLE_SANDBOX !== 'false') require('./demo-target/server');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const STAGES = [
  ['Detect change', 'Target reachable'], ['Learn the app', 'Crawl and traffic'],
  ['Plan attacks', 'Per endpoint'], ['Execute safely', 'Rate limited'],
  ['Verify', 'Minimal proof'], ['Triage', 'Severity and owner'],
  ['Report', 'Ticket ready'], ['Retest', 'After the fix'],
];
const trafficLog = JSON.parse(fs.readFileSync(path.join(__dirname, 'data/traffic-log.json'), 'utf8'));

let run = { running: false, stageIndex: -1, doneIndex: 0, targetUrl: null, inventoryReady: false, findingsReady: false };
let inventory = [];
let findings = []; // {id, testName, endpoint, request, evidence, score, severity, owner, status, fix}
let findingSeq = 1;

const clients = new Set();
function broadcast(event, data) { const line = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`; for (const res of clients) res.write(line); }
function log(message) { broadcast('log', { time: new Date().toLocaleTimeString('en-GB'), message }); }
safety.onAudit(entry => broadcast('audit', entry));

app.get('/api/stream', (req, res) => {
  res.set({ 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
  res.flushHeaders();
  res.write(`event: hello\ndata: ${JSON.stringify(run)}\n\n`);
  clients.add(res);
  req.on('close', () => clients.delete(res));
});

app.get('/api/state', (req, res) => res.json({ ...run, stages: STAGES, allowlist: safety.state.allowlist, maxRps: safety.state.maxRps, paused: safety.state.paused }));

app.post('/api/reset', (req, res) => {
  run = { running: false, stageIndex: -1, doneIndex: 0, targetUrl: null, inventoryReady: false, findingsReady: false };
  inventory = []; findings = []; findingSeq = 1;
  safety.reset();
  broadcast('reset', run);
  res.json({ ok: true });
});

// The one explicit consent step: the user must name the target before Kestrel will touch it.
app.post('/api/safety/allow', (req, res) => {
  const { hostname } = req.body || {};
  if (!hostname) return res.status(400).json({ error: 'hostname required' });
  safety.addToAllowlist(hostname);
  res.json({ allowlist: safety.state.allowlist });
});

app.post('/api/scan', async (req, res) => {
  if (run.running) return res.status(409).json({ error: 'A scan is already running.' });
  const { targetUrl } = req.body || {};
  if (!targetUrl) return res.status(400).json({ error: 'targetUrl is required.' });
  let hostname;
  try { hostname = new URL(targetUrl).hostname; } catch { return res.status(400).json({ error: 'targetUrl is not a valid URL.' }); }
  if (!safety.checkScope(targetUrl)) {
    return res.status(403).json({ error: `${hostname} is not on the allowlist yet. Call POST /api/safety/allow first.` });
  }

  run = { running: true, stageIndex: -1, doneIndex: 0, targetUrl, inventoryReady: false, findingsReady: false };
  findings = []; findingSeq = 1;
  res.json({ ok: true, started: true });
  runAgentLoop(targetUrl).catch(e => { log(`Run failed: ${e.message}`); run.running = false; broadcast('run-error', { message: e.message }); });
});

async function waitWhilePaused() { while (safety.state.paused) await new Promise(r => setTimeout(r, 200)); }
function setStage(i) { run.stageIndex = i; run.doneIndex = i; broadcast('stage', { active: i, done: i }); }

async function runAgentLoop(targetUrl) {
  const origin = new URL(targetUrl).origin;

  await waitWhilePaused(); setStage(0);
  log(`Deploy/target check: confirming ${targetUrl} is reachable.`);
  const home = await recon.safeGet(targetUrl, log);
  log(home ? `Target responded with status ${home.status}.` : 'Target did not respond — check it is running and on the allowlist.');
  if (!home) { run.running = false; broadcast('stage', { active: -1, done: 0 }); return; }

  await waitWhilePaused(); setStage(1);
  log('Crawling the UI, reading front-end JS, and probing hidden paths — no documentation used.');
  const discovered = await recon.crawl(targetUrl, log);
  inventory = recon.classify(discovered, trafficLog);
  run.inventoryReady = true;
  log(`Inventory built: ${inventory.length} endpoints (${inventory.filter(e => e.status === 'active').length} active, ${inventory.filter(e => e.status === 'zombie').length} zombie, ${inventory.filter(e => e.status === 'shadow').length} shadow).`);
  broadcast('inventory-ready', inventory);

  await waitWhilePaused(); setStage(2);
  const testPlan = inventory.map(ep => ({ endpoint: ep, tests: plan(ep) }));
  const totalTests = testPlan.reduce((n, p) => n + p.tests.length, 0);
  log(`Planner selected ${totalTests} targeted tests across ${inventory.length} endpoints (not spraying every payload everywhere).`);

  await waitWhilePaused(); setStage(3);
  log(`Executing at up to ${safety.state.maxRps} requests/second, inside the allowlist only.`);
  const rawHits = [];
  for (const { endpoint, tests } of testPlan) {
    for (const testName of tests) {
      await waitWhilePaused();
      const hit = await runTest(testName, origin, endpoint);
      if (hit) rawHits.push(hit);
    }
  }
  log(`${rawHits.length} raw hit(s) collected.`);

  await waitWhilePaused(); setStage(4);
  const verified = [];
  for (const hit of rawHits) {
    await waitWhilePaused();
    const v = await verify(hit, origin);
    log(`${hit.testName} on ${hit.endpoint.path}: ${v.reproducible ? 'reproduced' : 'discarded as noise'}.`);
    if (v.reproducible) verified.push({ ...hit, verifyNote: v.note });
  }

  await waitWhilePaused(); setStage(5);
  for (const hit of verified) {
    const sc = triage.score(hit);
    findings.push({
      id: 'F-' + (100 + findingSeq++),
      testName: hit.testName,
      title: titleFor(hit.testName, hit.endpoint),
      endpoint: hit.endpoint,
      request: hit.request,
      evidence: hit.evidence,
      verifyNote: hit.verifyNote,
      owner: hit.endpoint.owner,
      score: sc.total,
      scoreBreakdown: sc,
      severity: sc.severity,
      status: REQUIRES_APPROVAL.has(hit.testName) ? 'Awaiting approval' : 'Verified',
      fix: reporter.fixFor(hit.testName),
    });
  }
  log(`Triaged ${findings.length} verified finding(s).`);
  run.findingsReady = true;
  broadcast('findings-ready', findings);

  await waitWhilePaused(); setStage(6);
  log('Tickets drafted with evidence, impact, owner and suggested fix (see the Findings tab).');

  await waitWhilePaused(); setStage(7);
  log('Waiting for fix-deployed events. Open a finding and press Retest once you have patched it.');

  run.running = false;
  run.stageIndex = -1; run.doneIndex = STAGES.length;
  broadcast('stage', { active: -1, done: STAGES.length });
  broadcast('run-complete', {
    endpointCount: inventory.length,
    rawToVerified: `${rawHits.length} → ${verified.length}`,
    zombieShadowCount: inventory.filter(e => e.status !== 'active').length,
  });
}

function titleFor(testName, ep) {
  const map = {
    idor: `Cross-agency data read on ${ep.path}`,
    'double-spend': `${ep.path} can be called twice for the same resource`,
    'exposure-check': `${ep.path} returns sensitive data with no auth`,
    reflection: `Unescaped input reflected on ${ep.path}`,
    'verbose-error': `Stack trace exposed on ${ep.path}`,
    'security-headers': `Missing security headers on ${ep.path}`,
  };
  return map[testName] || `${testName} finding on ${ep.path}`;
}

// ---- inventory ----
app.get('/api/inventory', (req, res) => {
  const { status } = req.query;
  res.json(status && status !== 'All' ? inventory.filter(r => r.status === status) : inventory);
});
app.get('/api/inventory/openapi', (req, res) => {
  const paths = {};
  for (const r of inventory) {
    paths[r.path] = paths[r.path] || {};
    paths[r.path][r.method.toLowerCase()] = { 'x-status': r.status, 'x-owner': r.owner, responses: { 200: { description: 'OK' } } };
  }
  res.json({ openapi: '3.0.3', info: { title: 'Inferred API', version: 'discovered' }, paths });
});

// ---- findings ----
app.get('/api/findings', (req, res) => res.json(findings));
app.get('/api/findings/:id', (req, res) => {
  const f = findings.find(x => x.id === req.params.id);
  f ? res.json(f) : res.status(404).json({ error: 'not found' });
});
function setStatus(id, status) { const f = findings.find(x => x.id === id); if (f) { f.status = status; broadcast('finding-update', f); } return f; }
app.post('/api/findings/:id/approve', (req, res) => {
  safety.audit('orchestrator', req.params.id, 'allowed after human approval');
  const f = setStatus(req.params.id, 'Verified'); f ? res.json(f) : res.status(404).json({ error: 'not found' });
});
app.post('/api/findings/:id/reject', (req, res) => {
  safety.audit('orchestrator', req.params.id, 'rejected by human');
  const f = setStatus(req.params.id, 'Skipped'); f ? res.json(f) : res.status(404).json({ error: 'not found' });
});
app.post('/api/findings/:id/ticket', (req, res) => {
  const f = findings.find(x => x.id === req.params.id);
  if (!f) return res.status(404).json({ error: 'not found' });
  if (f.status !== 'Verified') return res.status(400).json({ error: 'Only verified findings can be ticketed.' });
  res.json(setStatus(req.params.id, 'Ticketed'));
});
app.get('/api/findings/:id/ticket.md', (req, res) => {
  const f = findings.find(x => x.id === req.params.id);
  if (!f) return res.status(404).send('not found');
  res.type('text/markdown').send(reporter.toTicket(f));
});
app.post('/api/findings/:id/retest', async (req, res) => {
  const f = findings.find(x => x.id === req.params.id);
  if (!f) return res.status(404).json({ error: 'not found' });
  const origin = new URL(run.targetUrl).origin;
  const hit = await runTest(f.testName, origin, f.endpoint);
  safety.audit('retest', f.id, hit ? 'still reproducible' : 'no longer reproducible');
  res.json(setStatus(req.params.id, hit ? 'Still open' : 'Closed'));
});

// ---- safety ----
app.post('/api/pause', (req, res) => { safety.setPaused(!safety.state.paused); broadcast('pause', { paused: safety.state.paused }); res.json({ paused: safety.state.paused }); });
app.post('/api/safety/rate', (req, res) => { safety.setMaxRps(Number(req.body.rps) || 4); res.json({ maxRps: safety.state.maxRps }); });
app.post('/api/safety/check-url', (req, res) => {
  let hostname; try { hostname = new URL(req.body.url || '').hostname; } catch { return res.status(400).json({ error: 'Not a valid URL.' }); }
  const allowed = safety.checkScope(req.body.url);
  safety.audit('safety', req.body.url, allowed ? 'allowed' : 'blocked: out of scope');
  res.json({ allowed, hostname });
});
app.get('/api/audit', (req, res) => res.json(safety.getAudit()));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Kestrel backend running at http://localhost:${PORT}`));
