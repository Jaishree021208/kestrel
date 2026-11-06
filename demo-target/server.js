// A small, deliberately vulnerable "travel platform" for Kestrel to practice on.
// Everything here is synthetic. Run it with: node demo-target/server.js (port 4000).
// Do NOT deploy this file anywhere public — it is a target, not a product.

const express = require('express');
const app = express();
app.use(express.json());

const bookings = {
  1: { id: 1, agency: 'AGENCY_A', traveller: 'J. Rao', passport: 'X1234567' },
  2: { id: 2, agency: 'AGENCY_B', traveller: 'S. Iyer', passport: 'Y7654321' },
};
let refundCount = 0;

app.get('/', (req, res) => {
  res.send(`<html><body>
    <h1>TBO staging (demo)</h1>
    <a href="/api/v3/bookings/1">booking 1</a>
    <a href="/api/v3/search?q=paris">search</a>
    <script src="/static/app.js"></script>
  </body></html>`);
});

// Front-end bundle: a real crawler reads this to find routes it was never given docs for.
app.get('/static/app.js', (req, res) => {
  res.type('application/javascript').send(`
    // app.js (demo bundle)
    fetch('/api/v3/bookings/' + id);
    fetch('/api/v3/payments/refund', { method: 'POST' }); // POST
    fetch('/api/v3/search?q=' + term);
    fetch('/api/v3/error-test?x=' + val);
  `);
});

// VULN 1 — IDOR: no check that the caller's agency owns this booking.
app.get('/api/v3/bookings/:id', (req, res) => {
  const b = bookings[req.params.id];
  if (!b) return res.status(404).json({ error: 'not found' });
  res.json(b); // should check req.headers['x-agency'] === b.agency and doesn't
});

// VULN 2 — business logic: refund is not idempotent, can be paid twice.
app.post('/api/v3/payments/refund', (req, res) => {
  refundCount++;
  res.json({ refundId: 'R' + refundCount, bookingId: req.body?.bookingId, status: 'refunded' });
});

// VULN 3 (zombie) — old, undocumented version of the bookings endpoint. No auth at all.
app.get('/api/v1/bookings/:id', (req, res) => {
  const b = bookings[req.params.id];
  if (!b) return res.status(404).json({ error: 'not found' });
  res.json(b);
});

// VULN 4 (shadow/zombie) — debug route, never linked from the UI, no auth.
app.get('/internal/debug/config', (req, res) => {
  res.json({ supplier_api_key: 'sk_test_12345', dbPassword: 'hunter2' });
});

// VULN 5 — reflected input, unescaped.
app.get('/api/v3/search', (req, res) => {
  res.send(`<div>Results for ${req.query.q || ''}</div>`);
});

// VULN 6 — verbose error: stack trace leaks to the client.
app.get('/api/v3/error-test', (req, res, next) => {
  try {
    if (isNaN(Number(req.query.x))) throw new Error('x must be numeric');
    res.json({ ok: true });
  } catch (e) { next(e); }
});
app.use((err, req, res, next) => res.status(500).send(`<pre>${err.stack}</pre>`));

const PORT = process.env.TARGET_PORT || 4000;
app.listen(PORT, () => console.log(`Demo target (safe to scan) running at http://localhost:${PORT}`));
