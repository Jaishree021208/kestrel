# Kestrel — agentic real-time DAST

Rebuilt so the **backend does the real work** (recon, planning, execution, verification,
triage, reporting) and the **frontend is a thin dashboard** — matching how the hackathon brief
is actually judged: 90% of the score is about valid findings, precision, safety and speed, not
the UI.

## Run it locally (one terminal)

```
cd kestrel-app
npm install
npm start              # starts Kestrel on :3000 AND the sandbox target on :4000
```

Open `http://localhost:3000`, leave the target box as `http://localhost:4000`, and press
**Scan target**. Everything you see after that comes from real HTTP requests Kestrel makes to
the sandbox app — nothing is pre-scripted.

`npm start` now launches both servers in one process (see `ENABLE_SANDBOX` in `server.js`) so
the same single command also works once this is deployed online. If you want the sandbox as a
separate process instead (e.g. to point Kestrel at it from a different machine), run
`npm run target-only` and set `ENABLE_SANDBOX=false` before `npm start`.

**Needs Node 18+** (it uses the built-in `fetch`).

## Run it online

Kestrel is a normal, persistent Node/Express server (it uses Server-Sent Events, so it needs a
host that keeps a process running, not a "serverless function" host). **Render** has a free
tier that fits this well:

1. Put the `kestrel-app` folder in a GitHub repo.
2. At [render.com](https://render.com), sign up (GitHub sign-in is easiest) and click
   **New → Web Service**, then pick that repo.
3. Set **Build Command** to `npm install` and **Start Command** to `npm start`. Leave the
   rest as default — Render sets `PORT` for you, and `server.js` already reads it.
4. Click **Deploy**. After a minute or two you'll get a link like
   `https://kestrel-app.onrender.com`.
5. Open it, leave the target box as `http://localhost:4000`, and press **Scan target** — the
   sandbox target is running inside that same deployed container, so this works exactly like
   it does locally. Nothing here reaches out to the public internet.

Free-tier note: Render puts an idle service to sleep after about 15 minutes with no visitors;
the next visitor waits roughly 30–50 seconds for it to wake up. That's normal.

If you later point Kestrel at a target that lives outside its own container (your actual
staging environment, say), that target's hostname needs to be reachable from wherever Kestrel
is hosted, and you'd add it to the allowlist the same way the UI already does for
`localhost:4000`.

## What's actually real here

| Stage | What runs |
|---|---|
| Detect change | A real `GET` to confirm the target responds |
| Learn the app | `lib/recon.js` fetches the homepage, parses `href`/`src`, fetches and regex-parses any JS bundle for API-looking routes, then **probes** `/v1`, `/old`, `/internal`, `/test`, `/beta` variants of discovered resource names plus a short guess list — all real requests |
| Plan attacks | `lib/planner.js` picks tests per endpoint shape (an `:id` segment gets an IDOR test, a path with "refund" gets a double-spend test, zombie/shadow endpoints get an exposure check) |
| Execute safely | `lib/executor.js` sends the actual test requests, every one gated through `lib/safety.js` (scope check + rate limiter) |
| Verify | `lib/verifier.js` re-runs idempotent tests a second time; money-moving tests are verified from their original pair of calls instead of a third trigger |
| Triage | `lib/triage.js` scores `base × context multiplier` (PII, money, credentials push the score up) |
| Report | `lib/reporter.js` builds a Markdown ticket per finding — download it from the Findings tab |
| Retest | Re-runs the same test against the live target and closes the finding if it's gone |

## The sandbox target (`demo-target/server.js`)

A ~70-line Express app standing in for the "production-like staging environment" the brief
mentions, since you don't have the real TBO staging environment. It has six planted,
synthetic bugs matching the brief's vulnerability classes: an IDOR on bookings, a non-idempotent
refund, an unauthenticated legacy `/api/v1/` clone (zombie), an unlinked debug route (shadow),
a reflected-input search endpoint, and a verbose error handler. **Never deploy this file
anywhere public** — it exists to be broken.

## The one safety rule that matters

Kestrel will not send a single test request to a host that isn't on `lib/safety.js`'s
allowlist. The dashboard adds a target's hostname automatically when you click **Scan target**,
which is the one explicit consent step — change `state.allowlist` in `lib/safety.js` if you
want different defaults.

## Pointing this at something real

- Swap `data/traffic-log.json` for a real export from your gateway/load balancer.
- Add more test functions to `lib/executor.js`'s `TESTS` map (same shape: return `null` for no
  finding, or `{request, evidence}`), and reference the new test name from `lib/planner.js`.
- Replace the hand-written probe list in `lib/recon.js` with a real wordlist, or feed it DNS/
  certificate-transparency results for subdomain discovery.
- Swap the in-memory `inventory`/`findings` arrays in `server.js` for a database if you need
  multiple concurrent scans or persistence across restarts.
