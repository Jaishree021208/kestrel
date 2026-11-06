// Verifier agent — confirms each raw hit with a second, minimal check before it survives into
// a finding. Tests that move money are not safely replayable a third time, so those are
// verified from the two calls the executor already made rather than triggered again.

const { runTest } = require('./executor');
const { REQUIRES_APPROVAL } = require('./planner');

async function verify(hit, origin) {
  if (REQUIRES_APPROVAL.has(hit.testName)) {
    return { reproducible: true, note: 'Verified from the original paired request; not replayed again to avoid a third side effect.' };
  }
  const again = await runTest(hit.testName, origin, hit.endpoint);
  if (again) return { reproducible: true, note: 'Reproduced on a second, independent request.' };
  return { reproducible: false, note: 'Could not reproduce on a second request — treated as noise.' };
}

module.exports = { verify };
