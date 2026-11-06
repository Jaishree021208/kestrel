// Attack planner — reasons over each endpoint's shape and status to pick a short, targeted
// set of tests, instead of running every payload against every endpoint.

function plan(endpoint) {
  const tests = ['security-headers']; // cheap, always worth checking
  if (endpoint.path.includes(':id')) tests.push('idor');
  if (endpoint.path.includes('search')) tests.push('reflection');
  if (endpoint.path.includes('error')) tests.push('verbose-error');
  if (endpoint.path.includes('refund')) tests.push('double-spend');
  if (endpoint.status !== 'active') tests.push('exposure-check'); // zombie/shadow get an extra look
  return tests;
}

// Tests that touch money or write state and so should not be auto-retriggered a third time
// once verified — the safety layer hands these to a human instead.
const REQUIRES_APPROVAL = new Set(['double-spend']);

module.exports = { plan, REQUIRES_APPROVAL };
