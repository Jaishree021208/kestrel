// Reporter agent — turns a verified, triaged finding into something ready to paste into a
// ticket: title, evidence, owner, and a suggested fix keyed to the vulnerability class.

const FIX = {
  idor: 'Check that the caller\'s agency owns the requested resource before returning it, on every lookup.',
  'double-spend': 'Make the operation idempotent per resource (an idempotency key or a state lock) so it cannot run twice.',
  'exposure-check': 'Remove the route from production, or put it behind the same auth as the rest of the API, and rotate anything it exposed.',
  reflection: 'Encode all user input before it is placed back into a response, or move to a templating engine that escapes by default.',
  'verbose-error': 'Return a generic error to the client and log the stack trace server-side only.',
  'security-headers': 'Add the missing security headers at the gateway or framework middleware level.',
};

function toTicket(finding) {
  return [
    `# ${finding.id} · ${finding.title}`,
    ``,
    `**Severity:** ${finding.severity} (${finding.score.toFixed(1)}/10)`,
    `**Endpoint:** ${finding.request}`,
    `**Owner:** ${finding.owner}`,
    `**Status:** ${finding.status}`,
    ``,
    `## Evidence`,
    '```',
    finding.evidence,
    '```',
    ``,
    `## Why this score`,
    `Base ${finding.scoreBreakdown.base} × ${finding.scoreBreakdown.mult} for ${finding.scoreBreakdown.label}.`,
    ``,
    `## Suggested fix`,
    finding.fix,
  ].join('\n');
}

function fixFor(testName) { return FIX[testName] || 'Review the endpoint manually.'; }

module.exports = { toTicket, fixFor };
