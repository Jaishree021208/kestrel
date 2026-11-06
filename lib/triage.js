// Triage and severity agent — scores each verified hit in business context, not with a
// generic CVSS-only number, and maps it to the owning team.

const BASE_SCORE = {
  idor: 8,
  'double-spend': 8,
  'exposure-check': 7,
  reflection: 6,
  'verbose-error': 6,
  'security-headers': 3,
};

function contextMultiplier(hit) {
  const blob = (hit.evidence || '') + ' ' + hit.endpoint.path;
  if (/passport|ssn/i.test(blob)) return [1.3, 'PII exposure'];
  if (/refund|payment|fare|price/i.test(blob)) return [1.3, 'money movement'];
  if (/api_key|password|secret/i.test(blob)) return [1.25, 'credential exposure'];
  return [1.0, 'general risk'];
}

function severityFor(score) {
  if (score >= 9) return 'Critical';
  if (score >= 7) return 'High';
  if (score >= 5) return 'Medium';
  return 'Low';
}

function score(hit) {
  const base = BASE_SCORE[hit.testName] ?? 4;
  const [mult, label] = contextMultiplier(hit);
  const total = Math.min(10, base * mult);
  return { base, mult, label, total, severity: severityFor(total) };
}

module.exports = { score, severityFor };
