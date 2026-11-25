'use strict';

const SECRET_PATTERNS = [
  { id: 'PRIVATE_KEY_BLOCK', regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/ },
  { id: 'AWS_ACCESS_KEY', regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { id: 'GITHUB_TOKEN', regex: /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/ },
  { id: 'BEARER_JWT_LIKE', regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/ },
];

function scanFixtureContents(entries, options = {}) {
  const allowlist = Array.isArray(options.allowlist) ? options.allowlist : [];
  const findings = [];

  for (const entry of entries) {
    const filePath = String(entry.path || '');
    const content = String(entry.content || '');

    for (const pattern of SECRET_PATTERNS) {
      const match = content.match(pattern.regex);
      if (!match) continue;

      const matchedText = match[0];
      const allowed = allowlist.some(
        (item) =>
          item.path === filePath &&
          item.patternId === pattern.id &&
          item.value === matchedText &&
          typeof item.rationale === 'string' &&
          item.rationale.trim().length > 0
      );

      if (!allowed) {
        findings.push({
          path: filePath,
          patternId: pattern.id,
          reason: 'POTENTIAL_SECRET_OR_KEY_IN_FIXTURE',
        });
      }
    }
  }

  return {
    ok: findings.length === 0,
    findings,
  };
}

module.exports = { scanFixtureContents, SECRET_PATTERNS };
