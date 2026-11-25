'use strict';

const fs = require('node:fs');
const path = require('node:path');

function verifyLockfileProvenance(lockfile, options = {}) {
  const allowedRegistries = new Set(
    options.allowedRegistries || ['https://registry.npmjs.org/']
  );
  const requireProvenance = options.requireProvenance !== false;
  const nowMs = options.nowMs ?? Date.now();
  const exceptions = Array.isArray(options.exceptions) ? options.exceptions : [];

  const packages = lockfile && typeof lockfile.packages === 'object' ? lockfile.packages : {};
  const violations = [];

  for (const [pkgPath, meta] of Object.entries(packages)) {
    if (!pkgPath || pkgPath === '') continue;
    if (!meta || typeof meta !== 'object') continue;

    const pkgName = meta.name || pkgPath.split('node_modules/').pop();
    const activeException = exceptions.find(
      (ex) =>
        ex.packageName === pkgName &&
        typeof ex.owner === 'string' &&
        ex.owner.trim().length > 0 &&
        typeof ex.reason === 'string' &&
        ex.reason.trim().length > 0 &&
        typeof ex.expiresAt === 'string' &&
        Date.parse(ex.expiresAt) > nowMs
    );

    const reasons = [];

    if (!meta.integrity || typeof meta.integrity !== 'string' || !meta.integrity.startsWith('sha')) {
      reasons.push('MISSING_OR_INVALID_INTEGRITY');
    }

    if (meta.resolved) {
      const registryMatched = Array.from(allowedRegistries).some((prefix) =>
        String(meta.resolved).startsWith(prefix)
      );
      if (!registryMatched) {
        reasons.push(`UNEXPECTED_REGISTRY:${meta.resolved}`);
      }
    }

    if (requireProvenance && meta.dev !== true && !meta.attestations && !meta.hasProvenance) {
      reasons.push('MISSING_PROVENANCE_ATTESTATION');
    }

    if (reasons.length > 0 && !activeException) {
      violations.push({
        package: pkgName,
        path: pkgPath,
        reasons,
      });
    }
  }

  return {
    ok: violations.length === 0,
    violations,
  };
}

function main() {
  const lockfilePath = path.resolve(process.cwd(), 'package-lock.json');
  const exceptionsPath = path.resolve(process.cwd(), 'config/provenance-exceptions.json');

  const lockfile = JSON.parse(fs.readFileSync(lockfilePath, 'utf8'));
  let exceptions = [];
  if (fs.existsSync(exceptionsPath)) {
    const raw = JSON.parse(fs.readFileSync(exceptionsPath, 'utf8'));
    exceptions = Array.isArray(raw.exceptions) ? raw.exceptions : [];
  }

  const result = verifyLockfileProvenance(lockfile, { exceptions });
  if (!result.ok) {
    console.error('Provenance verification failed:', JSON.stringify(result.violations, null, 2));
    process.exitCode = 1;
    return;
  }

  console.log('Provenance verification passed.');
}

if (require.main === module) {
  main();
}

module.exports = { verifyLockfileProvenance };
