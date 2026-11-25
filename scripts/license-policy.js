'use strict';

function sanitizeString(value) {
  if (typeof value !== 'string') return '';
  return value
    .replace(/(?:token|password|secret|key)=[^\s&]+/gi, '[REDACTED]')
    .replace(/\/(?:Users|home|var|tmp|opt)\/[^\s"')]+/g, '[PATH_REDACTED]')
    .replace(/[A-Za-z]:\\[^\s"')]+/g, '[PATH_REDACTED]');
}

function evaluateLicensePolicy(params) {
  const packages =
    params.lockfile && typeof params.lockfile.packages === 'object'
      ? params.lockfile.packages
      : {};
  const approved = new Set((params.approvedLicenses || []).map((s) => s.toUpperCase()));
  const denied = new Set((params.deniedLicenses || []).map((s) => s.toUpperCase()));
  const overrides = Array.isArray(params.overrides) ? params.overrides : [];
  const nowMs = params.nowMs ?? Date.now();

  const violations = [];
  const attributionEntries = [];

  for (const [pkgPath, meta] of Object.entries(packages)) {
    if (!pkgPath || pkgPath === '') continue;
    if (!meta || typeof meta !== 'object') continue;

    if (meta.dev === true) continue;

    const pkgName = meta.name || pkgPath.split('node_modules/').pop();
    const licenseRaw = typeof meta.license === 'string' && meta.license.trim()
      ? meta.license.trim()
      : 'UNKNOWN';
    const licenseUpper = licenseRaw.toUpperCase();

    const validOverride = overrides.find(
      (ov) =>
        ov.packageName === pkgName &&
        typeof ov.owner === 'string' &&
        ov.owner.trim().length > 0 &&
        typeof ov.rationale === 'string' &&
        ov.rationale.trim().length > 0 &&
        typeof ov.expiresAt === 'string' &&
        Date.parse(ov.expiresAt) > nowMs
    );

    const isDenied = denied.has(licenseUpper);
    const isApproved = approved.has(licenseUpper);

    if ((isDenied || !isApproved) && !validOverride) {
      violations.push({
        package: sanitizeString(pkgName),
        license: sanitizeString(licenseRaw),
        reason: isDenied ? 'LICENSE_DENIED' : 'LICENSE_UNKNOWN_OR_UNAPPROVED',
      });
    }

    attributionEntries.push({
      package: sanitizeString(pkgName),
      version: sanitizeString(meta.version || ''),
      license: sanitizeString(licenseRaw),
      overridden: Boolean(validOverride),
    });
  }

  attributionEntries.sort((a, b) => a.package.localeCompare(b.package));

  return {
    ok: violations.length === 0,
    violations,
    attribution: attributionEntries,
  };
}

module.exports = { evaluateLicensePolicy, sanitizeString };
