export type RouteSecurityClass = 'API' | 'DOCS' | 'HEALTH' | 'DOWNLOAD_CREDENTIAL' | 'ERROR';

export interface SecurityHeaderExpectation {
  cacheControl: string;
  contentDisposition?: RegExp;
  cspContains?: string[];
  requireHstsInProd: boolean;
}

export const SECURITY_HEADER_POLICY: Record<RouteSecurityClass, SecurityHeaderExpectation> = {
  API: {
    cacheControl: 'no-store',
    requireHstsInProd: true,
  },
  HEALTH: {
    cacheControl: 'no-store',
    requireHstsInProd: true,
  },
  DOCS: {
    cacheControl: 'no-cache',
    requireHstsInProd: true,
  },
  DOWNLOAD_CREDENTIAL: {
    cacheControl: 'no-store, private',
    contentDisposition: /^attachment;\s*filename="[^"]+"$/,
    requireHstsInProd: true,
  },
  ERROR: {
    cacheControl: 'no-store',
    requireHstsInProd: true,
  },
};

export const BASE_REQUIRED_HEADERS = {
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
} as const;