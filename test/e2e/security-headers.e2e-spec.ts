import * as request from 'supertest';
import { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { AppModule } from '../../src/app.module';
import { BASE_REQUIRED_HEADERS } from '../../src/common/http/security-headers.policy';

function assertNoDuplicateOrContradictoryHeaders(rawHeaders: string[]) {
  const counts = new Map<string, string[]>();
  for (let i = 0; i < rawHeaders.length; i += 2) {
    const key = rawHeaders[i].toLowerCase();
    const val = rawHeaders[i + 1];
    counts.set(key, [...(counts.get(key) ?? []), val]);
  }

  for (const singleHeader of [
    'x-content-type-options',
    'x-frame-options',
    'strict-transport-security',
    'cache-control',
    'content-disposition',
  ]) {
    const values = counts.get(singleHeader) ?? [];
    expect(values.length).toBeLessThanOrEqual(1);
  }

  const cacheControl = (counts.get('cache-control')?.[0] ?? '').toLowerCase();
  if (cacheControl.includes('no-store')) {
    expect(cacheControl).not.toContain('public');
  }
}

describe('Security Response Header Policy (#437)', () => {
  let app: INestApplication;

  beforeAll(async () => {
    const mod = await Test.createTestingModule({ imports: [AppModule] }).compile();
    app = mod.createNestApplication();
    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  it.each([
    ['HEALTH', '/api/v1/health', [200, 503]],
    ['ERROR (404)', '/api/v1/__nonexistent_route__', [404]],
    ['ERROR (401)', '/api/v1/organizations', [401, 403]],
  ])('enforces baseline security headers on %s path (%s)', async (_label, path, allowedStatuses) => {
    const res = await request(app.getHttpServer()).get(path);
    expect(allowedStatuses).toContain(res.status);

    for (const [header, expected] of Object.entries(BASE_REQUIRED_HEADERS)) {
      expect(res.headers[header]?.toLowerCase()).toBe(expected.toLowerCase());
    }
    expect(res.headers['cache-control']).toContain('no-store');
    assertNoDuplicateOrContradictoryHeaders(res.res.rawHeaders);
  });

  it('applies HSTS only in production environments', async () => {
    const res = await request(app.getHttpServer()).get('/api/v1/health');
    if (process.env.NODE_ENV === 'production') {
      expect(res.headers['strict-transport-security']).toMatch(/max-age=\d+/);
    } else {
      expect(res.headers['strict-transport-security']).toBeUndefined();
    }
  });
});