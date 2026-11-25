import { createHash, randomBytes } from 'crypto';
import { PrismaService } from '../../src/database/prisma.service';
import { SessionService } from '../../src/auth/session.service';

describe('Session Fixation & Concurrent Rotation (#438)', () => {
  let prisma: PrismaService;
  let sessionService: SessionService;
  const logSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
  const warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});

  const makeEphemeralToken = () => {
    const raw = randomBytes(32).toString('hex');
    const hash = createHash('sha256').update(raw).digest('hex');
    return { raw, hash };
  };

  afterEach(() => {
    logSpy.mockClear();
    warnSpy.mockClear();
  });

  it('rejects session fixation with caller-supplied pre-auth token', async () => {
    const attackerToken = makeEphemeralToken();
    // Creating a new authenticated session must always mint a fresh server-generated token
    const issued = await sessionService.createSession({ userId: 'user-fixation-1' });
    expect(issued.tokenHash).not.toBe(attackerToken.hash);

    // Pre-existing attacker token cannot authenticate
    await expect(sessionService.validateToken(attackerToken.raw)).rejects.toThrow();
  });

  it('allows exactly one successor under simultaneous rotation and rejects predecessor replay', async () => {
    const initial = await sessionService.createSession({ userId: 'user-race-1' });

    const [r1, r2] = await Promise.allSettled([
      sessionService.rotate(initial.rawToken),
      sessionService.rotate(initial.rawToken),
    ]);

    const fulfilled = [r1, r2].filter((r) => r.status === 'fulfilled');
    const rejected = [r1, r2].filter((r) => r.status === 'rejected');

    expect(fulfilled).toHaveLength(1);
    expect(rejected).toHaveLength(1);

    // Predecessor reuse is rejected after cutover
    await expect(sessionService.validateToken(initial.rawToken)).rejects.toThrow();

    // Only the winning successor remains active in durable DB state
    const activeSessions = await prisma.authSession.findMany({
      where: { userId: 'user-race-1', revokedAt: null },
    });
    expect(activeSessions).toHaveLength(1);

    // Raw tokens must never appear in logs
    const allLogs = [...logSpy.mock.calls, ...warnSpy.mock.calls].flat().join(' ');
    expect(allLogs).not.toContain(initial.rawToken);
  });

  it('prevents concurrent logout from being resurrected by an in-flight rotation', async () => {
    const initial = await sessionService.createSession({ userId: 'user-logout-race' });

    await Promise.allSettled([
      sessionService.revoke(initial.sessionId, 'USER_LOGOUT'),
      sessionService.rotate(initial.rawToken),
    ]);

    // If logout won, zero active sessions exist; if rotation won before logout, revoking family leaves zero
    const oldRow = await prisma.authSession.findUnique({ where: { id: initial.sessionId } });
    expect(oldRow?.revokedAt).not.toBeNull();
    await expect(sessionService.validateToken(initial.rawToken)).rejects.toThrow();
  });
});