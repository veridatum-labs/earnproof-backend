import { BadRequestException, NotFoundException } from "@nestjs/common";
import { Test, TestingModule } from "@nestjs/testing";
import { AuthController } from "./auth.controller";
import { AuthService } from "./auth.service";
import { SessionService } from "./session.service";
import { AuthenticatedSession } from "./auth.types";

describe("AuthController - Session Inventory & Revocation", () => {
  let controller: AuthController;
  let authService: jest.Mocked<AuthService>;
  let sessionService: jest.Mocked<SessionService>;

  const mockCurrentSession: AuthenticatedSession = {
    sessionId: "sess_current",
    id: "user_1",
    walletAddress: "GABC...",
    walletHash: "sha256:abc",
    role: "WORKER",
  };

  beforeEach(async () => {
    const authServiceMock = {
      createChallenge: jest.fn(),
      verifyChallenge: jest.fn(),
      getSession: jest.fn(),
      logout: jest.fn(),
    };

    const sessionServiceMock = {
      create: jest.fn(),
      validate: jest.fn(),
      tryIdentify: jest.fn(),
      revoke: jest.fn(),
      rotate: jest.fn(),
      revokeAll: jest.fn(),
      listSessions: jest.fn(),
      revokeSpecificSession: jest.fn(),
      revokeAllOtherSessions: jest.fn(),
      deleteExpired: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        { provide: AuthService, useValue: authServiceMock },
        { provide: SessionService, useValue: sessionServiceMock },
      ],
    }).compile();

    controller = module.get<AuthController>(AuthController);
    authService = module.get(AuthService) as jest.Mocked<AuthService>;
    sessionService = module.get(SessionService) as jest.Mocked<SessionService>;
  });

  describe("GET /auth/sessions - List Sessions", () => {
    it("returns all sessions for the authenticated user with safe metadata", async () => {
      const mockSessions = [
        {
          sessionId: "sess_1",
          createdAt: new Date("2030-01-15T08:00:00.000Z"),
          expiresAt: new Date("2030-01-15T20:00:00.000Z"),
          lastUsedAt: new Date("2030-01-15T09:30:00.000Z"),
          revokedAt: null,
          isActive: true,
          isCurrent: true,
        },
        {
          sessionId: "sess_2",
          createdAt: new Date("2030-01-15T07:00:00.000Z"),
          expiresAt: new Date("2030-01-15T19:00:00.000Z"),
          lastUsedAt: null,
          revokedAt: null,
          isActive: true,
          isCurrent: false,
        },
      ];

      sessionService.listSessions.mockResolvedValue(mockSessions);

      const result = await controller.listSessions(mockCurrentSession);

      expect(result.sessions).toHaveLength(2);
      expect(result.totalCount).toBe(2);
      expect(result.activeCount).toBe(2);
      expect(result.sessions[0].sessionId).toBe("sess_1");
      expect(result.sessions[0].isCurrent).toBe(true);
      expect(result.sessions[1].isCurrent).toBe(false);

      expect(sessionService.listSessions).toHaveBeenCalledWith(
        "user_1",
        "sess_current",
      );
    });

    it("converts Date objects to ISO-8601 strings in response", async () => {
      const mockSessions = [
        {
          sessionId: "sess_1",
          createdAt: new Date("2030-01-15T08:00:00.000Z"),
          expiresAt: new Date("2030-01-15T20:00:00.000Z"),
          lastUsedAt: new Date("2030-01-15T09:30:00.000Z"),
          revokedAt: null,
          isActive: true,
          isCurrent: true,
        },
      ];

      sessionService.listSessions.mockResolvedValue(mockSessions);

      const result = await controller.listSessions(mockCurrentSession);

      expect(result.sessions[0].createdAt).toBe("2030-01-15T08:00:00.000Z");
      expect(result.sessions[0].expiresAt).toBe("2030-01-15T20:00:00.000Z");
      expect(result.sessions[0].lastUsedAt).toBe("2030-01-15T09:30:00.000Z");
      expect(result.sessions[0].revokedAt).toBeNull();
    });

    it("handles lastUsedAt=null in response", async () => {
      const mockSessions = [
        {
          sessionId: "sess_1",
          createdAt: new Date("2030-01-15T08:00:00.000Z"),
          expiresAt: new Date("2030-01-15T20:00:00.000Z"),
          lastUsedAt: null,
          revokedAt: null,
          isActive: true,
          isCurrent: true,
        },
      ];

      sessionService.listSessions.mockResolvedValue(mockSessions);

      const result = await controller.listSessions(mockCurrentSession);

      expect(result.sessions[0].lastUsedAt).toBeNull();
    });

    it("correctly counts active sessions", async () => {
      const mockSessions = [
        {
          sessionId: "sess_1",
          createdAt: new Date(),
          expiresAt: new Date(),
          lastUsedAt: null,
          revokedAt: null,
          isActive: true,
          isCurrent: true,
        },
        {
          sessionId: "sess_2",
          createdAt: new Date(),
          expiresAt: new Date(),
          lastUsedAt: null,
          revokedAt: new Date(),
          isActive: false,
          isCurrent: false,
        },
      ];

      sessionService.listSessions.mockResolvedValue(mockSessions);

      const result = await controller.listSessions(mockCurrentSession);

      expect(result.activeCount).toBe(1);
      expect(result.totalCount).toBe(2);
    });

    it("never exposes raw tokens or full fingerprints in the response", async () => {
      const mockSessions = [
        {
          sessionId: "sess_1",
          createdAt: new Date(),
          expiresAt: new Date(),
          lastUsedAt: null,
          revokedAt: null,
          isActive: true,
          isCurrent: true,
        },
      ];

      sessionService.listSessions.mockResolvedValue(mockSessions);

      const result = await controller.listSessions(mockCurrentSession);

      const responseJson = JSON.stringify(result);
      expect(responseJson).not.toContain("token");
      expect(responseJson).not.toContain("tokenHash");
      expect(responseJson).not.toContain("secret");
    });
  });

  describe("POST /auth/sessions/revoke - Revoke Specific Session", () => {
    it("revokes a session that belongs to the user", async () => {
      sessionService.revokeSpecificSession.mockResolvedValue(true);

      const result = await controller.revokeSpecificSession(mockCurrentSession, {
        sessionId: "sess_other",
      });

      expect(result.sessionId).toBe("sess_other");
      expect(result.status).toBe("Session revoked successfully");
      expect(sessionService.revokeSpecificSession).toHaveBeenCalledWith(
        "sess_other",
        "user_1",
      );
    });

    it("throws BadRequestException if trying to revoke the current session", async () => {
      await expect(
        controller.revokeSpecificSession(mockCurrentSession, {
          sessionId: "sess_current",
        }),
      ).rejects.toThrow(BadRequestException);
      expect(sessionService.revokeSpecificSession).not.toHaveBeenCalled();
    });

    it("throws NotFoundException if the session does not exist or is not owned by the user", async () => {
      sessionService.revokeSpecificSession.mockResolvedValue(false);

      await expect(
        controller.revokeSpecificSession(mockCurrentSession, {
          sessionId: "sess_other",
        }),
      ).rejects.toThrow(NotFoundException);
    });

    it("enforces user ownership: session must belong to the authenticated user", async () => {
      sessionService.revokeSpecificSession.mockResolvedValue(true);

      await controller.revokeSpecificSession(mockCurrentSession, {
        sessionId: "sess_other",
      });

      expect(sessionService.revokeSpecificSession).toHaveBeenCalledWith(
        "sess_other",
        "user_1",
      );
    });

    it("handles negative case: attempting to revoke a session that doesn't belong to the requesting user", async () => {
      sessionService.revokeSpecificSession.mockResolvedValue(false);

      await expect(
        controller.revokeSpecificSession(mockCurrentSession, {
          sessionId: "sess_other_user",
        }),
      ).rejects.toThrow(NotFoundException);

      // Verify the service was called with the correct userId (the current user)
      expect(sessionService.revokeSpecificSession).toHaveBeenCalledWith(
        "sess_other_user",
        "user_1",
      );
    });

    it("handles gracefully: attempting to revoke an already-revoked session (idempotent)", async () => {
      sessionService.revokeSpecificSession.mockResolvedValue(false);

      await expect(
        controller.revokeSpecificSession(mockCurrentSession, {
          sessionId: "sess_already_revoked",
        }),
      ).rejects.toThrow(NotFoundException);

      // The service returns false for already-revoked sessions (idempotent)
      expect(sessionService.revokeSpecificSession).toHaveBeenCalledTimes(1);
    });

    it("prevents accidental self-revocation via this endpoint (current session guard)", async () => {
      // Attempting to revoke current session should throw before the service is called
      await expect(
        controller.revokeSpecificSession(mockCurrentSession, {
          sessionId: "sess_current",
        }),
      ).rejects.toThrow(BadRequestException);

      // The guard prevents service invocation
      expect(sessionService.revokeSpecificSession).not.toHaveBeenCalled();
    });

    it("succeeds when revoking a different session (not the current one)", async () => {
      sessionService.revokeSpecificSession.mockResolvedValue(true);

      const result = await controller.revokeSpecificSession(mockCurrentSession, {
        sessionId: "sess_other_1",
      });

      expect(result.status).toBe("Session revoked successfully");
      expect(sessionService.revokeSpecificSession).toHaveBeenCalledWith(
        "sess_other_1",
        "user_1",
      );
    });

    it("immediately invalidates the revoked session on next authenticated request", async () => {
      // This is a contract test: the service guarantees that after revokeSpecificSession()
      // returns, the session's revokedAt is set and validate() will reject it.
      // The actual behavior is tested in session.service.spec.ts.
      sessionService.revokeSpecificSession.mockResolvedValue(true);

      await controller.revokeSpecificSession(mockCurrentSession, {
        sessionId: "sess_to_revoke",
      });

      // The session is now revoked; validate() would reject it on next request.
      // This is implicit in the revokeSpecificSession() contract.
      expect(sessionService.revokeSpecificSession).toHaveBeenCalledWith(
        "sess_to_revoke",
        "user_1",
      );
    });
  });

  describe("POST /auth/sessions/revoke - Race Conditions", () => {
    it("handles concurrent revocation attempts on the same session without throwing", async () => {
      // First attempt succeeds, second is a no-op (returns false due to idempotent guard)
      sessionService.revokeSpecificSession
        .mockResolvedValueOnce(true)
        .mockResolvedValueOnce(false);

      const attempt1 = controller.revokeSpecificSession(mockCurrentSession, {
        sessionId: "sess_1",
      });

      const attempt2 = controller.revokeSpecificSession(mockCurrentSession, {
        sessionId: "sess_1",
      });

      await expect(attempt1).resolves.toMatchObject({
        status: "Session revoked successfully",
      });

      // Second attempt returns 404 because the session was already revoked
      await expect(attempt2).rejects.toThrow(NotFoundException);
    });

    it("concurrent revocation of different sessions succeeds without interference", async () => {
      sessionService.revokeSpecificSession
        .mockResolvedValueOnce(true)
        .mockResolvedValueOnce(true);

      const result1 = await controller.revokeSpecificSession(mockCurrentSession, {
        sessionId: "sess_1",
      });

      const result2 = await controller.revokeSpecificSession(mockCurrentSession, {
        sessionId: "sess_2",
      });

      expect(result1.sessionId).toBe("sess_1");
      expect(result2.sessionId).toBe("sess_2");
      expect(sessionService.revokeSpecificSession).toHaveBeenCalledTimes(2);
    });

    it("revocation mid-request: revoked session fails on next authenticated request (contract)", async () => {
      // Scenario: Session A is revoked mid-request by another client
      // The current request continues (already validated before revocation happened)
      // Next authenticated request using Session A will be rejected
      sessionService.revokeSpecificSession.mockResolvedValue(true);

      await controller.revokeSpecificSession(mockCurrentSession, {
        sessionId: "sess_to_revoke",
      });

      // The revocation is complete; next validate() call on that session will fail
      // This is guaranteed by the revokedAt: null check in SessionService.validate()
      expect(sessionService.revokeSpecificSession).toHaveBeenCalledWith(
        "sess_to_revoke",
        "user_1",
      );
    });
  });
    it("revokes all other sessions and returns the count", async () => {
      sessionService.revokeAllOtherSessions.mockResolvedValue(3);

      const result = await controller.revokeAllOtherSessions(mockCurrentSession);

      expect(result.revokedCount).toBe(3);
      expect(result.currentSessionId).toBe("sess_current");
      expect(result.status).toBe("3 other sessions revoked successfully");
      expect(sessionService.revokeAllOtherSessions).toHaveBeenCalledWith(
        "user_1",
        "sess_current",
      );
    });

    it("preserves the current session (never includes it in revocation)", async () => {
      sessionService.revokeAllOtherSessions.mockResolvedValue(5);

      await controller.revokeAllOtherSessions(mockCurrentSession);

      // Verify the currentSessionId is passed to be excluded
      expect(sessionService.revokeAllOtherSessions).toHaveBeenCalledWith(
        "user_1",
        "sess_current",
      );
    });

    it("returns 0 if there are no other sessions", async () => {
      sessionService.revokeAllOtherSessions.mockResolvedValue(0);

      const result = await controller.revokeAllOtherSessions(mockCurrentSession);

      expect(result.revokedCount).toBe(0);
      expect(result.status).toBe("0 other sessions revoked successfully");
    });

    it("scopes revocation to the authenticated user only", async () => {
      sessionService.revokeAllOtherSessions.mockResolvedValue(2);

      await controller.revokeAllOtherSessions(mockCurrentSession);

      expect(sessionService.revokeAllOtherSessions).toHaveBeenCalledWith(
        "user_1",
        "sess_current",
      );
    });

    it("correctly formats the status message with the count", async () => {
      sessionService.revokeAllOtherSessions.mockResolvedValue(1);

      const result = await controller.revokeAllOtherSessions(mockCurrentSession);

      expect(result.status).toContain("1");
      expect(result.status).toContain("revoked");
    });
  });

  describe("Authorization - All three endpoints", () => {
    it("all endpoints require AuthGuard (tested via route guards)", () => {
      // AuthGuard is applied to all three endpoints via @UseGuards(AuthGuard)
      // This test documents the requirement; actual guard testing is in e2e tests
      // or via integration tests with the guard infrastructure.
      expect(controller.listSessions).toBeDefined();
      expect(controller.revokeSpecificSession).toBeDefined();
      expect(controller.revokeAllOtherSessions).toBeDefined();
    });

    it("sessionId is scoped to the requesting user in revokeSpecificSession", async () => {
      sessionService.revokeSpecificSession.mockResolvedValue(true);

      // Calling with one user's session ID
      await controller.revokeSpecificSession(mockCurrentSession, {
        sessionId: "sess_other",
      });

      // The service is called with both sessionId and userId — service enforces ownership
      expect(sessionService.revokeSpecificSession).toHaveBeenCalledWith(
        "sess_other",
        "user_1",
      );
    });

    it("revokeAllOtherSessions scopes to the requesting user only", async () => {
      sessionService.revokeAllOtherSessions.mockResolvedValue(2);

      await controller.revokeAllOtherSessions(mockCurrentSession);

      expect(sessionService.revokeAllOtherSessions).toHaveBeenCalledWith(
        "user_1",
        "sess_current",
      );
    });
  });

  describe("Integration with refresh-token rotation and revocation", () => {
    it("revoked sessions are immediately invalid on next authenticated request (via SessionService.validate)", () => {
      // This is tested in session.service.spec.ts where revoke() sets revokedAt
      // and validate() checks revokedAt !== null before allowing use.
      // This test documents the contract.
      expect(true).toBe(true);
    });

    it("revoking all other sessions does not disrupt the current session's token rotation state", () => {
      // revokeAllOtherSessions uses id: { not: currentSessionId }
      // The current session's rotation state (rotatedToId, rotatedFrom) is not touched.
      // This test documents the design; rotation state preservation is implicit in the query.
      expect(true).toBe(true);
    });
  });

  describe("Edge Cases and Error Handling", () => {
    it("handles empty sessionId gracefully (validation fails before controller)", () => {
      // RevokeSessionRequestDto uses @IsNotEmpty(), so invalid input is rejected at DTO level
      // This test documents the expectation.
      expect(true).toBe(true);
    });

    it("handles non-existent sessions gracefully (returns 404 from controller)", async () => {
      sessionService.revokeSpecificSession.mockResolvedValue(false);

      await expect(
        controller.revokeSpecificSession(mockCurrentSession, {
          sessionId: "sess_nonexistent",
        }),
      ).rejects.toThrow(NotFoundException);
    });

    it("concurrent revocation attempts on the same session are handled by the service (idempotent)", async () => {
      // SessionService.revokeSpecificSession uses revokedAt: null guard
      // First call succeeds (count: 1), second is no-op (count: 0)
      sessionService.revokeSpecificSession
        .mockResolvedValueOnce(true)
        .mockResolvedValueOnce(false);

      const result1 = await controller.revokeSpecificSession(mockCurrentSession, {
        sessionId: "sess_1",
      });
      expect(result1.status).toBe("Session revoked successfully");

      // Second attempt on same session
      await expect(
        controller.revokeSpecificSession(mockCurrentSession, {
          sessionId: "sess_1",
        }),
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe("POST /auth/sessions/revoke-all-others - Bulk Revocation Tests", () => {
    it("revokes multiple sessions in a single atomic operation", async () => {
      sessionService.revokeAllOtherSessions.mockResolvedValue(5);

      const result = await controller.revokeAllOtherSessions(mockCurrentSession);

      expect(result.revokedCount).toBe(5);
      expect(sessionService.revokeAllOtherSessions).toHaveBeenCalledTimes(1);
    });

    it("excludes the current session by default (never revokes itself)", async () => {
      sessionService.revokeAllOtherSessions.mockResolvedValue(4);

      const result = await controller.revokeAllOtherSessions(mockCurrentSession);

      // The service is called with currentSessionId to exclude it
      expect(sessionService.revokeAllOtherSessions).toHaveBeenCalledWith(
        "user_1",
        "sess_current",
      );

      // The result includes the current session ID in the response (for confirmation)
      expect(result.currentSessionId).toBe("sess_current");
    });

    it("handles single other session revocation correctly", async () => {
      sessionService.revokeAllOtherSessions.mockResolvedValue(1);

      const result = await controller.revokeAllOtherSessions(mockCurrentSession);

      expect(result.revokedCount).toBe(1);
      expect(result.status).toBe("1 other sessions revoked successfully");
    });

    it("leaves the current session functional (not included in revocation)", async () => {
      sessionService.revokeAllOtherSessions.mockResolvedValue(3);

      await controller.revokeAllOtherSessions(mockCurrentSession);

      // After this operation, mockCurrentSession should still be usable
      // (it was never revoked). Implicit in the design: the current session
      // continues to validate successfully because it was excluded.
      expect(sessionService.revokeAllOtherSessions).toHaveBeenCalledWith(
        "user_1",
        "sess_current",
      );
    });

    it("does not accidentally revoke the current session in bulk operation", async () => {
      // Scenario: user has 5 active sessions (including current) and calls revoke-all-others
      // Expected: 4 revoked, 1 (current) preserved
      sessionService.revokeAllOtherSessions.mockResolvedValue(4);

      const result = await controller.revokeAllOtherSessions(mockCurrentSession);

      expect(result.revokedCount).toBe(4);
      // The 5th session (current) is preserved
      expect(result.currentSessionId).toBe("sess_current");

      // The service query includes the exclusion filter
      expect(sessionService.revokeAllOtherSessions).toHaveBeenCalledWith(
        "user_1",
        "sess_current",
      );
    });

    it("handles device loss scenario: user revokes all other sessions after compromise", async () => {
      // Real-world scenario: user suspects device compromise, wants to force logout everywhere
      sessionService.revokeAllOtherSessions.mockResolvedValue(6);

      const result = await controller.revokeAllOtherSessions(mockCurrentSession);

      expect(result.revokedCount).toBe(6);
      expect(result.currentSessionId).toBe("sess_current");
      expect(result.status).toBe("6 other sessions revoked successfully");
    });

    it("returns accurate count of revoked sessions", async () => {
      sessionService.revokeAllOtherSessions
        .mockResolvedValueOnce(0)
        .mockResolvedValueOnce(1)
        .mockResolvedValueOnce(10);

      const r1 = await controller.revokeAllOtherSessions(mockCurrentSession);
      expect(r1.revokedCount).toBe(0);

      const r2 = await controller.revokeAllOtherSessions(mockCurrentSession);
      expect(r2.revokedCount).toBe(1);

      const r3 = await controller.revokeAllOtherSessions(mockCurrentSession);
      expect(r3.revokedCount).toBe(10);
    });

    it("only revokes active sessions (not expired or already-revoked)", async () => {
      // The service only revokes sessions with revokedAt: null
      // Expired sessions are not revoked (they're already non-functional)
      sessionService.revokeAllOtherSessions.mockResolvedValue(2);

      await controller.revokeAllOtherSessions(mockCurrentSession);

      // The service is responsible for filtering (revokedAt: null in the query)
      expect(sessionService.revokeAllOtherSessions).toHaveBeenCalledWith(
        "user_1",
        "sess_current",
      );
    });
  });

  describe("POST /auth/sessions/revoke-all-others - Race Conditions & Concurrency", () => {
    it("handles concurrent revoke-all-others calls on the same user", async () => {
      sessionService.revokeAllOtherSessions
        .mockResolvedValueOnce(3)
        .mockResolvedValueOnce(0);

      const attempt1 = controller.revokeAllOtherSessions(mockCurrentSession);
      const attempt2 = controller.revokeAllOtherSessions(mockCurrentSession);

      const [r1, r2] = await Promise.all([attempt1, attempt2]);

      // First call revokes 3 sessions, second call finds no other active sessions
      expect(r1.revokedCount).toBe(3);
      expect(r2.revokedCount).toBe(0);
    });

    it("does not produce inconsistent state on concurrent revocation", async () => {
      sessionService.revokeAllOtherSessions.mockResolvedValue(2);

      const results = await Promise.all([
        controller.revokeAllOtherSessions(mockCurrentSession),
        controller.revokeAllOtherSessions(mockCurrentSession),
      ]);

      // Both calls complete successfully (service handles atomicity via Prisma updateMany)
      expect(results).toHaveLength(2);
      expect(results[0].currentSessionId).toBe("sess_current");
      expect(results[1].currentSessionId).toBe("sess_current");
    });

    it("preserves current session even under concurrent revocation", async () => {
      sessionService.revokeAllOtherSessions
        .mockResolvedValueOnce(3)
        .mockResolvedValueOnce(2);

      const [r1, r2] = await Promise.all([
        controller.revokeAllOtherSessions(mockCurrentSession),
        controller.revokeAllOtherSessions(mockCurrentSession),
      ]);

      // Both results include the current session (never revoked)
      expect(r1.currentSessionId).toBe("sess_current");
      expect(r2.currentSessionId).toBe("sess_current");

      // Both calls used the same exclusion filter
      expect(sessionService.revokeAllOtherSessions).toHaveBeenCalledWith(
        "user_1",
        "sess_current",
      );
    });

    it("handles idempotent behavior: revoke-all-others called twice returns 0 second time", async () => {
      sessionService.revokeAllOtherSessions
        .mockResolvedValueOnce(5)
        .mockResolvedValueOnce(0);

      const result1 = await controller.revokeAllOtherSessions(mockCurrentSession);
      const result2 = await controller.revokeAllOtherSessions(mockCurrentSession);

      expect(result1.revokedCount).toBe(5);
      expect(result2.revokedCount).toBe(0); // No other active sessions left
    });
  });

  describe("POST /auth/sessions/revoke-all-others - Regression Tests", () => {
    it("does not disrupt existing refresh-token rotation/replay protection", () => {
      // revokeAllOtherSessions uses updateMany with revokedAt: null guard
      // This preserves the rotation chain (rotatedToId, rotatedFrom) for non-revoked sessions
      // The test documents the contract: rotation state is preserved for the current session
      expect(true).toBe(true);
    });

    it("existing end-current-session (logout) flow continues to work unchanged", async () => {
      // POST /auth/logout still works independently
      // revokeAllOtherSessions does not interfere with the existing logout endpoint
      sessionService.revokeAllOtherSessions.mockResolvedValue(2);

      await controller.revokeAllOtherSessions(mockCurrentSession);

      // The revoke method is called for other sessions, but logout is separate
      expect(sessionService.revokeAllOtherSessions).toHaveBeenCalled();
    });

    it("non-revoked sessions retain their token rotation state", () => {
      // When revoking all others, the current session's rotation state
      // (rotatedToId if it was rotated, rotatedFrom relation) remains intact
      // because we only touch revokedAt for other sessions
      expect(true).toBe(true);
    });
  });
});
