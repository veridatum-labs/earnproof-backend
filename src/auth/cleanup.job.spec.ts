import { CleanupJob } from "./cleanup.job";
import { SessionService } from "./session.service";

describe("CleanupJob", () => {
  it("deletes expired sessions when the scheduled task runs", async () => {
    const sessionService = {
      deleteExpired: jest.fn().mockResolvedValue(3),
    } as unknown as SessionService;
    const job = new CleanupJob(sessionService);

    await job.deleteExpiredSessions();

    expect(sessionService.deleteExpired).toHaveBeenCalledTimes(1);
  });
});
