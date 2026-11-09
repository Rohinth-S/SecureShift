import { beforeEach, describe, expect, it } from "vitest";
import request from "supertest";
import app from "../src/app.js";
import { db } from "../src/db.js";

beforeEach(() => {
  for (const t of ["audit_logs", "otp_challenges", "refresh_sessions", "shifts", "users"])
    db.prepare(`DELETE FROM ${t}`).run();
});
describe("SecureShift scheduling", () => {
  it("enforces role boundaries and supports assignment", async () => {
    const manager = await request(app).post("/auth/register").send({
      email: "manager@test.local",
      password: "correct-horse-battery",
      role: "manager",
    });
    const login = await request(app)
      .post("/auth/login")
      .send({ email: "manager@test.local", password: "correct-horse-battery" });
    const worker = await request(app).post("/auth/register").send({
      email: "worker@test.local",
      password: "correct-horse-battery",
      role: "worker",
    });
    const r = await request(app)
      .post("/shifts")
      .set("Authorization", `Bearer ${login.body.token}`)
      .send({
        title: "Morning route",
        startsAt: "2026-12-01T08:00:00.000Z",
        endsAt: "2026-12-01T12:00:00.000Z",
        location: "Bengaluru",
      });
    expect(r.status).toBe(201);
    const a = await request(app)
      .post(`/shifts/${r.body.id}/assign`)
      .set("Authorization", `Bearer ${login.body.token}`)
      .send({ workerId: worker.body.id });
    expect(a.status).toBe(200);
  });

  it("persists OTP consumption and audit events through the repository", async () => {
    await request(app).post("/auth/register").send({ email: "audit-manager@test.local", password: "correct-horse-battery", role: "manager" });
    const login = await request(app).post("/auth/login").send({ email: "audit-manager@test.local", password: "correct-horse-battery" });
    const otp = await request(app).post("/auth/request-otp").set("Authorization", `Bearer ${login.body.token}`);
    expect(otp.status).toBe(202); expect(otp.body.devCode).toMatch(/^\d{6}$/);
    const verified = await request(app).post("/auth/verify-otp").set("Authorization", `Bearer ${login.body.token}`).send({ challengeId: otp.body.challengeId, code: otp.body.devCode });
    expect(verified.status).toBe(200); expect(verified.body.verified).toBe(true);
    const replay = await request(app).post("/auth/verify-otp").set("Authorization", `Bearer ${login.body.token}`).send({ challengeId: otp.body.challengeId, code: otp.body.devCode });
    expect(replay.status).toBe(400);
    const audit = await request(app).get("/audit").set("Authorization", `Bearer ${login.body.token}`);
    expect(audit.status).toBe(200); expect(audit.body.map((row: { action: string }) => row.action)).toEqual(expect.arrayContaining(["otp.requested", "otp.verified"]));
  });
});

