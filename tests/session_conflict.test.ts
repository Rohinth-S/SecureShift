import { beforeEach, describe, expect, it } from "vitest";
import request from "supertest";
import app from "../src/app.js";
import { db } from "../src/db.js";

beforeEach(() => {
  for (const table of ["audit_logs", "otp_challenges", "refresh_sessions", "shifts", "users"]) db.prepare(`DELETE FROM ${table}`).run();
});

describe("SecureShift scheduling and sessions", () => {
  it("rejects overlapping assignments for the same worker", async () => {
    const manager = await request(app).post("/auth/register").send({ email: "manager-conflict@test.local", password: "correct-horse-battery", role: "manager" });
    const login = await request(app).post("/auth/login").send({ email: "manager-conflict@test.local", password: "correct-horse-battery" });
    const worker = await request(app).post("/auth/register").send({ email: "worker-conflict@test.local", password: "correct-horse-battery", role: "worker" });
    const headers = { Authorization: `Bearer ${login.body.token}` };
    const first = await request(app).post("/shifts").set(headers).send({ title: "Morning route", startsAt: "2026-12-01T08:00:00.000Z", endsAt: "2026-12-01T12:00:00.000Z", location: "Bengaluru" });
    const second = await request(app).post("/shifts").set(headers).send({ title: "Midday route", startsAt: "2026-12-01T11:00:00.000Z", endsAt: "2026-12-01T14:00:00.000Z", location: "Bengaluru" });
    expect((await request(app).post(`/shifts/${first.body.id}/assign`).set(headers).send({ workerId: worker.body.id })).status).toBe(200);
    const overlap = await request(app).post(`/shifts/${second.body.id}/assign`).set(headers).send({ workerId: worker.body.id });
    expect(overlap.status).toBe(409);
    expect(overlap.body.error).toMatch(/overlapping/);
  });

  it("rotates refresh sessions and rejects replayed tokens", async () => {
    await request(app).post("/auth/register").send({ email: "refresh@test.local", password: "correct-horse-battery", role: "worker" });
    const login = await request(app).post("/auth/login").send({ email: "refresh@test.local", password: "correct-horse-battery" });
    expect(login.body.refreshToken).toMatch(/^[A-Za-z0-9_-]{30,}$/);
    const rotated = await request(app).post("/auth/refresh").send({ refreshToken: login.body.refreshToken });
    expect(rotated.status).toBe(200);
    expect(rotated.body.refreshToken).not.toBe(login.body.refreshToken);
    const replay = await request(app).post("/auth/refresh").send({ refreshToken: login.body.refreshToken });
    expect(replay.status).toBe(401);
    const logout = await request(app).post("/auth/logout").set("Authorization", `Bearer ${rotated.body.token}`).send({ refreshToken: rotated.body.refreshToken });
    expect(logout.status).toBe(204);
    expect((await request(app).post("/auth/refresh").send({ refreshToken: rotated.body.refreshToken })).status).toBe(401);
  });
});
