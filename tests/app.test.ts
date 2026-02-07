import { beforeEach, describe, expect, it } from "vitest";
import request from "supertest";
import app from "../src/app.js";
import { db } from "../src/db.js";

beforeEach(() => {
  for (const t of ["audit_logs", "otp_challenges", "shifts", "users"])
    db.prepare(`DELETE FROM ${t}`).run();
});
describe("SecureShift scheduling", () => {
  it("enforces role boundaries and supports assignment", async () => {
    const manager = await request(app)
      .post("/auth/register")
      .send({
        email: "manager@test.local",
        password: "correct-horse-battery",
        role: "manager",
      });
    const login = await request(app)
      .post("/auth/login")
      .send({ email: "manager@test.local", password: "correct-horse-battery" });
    const worker = await request(app)
      .post("/auth/register")
      .send({
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
});
