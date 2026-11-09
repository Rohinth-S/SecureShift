import express, { NextFunction, Request, Response } from "express";
import cors from "cors";
import crypto from "node:crypto";
import { z } from "zod";
import { repository } from "./repository.js";
import { hashOtp, hashPassword, verifyPassword, signToken, verifyToken, Claims, Role, createRefreshToken, hashRefreshToken } from "./security.js";

const app = express();
const corsOrigins = (process.env.CORS_ORIGINS ?? "").split(",").map((v) => v.trim()).filter(Boolean);
app.use(cors({ origin: (origin, callback) => {
  if (!origin || (process.env.NODE_ENV !== "production" && corsOrigins.length === 0) || corsOrigins.includes(origin)) callback(null, true);
  else callback(new Error("origin not allowed"));
} }));
app.use(express.json({ limit: "1mb" }));
type Authed = Request & { user?: Claims };
function auth(req: Authed, res: Response, next: NextFunction) {
  const h = req.header("authorization");
  if (!h?.startsWith("Bearer ")) return res.status(401).json({ error: "missing bearer token" });
  try { req.user = verifyToken(h.slice(7)); next(); } catch { return res.status(401).json({ error: "invalid or expired token" }); }
}
function allow(...roles: Role[]) { return (req: Authed, res: Response, next: NextFunction) => { if (!req.user || !roles.includes(req.user.role)) return res.status(403).json({ error: "insufficient role" }); next(); }; }
async function audit(actor: string, action: string, type: string, id: string, meta: unknown = {}) {
  await repository.appendAudit({ id: crypto.randomUUID(), actor_id: actor, action, entity_type: type, entity_id: id, metadata_json: JSON.stringify(meta), created_at: new Date().toISOString() });
}
const refreshLifetimeMs = 30 * 24 * 60 * 60 * 1000;
async function issueRefreshSession(userId: string) {
  const issued = createRefreshToken();
  const now = new Date();
  await repository.createRefreshSession({ id: crypto.randomUUID(), user_id: userId, token_hash: issued.tokenHash, expires_at: new Date(now.getTime() + refreshLifetimeMs).toISOString(), revoked_at: null, created_at: now.toISOString() });
  return issued.token;
}
const register = z.object({ email: z.string().email(), password: z.string().min(12), role: z.enum(["admin", "manager", "worker"]).default("worker"), phone: z.string().optional() });
app.get("/health", (_, res) => res.json({ service: "secureshift", status: "ok", persistence: repository.mode, time: new Date().toISOString() }));
app.post("/auth/register", async (req, res) => {
  const p = register.safeParse(req.body); if (!p.success) return res.status(400).json({ error: p.error.flatten() });
  const id = crypto.randomUUID(); const createdAt = new Date().toISOString();
  try { await repository.createUser({ id, email: p.data.email.toLowerCase(), password_hash: hashPassword(p.data.password), role: p.data.role, phone: p.data.phone ?? null, created_at: createdAt }); return res.status(201).json({ id, email: p.data.email.toLowerCase(), role: p.data.role }); }
  catch { return res.status(409).json({ error: "email already registered" }); }
});
app.post("/auth/login", async (req, res) => {
  const p = z.object({ email: z.string().email(), password: z.string() }).safeParse(req.body); if (!p.success) return res.status(400).json({ error: "invalid credentials" });
  const u = await repository.findUserByEmail(p.data.email.toLowerCase());
  if (!u || !verifyPassword(p.data.password, u.password_hash)) return res.status(401).json({ error: "invalid credentials" });
  const claims = { sub: u.id, email: u.email, role: u.role } as Claims;
  return res.json({ token: signToken(claims), refreshToken: await issueRefreshSession(u.id), user: { id: u.id, email: u.email, role: u.role } });
});
app.post("/auth/refresh", async (req, res) => {
  const p = z.object({ refreshToken: z.string().min(20).max(200) }).safeParse(req.body); if (!p.success) return res.status(400).json({ error: "refreshToken required" });
  const session = await repository.findRefreshSession(hashRefreshToken(p.data.refreshToken));
  if (!session || session.revoked_at || new Date(session.expires_at) <= new Date()) return res.status(401).json({ error: "invalid or expired refresh token" });
  const user = await repository.findUserById(session.user_id); if (!user) return res.status(401).json({ error: "invalid refresh session" });
  await repository.revokeRefreshSession(session.id, new Date().toISOString());
  const claims = { sub: user.id, email: user.email, role: user.role } as Claims;
  return res.json({ token: signToken(claims), refreshToken: await issueRefreshSession(user.id) });
});
app.post("/auth/logout", auth, async (req: Authed, res) => {
  const p = z.object({ refreshToken: z.string().min(20).max(200) }).safeParse(req.body); if (!p.success) return res.status(400).json({ error: "refreshToken required" });
  const session = await repository.findRefreshSession(hashRefreshToken(p.data.refreshToken));
  if (session && session.user_id === req.user!.sub) await repository.revokeRefreshSession(session.id, new Date().toISOString());
  return res.status(204).send();
});
app.post("/auth/request-otp", auth, async (req: Authed, res) => {
  const id = crypto.randomUUID(); const code = String(Math.floor(100000 + Math.random() * 900000)); const expires = new Date(Date.now() + 5 * 60_000).toISOString();
  await repository.createOtp({ id, user_id: req.user!.sub, code_hash: hashOtp(code), expires_at: expires, consumed_at: null }); await audit(req.user!.sub, "otp.requested", "otp", id);
  res.status(202).json({ challengeId: id, expiresAt: expires, devCode: process.env.NODE_ENV === "production" ? undefined : code });
});
app.post("/auth/verify-otp", auth, async (req: Authed, res) => {
  const p = z.object({ challengeId: z.string(), code: z.string().length(6) }).safeParse(req.body); if (!p.success) return res.status(400).json({ error: "invalid payload" });
  const c = await repository.findActiveOtp(p.data.challengeId, req.user!.sub);
  if (!c || new Date(c.expires_at) < new Date() || c.code_hash !== hashOtp(p.data.code)) return res.status(400).json({ error: "invalid or expired code" });
  await repository.consumeOtp(c.id, new Date().toISOString()); await audit(req.user!.sub, "otp.verified", "otp", c.id); res.json({ verified: true });
});
const shift = z.object({ title: z.string().min(2).max(120), startsAt: z.string().datetime(), endsAt: z.string().datetime(), location: z.string().min(2).max(160) });
app.get("/shifts", auth, async (_req: Authed, res) => res.json(await repository.listShifts()));
app.post("/shifts", auth, allow("admin", "manager"), async (req: Authed, res) => {
  const p = shift.safeParse(req.body); if (!p.success) return res.status(400).json({ error: p.error.flatten() });
  if (new Date(p.data.endsAt) <= new Date(p.data.startsAt)) return res.status(422).json({ error: "endsAt must be after startsAt" });
  const row = { id: crypto.randomUUID(), title: p.data.title, starts_at: p.data.startsAt, ends_at: p.data.endsAt, location: p.data.location, status: "open" as const, assignee_id: null, created_by: req.user!.sub, created_at: new Date().toISOString() };
  await repository.createShift(row); await audit(req.user!.sub, "shift.created", "shift", row.id, p.data); res.status(201).json({ id: row.id, ...p.data, status: row.status });
});
app.post("/shifts/:id/assign", auth, allow("admin", "manager"), async (req: Authed, res) => {
  const shiftId = String(req.params.id);
  const p = z.object({ workerId: z.string() }).safeParse(req.body); if (!p.success) return res.status(400).json({ error: "workerId required" });
  const worker = await repository.findUserById(p.data.workerId); if (!worker || worker.role !== "worker") return res.status(422).json({ error: "assignee must be a worker" });
  const s = await repository.findShift(shiftId); if (!s) return res.status(404).json({ error: "shift not found" }); if (s.status !== "open") return res.status(409).json({ error: "only open shifts can be assigned" });
  if (await repository.hasOverlappingShift(worker.id, s.starts_at, s.ends_at, s.id)) return res.status(409).json({ error: "worker has overlapping shift" });
  const changed = await repository.assignShift(s.id, worker.id); if (!changed) return res.status(409).json({ error: "only open shifts can be assigned" });
  await audit(req.user!.sub, "shift.assigned", "shift", s.id, { workerId: worker.id }); res.json({ id: s.id, status: "assigned", assigneeId: worker.id });
});
app.post("/shifts/:id/complete", auth, async (req: Authed, res) => {
  const shiftId = String(req.params.id);
  const s = await repository.findShift(shiftId); if (!s) return res.status(404).json({ error: "shift not found" });
  if (req.user!.role !== "admin" && req.user!.role !== "manager" && s.assignee_id !== req.user!.sub) return res.status(403).json({ error: "only the assignee or manager can complete" });
  if (s.status !== "assigned") return res.status(409).json({ error: "shift is not assigned" });
  const changed = await repository.completeShift(s.id); if (!changed) return res.status(409).json({ error: "shift is not assigned" });
  await audit(req.user!.sub, "shift.completed", "shift", s.id); res.json({ id: s.id, status: "completed" });
});
app.get("/audit", auth, allow("admin", "manager"), async (req, res) => {
  const rawLimit = Number(req.query.limit ?? 200); const limit = Number.isInteger(rawLimit) ? Math.min(500, Math.max(1, rawLimit)) : 200;
  const action = typeof req.query.action === "string" && req.query.action.length <= 80 ? req.query.action : undefined;
  res.setHeader("x-audit-limit", String(limit)); if (action) res.setHeader("x-audit-action", action);
  return res.json(await repository.listAudit(limit, action));
});
app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => { console.error(err); res.status(500).json({ error: "internal error" }); });
export default app;
