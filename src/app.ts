import express, { NextFunction, Request, Response } from "express";
import cors from "cors";
import crypto from "node:crypto";
import { z } from "zod";
import { db } from "./db.js";
import {
  hashOtp,
  hashPassword,
  verifyPassword,
  signToken,
  verifyToken,
  Claims,
  Role,
} from "./security.js";

const app = express();
const corsOrigins = (process.env.CORS_ORIGINS ?? "")
  .split(",")
  .map((v) => v.trim())
  .filter(Boolean);
app.use(
  cors({
    origin: (origin, callback) => {
      if (
        !origin ||
        (process.env.NODE_ENV !== "production" && corsOrigins.length === 0) ||
        corsOrigins.includes(origin)
      )
        callback(null, true);
      else callback(new Error("origin not allowed"));
    },
  }),
);
app.use(express.json({ limit: "1mb" }));
type Authed = Request & { user?: Claims };
function auth(req: Authed, res: Response, next: NextFunction) {
  const h = req.header("authorization");
  if (!h?.startsWith("Bearer "))
    return res.status(401).json({ error: "missing bearer token" });
  try {
    req.user = verifyToken(h.slice(7));
    next();
  } catch {
    return res.status(401).json({ error: "invalid or expired token" });
  }
}
function allow(...roles: Role[]) {
  return (req: Authed, res: Response, next: NextFunction) => {
    if (!req.user || !roles.includes(req.user.role))
      return res.status(403).json({ error: "insufficient role" });
    next();
  };
}
function audit(
  actor: string,
  action: string,
  type: string,
  id: string,
  meta: unknown = {},
) {
  db.prepare("INSERT INTO audit_logs VALUES (?,?,?,?,?,?,?)").run(
    crypto.randomUUID(),
    actor,
    action,
    type,
    id,
    JSON.stringify(meta),
    new Date().toISOString(),
  );
}
const register = z.object({
  email: z.string().email(),
  password: z.string().min(12),
  role: z.enum(["admin", "manager", "worker"]).default("worker"),
  phone: z.string().optional(),
});
app.get("/health", (_, res) =>
  res.json({
    service: "secureshift",
    status: "ok",
    time: new Date().toISOString(),
  }),
);
app.post("/auth/register", (req, res) => {
  const p = register.safeParse(req.body);
  if (!p.success) return res.status(400).json({ error: p.error.flatten() });
  const id = crypto.randomUUID();
  try {
    db.prepare("INSERT INTO users VALUES (?,?,?,?,?,?)").run(
      id,
      p.data.email.toLowerCase(),
      hashPassword(p.data.password),
      p.data.role,
      p.data.phone ?? null,
      new Date().toISOString(),
    );
    return res.status(201).json({ id, email: p.data.email, role: p.data.role });
  } catch {
    return res.status(409).json({ error: "email already registered" });
  }
});
app.post("/auth/login", (req, res) => {
  const p = z
    .object({ email: z.string().email(), password: z.string() })
    .safeParse(req.body);
  if (!p.success) return res.status(400).json({ error: "invalid credentials" });
  const u = db
    .prepare("SELECT * FROM users WHERE email=?")
    .get(p.data.email.toLowerCase()) as any;
  if (!u || !verifyPassword(p.data.password, u.password_hash))
    return res.status(401).json({ error: "invalid credentials" });
  return res.json({
    token: signToken({ sub: u.id, email: u.email, role: u.role }),
    user: { id: u.id, email: u.email, role: u.role },
  });
});
app.post("/auth/request-otp", auth, (req: Authed, res) => {
  const id = crypto.randomUUID();
  const code = String(Math.floor(100000 + Math.random() * 900000));
  const expires = new Date(Date.now() + 5 * 60_000).toISOString();
  db.prepare("INSERT INTO otp_challenges VALUES (?,?,?,?,NULL)").run(
    id,
    req.user!.sub,
    hashOtp(code),
    expires,
  );
  audit(req.user!.sub, "otp.requested", "otp", id);
  res.status(202).json({
    challengeId: id,
    expiresAt: expires,
    devCode: process.env.NODE_ENV === "production" ? undefined : code,
  });
});
app.post("/auth/verify-otp", auth, (req: Authed, res) => {
  const p = z
    .object({ challengeId: z.string(), code: z.string().length(6) })
    .safeParse(req.body);
  if (!p.success) return res.status(400).json({ error: "invalid payload" });
  const c = db
    .prepare(
      "SELECT * FROM otp_challenges WHERE id=? AND user_id=? AND consumed_at IS NULL",
    )
    .get(p.data.challengeId, req.user!.sub) as any;
  if (
    !c ||
    new Date(c.expires_at) < new Date() ||
    c.code_hash !== hashOtp(p.data.code)
  )
    return res.status(400).json({ error: "invalid or expired code" });
  db.prepare("UPDATE otp_challenges SET consumed_at=? WHERE id=?").run(
    new Date().toISOString(),
    c.id,
  );
  audit(req.user!.sub, "otp.verified", "otp", c.id);
  res.json({ verified: true });
});
const shift = z.object({
  title: z.string().min(2).max(120),
  startsAt: z.string().datetime(),
  endsAt: z.string().datetime(),
  location: z.string().min(2).max(160),
});
app.get("/shifts", auth, (req: Authed, res) => {
  const rows = db.prepare("SELECT * FROM shifts ORDER BY starts_at").all();
  res.json(rows);
});
app.post("/shifts", auth, allow("admin", "manager"), (req: Authed, res) => {
  const p = shift.safeParse(req.body);
  if (!p.success) return res.status(400).json({ error: p.error.flatten() });
  if (new Date(p.data.endsAt) <= new Date(p.data.startsAt))
    return res.status(422).json({ error: "endsAt must be after startsAt" });
  const id = crypto.randomUUID();
  db.prepare("INSERT INTO shifts VALUES (?,?,?,?,?,?,?,?,?)").run(
    id,
    p.data.title,
    p.data.startsAt,
    p.data.endsAt,
    p.data.location,
    "open",
    null,
    req.user!.sub,
    new Date().toISOString(),
  );
  audit(req.user!.sub, "shift.created", "shift", id, p.data);
  res.status(201).json({ id, ...p.data, status: "open" });
});
app.post(
  "/shifts/:id/assign",
  auth,
  allow("admin", "manager"),
  (req: Authed, res) => {
    const p = z.object({ workerId: z.string() }).safeParse(req.body);
    if (!p.success) return res.status(400).json({ error: "workerId required" });
    const worker = db
      .prepare("SELECT id,role FROM users WHERE id=?")
      .get(p.data.workerId) as any;
    if (!worker || worker.role !== "worker")
      return res.status(422).json({ error: "assignee must be a worker" });
    const s = db
      .prepare("SELECT * FROM shifts WHERE id=?")
      .get(req.params.id) as any;
    if (!s) return res.status(404).json({ error: "shift not found" });
    if (s.status !== "open")
      return res
        .status(409)
        .json({ error: "only open shifts can be assigned" });
    db.prepare(
      "UPDATE shifts SET assignee_id=?,status='assigned' WHERE id=?",
    ).run(worker.id, s.id);
    audit(req.user!.sub, "shift.assigned", "shift", s.id, {
      workerId: worker.id,
    });
    res.json({ id: s.id, status: "assigned", assigneeId: worker.id });
  },
);
app.post("/shifts/:id/complete", auth, (req: Authed, res) => {
  const s = db
    .prepare("SELECT * FROM shifts WHERE id=?")
    .get(req.params.id) as any;
  if (!s) return res.status(404).json({ error: "shift not found" });
  if (
    req.user!.role !== "admin" &&
    req.user!.role !== "manager" &&
    s.assignee_id !== req.user!.sub
  )
    return res
      .status(403)
      .json({ error: "only the assignee or manager can complete" });
  if (s.status !== "assigned")
    return res.status(409).json({ error: "shift is not assigned" });
  db.prepare("UPDATE shifts SET status='completed' WHERE id=?").run(s.id);
  audit(req.user!.sub, "shift.completed", "shift", s.id);
  res.json({ id: s.id, status: "completed" });
});
app.get("/audit", auth, allow("admin", "manager"), (req, res) =>
  res.json(
    db
      .prepare("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 200")
      .all(),
  ),
);
app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
  console.error(err);
  res.status(500).json({ error: "internal error" });
});
export default app;
