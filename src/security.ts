import crypto from "node:crypto";
import jwt from "jsonwebtoken";

const configuredSecret = process.env.JWT_SECRET;
if (process.env.NODE_ENV === "production" && (!configuredSecret || configuredSecret.length < 32)) {
  throw new Error("JWT_SECRET must be at least 32 characters in production");
}
const secret = configuredSecret ?? "dev-only-secret-change-me-please-32-chars";
export type Role = "admin" | "manager" | "worker";
export type Claims = { sub: string; email: string; role: Role };
export function hashPassword(password: string) {
  const salt = crypto.randomBytes(16).toString("hex");
  const digest = crypto.scryptSync(password, salt, 32).toString("hex");
  return `scrypt$${salt}$${digest}`;
}
export function verifyPassword(password: string, encoded: string) {
  try {
    const [scheme, salt, expected] = encoded.split("$");
    if (scheme !== "scrypt" || !salt || !expected) return false;
    const actual = crypto.scryptSync(password, salt, 32).toString("hex");
    const a = Buffer.from(actual, "hex"); const b = Buffer.from(expected, "hex");
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  } catch { return false; }
}
export function signToken(c: Claims) { return jwt.sign(c, secret, { expiresIn: "2h", issuer: "secureshift" }); }
export function verifyToken(token: string) { return jwt.verify(token, secret, { issuer: "secureshift" }) as Claims; }
export function hashOtp(code: string) { return crypto.createHash("sha256").update(code).digest("hex"); }
